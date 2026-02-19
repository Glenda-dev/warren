mod buddy;
mod data;
mod fault;
mod memory;
mod process;
mod resource;
mod server;
mod thread;

pub use self::buddy::BuddyAllocator;
use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD, PT_TLS};
use crate::layout::{
    BOOTINFO_SLOT, IRQ_SLOT, MMIO_SLOT, SCRATCH_SIZE, SCRATCH_VA, STACK_SIZE, UNTYPED_SLOT,
};
use crate::warren::resource::ResourceRegistry;
use crate::{error, log, warn};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use core::cmp::min;
pub use data::*;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, Rights, TCB, Untyped, VSpace};
use glenda::cap::{CSPACE_SLOT, KERNEL_SLOT, MONITOR_SLOT, TCB_SLOT, VSPACE_SLOT};
use glenda::error::Error;
use glenda::ipc::{Badge, IpcRouter};
use glenda::mem::{ENTRY_VA, HEAP_SIZE, HEAP_VA, STACK_BASE};
use glenda::mem::{Perms, get_trapframe_va, get_utcb_va};
use glenda::utils::align::align_up;
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};
pub use thread::TLS;

const SERVICE_PRIORITY: u8 = 252;

pub struct SystemContext<'a> {
    pub root_cnode: CNode,
    pub vspace_mgr: &'a mut VSpaceManager,
    // pub untyped_mgr: &'a mut UntypedManager, // Replaced by buddy
    pub buddy: &'a mut BuddyAllocator,
    pub cspace_mgr: &'a mut CSpaceManager,
}

pub struct WarrenManager<'a> {
    processes: BTreeMap<Badge, Process>,
    pid: Badge,

    // Communication
    endpoint: Endpoint,
    reply: Reply,
    recv: CapPtr,

    // Sync
    wait_queues: BTreeMap<(Badge, usize), VecDeque<CapPtr>>,

    // Initrd
    initrd: Initrd<'a>,

    // Resources
    res: ResourceRegistry,

    // Context
    ctx: SystemContext<'a>,
    running: bool,
    router: IpcRouter<WarrenManager<'a>>,
}

impl<'a> WarrenManager<'a> {
    pub fn new(
        root_cnode: CNode,
        vspace_mgr: &'a mut VSpaceManager,
        buddy: &'a mut BuddyAllocator,
        cspace_mgr: &'a mut CSpaceManager,
        initrd: Initrd<'a>,
    ) -> Self {
        // Init self vspace with known regions (to populate shadow tables)
        // 1. Text/Data - Low mem 0x10000+
        vspace_mgr.mark_existing(ENTRY_VA, PGSIZE);
        // 2. Stack - High mem
        // STACK_BASE is the top address (TRAMPOLINE_VA)
        // Stack grows down, range: [STACK_BASE - STACK_SIZE, STACK_BASE)
        vspace_mgr.mark_existing(STACK_BASE - STACK_SIZE, STACK_SIZE);
        // 3. Heap
        vspace_mgr.mark_existing(HEAP_VA, HEAP_SIZE);
        // 4. UTCB
        vspace_mgr.mark_existing(get_utcb_va(0), PGSIZE);
        // 5. TrapFrame
        vspace_mgr.mark_existing(get_trapframe_va(0), PGSIZE);

        Self {
            processes: BTreeMap::new(),
            pid: Badge::null(),
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            recv: CapPtr::null(),
            wait_queues: BTreeMap::new(),
            initrd,
            res: ResourceRegistry {
                kernel_cap: KERNEL_SLOT,
                irq_cap: IRQ_SLOT,
                mmio_cap: MMIO_SLOT,
                untyped_cap: UNTYPED_SLOT,
                bootinfo_cap: BOOTINFO_SLOT,
                endpoints: BTreeMap::new(),
            },
            ctx: SystemContext { root_cnode, vspace_mgr, buddy, cspace_mgr },
            running: false,
            router: IpcRouter::new(),
        }
    }
    fn alloc_pid(&mut self) -> Result<Badge, Error> {
        let next = self.pid.bits().checked_add(1).ok_or(Error::CNodeFull)?;
        self.pid = Badge::new(next);
        Ok(self.pid)
    }

    pub fn refill_buddy(&mut self) {
        // Maintain at least 128 reserved slots for buddy splitting
        const LOW_RESERVE: usize = 128;
        const FULL_RESERVE: usize = 256;
        if self.ctx.buddy.reserve_count() < LOW_RESERVE {
            for _ in 0..(FULL_RESERVE - self.ctx.buddy.reserve_count()) {
                if let Ok(slot) = self.ctx.cspace_mgr.alloc(self.ctx.buddy) {
                    self.ctx.buddy.add_free_slot(slot);
                } else {
                    break;
                }
            }
        }
    }

    fn create(&mut self, name: &str) -> Result<Process, Error> {
        let pid = self.alloc_pid()?;

        let utcb_va = get_utcb_va(0);
        let trapframe_va = get_trapframe_va(0);

        let ep_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        // Use pid << 16 | tid (0) for the main thread badge
        let badge = Badge::new(pid.bits() << 16);
        self.ctx.root_cnode.mint(self.endpoint.cap(), ep_slot, badge, Rights::ALL)?;
        let child_endpoint = Endpoint::from(ep_slot);

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_cnode_dest = CapPtr::concat(self.ctx.root_cnode.cap(), cnode_slot);
        self.ctx.buddy.alloc(CapType::CNode, 0, full_cnode_dest)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_pd_dest = CapPtr::concat(self.ctx.root_cnode.cap(), pd_slot);
        self.ctx.buddy.alloc(CapType::VSpace, 0, full_pd_dest)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_tcb_dest = CapPtr::concat(self.ctx.root_cnode.cap(), tcb_slot);
        self.ctx.buddy.alloc(CapType::TCB, 0, full_tcb_dest)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_utcb_dest = CapPtr::concat(self.ctx.root_cnode.cap(), utcb_slot);
        self.ctx.buddy.alloc(CapType::Frame, 1, full_utcb_dest)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_tf_dest = CapPtr::concat(self.ctx.root_cnode.cap(), trapframe_slot);
        self.ctx.buddy.alloc(CapType::Frame, 1, full_tf_dest)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let stack_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_stack_dest = CapPtr::concat(self.ctx.root_cnode.cap(), stack_slot);
        self.ctx.buddy.alloc(CapType::Frame, 1, full_stack_dest)?;
        let child_stack = Frame::from(stack_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_kstack_dest = CapPtr::concat(self.ctx.root_cnode.cap(), kstack_slot);
        self.ctx.buddy.alloc(CapType::Frame, KSTACK_PAGES, full_kstack_dest)?;
        let child_kstack = Frame::from(kstack_slot);

        let heap_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let full_heap_dest = CapPtr::concat(self.ctx.root_cnode.cap(), heap_slot);
        self.ctx.buddy.alloc(CapType::Frame, 1, full_heap_dest)?;
        let child_heap = Frame::from(heap_slot);

        child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL)?;
        child_cnode.copy(child_endpoint.cap(), MONITOR_SLOT, Rights::ALL)?;

        // Child process vspace manager doesn't use scratch area from self, or we can give it one?
        // For now, pass 0 size to indicate no scratch area.
        let mut vspace_mgr = VSpaceManager::new(child_pd, SCRATCH_VA, SCRATCH_SIZE);
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;
        // Enable fault handler with badge=pid
        child_tcb.set_fault_handler(child_endpoint, true)?;
        child_tcb.set_address(utcb_va, trapframe_va)?;
        vspace_mgr.map_frame(
            child_utcb,
            utcb_va,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_trapframe,
            trapframe_va,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_stack,
            STACK_BASE - PGSIZE,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_heap,
            HEAP_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.setup()?;

        let mut process = Process::new(
            pid,
            Badge::null(),
            name.to_string(),
            child_tcb, // passed to new and used for thread 0
            child_pd,
            child_cnode,
            child_utcb, // passed to new and used for thread 0
            vspace_mgr,
            STACK_BASE, // passed to new and used for thread 0
        );
        process.heap_start = HEAP_VA;
        process.heap_brk = HEAP_VA + PGSIZE;
        {
            let thread = process.threads.get_mut(&0).unwrap();
            thread.stack_pages = 1;
            thread.allocated_slots.push(tcb_slot);
            thread.allocated_slots.push(utcb_slot);
            thread.allocated_slots.push(trapframe_slot);
            thread.allocated_slots.push(kstack_slot);
            thread.allocated_slots.push(stack_slot);
        }

        process.allocated_slots.push(cnode_slot);
        process.allocated_slots.push(pd_slot);
        process.allocated_slots.push(ep_slot);
        process.allocated_slots.push(heap_slot);
        Ok(process)
    }
    fn load_elf(&mut self, pid: Badge, elf_data: &[u8]) -> Result<(usize, usize), Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidArgs)?;
        let mut max_vaddr = 0;
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let root_cnode = self.ctx.root_cnode;
        let mut _tls = None;
        for phdr in elf.program_headers() {
            let type_ = phdr.p_type as usize;
            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;
            let align = phdr.p_align as usize;

            if vaddr + mem_size > max_vaddr {
                max_vaddr = vaddr + mem_size;
            }
            let mut perms = Perms::USER | Perms::READ;
            if phdr.p_flags & PF_W != 0 {
                perms |= Perms::WRITE;
            }
            if phdr.p_flags & PF_X != 0 {
                perms |= Perms::EXECUTE;
            }

            log!(
                "Loading segment: type={:#x}, vaddr={:#x}, mem_size={:#x}, file_size={:#x}, perms={:?}",
                type_,
                vaddr,
                mem_size,
                file_size,
                perms
            );
            match phdr.p_type {
                PT_LOAD => {
                    let start_page = vaddr & !(PGSIZE - 1);
                    let end_page = (vaddr + mem_size + PGSIZE - 1) & !(PGSIZE - 1);
                    let num_pages = (end_page - start_page) / PGSIZE;

                    let frame_cap = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
                    self.ctx.buddy.alloc(
                        CapType::Frame,
                        num_pages,
                        CapPtr::concat(root_cnode.cap(), frame_cap),
                    )?;
                    let frame = Frame::from(frame_cap);

                    process.vspace_mgr.map_frame(
                        frame,
                        start_page,
                        perms,
                        num_pages,
                        self.ctx.buddy,
                        self.ctx.cspace_mgr,
                        root_cnode,
                    )?;
                    let scratch_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
                    self.ctx.root_cnode.copy(frame_cap, scratch_slot, Rights::ALL)?;
                    let scratch_frame = Frame::from(scratch_slot);

                    let scratch_vaddr = self.ctx.vspace_mgr.map_scratch(
                        scratch_frame,
                        Perms::READ | Perms::WRITE | Perms::USER,
                        num_pages,
                        self.ctx.buddy,
                        self.ctx.cspace_mgr,
                        root_cnode,
                    )?;

                    let dest_slice = unsafe {
                        core::slice::from_raw_parts_mut(
                            scratch_vaddr as *mut u8,
                            num_pages * PGSIZE,
                        )
                    };
                    dest_slice.fill(0);
                    let padding = vaddr - start_page;
                    if padding < dest_slice.len() {
                        let actual_copy = min(file_size, dest_slice.len() - padding);
                        dest_slice[padding..padding + actual_copy]
                            .copy_from_slice(&elf_data[offset..offset + actual_copy]);
                    }
                    self.ctx.vspace_mgr.unmap_scratch(scratch_vaddr, num_pages)?;
                }
                PT_TLS => {
                    _tls = Some(TLS {
                        master_vaddr: vaddr,
                        mem_size: mem_size,
                        align: align,
                        file_size: file_size,
                    });
                }
                _ => {}
            }
        }

        let ep = elf.entry_point();
        let heap = align_up(max_vaddr, PGSIZE);
        log!("Image loaded with entry_point: {:#x}, heap: {:#x}", ep, heap);
        Ok((ep, heap))
    }

    fn exit_wrapper(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;

            // Suspend and cleanup threads
            for (_, thread) in p.threads.iter() {
                thread.tcb.suspend()?;
                // Recycle thread resources
                for slot in thread.allocated_slots.iter() {
                    self.ctx.root_cnode.revoke(*slot)?;
                    match self.ctx.root_cnode.recycle(*slot) {
                        Ok(pages) => {
                            if pages > 0 {
                                let order = (pages * PGSIZE).ilog2() as usize;
                                self.ctx.buddy.add_block(Untyped::from(*slot), order);
                            } else {
                                match self.ctx.root_cnode.delete(*slot) {
                                    Ok(()) => {
                                        self.ctx.cspace_mgr.free(*slot)?;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to delete slot {}: {:?}, skipping free",
                                            slot, e
                                        );
                                        Err(e)?;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to recycle slot {:?}: {:?}, deleting instead", slot, e);
                            // FIXME
                            match self.ctx.root_cnode.delete(*slot) {
                                Ok(()) => {
                                    self.ctx.cspace_mgr.free(*slot)?;
                                }
                                Err(e) => {
                                    warn!("Failed to delete slot {}: {:?}, skipping free", slot, e);
                                    Err(e)?;
                                }
                            }
                        }
                    }
                }
            }

            // Recycle process resources
            for slot in p.allocated_slots.iter() {
                self.ctx.root_cnode.revoke(*slot)?;
                match self.ctx.root_cnode.recycle(*slot) {
                    Ok(pages) => {
                        if pages > 0 {
                            let order = (pages * PGSIZE).ilog2() as usize;
                            self.ctx.buddy.add_block(Untyped::from(*slot), order);
                        } else {
                            self.ctx.root_cnode.delete(*slot)?;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to recycle slot {}: {:?}, deleting instead", slot, e);
                        self.ctx.root_cnode.delete(*slot)?;
                    }
                }
                // Always free the slot from CSpaceManager to prevent leaks
                self.ctx.cspace_mgr.free(*slot)?;
            }
            log!("Process exited: pid: {:?}, code={}", pid, code);
        } else {
            error!("Failed to find process with pid: {:?}", pid);
            return Err(Error::NotFound);
        }
        Ok(())
    }
}
