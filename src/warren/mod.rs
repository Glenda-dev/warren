mod data;
mod fault;
mod memory;
mod process;
mod resource;
mod server;
mod thread;

use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD, PT_TLS};
use crate::layout::*;
use crate::policy::{ArenaAllocator, MemoryPolicy};
use crate::warren::resource::ResourceRegistry;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use core::cmp::min;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::{
    CNode, CapPtr, CapType, Endpoint, Frame, Kernel, Reply, Rights, TCB, Untyped, VSpace,
};
use glenda::cap::{CONSOLE_SLOT, CSPACE_SLOT, MONITOR_SLOT, TCB_SLOT, VSPACE_SLOT};
use glenda::error::Error;
use glenda::interface::{CSpaceService, VSpaceService};
use glenda::ipc::{Badge, IpcRouter};
use glenda::mem::Perms;
use glenda::mem::{
    ENTRY_VA, HEAP_SIZE, HEAP_VA, STACK_BASE, TRAMPOLINE_VA, get_trapframe_va, get_utcb_va,
};
use glenda::utils::align::{align_down, align_up};
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};

pub use data::*;
pub use thread::TLS;

const SERVICE_PRIORITY: u8 = 252;

pub struct SystemContext<'a> {
    pub vspace_mgr: &'a mut VSpaceManager,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub allocator: &'a mut dyn MemoryPolicy<'a>,
    pub root_cnode: CNode,
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
        vspace_mgr: &'a mut VSpaceManager,
        cspace_mgr: &'a mut CSpaceManager,
        allocator: &'a mut dyn MemoryPolicy<'a>,
        root_cnode: CNode,
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
        // 6. Trampoline
        vspace_mgr.mark_existing(TRAMPOLINE_VA, PGSIZE);

        Self {
            processes: BTreeMap::new(),
            pid: Badge::null(),
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            recv: CapPtr::null(),
            wait_queues: BTreeMap::new(),
            initrd,
            res: ResourceRegistry {
                kernel_cap: Kernel::from(KERNEL_SLOT),
                irq_cap: IRQ_CONTROL_SLOT,
                console_cap: CONSOLE_SLOT,
                untyped_cap: UNTYPED_SLOT,
                bootinfo_cap: BOOTINFO_SLOT,
                endpoints: BTreeMap::new(),
            },
            ctx: SystemContext { vspace_mgr, cspace_mgr, allocator, root_cnode },
            running: false,
            router: IpcRouter::new(),
        }
    }
    fn alloc_pid(&mut self) -> Result<Badge, Error> {
        let next = self.pid.bits().checked_add(1).ok_or(Error::OutOfMemory)?;
        self.pid = Badge::new(next);
        Ok(self.pid)
    }

    fn create(&mut self, name: &str) -> Result<Process, Error> {
        let pid = self.alloc_pid()?;

        let utcb_va = get_utcb_va(0);
        let trapframe_va = get_trapframe_va(0);

        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        let ep_slot = cspace_mgr.alloc(allocator)?;
        // Use pid << 16 | tid (0) for the main thread badge
        let badge = Badge::new(pid.bits() << 16);
        self.ctx.root_cnode.mint(self.endpoint.cap(), ep_slot, badge, Rights::ALL)?;
        let child_endpoint = Endpoint::from(ep_slot);

        let cnode_slot = cspace_mgr.alloc(allocator)?;
        allocator.alloc(CapType::CNode, 0, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = cspace_mgr.alloc(allocator)?;
        allocator.alloc(CapType::VSpace, 0, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        // 为进程分配 Arena 专用的 CNode 和 CSpaceManager
        let arena_cnode_slot = cspace_mgr.alloc(allocator)?;
        allocator.alloc(CapType::CNode, 0, arena_cnode_slot)?;
        let arena_cnode = CNode::from(arena_cnode_slot);

        // 我们需要手动分配第一个二级 CNode，因为 ArenaAllocator 无法递归分配
        let mut arena_cspace_mgr = CSpaceManager::new(arena_cnode, 1);
        let first_l1_slot = CapPtr::concat(arena_cnode.cap(), CapPtr::from(1));
        allocator.alloc(CapType::CNode, 0, first_l1_slot)?;
        arena_cspace_mgr.mark_present(1);

        // 从全局分配器预拨一块内存作为 Arena 的根 Untyped
        let arena_untyped_slot = cspace_mgr.alloc(allocator)?;
        let arena_size_pages = 256; // 1MB 初始大小
        let arena_paddr =
            allocator.alloc(CapType::Untyped, arena_size_pages, arena_untyped_slot)?;
        let arena_untyped = Untyped::from(arena_untyped_slot);

        let mut arena_allocator = ArenaAllocator::new(
            arena_cspace_mgr,
            Some((arena_untyped, arena_paddr, arena_size_pages)),
            arena_size_pages,
        );

        let tcb_slot = cspace_mgr.alloc(allocator)?;
        allocator.alloc(CapType::TCB, 0, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        // 使用 Arena 分配 UTCB, TrapFrame 等资源
        let (_, utcb_slot) = arena_allocator.alloc(1, allocator)?;
        let child_utcb = Frame::from(utcb_slot);

        let (_, trapframe_slot) = arena_allocator.alloc(1, allocator)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let (_, stack_slot) = arena_allocator.alloc(1, allocator)?;
        let child_stack = Frame::from(stack_slot);

        let (_, kstack_slot) = arena_allocator.alloc(KSTACK_PAGES, allocator)?;
        let child_kstack = Frame::from(kstack_slot);

        let (_, heap_slot) = arena_allocator.alloc(1, allocator)?;
        let child_heap = Frame::from(heap_slot);

        child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL)?;
        child_cnode.copy(child_endpoint.cap(), MONITOR_SLOT, Rights::ALL)?;
        child_cnode.copy(self.res.console_cap, CONSOLE_SLOT, Rights::ALL)?;

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
            Perms::READ | Perms::WRITE,
            1,
            allocator,
            cspace_mgr,
        )?;
        vspace_mgr.map_frame(
            child_trapframe,
            trapframe_va,
            Perms::READ | Perms::WRITE | Perms::SUPERVISOR,
            1,
            allocator,
            cspace_mgr,
        )?;
        vspace_mgr.map_frame(
            child_stack,
            STACK_BASE - PGSIZE,
            Perms::READ | Perms::WRITE,
            1,
            allocator,
            cspace_mgr,
        )?;
        vspace_mgr.map_frame(
            child_heap,
            HEAP_VA,
            Perms::READ | Perms::WRITE,
            1,
            allocator,
            cspace_mgr,
        )?;
        vspace_mgr.setup(allocator, cspace_mgr)?;

        let mut process = Process::new(
            pid,
            Badge::null(),
            name.to_string(),
            child_tcb,
            child_pd,
            child_cnode,
            child_utcb,
            vspace_mgr,
            arena_allocator,
            STACK_BASE,
        );
        process.heap_start = HEAP_VA;
        process.heap_brk = HEAP_VA + PGSIZE;

        // 记录在父进程 CSpace 中分配的槽位，以便在进程退出时回收
        process.allocated_slots.insert(ep_slot);
        process.allocated_slots.insert(cnode_slot);
        process.allocated_slots.insert(pd_slot);
        process.allocated_slots.insert(arena_cnode_slot);
        process.allocated_slots.insert(arena_untyped_slot);

        {
            let thread = process.threads.get_mut(&0).unwrap();
            thread.stack_pages = 1;
            thread.allocated_slots.insert(tcb_slot);
            thread.allocated_slots.insert(utcb_slot);
            thread.allocated_slots.insert(trapframe_slot);
            thread.allocated_slots.insert(kstack_slot);
            thread.allocated_slots.insert(stack_slot);
        }

        process.allocated_slots.insert(cnode_slot);
        process.allocated_slots.insert(pd_slot);
        process.allocated_slots.insert(ep_slot);
        process.allocated_slots.insert(heap_slot);
        Ok(process)
    }
    fn load_elf(&mut self, pid: Badge, elf_data: &[u8]) -> Result<(usize, usize), Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidArgs)?;
        let mut max_vaddr = 0;
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
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
            let mut perms = Perms::READ;
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
                    let start_page = align_down(vaddr, PGSIZE);
                    let end_page = align_up(vaddr + mem_size, PGSIZE);
                    let num_pages = (end_page - start_page) / PGSIZE;

                    let global_allocator = &mut *self.ctx.allocator;
                    let cspace_mgr = &mut *self.ctx.cspace_mgr;

                    let (_, frame_cap) =
                        process.arena_allocator.alloc(num_pages, global_allocator)?;
                    let frame = Frame::from(frame_cap);

                    process.vspace_mgr.map_frame(
                        frame,
                        start_page,
                        perms,
                        num_pages,
                        global_allocator,
                        cspace_mgr,
                    )?;
                    process.allocated_slots.insert(frame_cap);

                    let scratch_vaddr = self.ctx.vspace_mgr.map_scratch(
                        frame,
                        Perms::READ | Perms::WRITE,
                        num_pages,
                        global_allocator,
                        cspace_mgr,
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
                    self.ctx.vspace_mgr.unmap(scratch_vaddr, num_pages)?;
                    process.image_slots.insert(frame_cap);
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
            let allocator = &mut *self.ctx.allocator;
            let cspace_mgr = &mut *self.ctx.cspace_mgr;
            for (tid, thread) in p.threads.iter() {
                if let Err(e) = thread.tcb.suspend() {
                    warn!("Failed to suspend thread {} of pid {:?}: {:?}", tid, pid, e);
                }
                // Recycle thread resources
                for slot in thread.allocated_slots.iter() {
                    if let Err(e) = allocator.free(*slot) {
                        warn!("Failed to recycle thread slot {:?}: {:?}", slot, e);
                    }
                    cspace_mgr.free(*slot);
                }
            }

            // Recycle process resources
            for slot in p.allocated_slots.iter() {
                if let Err(e) = allocator.free(*slot) {
                    warn!("Failed to recycle process slot {:?}: {:?}", slot, e);
                }
                cspace_mgr.free(*slot);
            }

            // Recycle VSpace shadow resources
            p.vspace_mgr.drop(allocator, cspace_mgr);

            log!("Process exited: pid: {:?}, code={}", pid, code);
        } else {
            error!("Failed to find process with pid: {:?}", pid);
            return Err(Error::NotFound);
        }
        Ok(())
    }
    pub fn refill_allocator(&mut self) {
        let rev = self.ctx.allocator.reserve_count();
        if rev < LOW_RESERVE {
            warn!("Allocator reserve low: {}. Refilling...", rev);
            for _ in 0..(FULL_RESERVE - self.ctx.allocator.reserve_count()) {
                if let Ok(slot) = self.ctx.cspace_mgr.alloc(self.ctx.allocator) {
                    self.ctx.allocator.add_free_slot(slot);
                } else {
                    break;
                }
            }
        }
    }
}
