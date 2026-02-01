use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD};
use crate::layout::INIT_NAME;
use crate::layout::{REPLY_CAP, SCRATCH_VA};
use crate::log;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::min;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, Rights, TCB, VSpace};
use glenda::cap::{
    CSPACE_SLOT, FAULT_SLOT, KERNEL_SLOT, MMIO_SLOT, PLATFORM_SLOT, TCB_SLOT, VSPACE_CAP,
    VSPACE_SLOT,
};
use glenda::error::Error;
use glenda::ipc::utcb;
use glenda::ipc::{MsgFlags, MsgTag};
use glenda::manager::{
    IMemoryService, IProcessManager, IResourceManager, ISlotManager, IVSpaceManager,
    ResourceManager, SlotManager, VSpaceManager,
};
use glenda::mem::Perms;
use glenda::mem::{ENTRY_VA, HEAP_VA, STACK_VA, TRAPFRAME_VA, UTCB_VA};
use glenda::protocol::process as proto;
use glenda::utils::initrd::Initrd;

/// Process Control Block in Factotum
pub struct Process {
    pub pid: usize,
    pub parent_pid: usize,
    pub name: String,

    // Capabilities
    pub tcb: TCB,
    pub vspace: VSpace, // Root VSpace
    pub cnode: CNode,   // Root CNode

    // State
    pub state: ProcessState,
    pub exit_code: usize,
    // Manage process mappings
    pub vspace_mgr: VSpaceManager,
    pub heap_start: usize,
    pub heap_brk: usize,

    pub allocated_slots: Vec<CapPtr>, // 记录 Factotum 为此进程占用的所有槽位
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Suspended,
    Dead,
}

impl Process {
    pub fn new(
        pid: usize,
        parent_pid: usize,
        name: String,
        tcb: TCB,
        vspace: VSpace,
        cnode: CNode,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            name,
            tcb,
            vspace,
            cnode,
            state: ProcessState::Suspended, // Starts suspended until scheduled/loaded
            exit_code: 0,
            vspace_mgr: VSpaceManager::new(vspace),
            heap_start: 0,
            allocated_slots: Vec::new(),
            heap_brk: 0,
        }
    }
}
const SERVICE_PRIORITY: u8 = 252;

pub struct ProcessManager<'a> {
    processes: BTreeMap<usize, Process>,
    next_pid: usize,

    // Self Resources
    root_cnode: CNode,
    endpoint: Endpoint,
    reply_cap: Reply,
    vspace: VSpaceManager,

    resource_mgr: ResourceManager,
    initrd: Initrd<'a>,
    slot_mgr: SlotManager,
}

impl<'a> ProcessManager<'a> {
    pub fn new(
        root_cnode: CNode,
        endpoint: Endpoint,
        reply: Reply,
        resource_mgr: ResourceManager,
        initrd: Initrd<'a>,
    ) -> Self {
        let mut vspace = VSpaceManager::new(VSPACE_CAP);
        // Init self vspace with known regions (to populate shadow tables)
        // 1. Text/Data - Low mem 0x10000+
        vspace.mark_existing(ENTRY_VA);
        // 2. Stack - High mem
        vspace.mark_existing(STACK_VA);
        // 3. Heap
        vspace.mark_existing(HEAP_VA);
        // 4. UTCB
        vspace.mark_existing(UTCB_VA);
        // 5. TrapFrame
        vspace.mark_existing(TRAPFRAME_VA);

        Self {
            processes: BTreeMap::new(),
            next_pid: 1,
            root_cnode,
            endpoint,
            reply_cap: reply,
            vspace,
            resource_mgr,
            initrd,
            slot_mgr: SlotManager::new(root_cnode, 16),
        }
    }

    fn alloc_slot(&mut self) -> Result<CapPtr, Error> {
        glenda::manager::SlotManager::alloc(&mut self.slot_mgr, &mut self.resource_mgr)
    }

    pub fn init(&mut self) -> Result<(), Error> {
        // Use trait interface to spawn
        self.spawn(INIT_NAME).map(|pid| {
            log!("Started init with PID: {}", pid);
        })
    }

    pub fn run(&mut self) -> ! {
        loop {
            let badge = match self.endpoint.recv(REPLY_CAP.cap()) {
                Ok(b) => b,
                Err(e) => {
                    crate::log!("Recv error: {:?}", e);
                    continue;
                }
            };
            let utcb = unsafe { utcb::get() };
            let msg_info = utcb.msg_tag;
            let label = msg_info.label();
            let proto = msg_info.proto();
            let args = utcb.mrs_regs;

            if proto != proto::PROCESS_PROTO {
                self.reply_err(Error::InvalidProtocol);
                continue;
            }

            // Dispatch through trait methods
            let result = match label {
                proto::SPAWN_SERVICE => {
                    let name_len = args[0];
                    let name_res = unsafe { utcb::get() }.read_str(0, name_len);
                    if let Some(name) = name_res {
                        self.spawn(&name).map(Some)
                    } else {
                        Err(Error::InvalidArgs)
                    }
                }
                proto::FORK => self.fork(badge).map(Some),
                proto::EXIT => self.exit(badge, args[0]).map(|_| None),
                proto::SBRK => self.brk(badge, args[0] as isize).map(Some),
                proto::MMAP => self.mmap(badge, &args).map(Some),
                proto::MUNMAP => self.munmap(badge, &args).map(|_| Some(0)),
                _ => Err(Error::InvalidMethod),
            };

            match result {
                Ok(Some(val)) => self.reply_ok(val),
                Ok(None) => {}
                Err(e) => self.reply_err(e),
            }
        }
    }

    fn reply_ok(&self, val: usize) {
        let tag = MsgTag::new(0, 2, MsgFlags::NONE);
        let _ = self.reply_cap.reply(tag, [0, val, 0, 0, 0, 0, 0]);
    }

    fn reply_err(&self, e: Error) {
        let tag = MsgTag::new(0, 1, MsgFlags::NONE);
        let _ = self.reply_cap.reply(tag, [(e as usize) | 1, 0, 0, 0, 0, 0, 0]);
    }

    fn create_inactive_process(&mut self, name: &str) -> Result<Process, Error> {
        let cnode_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::CNode, 0, self.root_cnode, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::VSpace, 0, self.root_cnode, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::TCB, 1, self.root_cnode, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, 1, self.root_cnode, utcb_slot)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, 1, self.root_cnode, trapframe_slot)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, KSTACK_PAGES, self.root_cnode, kstack_slot)?;
        let child_kstack = Frame::from(kstack_slot);

        let pid = self.next_pid;
        self.next_pid += 1;

        child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL)?;
        child_cnode.copy(KERNEL_SLOT, KERNEL_SLOT, Rights::ALL)?;
        child_cnode.copy(PLATFORM_SLOT, PLATFORM_SLOT, Rights::ALL)?;
        child_cnode.copy(MMIO_SLOT, MMIO_SLOT, Rights::ALL)?;
        child_cnode.mint(self.endpoint.cap(), FAULT_SLOT, pid, Rights::ALL)?;

        let mut vspace_mgr = VSpaceManager::new(child_pd);
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;

        vspace_mgr.map_frame(
            child_utcb,
            UTCB_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            &mut self.resource_mgr,
            &mut self.slot_mgr,
            self.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            &mut self.resource_mgr,
            &mut self.slot_mgr,
            self.root_cnode,
        )?;
        vspace_mgr.setup()?;

        Ok(Process::new(pid, 0, name.to_string(), child_tcb, child_pd, child_cnode))
    }
}

impl<'a> IProcessManager for ProcessManager<'a> {
    fn spawn(&mut self, name: &str) -> Result<usize, Error> {
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?.to_vec();

        let process = self.create_inactive_process(name)?;
        let pid = process.pid;

        self.processes.insert(pid, process);

        match self.load_image(pid, &file) {
            Ok((entry, heap)) => {
                let process = self.processes.get_mut(&pid).unwrap();
                process.heap_start = heap;
                process.heap_brk = heap;
                process.tcb.set_registers(entry, STACK_VA)?;
                process.tcb.set_priority(SERVICE_PRIORITY)?;
                process.tcb.resume()?;
                Ok(pid)
            }
            Err(e) => {
                self.processes.remove(&pid);
                Err(e)
            }
        }
    }

    fn fork(&mut self, parent_pid: usize) -> Result<usize, Error> {
        let (heap_start, heap_brk, name) = {
            let p = self.processes.get(&parent_pid).ok_or(Error::NotFound)?;
            (p.heap_start, p.heap_brk, p.name.clone())
        };

        let pid = self.next_pid;
        self.next_pid += 1;

        let cnode_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::CNode, 0, self.root_cnode, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::VSpace, 0, self.root_cnode, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::TCB, 0, self.root_cnode, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, 1, self.root_cnode, utcb_slot)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, 1, self.root_cnode, trapframe_slot)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.alloc_slot()?;
        self.resource_mgr.alloc(CapType::Frame, KSTACK_PAGES, self.root_cnode, kstack_slot)?;
        let child_kstack = Frame::from(kstack_slot);

        let mut child_vspace_mgr = VSpaceManager::new(child_pd);
        child_vspace_mgr.setup()?;

        let self_ptr = self as *mut ProcessManager;
        let root_cnode = self.root_cnode;
        let parent = self.processes.get(&parent_pid).unwrap();

        parent
            .vspace_mgr
            .clone_space(
                &mut child_vspace_mgr,
                unsafe { &mut (*self_ptr).resource_mgr },
                unsafe { &mut (*self_ptr).slot_mgr },
                root_cnode,
                SCRATCH_VA,
                SCRATCH_VA + PGSIZE,
                &mut self.vspace,
            )
            .map_err(|_| Error::UntypeOOM)?;

        child_vspace_mgr.map_frame(
            child_utcb,
            UTCB_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            &mut self.resource_mgr,
            &mut self.slot_mgr,
            root_cnode,
        )?;
        child_vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            &mut self.resource_mgr,
            &mut self.slot_mgr,
            root_cnode,
        )?;

        child_cnode.mint(self.endpoint.cap(), FAULT_SLOT, pid, Rights::ALL)?;
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;

        let mut process = Process::new(pid, parent_pid, name, child_tcb, child_pd, child_cnode);
        process.heap_start = heap_start;
        process.heap_brk = heap_brk;
        process.vspace_mgr = child_vspace_mgr;

        self.processes.insert(pid, process);
        Ok(pid)
    }

    fn exit(&mut self, pid: usize, code: usize) -> Result<(), Error> {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;
            p.tcb.suspend()?;
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }
    fn load_image(&mut self, pid: usize, elf_data: &[u8]) -> Result<(usize, usize), Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidArgs)?;
        let mut max_vaddr = 0;

        let self_ptr = self as *mut ProcessManager;
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let dest_mgr = &mut process.vspace_mgr;
        let objects = unsafe { &mut (*self_ptr).resource_mgr };
        let slots = unsafe { &mut (*self_ptr).slot_mgr };
        let current_vspace = &mut self.vspace;
        let root_cnode = self.root_cnode;

        for phdr in elf.program_headers() {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;

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

            let start_page = vaddr & !(PGSIZE - 1);
            let end_page = (vaddr + mem_size + PGSIZE - 1) & !(PGSIZE - 1);
            let num_pages = (end_page - start_page) / PGSIZE;

            let frame_cap = slots.alloc(objects)?;
            objects.alloc(CapType::Frame, num_pages, root_cnode, frame_cap)?;
            let frame = Frame::from(frame_cap);

            dest_mgr.map_frame(frame, start_page, perms, num_pages, objects, slots, root_cnode)?;
            current_vspace.map_frame(
                frame,
                SCRATCH_VA,
                Perms::READ | Perms::WRITE | Perms::USER,
                num_pages,
                objects,
                slots,
                root_cnode,
            )?;

            let dest_slice = unsafe {
                core::slice::from_raw_parts_mut(SCRATCH_VA as *mut u8, num_pages * PGSIZE)
            };
            dest_slice.fill(0);
            let padding = vaddr - start_page;
            if padding < dest_slice.len() {
                let actual_copy = min(file_size, dest_slice.len() - padding);
                dest_slice[padding..padding + actual_copy]
                    .copy_from_slice(&elf_data[offset..offset + actual_copy]);
            }
            current_vspace.unmap(SCRATCH_VA, num_pages)?;
        }
        Ok((elf.entry_point(), (max_vaddr + PGSIZE - 1) & !(PGSIZE - 1)))
    }
}

impl<'a> IMemoryService for ProcessManager<'a> {
    fn brk(&mut self, pid: usize, incr: isize) -> Result<usize, Error> {
        let root_cnode = self.root_cnode;
        let self_ptr = self as *mut ProcessManager;
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let old_brk = process.heap_brk;
        let new_brk = (old_brk as isize + incr) as usize;

        if new_brk < process.heap_start {
            return Err(Error::InvalidArgs);
        }

        if incr > 0 {
            let start_page = (old_brk + PGSIZE - 1) & !(PGSIZE - 1);
            let end_page = (new_brk + PGSIZE - 1) & !(PGSIZE - 1);

            for vaddr in (start_page..end_page).step_by(PGSIZE) {
                let slot = unsafe { (*self_ptr).alloc_slot()? };
                unsafe { &mut (*self_ptr).resource_mgr }.alloc(
                    CapType::Frame,
                    1,
                    root_cnode,
                    slot,
                )?;
                process.vspace_mgr.map_frame(
                    Frame::from(slot),
                    vaddr,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    1,
                    unsafe { &mut (*self_ptr).resource_mgr },
                    unsafe { &mut (*self_ptr).slot_mgr },
                    root_cnode,
                )?;
            }
        }
        process.heap_brk = new_brk;
        Ok(new_brk)
    }

    fn mmap(&mut self, pid: usize, args: &[usize]) -> Result<usize, Error> {
        let msg_addr = args[0];
        let len = args[1];
        let root_cnode = self.root_cnode;
        let self_ptr = self as *mut ProcessManager;
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;

        let vaddr = if msg_addr == 0 { HEAP_VA + process.heap_brk } else { msg_addr };
        let start_page = vaddr & !(PGSIZE - 1);
        let end_page = (vaddr + len + PGSIZE - 1) & !(PGSIZE - 1);

        for v in (start_page..end_page).step_by(PGSIZE) {
            let slot = unsafe { (*self_ptr).alloc_slot()? };
            unsafe { &mut (*self_ptr).resource_mgr }.alloc(CapType::Frame, 1, root_cnode, slot)?;
            process.vspace_mgr.map_frame(
                Frame::from(slot),
                v,
                Perms::READ | Perms::WRITE | Perms::USER,
                1,
                unsafe { &mut (*self_ptr).resource_mgr },
                unsafe { &mut (*self_ptr).slot_mgr },
                root_cnode,
            )?;
        }
        Ok(vaddr)
    }

    fn munmap(&mut self, pid: usize, args: &[usize]) -> Result<(), Error> {
        let addr = args[0];
        let len = args[1];
        if addr % PGSIZE != 0 {
            return Err(Error::InvalidArgs);
        }
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        process.vspace_mgr.unmap(addr, (len + PGSIZE - 1) / PGSIZE)
    }
}
