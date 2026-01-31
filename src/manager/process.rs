use super::{ResourceManager, SlotManager, VSpaceManager};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use crate::layout::INIT_NAME;
use crate::layout::{ENDPOINT_SLOT, REPLY_CAP, SCRATCH_VA, SCRATCH_VA2};
use crate::log;
use crate::process::{Process, ProcessState};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, Rights, TCB, VSpace};
use glenda::cap::{CONSOLE_SLOT, CSPACE_SLOT, TCB_SLOT, VSPACE_CAP, VSPACE_SLOT};
use glenda::error::{Error, code};
use glenda::ipc::utcb;
use glenda::ipc::{MsgFlags, MsgTag};
use glenda::mem::Perms;
use glenda::mem::{ENTRY_VA, HEAP_VA, STACK_VA};
use glenda::protocol::process as proto;
use glenda::runtime::MMIO_SLOT;
use glenda::runtime::initrd::Initrd;
use glenda::runtime::service::PLATFORM_SLOT;
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

        Self {
            processes: BTreeMap::new(),
            next_pid: 1,
            root_cnode,
            endpoint,
            reply_cap: REPLY_CAP,
            vspace,
            resource_mgr,
            initrd,
            slot_mgr: SlotManager::new(root_cnode, 101),
        }
    }

    fn alloc_slot(&mut self) -> Result<CapPtr, Error> {
        self.slot_mgr.alloc(&mut self.resource_mgr)
    }

    pub fn init(&mut self) -> Result<(), Error> {
        // Init 9ball (Init/Root service)
        match self.spawn_service_initrd(INIT_NAME.to_string()) {
            Ok(pid) => {
                // Should we log?
                log!("Started init with PID: {}", pid);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn run(&mut self) -> ! {
        loop {
            // Receive message, putting reply cap in REPLY_SLOT
            let badge = self.endpoint.recv(REPLY_CAP.cap());

            // Get message info from UTCB
            let utcb = unsafe { utcb::get() };
            let msg_info = utcb.msg_tag;
            let label = msg_info.label();
            let proto = msg_info.proto();
            let args = utcb.mrs_regs;

            if proto != proto::PROCESS_PROTO {
                // Invalid protocol
                self.reply_err(Error::InvalidProtocol);
                continue;
            }

            // Dispatch
            let result = self.dispatch(badge, label, &args);

            // Reply
            match result {
                Ok(Some(val)) => {
                    self.reply_ok(val);
                }
                Ok(None) => {
                    // Process exited or asynchronous operation; do NOT reply.
                    // If we try to reply to a dead TCB, cap invocation fails.
                }
                Err(e) => {
                    self.reply_err(e);
                }
            }
        }
    }

    fn reply_ok(&self, val: usize) {
        let utcb = unsafe { utcb::get() };
        utcb.mrs_regs[0] = 0; // OK
        utcb.mrs_regs[1] = val;
        let tag = MsgTag::new(0, 2, MsgFlags::NONE);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn reply_err(&self, err: Error) {
        let utcb = unsafe { utcb::get() };
        utcb.mrs_regs[0] = err as usize;
        let tag = MsgTag::new(0, 1, MsgFlags::NONE);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn dispatch(
        &mut self,
        badge: usize,
        label: usize,
        args: &[usize],
    ) -> Result<Option<usize>, Error> {
        match label {
            proto::SPAWN_SERVICE => {
                let name_len = args[0];
                // 1. Read name from UTCB
                let utcb = unsafe { utcb::get() };
                let name = utcb.read_str(0, name_len).ok_or(Error::InvalidParam)?; // Assuming name is path for now
                self.spawn_service_initrd(name).map(Some)
            }
            proto::FORK => self.fork_process(badge).map(Some),
            proto::EXIT => {
                let code = args[0];
                self.exit_process(badge, code);
                // Exit successful, but do NOT reply because the thread is dead/suspended.
                Ok(None)
            }
            proto::SBRK => {
                let incr = args[0] as isize;
                self.sys_brk(badge, incr).map(Some)
            }
            proto::MMAP => {
                // args: [addr, len, prot, flags, fd, offset]
                self.mmap(badge, args).map(Some)
            }
            proto::MUNMAP => self.munmap(badge, args).map(Some),
            _ => Err(Error::InvalidMethod),
        }
    }

    fn spawn_service_initrd(&mut self, name: String) -> Result<usize, Error> {
        // 1. Find file in Initrd
        let file = self.initrd.get_file(&name).ok_or(Error::InvalidParam)?;

        // 2. Create Process Structures (allocating in Factotum CNode)
        let cnode_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::CNode, 0, self.root_cnode, cnode_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::VSpace, 0, self.root_cnode, pd_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::TCB, 1, self.root_cnode, tcb_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_tcb = TCB::from(tcb_slot);

        let pid = self.next_pid;
        self.next_pid += 1;

        // 3. Setup CSpace
        if child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.copy(CONSOLE_SLOT, CONSOLE_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.copy(PLATFORM_SLOT, PLATFORM_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.copy(MMIO_SLOT, MMIO_SLOT, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }
        if child_cnode.mint(self.endpoint.cap(), ENDPOINT_SLOT, pid, Rights::ALL) != code::SUCCESS {
            return Err(Error::CNodeFull);
        }

        // 4. Init child VSpace
        let mut vspace_mgr = VSpaceManager::new(child_pd);

        let (entry_point, heap_start) = Self::load_elf(
            &file,
            &mut vspace_mgr,
            &mut self.resource_mgr,
            self.root_cnode,
            &mut self.slot_mgr,
            &mut self.vspace,
        )?;

        child_tcb.configure(
            child_cnode,
            child_pd,
            Frame::from(CapPtr::from(0)),
            Frame::from(CapPtr::from(0)),
            Frame::from(CapPtr::from(0)),
        );

        child_tcb.set_registers(entry_point, STACK_VA);
        child_tcb.set_priority(SERVICE_PRIORITY);
        child_tcb.resume();

        let mut process = Process::new(pid, 0, name.to_string(), child_tcb, child_pd, child_cnode);
        process.heap_start = heap_start;
        process.heap_brk = heap_start;
        self.processes.insert(pid, process);

        Ok(pid)
    }

    fn fork_process(&mut self, parent_pid: usize) -> Result<usize, Error> {
        let (heap_start, heap_brk, name) = {
            let p = self.processes.get(&parent_pid).ok_or(Error::InvalidParam)?;
            (p.heap_start, p.heap_brk, p.name.clone() + "(child)")
        };

        // Alloc child resources
        let pid = self.next_pid;
        self.next_pid += 1;

        let cnode_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::CNode, 0, self.root_cnode, cnode_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::VSpace, 0, self.root_cnode, pd_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.alloc_slot()?;
        self.resource_mgr
            .alloc(CapType::TCB, 0, self.root_cnode, tcb_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_tcb = TCB::from(tcb_slot);

        let mut _child_vspace_mgr = VSpaceManager::new(child_pd);

        // unsafe workaround for double borrow
        let res_mgr_ptr = &mut self.resource_mgr as *mut ResourceManager;
        let slot_mgr_ptr = &mut self.slot_mgr as *mut SlotManager;
        let vspace_ptr = &mut self.vspace as *mut VSpaceManager;
        let root_cnode = self.root_cnode;

        let parent = self.processes.get(&parent_pid).unwrap(); // Checked above

        let mut get_slot = |rm: &mut ResourceManager| unsafe { (&mut *slot_mgr_ptr).alloc(rm) };

        let mut child_vspace_mgr = VSpaceManager::new(child_pd);

        parent
            .vspace_mgr
            .clone_space(
                &mut child_vspace_mgr,
                unsafe { &mut *res_mgr_ptr },
                root_cnode,
                &mut get_slot,
                SCRATCH_VA,
                SCRATCH_VA2,
                unsafe { &mut *vspace_ptr },
            )
            .map_err(|_| Error::UntypeOOM)?;

        // Mint Endpoint
        if child_cnode.mint(self.endpoint.cap(), ENDPOINT_SLOT, pid, Rights::ALL) != 0 {
            return Err(Error::CNodeFull);
        }

        // Configure TCB - Minimal config
        child_tcb.configure(
            child_cnode,
            child_pd,
            Frame::from(CapPtr::from(0)),
            Frame::from(CapPtr::from(0)),
            Frame::from(CapPtr::from(0)),
        );

        let mut process = Process::new(pid, parent_pid, name, child_tcb, child_pd, child_cnode);
        process.heap_start = heap_start;
        process.heap_brk = heap_brk;
        process.vspace_mgr = child_vspace_mgr;

        self.processes.insert(pid, process);

        Ok(pid)
    }

    fn exit_process(&mut self, pid: usize, code: usize) {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;
            p.tcb.suspend();
            log!("Process {} exited with code {}", pid, code);
        }
    }

    fn sys_brk(&mut self, pid: usize, incr: isize) -> Result<usize, Error> {
        // Pointers for disjoint borrow
        let resource_mgr_ptr = &mut self.resource_mgr as *mut ResourceManager;
        let slot_mgr_ptr = &mut self.slot_mgr as *mut SlotManager;
        let root_cnode = self.root_cnode;

        let process = self.processes.get_mut(&pid).ok_or(Error::InvalidParam)?;
        // Current implementation: Just update limit. Lazy allocation on Fault?
        // Or eager allocation.
        // Given we don't handle faults fully yet, eager allocation is safer if incr > 0.

        let old_brk = process.heap_brk;
        let new_brk = (old_brk as isize + incr) as usize;

        if new_brk < process.heap_start {
            return Err(Error::InvalidParam);
        }

        if incr > 0 {
            // Allocate pages
            // Round up to page boundary
            let start_page = (old_brk + PGSIZE - 1) & !(PGSIZE - 1);
            let end_page = (new_brk + PGSIZE - 1) & !(PGSIZE - 1);

            for vaddr in (start_page..end_page).step_by(PGSIZE) {
                // Inline alloc_slot
                let slot = unsafe { (&mut *slot_mgr_ptr).alloc(&mut *resource_mgr_ptr)? };

                unsafe { &mut *resource_mgr_ptr }
                    .alloc(CapType::Frame, 1, root_cnode, slot)
                    .map_err(|_| Error::UntypeOOM)?;
                let frame = Frame::from(slot);
                let perms = Perms::READ | Perms::WRITE | Perms::USER; // Heap is RW
                process
                    .vspace_mgr
                    .map_frame(
                        frame,
                        vaddr,
                        perms,
                        1,
                        unsafe { &mut *resource_mgr_ptr },
                        root_cnode,
                        |rm| unsafe { (&mut *slot_mgr_ptr).alloc(rm) },
                    )
                    .map_err(|_| Error::MappingFailed)?;
            }
        } else {
            // Dealloc unused pages?
            // Simplest is ignoring (leak/keep mapped).
        }

        process.heap_brk = new_brk;
        Ok(new_brk)
    }

    fn mmap(&mut self, pid: usize, args: &[usize]) -> Result<usize, Error> {
        // [addr, len, prot, flags, fd, offset]
        // Ignore fd/offset for anonymous.
        // We only support Anon RW for now.
        let msg_addr = args[0];
        let len = args[1];

        // Pointers for disjoint borrow
        let resource_mgr_ptr = &mut self.resource_mgr as *mut ResourceManager;
        let slot_mgr_ptr = &mut self.slot_mgr as *mut SlotManager;
        let root_cnode = self.root_cnode;

        let process = self.processes.get_mut(&pid).ok_or(Error::InvalidParam)?;

        // ... omitted ...
        // Find suitable address if addr=0
        let vaddr = if msg_addr == 0 {
            // Simple bump allocator for mmap area?
            // Or use heap_brk + offset?
            // Lets assume high memory 0x40000000
            HEAP_VA + process.heap_brk // Hack
        } else {
            msg_addr
        };

        // Eager map
        let start_page = vaddr & !(PGSIZE - 1);
        let end_page = (vaddr + len + PGSIZE - 1) & !(PGSIZE - 1);

        for v in (start_page..end_page).step_by(PGSIZE) {
            // Inline alloc_slot
            let slot = unsafe { (&mut *slot_mgr_ptr).alloc(&mut *resource_mgr_ptr)? };

            unsafe { &mut *resource_mgr_ptr }
                .alloc(CapType::Frame, 1, root_cnode, slot)
                .map_err(|_| Error::UntypeOOM)?;
            let frame = Frame::from(slot);
            process
                .vspace_mgr
                .map_frame(
                    frame,
                    v,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    1,
                    unsafe { &mut *resource_mgr_ptr },
                    root_cnode,
                    |rm| unsafe { (&mut *slot_mgr_ptr).alloc(rm) },
                )
                .map_err(|_| Error::MappingFailed)?;
        }

        Ok(vaddr)
    }

    fn munmap(&mut self, pid: usize, args: &[usize]) -> Result<usize, Error> {
        let addr = args[0];
        let len = args[1];

        if addr % PGSIZE != 0 {
            return Err(Error::InvalidParam);
        }

        let process = self.processes.get_mut(&pid).ok_or(Error::InvalidParam)?;
        let num_pages = (len + PGSIZE - 1) / PGSIZE;

        process.vspace_mgr.unmap(addr, num_pages);

        Ok(0)
    }

    fn load_elf(
        elf_data: &[u8],
        dest_mgr: &mut VSpaceManager,
        resource_mgr: &mut ResourceManager,
        root_cnode: CNode,
        slot_mgr: &mut SlotManager,
        vspace: &mut VSpaceManager,
    ) -> Result<(usize, usize), Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidParam)?;
        let mut max_vaddr = 0;

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

            log!(
                "Loading segment: vaddr=0x{:x}, mem_size=0x{:x}, file_size=0x{:x}, offset=0x{:x}, perms={:?}",
                vaddr,
                mem_size,
                file_size,
                offset,
                perms
            );

            for page_vaddr in (start_page..end_page).step_by(PGSIZE) {
                // Alloc Frame in Factotum
                let frame_cap = slot_mgr.alloc(resource_mgr)?;

                resource_mgr
                    .alloc(CapType::Frame, 1, root_cnode, frame_cap)
                    .map_err(|_| Error::UntypeOOM)?;
                let frame = Frame::from(frame_cap);

                // Map to Self (Scratch) using vspace manager
                // Note: We use SCRATCH_VA. vspace must know about existing PTs to avoid re-mapping.
                vspace
                    .map_frame(
                        frame,
                        SCRATCH_VA,
                        Perms::READ | Perms::WRITE,
                        1,
                        resource_mgr,
                        root_cnode,
                        |rm| slot_mgr.alloc(rm),
                    )
                    .map_err(|_| Error::MappingFailed)?;

                // Copy Data
                let dest_slice =
                    unsafe { core::slice::from_raw_parts_mut(SCRATCH_VA as *mut u8, PGSIZE) };
                dest_slice.fill(0);

                let offset_in_segment = page_vaddr.saturating_sub(vaddr);
                if offset_in_segment < file_size {
                    let copy_start = if page_vaddr < vaddr { vaddr - page_vaddr } else { 0 };
                    let copy_len =
                        core::cmp::min(PGSIZE - copy_start, file_size - offset_in_segment);
                    let src_offset = offset + offset_in_segment + copy_start;
                    dest_slice[copy_start..copy_start + copy_len]
                        .copy_from_slice(&elf_data[src_offset..src_offset + copy_len]);
                }
                // Clear shadow entry for SCRATCH_VA
                vspace.unmap(SCRATCH_VA, 1);

                // Map to Child
                dest_mgr
                    .map_frame(
                        frame,
                        page_vaddr,
                        perms.clone(),
                        1,
                        resource_mgr,
                        root_cnode,
                        |rm| slot_mgr.alloc(rm),
                    )
                    .map_err(|_| Error::MappingFailed)?;
            }
        }

        let heap_start = (max_vaddr + PGSIZE - 1) & !(PGSIZE - 1);
        Ok((elf.entry_point(), heap_start))
    }
}
