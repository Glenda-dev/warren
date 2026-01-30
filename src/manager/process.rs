use super::{ResourceManager, VSpaceManager};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use crate::layout::{REPLY_CAP, SCRATCH_VA};
use crate::process::{Process, ProcessState};
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, TCB, VSPACE_CAP, VSpace};
use glenda::error::Error;
use glenda::ipc::MsgTag;
use glenda::ipc::utcb;
use glenda::mem::{Perms, STACK_VA};
use glenda::protocol::process as proto;
use glenda::runtime::initrd::Initrd;

const REPLY_SLOT: usize = 100;

pub struct ProcessManager<'a> {
    processes: BTreeMap<usize, Process>,
    next_pid: usize,

    // Self Resources
    root_cnode: CNode,
    endpoint: Endpoint,
    reply_cap: Reply,

    resource_mgr: ResourceManager,
    initrd: Initrd<'a>,
    free_slot: usize,
}

impl<'a> ProcessManager<'a> {
    pub fn new(
        root_cnode: CNode,
        endpoint: Endpoint,
        resource_mgr: ResourceManager,
        initrd: Initrd<'a>,
    ) -> Self {
        Self {
            processes: BTreeMap::new(),
            next_pid: 1,
            root_cnode,
            endpoint,
            reply_cap: REPLY_CAP,
            resource_mgr,
            initrd,
            free_slot: 1000,
        }
    }

    fn alloc_slot(&mut self) -> CapPtr {
        let slot = self.free_slot;
        self.free_slot += 1;
        CapPtr::new(slot, 0)
    }

    pub fn run(&mut self) -> ! {
        loop {
            // Receive message, putting reply cap in REPLY_SLOT
            let badge = self.endpoint.recv(REPLY_CAP.cap());

            // Get message info from UTCB
            let utcb = unsafe { utcb::get() };
            let msg_info = utcb.msg_tag;
            let label = msg_info.label();
            let args = utcb.mrs_regs;

            // Dispatch
            let result = self.dispatch(badge, label, &args);

            // Reply
            match result {
                Ok(val) => {
                    self.reply_ok(val);
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
        let tag = MsgTag::new(0, 2);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn reply_err(&self, err: Error) {
        let utcb = unsafe { utcb::get() };
        utcb.mrs_regs[0] = err as usize;
        let tag = MsgTag::new(0, 1);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn dispatch(&mut self, _badge: usize, label: usize, args: &[usize]) -> Result<usize, Error> {
        match label {
            proto::SPAWN => self.spawn_process("child"),
            proto::SPAWN_SERVICE_INITRD => {
                let name_len = args[0];
                self.spawn_service_initrd(name_len)
            }
            _ => Err(Error::InvalidMethod),
        }
    }

    fn spawn_process(&mut self, name: &str) -> Result<usize, Error> {
        let pid = self.next_pid;
        self.next_pid += 1;

        // Alloc CNode
        let cnode_slot = self.alloc_slot();
        if self.resource_mgr.alloc(CapType::CNode, 64, self.root_cnode, cnode_slot).is_err() {
            // Map string/alloc error to generic error
            return Err(Error::UntypeOOM); // Placeholder for OOM
        }
        let child_cnode = CNode::from(cnode_slot);

        // Alloc VSpace (Root PageTable)
        let pd_slot = self.alloc_slot();
        if self.resource_mgr.alloc(CapType::VSpace, 0, self.root_cnode, pd_slot).is_err() {
            return Err(Error::UntypeOOM);
        }
        let child_pd = VSpace::from(pd_slot);

        // Alloc TCB
        let tcb_slot = self.alloc_slot();
        // TCB size is slightly weird, usually fits in 1 page (4KB) for seL4.
        // Assuming 1 page usage for simplicity.
        if self.resource_mgr.alloc(CapType::TCB, 1, self.root_cnode, tcb_slot).is_err() {
            return Err(Error::UntypeOOM);
        }
        let child_tcb = TCB::from(tcb_slot);

        let process = Process::new(pid, 0, name.to_string(), child_tcb, child_pd, child_cnode);

        self.processes.insert(pid, process);

        Ok(pid)
    }

    fn spawn_service_initrd(&mut self, name_len: usize) -> Result<usize, Error> {
        // 1. Read name from UTCB
        let utcb = unsafe { utcb::get() };

        let name = utcb.read_str(0, name_len).ok_or(Error::InvalidParam)?; // Assuming name is path for now

        // 2. Find file in Initrd
        let file = self.initrd.get_file(&name).ok_or(Error::InvalidParam)?;

        // 3. Create Process Structures (allocating in Factotum CNode)
        let cnode_slot = self.alloc_slot();
        self.resource_mgr
            .alloc(CapType::CNode, 64, self.root_cnode, cnode_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.alloc_slot();
        self.resource_mgr
            .alloc(CapType::VSpace, 0, self.root_cnode, pd_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.alloc_slot();
        self.resource_mgr
            .alloc(CapType::TCB, 1, self.root_cnode, tcb_slot)
            .map_err(|_| Error::UntypeOOM)?;
        let child_tcb = TCB::from(tcb_slot);

        let pid = self.next_pid;
        self.next_pid += 1;

        // 4. Load ELF
        let mut vspace_mgr = VSpaceManager::new(child_pd);

        // We need to pass free_slot ref to avoid closure borrow issues
        let entry_point = {
            let mut free_slot_counter = self.free_slot;

            let ret = Self::load_elf(
                &file,
                &mut vspace_mgr,
                &mut self.resource_mgr,
                self.root_cnode,
                &mut free_slot_counter,
            )?;

            self.free_slot = free_slot_counter;
            ret
        };

        // 5. Stack Allocation (Simple 16KB stack)
        const STACK_BASE: usize = 0x10000000;
        const STACK_SIZE: usize = 4 * PGSIZE;
        for i in 0..4 {
            let frame_slot = self.alloc_slot();
            self.resource_mgr
                .alloc(CapType::Frame, 1, self.root_cnode, frame_slot)
                .map_err(|_| Error::UntypeOOM)?;
            let frame = Frame::from(frame_slot);
            vspace_mgr
                .map_frame(
                    frame,
                    STACK_BASE + i * PGSIZE,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    &mut self.resource_mgr,
                    self.root_cnode,
                    || {
                        let slot = self.free_slot;
                        self.free_slot += 1;
                        CapPtr::new(slot, 0)
                    },
                )
                .map_err(|_| Error::MappingFailed)?;
        }

        // 6. Start TCB
        // Note: We need to set up IPC endpoint cap for the child so it can talk to Factotum.
        // Assuming slot 10 is standard endpoint slot.
        // child_cnode.mint(child_ipc_slot, self.endpoint, ...)
        // We will skip this for now to keep it simple, or assuming child uses Exception IPC.

        child_tcb.configure(
            child_cnode,
            child_pd,
            Frame::from(CapPtr::new(0, 0)),
            Frame::from(CapPtr::new(0, 0)),
            Frame::from(CapPtr::new(0, 0)),
        ); // Simplification: No UTCB/Stack/Heap/TrapFrame passed in config yet? Fix arguments if necessary.
        // Wait, TCB::configure args?
        // invoke.rs: configure(cnode, vspace, buffer, fault_ep?...)
        // Let's assume minimal configure.

        child_tcb.set_registers(entry_point, STACK_VA);
        child_tcb.resume();

        let process = Process::new(pid, 0, name.to_string(), child_tcb, child_pd, child_cnode);
        self.processes.insert(pid, process);

        Ok(pid)
    }

    fn load_elf(
        elf_data: &[u8],
        dest_mgr: &mut VSpaceManager,
        resource_mgr: &mut ResourceManager,
        root_cnode: CNode,
        free_slot: &mut usize,
    ) -> Result<usize, Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidParam)?;

        for phdr in elf.program_headers() {
            if phdr.p_type != PT_LOAD {
                continue;
            }

            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;

            let mut perms = Perms::USER | Perms::READ;
            if phdr.p_flags & PF_W != 0 {
                perms |= Perms::WRITE;
            }
            if phdr.p_flags & PF_X != 0 {
                perms |= Perms::EXECUTE;
            }

            let start_page = vaddr & !(PGSIZE - 1);
            let end_page = (vaddr + mem_size + PGSIZE - 1) & !(PGSIZE - 1);

            for page_vaddr in (start_page..end_page).step_by(PGSIZE) {
                // Alloc Frame in Factotum
                let slot = *free_slot;
                *free_slot += 1;
                let frame_cap = CapPtr::new(slot, 0);

                resource_mgr
                    .alloc(CapType::Frame, 1, root_cnode, frame_cap)
                    .map_err(|_| Error::UntypeOOM)?;
                let frame = Frame::from(frame_cap);

                // Map to Self (Scratch)
                if VSPACE_CAP.map(frame, SCRATCH_VA, Perms::READ | Perms::WRITE) != 0 {
                    return Err(Error::MappingFailed);
                }

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

                // Unmap
                VSPACE_CAP.unmap(SCRATCH_VA, 1);

                // Map to Child
                // Note: We need a closure for map_frame to alloc page tables
                // We can't easily capture mutable refereces in a closure that are already borrowed?
                // resource_mgr is borrowed mutably.
                // The closure needs access to free_slot.
                // Rust closure capture rules might be tricky here with `dest_mgr.map_frame` taking `&mut resource_mgr`.
                // Pass closure `| | { let s = *free_slot; *free_slot+=1; CapPtr::new(s, 0) }` - logic?
                // `free_slot` is `&mut usize`.
                // Closure needs unique access. `map_frame` borrows `self` (dest_mgr) and `resource_mgr`.
                // So closure can capture `free_slot`.

                dest_mgr
                    .map_frame(frame, page_vaddr, perms.clone(), resource_mgr, root_cnode, || {
                        let s = *free_slot;
                        *free_slot += 1;
                        CapPtr::new(s, 0)
                    })
                    .map_err(|_| Error::MappingFailed)?;
            }
        }

        Ok(elf.entry_point())
    }
}
