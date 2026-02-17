use super::{Process, TLS};
use super::{ProcessState, WarrenManager};
use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD, PT_TLS};
use crate::layout::SCRATCH_VA;
use crate::log;
use core::cmp::min;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CNode, CapPtr, CapType, Frame, Rights, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::ProcessService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::{STACK_BASE, get_trapframe_va, get_utcb_va};
use glenda::utils::align::align_up;
use glenda::utils::manager::VSpaceManager;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

pub const SERVICE_PRIORITY: u8 = 128;

impl<'a> ProcessService for WarrenManager<'a> {
    fn spawn(&mut self, parent_pid: Badge, name: &str) -> Result<usize, Error> {
        log!("Spawning process: {}, parent_pid: {:?}", name, parent_pid);
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?.to_vec();
        let mut process = self.create(name)?;
        process.parent_pid = parent_pid;
        let pid = process.pid;
        self.processes.insert(pid, process);
        match self.exec(pid, &file) {
            Ok((entry, _heap)) => {
                let process = self.processes.get_mut(&pid).unwrap();
                let thread = process.threads.get_mut(&0).unwrap();
                thread.tcb.set_entrypoint(entry, STACK_BASE, 0)?;
                thread.tcb.set_address(get_utcb_va(0), get_trapframe_va(0))?;
                thread.tcb.set_priority(SERVICE_PRIORITY)?;
                thread.tcb.resume()?;
                Ok(pid.bits())
            }
            Err(e) => {
                self.processes.remove(&pid);
                Err(e)
            }
        }
    }

    fn fork(&mut self, parent_pid: Badge) -> Result<usize, Error> {
        log!("Forking process, parent_pid: {:?}", parent_pid);
        let (heap_start, heap_brk, name, stack_base, stack_pages) = {
            let p = self.processes.get(&parent_pid).ok_or(Error::NotFound)?;
            let t = p.threads.get(&0).ok_or(Error::NotFound)?;
            (p.heap_start, p.heap_brk, p.name.clone(), t.stack_base, t.stack_pages)
        };

        let pid = self.alloc_pid()?;

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::CNode,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), cnode_slot),
        )?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::VSpace,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), pd_slot),
        )?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::TCB,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), tcb_slot),
        )?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), utcb_slot),
        )?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), trapframe_slot),
        )?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            CapPtr::concat(self.ctx.root_cnode.cap(), kstack_slot),
        )?;
        let child_kstack = Frame::from(kstack_slot);

        let mut child_vspace_mgr = VSpaceManager::new(child_pd, 0, 0);
        child_vspace_mgr.setup()?;

        let root_cnode = self.ctx.root_cnode;
        let parent = self.processes.get(&parent_pid).unwrap();

        parent
            .vspace_mgr
            .clone_space(
                &mut child_vspace_mgr,
                self.ctx.untyped_mgr,
                self.ctx.cspace_mgr,
                root_cnode,
                SCRATCH_VA,
                SCRATCH_VA + PGSIZE,
                self.ctx.vspace_mgr,
            )
            .map_err(|_| Error::OutOfMemory)?;

        child_vspace_mgr.map_frame(
            child_utcb,
            get_utcb_va(0),
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;
        child_vspace_mgr.map_frame(
            child_trapframe,
            get_trapframe_va(0),
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;

        let badge = Badge::new(pid.bits() << 16);
        child_cnode.mint(self.endpoint.cap(), MONITOR_SLOT, badge, Rights::ALL)?;
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;

        let mut process = Process::new(
            pid,
            parent_pid,
            name,
            child_tcb,
            child_pd,
            child_cnode,
            child_utcb,
            child_vspace_mgr,
            stack_base,
        );
        process.heap_start = heap_start;
        process.heap_brk = heap_brk;
        {
            let thread = process.threads.get_mut(&0).unwrap();
            thread.stack_pages = stack_pages;
        }

        self.processes.insert(pid, process);
        log!("Process forked: parent_pid: {:?}, child_pid: {:?}", parent_pid, pid);
        Ok(pid.bits())
    }

    fn exit(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;
            for (_, thread) in p.threads.iter() {
                thread.tcb.suspend()?;
            }
            log!("Process exited with pid: {:?}, code={}", pid, code);
        } else {
            log!("Failed to find process with pid: {:?}", pid);
        }
        Ok(())
    }

    fn get_pid(&mut self, pid: Badge) -> Result<usize, Error> {
        log!("Get pid: {:?}", pid);
        Ok(pid.bits())
    }

    fn get_ppid(&mut self, pid: Badge) -> Result<usize, Error> {
        log!("Get Ppid: {:?}", pid);
        let p = self.processes.get(&pid).ok_or(Error::NotFound)?;
        let ppid = p.parent_pid;
        Ok(ppid.bits())
    }

    fn get_cnode(&mut self, pid: Badge, target: Badge, _recv: CapPtr) -> Result<CNode, Error> {
        log!("Get CNode: {}", pid);
        let p = self.processes.get(&target).ok_or(Error::NotFound)?;
        if p.parent_pid != pid {
            return Err(Error::PermissionDenied);
        }
        let cnode = p.cnode;
        Ok(cnode)
    }

    fn exec(&mut self, pid: Badge, elf_data: &[u8]) -> Result<(usize, usize), Error> {
        log!("Loading image for pid: {:?}, size: {} KB", pid, elf_data.len() / 1024);
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

                    let frame_cap = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
                    self.ctx.untyped_mgr.alloc(
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
                        self.ctx.untyped_mgr,
                        self.ctx.cspace_mgr,
                        root_cnode,
                    )?;
                    let scratch_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
                    self.ctx.root_cnode.copy(frame_cap, scratch_slot, Rights::ALL)?;
                    let scratch_frame = Frame::from(scratch_slot);

                    let scratch_vaddr = self.ctx.vspace_mgr.map_scratch(
                        scratch_frame,
                        Perms::READ | Perms::WRITE | Perms::USER,
                        num_pages,
                        self.ctx.untyped_mgr,
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

        unsafe {
            core::arch::asm!("fence.i");
        }

        let ep = elf.entry_point();
        let heap = align_up(max_vaddr, PGSIZE);
        log!("Image loaded with entry_point: {:#x}, heap: {:#x}", ep, heap);
        Ok((ep, heap))
    }

    fn kill(&mut self, _pid: Badge, _target: usize) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
}
