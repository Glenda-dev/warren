use super::{Process, TLS};
use super::{ProcessManager, ProcessState};
use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD, PT_TLS};
use crate::layout::SCRATCH_VA;
use crate::log;
use core::cmp::min;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CNode, CapType, Frame, Rights, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::manager::VSpaceManager;
use glenda::mem::Perms;
use glenda::mem::{STACK_VA, TRAPFRAME_VA, UTCB_VA};
use glenda::utils::align::align_up;

pub const SERVICE_PRIORITY: u8 = 128;

impl<'a> ProcessService for ProcessManager<'a> {
    fn spawn(&mut self, name: &str) -> Result<usize, Error> {
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?.to_vec();
        let process = self.create(name)?;
        let pid = process.pid;
        self.processes.insert(pid, process);
        match self.load_image(pid, &file) {
            Ok((entry, heap)) => {
                let process = self.processes.get_mut(&pid).unwrap();
                process.setup_heap(heap, 0)?;
                process.tcb.set_entrypoint(entry, STACK_VA)?;
                process.tcb.set_priority(SERVICE_PRIORITY)?;
                process.tcb.resume()?;
                Ok(pid.bits())
            }
            Err(e) => {
                self.processes.remove(&pid);
                Err(e)
            }
        }
    }

    fn fork(&mut self, parent_pid: Badge) -> Result<usize, Error> {
        let (heap_start, heap_brk, name, stack_base, stack_pages) = {
            let p = self.processes.get(&parent_pid).ok_or(Error::NotFound)?;
            (p.heap_start, p.heap_brk, p.name.clone(), p.stack_base, p.stack_pages)
        };

        let pid = self.alloc_pid()?;

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::CNode, 0, self.ctx.root_cnode, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::VSpace, 0, self.ctx.root_cnode, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::TCB, 0, self.ctx.root_cnode, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, utcb_slot)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, trapframe_slot)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            self.ctx.root_cnode,
            kstack_slot,
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
                self.ctx.resource_mgr,
                self.ctx.cspace_mgr,
                root_cnode,
                SCRATCH_VA,
                SCRATCH_VA + PGSIZE,
                self.ctx.vspace_mgr,
            )
            .map_err(|_| Error::OutOfMemory)?;

        child_vspace_mgr.map_frame(
            child_utcb,
            UTCB_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;
        child_vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;

        child_cnode.mint(self.endpoint.cap(), MONITOR_SLOT, pid, Rights::ALL)?;
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
        process.stack_pages = stack_pages;

        self.processes.insert(pid, process);
        Ok(pid.bits())
    }

    fn exit(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;
            p.tcb.suspend()?;
            log!("Process exited with pid: {}, code={}", pid, code);
        } else {
            log!("Failed to find process with pid: {}", pid);
        }
        unreachable!();
        Err(Error::Success)
    }
    fn load_image(&mut self, pid: Badge, elf_data: &[u8]) -> Result<(usize, usize), Error> {
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

                    let frame_cap = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
                    self.ctx.resource_mgr.alloc(
                        CapType::Frame,
                        num_pages,
                        root_cnode,
                        frame_cap,
                    )?;
                    let frame = Frame::from(frame_cap);

                    process.vspace_mgr.map_frame(
                        frame,
                        start_page,
                        perms,
                        num_pages,
                        self.ctx.resource_mgr,
                        self.ctx.cspace_mgr,
                        root_cnode,
                    )?;
                    let scratch_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
                    self.ctx.root_cnode.copy(frame_cap, scratch_slot, Rights::ALL)?;
                    let scratch_frame = Frame::from(scratch_slot);

                    let scratch_vaddr = self.ctx.vspace_mgr.map_scratch(
                        scratch_frame,
                        Perms::READ | Perms::WRITE | Perms::USER,
                        num_pages,
                        self.ctx.resource_mgr,
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
                    self.ctx.vspace_mgr.unmap(
                        scratch_vaddr,
                        num_pages,
                        self.ctx.resource_mgr,
                        root_cnode,
                    )?;
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
}

impl<'a> ProcessManager<'a> {
    #[warn(deprecated_in_future)]
    pub fn procinit(&mut self, pid: Badge) -> Result<usize, Error> {
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        Ok(process.heap_start)
    }
}
