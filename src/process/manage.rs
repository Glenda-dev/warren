use super::Process;
use super::{ProcessManager, ProcessState};
use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD};
use crate::layout::SCRATCH_VA;
use core::cmp::min;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CNode, CapType, Frame, Rights, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, ResourceService, VSpaceService};
use glenda::manager::VSpaceManager;
use glenda::mem::Perms;
use glenda::mem::{STACK_VA, TRAPFRAME_VA, UTCB_VA};

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
                process.heap_start = heap;
                process.heap_brk = heap;
                process.tcb.set_entrypoint(entry, STACK_VA)?;
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

        let cnode_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::CNode, 0, self.ctx.root_cnode, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::VSpace, 0, self.ctx.root_cnode, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::TCB, 0, self.ctx.root_cnode, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, utcb_slot)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, trapframe_slot)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            self.ctx.root_cnode,
            kstack_slot,
        )?;
        let child_kstack = Frame::from(kstack_slot);

        let mut child_vspace_mgr = VSpaceManager::new(child_pd);
        child_vspace_mgr.setup()?;

        let root_cnode = self.ctx.root_cnode;
        let parent = self.processes.get(&parent_pid).unwrap();

        parent
            .vspace_mgr
            .clone_space(
                &mut child_vspace_mgr,
                self.ctx.resource_mgr,
                self.ctx.slot_mgr,
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
            self.ctx.slot_mgr,
            root_cnode,
        )?;
        child_vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.resource_mgr,
            self.ctx.slot_mgr,
            root_cnode,
        )?;

        child_cnode.mint(self.endpoint.cap(), MONITOR_SLOT, pid, Rights::ALL)?;
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;

        let mut process =
            Process::new(pid, parent_pid, name, child_tcb, child_pd, child_cnode, child_vspace_mgr);
        process.heap_start = heap_start;
        process.heap_brk = heap_brk;

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
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let root_cnode = self.ctx.root_cnode;

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

            let frame_cap = self.ctx.slot_mgr.alloc(self.ctx.resource_mgr)?;
            self.ctx.resource_mgr.alloc(CapType::Frame, num_pages, root_cnode, frame_cap)?;
            let frame = Frame::from(frame_cap);

            process.vspace_mgr.map_frame(
                frame,
                start_page,
                perms,
                num_pages,
                self.ctx.resource_mgr,
                self.ctx.slot_mgr,
                root_cnode,
            )?;
            process.vspace_mgr.map_frame(
                frame,
                SCRATCH_VA,
                Perms::READ | Perms::WRITE | Perms::USER,
                num_pages,
                self.ctx.resource_mgr,
                self.ctx.slot_mgr,
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
            process.vspace_mgr.unmap(SCRATCH_VA, num_pages, self.ctx.resource_mgr, root_cnode)?;
        }
        Ok((elf.entry_point(), (max_vaddr + PGSIZE - 1) & !(PGSIZE - 1)))
    }
}
