use super::ProcessManager;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{CSpaceService, MemoryService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;

impl<'a> MemoryService for ProcessManager<'a> {
    fn brk(&mut self, pid: Badge, incr: isize) -> Result<usize, Error> {
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
                let slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
                self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, slot)?;
                process.vspace_mgr.map_frame(
                    Frame::from(slot),
                    vaddr,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    1,
                    self.ctx.resource_mgr,
                    self.ctx.cspace_mgr,
                    self.ctx.root_cnode,
                )?;
            }
        }
        process.heap_brk = new_brk;
        Ok(new_brk)
    }

    fn mmap(&mut self, pid: Badge, addr: usize, len: usize) -> Result<usize, Error> {
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;

        let vaddr = addr;

        let start_page = vaddr & !(PGSIZE - 1);
        let end_page = (vaddr + len + PGSIZE - 1) & !(PGSIZE - 1);

        for v in (start_page..end_page).step_by(PGSIZE) {
            let slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
            self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, slot)?;
            process.vspace_mgr.map_frame(
                Frame::from(slot),
                v,
                Perms::READ | Perms::WRITE | Perms::USER,
                1,
                self.ctx.resource_mgr,
                self.ctx.cspace_mgr,
                self.ctx.root_cnode,
            )?;
        }
        Ok(vaddr)
    }

    fn munmap(&mut self, pid: Badge, addr: usize, len: usize) -> Result<(), Error> {
        if addr % PGSIZE != 0 {
            return Err(Error::InvalidArgs);
        }
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        process.vspace_mgr.unmap(
            addr,
            (len + PGSIZE - 1) / PGSIZE,
            self.ctx.resource_mgr, // Use Factotum's resource manager to free slots
            self.ctx.root_cnode,   // Process cnode where cap resides
        )
    }
}
