use super::WarrenManager;
use crate::log;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::MemoryService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

impl<'a> MemoryService for WarrenManager<'a> {
    fn brk(&mut self, pid: Badge, incr: isize) -> Result<usize, Error> {
        log!("brk: pid: {:?}, incr={:#x}", pid, incr);
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
                let slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
                self.ctx.untyped_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, slot)?;
                process.vspace_mgr.map_frame(
                    Frame::from(slot),
                    vaddr,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    1,
                    self.ctx.untyped_mgr,
                    self.ctx.cspace_mgr,
                    self.ctx.root_cnode,
                )?;
            }
        }
        process.heap_brk = new_brk;
        log!("brk: new_brk={:#x}", new_brk);
        Ok(new_brk)
    }

    fn mmap(&mut self, pid: Badge, frame: Frame, addr: usize, len: usize) -> Result<usize, Error> {
        log!("mmap: pid: {:?}, frame={:?}, addr={:#x}, len={:#x}", pid, frame, addr, len);
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        // Use Warren's root CNode for managing intermediate page tables
        let cspace = self.ctx.root_cnode;
        process.vspace_mgr.map_frame(
            frame,
            addr,
            Perms::READ | Perms::WRITE | Perms::USER,
            align_up(len, PGSIZE) / PGSIZE,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            cspace,
        )?;
        Ok(addr)
    }

    fn munmap(&mut self, pid: Badge, addr: usize, len: usize) -> Result<(), Error> {
        log!("munmap: pid: {:?}, addr={:#x}, len={:#x}", pid, addr, len);
        if addr % PGSIZE != 0 {
            return Err(Error::InvalidArgs);
        }
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        process.vspace_mgr.unmap(
            addr,
            (len + PGSIZE - 1) / PGSIZE,
            self.ctx.untyped_mgr, // Use Warren's resource manager to free slots
            self.ctx.root_cnode,  // Process cnode where cap resides
        )
    }
}
