use super::WarrenManager;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame};
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
            error!("brk: new_brk {:#x} is below heap_start {:#x}", new_brk, process.heap_start);
            return Err(Error::InvalidArgs);
        }

        if incr > 0 {
            // 只映射尚未映射的新页面
            let start_map = align_up(old_brk, PGSIZE);
            let end_map = align_up(new_brk, PGSIZE);

            if end_map > start_map {
                let pages = (end_map - start_map) / PGSIZE;

                let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
                self.ctx.buddy.alloc(
                    CapType::Frame,
                    pages,
                    CapPtr::concat(self.ctx.root_cnode.cap(), slot),
                )?;
                process.vspace_mgr.map_frame(
                    Frame::from(slot),
                    start_map,
                    Perms::READ | Perms::WRITE | Perms::USER,
                    pages,
                    self.ctx.buddy,
                    self.ctx.cspace_mgr,
                    self.ctx.root_cnode,
                )?;
            }
        }
        process.heap_brk = new_brk;
        log!("brk: old_brk={:#x}, new_brk={:#x}", old_brk, new_brk);
        // 返回 old_brk 以符合 sbrk 语义（返回新区域的起始地址）
        Ok(old_brk)
    }

    fn mmap(&mut self, pid: Badge, frame: Frame, addr: usize, len: usize) -> Result<usize, Error> {
        log!("mmap: pid: {:?}, frame={:?}, addr={:#x}, len={:#x}", pid, frame, addr, len);
        if addr % PGSIZE != 0 || len == 0 {
            error!("mmap: Invalid address {:#x} or length {:#x}", addr, len);
            return Err(Error::InvalidArgs);
        }
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        // Use Warren's root CNode for managing intermediate page tables
        let cspace = self.ctx.root_cnode;
        // Check Range
        if addr < 0x30000000 || addr >= 0x3F_0000_0000 {
            error!("mmap: Address {:#x} out of allowed range", addr);
            return Err(Error::PermissionDenied);
        }
        process.vspace_mgr.map_frame(
            frame,
            addr,
            Perms::READ | Perms::WRITE | Perms::USER,
            align_up(len, PGSIZE) / PGSIZE,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            cspace,
        )?;
        Ok(addr)
    }

    fn munmap(&mut self, pid: Badge, addr: usize, len: usize) -> Result<(), Error> {
        log!("munmap: pid: {:?}, addr={:#x}, len={:#x}", pid, addr, len);
        if addr % PGSIZE != 0 {
            error!("munmap: Invalid address {:#x}", addr);
            return Err(Error::InvalidArgs);
        }
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        process.vspace_mgr.unmap(
            addr,
            (len + PGSIZE - 1) / PGSIZE,
            self.ctx.buddy,      // Use Warren's resource manager to free slots
            self.ctx.root_cnode, // Process cnode where cap resides
        )
    }
}
