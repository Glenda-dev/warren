use super::WarrenManager;
use glenda::arch::mem::PGSIZE;
use glenda::cap::Frame;
use glenda::error::Error;
use glenda::interface::VSpaceService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::utils::align::align_up;

impl<'a> WarrenManager<'a> {
    pub fn brk(&mut self, pid: Badge, incr: isize) -> Result<usize, Error> {
        log!("brk: pid: {:?}, incr={:#x}", pid, incr);
        let process = self.processes.get_mut(&pid.bits()).ok_or(Error::NotFound)?;
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

                let allocator = &mut *self.ctx.allocator;
                let cspace_mgr = &mut *self.ctx.cspace_mgr;
                let (_, slot) = process.arena_allocator.alloc(pages, allocator)?;
                process.vspace_mgr.map_frame(
                    Frame::from(slot),
                    start_map,
                    Perms::READ | Perms::WRITE,
                    pages,
                    allocator,
                    cspace_mgr,
                )?;
            }
        }
        process.heap_brk = new_brk;
        log!("brk: old_brk={:#x}, new_brk={:#x}", old_brk, new_brk);
        // 返回 old_brk 以符合 sbrk 语义（返回新区域的起始地址）
        Ok(old_brk)
    }
}
