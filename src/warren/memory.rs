use super::WarrenManager;
use glenda::arch::mem::PGSIZE;
use glenda::cap::Page;
use glenda::error::Error;
use glenda::interface::VSpaceService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::utils::align::align_up;
use glenda::utils::manager::vspace::{L1_HUGE_PAGES, L1_HUGE_SIZE};

impl<'a> WarrenManager<'a> {
    pub fn brk(&mut self, pid: Badge, incr: isize) -> Result<usize, Error> {
        let pid_bits = pid.bits();
        let process = self.state.processes.get_mut(&pid_bits).ok_or(Error::NotFound)?;
        let old_brk = process.heap_brk;
        let new_brk = (old_brk as isize + incr) as usize;
        let mut allocated_pages = 0usize;

        if new_brk < process.heap_start {
            error!("brk: new_brk {:#x} is below heap_start {:#x}", new_brk, process.heap_start);
            return Err(Error::InvalidArgs);
        }

        if incr > 0 {
            // 只映射尚未映射的新页面
            let start_map = align_up(old_brk, PGSIZE);
            let end_map = align_up(new_brk, PGSIZE);

            if end_map > start_map {
                let allocator = &mut *self.ctx.allocator;
                let cspace_mgr = &mut *self.ctx.cspace_mgr;

                let mut cursor = start_map;
                let mut remain_pages = (end_map - start_map) / PGSIZE;
                while remain_pages > 0 {
                    let to_next_huge_boundary_pages = if cursor % L1_HUGE_SIZE == 0 {
                        L1_HUGE_PAGES
                    } else {
                        (L1_HUGE_SIZE - (cursor % L1_HUGE_SIZE)) / PGSIZE
                    };

                    let mut chunk_pages = core::cmp::min(remain_pages, to_next_huge_boundary_pages);
                    if chunk_pages == 0 {
                        chunk_pages = core::cmp::min(remain_pages, 1);
                    }

                    // 在 huge 边界上优先尝试 2MiB 映射；失败时自动回退 4KiB 映射。
                    let try_huge = cursor % L1_HUGE_SIZE == 0 && remain_pages >= L1_HUGE_PAGES;
                    let target_pages = if try_huge { L1_HUGE_PAGES } else { chunk_pages };

                    let (paddr, slot) = process.arena_allocator.alloc(target_pages, allocator)?;
                    allocated_pages = allocated_pages.saturating_add(target_pages);
                    let frame = Page::from(slot);
                    let perms = Perms::READ | Perms::WRITE;

                    if try_huge && paddr % L1_HUGE_SIZE == 0 {
                        let mapped_huge = process
                            .vspace_mgr
                            .map_frame_huge_2m(frame, cursor, perms, allocator, cspace_mgr)?;
                        if !mapped_huge {
                            process.vspace_mgr.map_page(
                                frame,
                                cursor,
                                perms,
                                target_pages,
                                allocator,
                                cspace_mgr,
                            )?;
                        }
                        cursor += target_pages * PGSIZE;
                        remain_pages -= target_pages;
                    } else {
                        process.vspace_mgr.map_page(
                            frame,
                            cursor,
                            perms,
                            target_pages,
                            allocator,
                            cspace_mgr,
                        )?;
                        cursor += target_pages * PGSIZE;
                        remain_pages -= target_pages;
                    }
                }
            }
        }
        process.heap_brk = new_brk;
        if allocated_pages > 0 {
            self.ledger_record_internal_pages(pid_bits, allocated_pages, "brk_expand");
        }
        Ok(old_brk)
    }
}
