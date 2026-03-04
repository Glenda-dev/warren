use alloc::vec::Vec;
use core::cmp::max;
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, Untyped};
use glenda::error::Error;
use glenda::interface::UntypedService;
use glenda::utils::manager::CSpaceManager;

/// Arena allocator that manages large chunks of memory (arenas)
/// obtained from the Buddy allocator. It's capability-aware and
/// keeps track of the untyped capabilities used.
pub struct Arena {
    pub untyped: Untyped,
    pub paddr: usize,
    pub pages: usize,
    pub used_pages: usize,
}

pub struct ArenaAllocator {
    pub cspace_mgr: CSpaceManager,
    arenas: Vec<Arena>,
    arena_size_pages: usize,
}

impl ArenaAllocator {
    pub fn new(
        cspace_mgr: CSpaceManager,
        initial_untyped: Option<(Untyped, usize, usize)>,
        arena_size_pages: usize,
    ) -> Self {
        let mut arenas = Vec::new();
        if let Some((untyped, paddr, pages)) = initial_untyped {
            arenas.push(Arena { untyped, paddr, pages, used_pages: 0 });
        }
        Self { cspace_mgr, arenas, arena_size_pages }
    }

    /// Allocate a frame from arenas.
    /// Returns (physical address, absolute capability pointer in process CSpace).
    pub fn alloc(
        &mut self,
        pages: usize,
        untyped_service: &mut dyn UntypedService,
    ) -> Result<(usize, CapPtr), Error> {
        // 1. Try to find a free slot in existing arenas
        for arena in &mut self.arenas {
            if arena.pages - arena.used_pages >= pages {
                let paddr = arena.paddr + arena.used_pages * 4096;
                let slot = self.cspace_mgr.alloc_direct()?;
                arena.untyped.retype_frame(pages, slot)?;
                arena.used_pages += pages;
                return Ok((paddr, slot));
            }
        }

        // 2. No space, allocate a new arena
        let pages_to_alloc = max(self.arena_size_pages, pages);
        let arena_slot = self.cspace_mgr.alloc_direct()?;
        let paddr = untyped_service.alloc(CapType::Untyped, pages_to_alloc, arena_slot)?;

        let untyped = Untyped::from(arena_slot);
        let mut arena = Arena { untyped, paddr, pages: pages_to_alloc, used_pages: 0 };

        // Allocate from the new arena
        let dest_slot = self.cspace_mgr.alloc_direct()?;
        arena.untyped.retype_frame(pages, dest_slot)?;
        arena.used_pages += pages;
        let result_paddr = arena.paddr;
        self.arenas.push(arena);

        Ok((result_paddr, dest_slot))
    }

    pub fn add_arena(&mut self, untyped: Untyped, paddr: usize, pages: usize) {
        self.arenas.push(Arena { untyped, paddr, pages, used_pages: 0 });
    }
}

impl Drop for ArenaAllocator {
    fn drop(&mut self) {
        // Revoke and delete each arena's untyped from the global CSpace
        // This will recursively invalidate all frames retyped from it.
        for arena in &self.arenas {
            let _ = CSPACE_CAP.revoke(arena.untyped.cap());
            let _ = CSPACE_CAP.delete(arena.untyped.cap());
        }
    }
}
