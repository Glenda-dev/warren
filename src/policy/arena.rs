use alloc::vec::Vec;
use core::cmp::max;
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, Untyped};
use glenda::error::Error;
use glenda::interface::{CSpaceService, UntypedService};
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

    pub fn alloc_slot(&mut self) -> Result<CapPtr, Error> {
        let slot = self.cspace_mgr.alloc_direct()?;
        Ok(slot)
    }

    fn retype_from_arena(
        arena: &mut Arena,
        obj_type: CapType,
        flags: usize,
        dest_cnode: CapPtr,
        dest_slot: CapPtr,
    ) -> Result<(), Error> {
        match obj_type {
            CapType::Untyped => arena.untyped.retype_untyped(flags, dest_cnode, dest_slot),
            CapType::TCB => arena.untyped.retype_tcb(dest_cnode, dest_slot),
            CapType::Endpoint => arena.untyped.retype_endpoint(dest_cnode, dest_slot),
            CapType::Frame => arena.untyped.retype_frame(flags, dest_cnode, dest_slot),
            CapType::PageTable => arena.untyped.retype_pagetable(flags, dest_cnode, dest_slot),
            CapType::CNode => arena.untyped.retype_cnode(dest_cnode, dest_slot),
            CapType::VSpace => arena.untyped.retype_vspace(dest_cnode, dest_slot),
            _ => Err(Error::NotSupported),
        }
    }

    /// Allocate an object from per-process arenas.
    /// Returns (physical address hint, absolute capability pointer in process CSpace).
    pub fn alloc_cap(
        &mut self,
        obj_type: CapType,
        flags: usize,
        untyped_service: &mut dyn UntypedService,
    ) -> Result<(usize, CapPtr), Error> {
        let pages = obj_type.pages(flags)?;

        for arena in &mut self.arenas {
            if arena.pages - arena.used_pages < pages {
                continue;
            }

            let paddr = arena.paddr + arena.used_pages * 4096;
            let slot = self.cspace_mgr.alloc_direct()?;
            match Self::retype_from_arena(arena, obj_type, flags, CSPACE_CAP.cap(), slot) {
                Ok(()) => {
                    arena.used_pages += pages;
                    return Ok((paddr, slot));
                }
                Err(e) => {
                    self.cspace_mgr.free(slot);
                    if e != Error::OutOfMemory {
                        return Err(e);
                    }
                }
            }
        }

        let pages_to_alloc = max(self.arena_size_pages, pages);
        let arena_slot = self.cspace_mgr.alloc_direct()?;
        let paddr = untyped_service.alloc(CapType::Untyped, pages_to_alloc, arena_slot)?;
        let untyped = Untyped::from(arena_slot);
        self.arenas.push(Arena { untyped, paddr, pages: pages_to_alloc, used_pages: 0 });

        self.alloc_cap(obj_type, flags, untyped_service)
    }

    /// Allocate an object from per-process arenas directly into `dest`.
    /// Returns physical address hint.
    pub fn alloc_cap_into(
        &mut self,
        obj_type: CapType,
        flags: usize,
        dest_cnode: CapPtr,
        dest_slot: CapPtr,
        untyped_service: &mut dyn UntypedService,
    ) -> Result<usize, Error> {
        let pages = obj_type.pages(flags)?;

        for arena in &mut self.arenas {
            if arena.pages - arena.used_pages < pages {
                continue;
            }

            let paddr = arena.paddr + arena.used_pages * 4096;
            match Self::retype_from_arena(arena, obj_type, flags, dest_cnode, dest_slot) {
                Ok(()) => {
                    arena.used_pages += pages;
                    return Ok(paddr);
                }
                Err(e) => {
                    if e != Error::OutOfMemory {
                        return Err(e);
                    }
                }
            }
        }

        let pages_to_alloc = max(self.arena_size_pages, pages);
        let arena_slot = self.cspace_mgr.alloc_direct()?;
        let paddr = untyped_service.alloc(CapType::Untyped, pages_to_alloc, arena_slot)?;
        let untyped = Untyped::from(arena_slot);
        self.arenas.push(Arena { untyped, paddr, pages: pages_to_alloc, used_pages: 0 });

        self.alloc_cap_into(obj_type, flags, dest_cnode, dest_slot, untyped_service)
    }

    /// Allocate a frame from arenas.
    /// Returns (physical address, absolute capability pointer in process CSpace).
    pub fn alloc(
        &mut self,
        pages: usize,
        untyped_service: &mut dyn UntypedService,
    ) -> Result<(usize, CapPtr), Error> {
        self.alloc_cap(CapType::Frame, pages, untyped_service)
    }

    /// Allocate a frame from arenas directly into `dest`.
    /// Returns physical address.
    pub fn alloc_into(
        &mut self,
        pages: usize,
        dest_cnode: CapPtr,
        dest_slot: CapPtr,
        untyped_service: &mut dyn UntypedService,
    ) -> Result<usize, Error> {
        self.alloc_cap_into(CapType::Frame, pages, dest_cnode, dest_slot, untyped_service)
    }

    pub fn add_arena(&mut self, untyped: Untyped, paddr: usize, pages: usize) {
        self.arenas.push(Arena { untyped, paddr, pages, used_pages: 0 });
    }

    /// Explicitly release all arena roots back to the global untyped policy.
    /// Returns released untyped cap slots for caller-side slot-manager bookkeeping.
    pub fn release_to(&mut self, untyped_service: &mut dyn UntypedService) -> Vec<CapPtr> {
        let arenas = core::mem::take(&mut self.arenas);
        let mut released = Vec::with_capacity(arenas.len());

        for arena in arenas {
            let cap = arena.untyped.cap();
            if let Err(e) = untyped_service.free(cap) {
                warn!("arena: failed to return untyped {:?}: {:?}", cap, e);
                let _ = CSPACE_CAP.revoke(cap);
                let _ = CSPACE_CAP.delete(cap);
            }
            released.push(cap);
        }

        released
    }
}
