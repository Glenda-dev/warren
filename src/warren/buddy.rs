use alloc::vec::Vec;
use core::cmp::max;
use glenda::arch::mem::PGSIZE;
use glenda::cap::CNODE_PAGES;
use glenda::cap::{CapPtr, CapType, Untyped};
use glenda::error::Error;
use glenda::utils::manager::{CSpaceProvider, UntypedService};

// Max order 30 (1GB), Min order 12 (4KB)
const MAX_ORDER: usize = 30;
const MIN_ORDER: usize = 12;

pub struct BuddyAllocator {
    // Stores Untyped capabilities of size 2^order
    free_lists: [Vec<Untyped>; MAX_ORDER + 1],
    // Reserve slots for splitting operations
    free_slots: Vec<CapPtr>,
}

impl BuddyAllocator {
    pub fn new() -> Self {
        const EMPTY_VEC: Vec<Untyped> = Vec::new();
        Self { free_lists: [EMPTY_VEC; MAX_ORDER + 1], free_slots: Vec::with_capacity(128) }
    }

    pub fn add_block(&mut self, cap: Untyped, order: usize) {
        if order <= MAX_ORDER && order >= MIN_ORDER {
            self.free_lists[order].push(cap);
        }
    }

    pub fn add_free_slot(&mut self, slot: CapPtr) {
        self.free_slots.push(slot);
    }

    pub fn reserve_count(&self) -> usize {
        self.free_slots.len()
    }

    // Internal alloc helper that returns the Untyped cap
    fn alloc_untyped(&mut self, order: usize) -> Result<Untyped, Error> {
        let order = max(order, MIN_ORDER);
        if order > MAX_ORDER {
            return Err(Error::OutOfMemory);
        }

        // 1. Try exact match
        if let Some(cap) = self.free_lists[order].pop() {
            return Ok(cap);
        }

        // 2. Find larger block to split
        for i in (order + 1)..=MAX_ORDER {
            if !self.free_lists[i].is_empty() {
                let parent_cap = self.free_lists[i].pop().unwrap();
                let mut current_cap = parent_cap;

                // Split from i down to order
                for current_order in (order + 1..=i).rev() {
                    let child_order = current_order - 1;

                    // Alloc slots for two children from reserve
                    if self.free_slots.len() < 2 {
                        return Err(Error::CNodeFull);
                    }
                    let child1_slot = self.free_slots.pop().unwrap();
                    let child2_slot = self.free_slots.pop().unwrap();

                    let child_pages = 1 << (child_order - MIN_ORDER);

                    // Retype into two halves
                    current_cap.retype_untyped(child_pages, child1_slot)?;
                    current_cap.retype_untyped(child_pages, child2_slot)?;

                    let child1 = Untyped::from(child1_slot);
                    let child2 = Untyped::from(child2_slot);

                    // Keep child1 for next iteration (or return it if we are done)
                    // Put child2 into free list
                    self.free_lists[child_order].push(child2);

                    current_cap = child1;
                }

                return Ok(current_cap);
            }
        }

        Err(Error::OutOfMemory)
    }

    pub fn free(&mut self, cap: Untyped, order: usize) {
        self.add_block(cap, order);
    }
}

impl UntypedService for BuddyAllocator {
    fn alloc(&mut self, obj_type: CapType, flags: usize, dest: CapPtr) -> Result<usize, Error> {
        // Calculate required order
        let order = match obj_type {
            CapType::Frame => (flags * PGSIZE).next_power_of_two().ilog2() as usize,
            CapType::Untyped => (flags * PGSIZE).next_power_of_two().ilog2() as usize,
            CapType::CNode => (CNODE_PAGES * PGSIZE).next_power_of_two().ilog2() as usize,
            CapType::VSpace | CapType::PageTable => 12, // 4KB for PageTable
            _ => MIN_ORDER,
        };

        let untyped = self.alloc_untyped(order)?;
        let paddr = 0;

        match obj_type {
            CapType::Untyped => untyped.retype_untyped(flags, dest)?,
            CapType::Frame => untyped.retype_frame(flags, dest)?,
            CapType::CNode => untyped.retype_cnode(dest)?,
            CapType::PageTable => untyped.retype_pagetable(flags, dest)?,
            CapType::TCB => untyped.retype_tcb(dest)?,
            CapType::Endpoint => untyped.retype_endpoint(dest)?,
            CapType::VSpace => untyped.retype_vspace(dest)?,
            _ => return Err(Error::NotSupported),
        }

        Ok(paddr)
    }

    fn free(&mut self, _cap: CapPtr) -> Result<(), Error> {
        Ok(())
    }

    fn as_cspace_provider(&mut self) -> &mut dyn CSpaceProvider {
        self
    }
}

impl CSpaceProvider for BuddyAllocator {
    fn alloc_cnode(&mut self, dest: CapPtr) -> Result<(), Error> {
        let order = (CNODE_PAGES * PGSIZE).ilog2() as usize;
        let untyped = self.alloc_untyped(order)?;
        untyped.retype_cnode(dest)?;
        Ok(())
    }
}
