use super::MemoryPolicy;
use crate::layout::UNTYPED_SLOT;
use alloc::vec::Vec;
use core::cmp::max;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CNODE_PAGES, CNode, CSPACE_CAP};
use glenda::cap::{CapPtr, CapType, Untyped};
use glenda::error::Error;
use glenda::interface::{CSpaceProvider, UntypedService, VSpaceProvider};
use glenda::utils::BootInfo;
use glenda::utils::bootinfo::MAX_UNTYPED_REGIONS;

// Max order 30 (1GB), Min order 12 (4KB)
const MAX_ORDER: usize = 30;
const MIN_ORDER: usize = 12;

pub struct BuddyAllocator {
    free_slots: Vec<CapPtr>,
    // Stores (Untyped capability, physical address, parent untyped cap, grand-parent untyped cap) of size 2^order
    free_lists: [Vec<(Untyped, usize, Option<Untyped>, Option<Untyped>)>; MAX_ORDER + 1],
}

impl<'a> MemoryPolicy<'a> for BuddyAllocator {
    fn init(&mut self, bootinfo: &BootInfo) -> Result<(), Error> {
        // 1. Collect untyped information FIRST (No retype here to preserve watermark)
        let mut raw_untyped = Vec::new();
        for i in 0..bootinfo.untyped_count {
            if i >= MAX_UNTYPED_REGIONS {
                break;
            }

            let start = bootinfo.untyped_list[i];
            if start == 0 {
                continue;
            }

            let cptr = CapPtr::concat(UNTYPED_SLOT, CapPtr::from(i + 1));
            let cap = Untyped::from(cptr);
            let (pages, watermark) = cap
                .get_info()
                .map_err(|e| {
                    error!("Failed to get info for untyped cap {:?}: {:?}", cptr, e);
                })
                .unwrap_or((0, 0));

            if pages > watermark {
                raw_untyped.push((cap, start + watermark * PGSIZE, pages - watermark));
            }
        }

        // 2. Fragment the collected untyped regions into buddy blocks
        for (original_cap, start, mut pages) in raw_untyped {
            let mut current_start = start;
            while pages > 0 {
                let align_order =
                    if current_start == 0 { 30 } else { current_start.trailing_zeros() as usize };
                let size_order = (pages * PGSIZE).ilog2() as usize;
                let mut order = core::cmp::min(align_order, size_order);

                if order > MAX_ORDER {
                    order = MAX_ORDER;
                }
                if order < MIN_ORDER {
                    break;
                }

                let block_pages = 1 << (order - 12);

                if let Some(slot) = self.free_slots.pop() {
                    if original_cap.retype_untyped(block_pages, slot).is_ok() {
                        self.add_block(
                            Untyped::from(slot),
                            order,
                            current_start,
                            Some(original_cap),
                            None,
                        );
                        current_start += block_pages * PGSIZE;
                        pages -= block_pages;
                    } else {
                        self.free_slots.push(slot);
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    fn add_memory_block(&mut self, cap: Untyped, order: usize, paddr: usize) {
        self.add_block(cap, order, paddr, None, None);
    }
    /// Add pre-allocated slots to the allocator's internal pool.
    fn add_free_slot(&mut self, slot: CapPtr) {
        self.free_slots.push(slot);
    }

    fn reserve_count(&self) -> usize {
        self.free_slots.len()
    }
}

impl BuddyAllocator {
    pub fn new(free_slots: Vec<CapPtr>) -> Self {
        const EMPTY_VEC: Vec<(Untyped, usize, Option<Untyped>, Option<Untyped>)> = Vec::new();
        Self { free_slots, free_lists: [EMPTY_VEC; MAX_ORDER + 1] }
    }

    pub fn add_block(
        &mut self,
        mut cap: Untyped,
        mut order: usize,
        mut paddr: usize,
        mut parent: Option<Untyped>,
        mut grand_parent: Option<Untyped>,
    ) {
        if order > MAX_ORDER || order < MIN_ORDER {
            error!(
                "BuddyAllocator: Invalid block order {} for block at paddr {:#x}. Must be between {} and {}.",
                order, paddr, MIN_ORDER, MAX_ORDER
            );
            return;
        }

        while order < MAX_ORDER {
            let buddy_paddr = paddr ^ (1 << order);
            let buddy_pos =
                self.free_lists[order].iter().position(|&(_, addr, _, _)| addr == buddy_paddr);

            if let Some(idx) = buddy_pos {
                let (buddy_cap, _, buddy_parent, buddy_grand) = self.free_lists[order].remove(idx);

                // Both must share the same parent to be merged back into it
                if buddy_parent == parent && parent.is_some() {
                    let parent_cap = parent.unwrap();

                    // Revoke the parent to kill all children (cap and buddy_cap)
                    let _ = CNode::from(CapPtr::null()).revoke(parent_cap.cap());

                    paddr &= !(1 << order);
                    order += 1;

                    // Recycle child slots back into free_slots
                    self.free_slots.push(cap.cap());
                    self.free_slots.push(buddy_cap.cap());

                    cap = parent_cap;
                    parent = grand_parent;
                    grand_parent = buddy_grand; // Both buddies should have the same grand_parent if they have the same parent
                    continue;
                } else {
                    self.free_lists[order].push((
                        buddy_cap,
                        buddy_paddr,
                        buddy_parent,
                        buddy_grand,
                    ));
                    break;
                }
            } else {
                // No buddy to merge with, just insert
                break;
            }
        }

        self.free_lists[order].push((cap, paddr, parent, grand_parent));
    }

    pub fn free_untyped(
        &mut self,
        cap: Untyped,
        order: usize,
        paddr: usize,
        parent: Option<Untyped>,
        grand_parent: Option<Untyped>,
    ) {
        self.add_block(cap, order, paddr, parent, grand_parent);
    }

    // Internal alloc helper that returns the Untyped cap, its physical address and parent cap
    fn alloc_untyped(
        &mut self,
        order: usize,
    ) -> Result<(Untyped, usize, Option<Untyped>, Option<Untyped>), Error> {
        let order = max(order, MIN_ORDER);
        if order > MAX_ORDER {
            return Err(Error::OutOfMemory);
        }

        // 1. Try exact match
        if let Some((cap, paddr, parent, grand_parent)) = self.free_lists[order].pop() {
            return Ok((cap, paddr, parent, grand_parent));
        }

        // 2. Find larger block to split
        for i in (order + 1)..=MAX_ORDER {
            if !self.free_lists[i].is_empty() {
                // Pre-reserve slots for all possible splits to avoid re-entrancy in CSpaceManager
                // Each split depth (i - order) needs 2 slots.
                let slots_needed = (i - order) * 2;
                if self.free_slots.len() < slots_needed {
                    error!(
                        "BuddyAllocator: Not enough free slots to split untyped block of order {}: needed {}, available {}",
                        i,
                        slots_needed,
                        self.free_slots.len()
                    );
                    return Err(Error::OutOfMemory);
                }

                let (parent_cap, parent_paddr, grand_parent, grand_grand_parent) =
                    self.free_lists[i].pop().unwrap();
                let mut current_cap = parent_cap;
                let current_paddr = parent_paddr;
                let mut current_parent = grand_parent;
                let mut current_grand_parent = grand_grand_parent;

                // Split from i down to order
                for current_order in (order + 1..=i).rev() {
                    let child_order = current_order - 1;

                    // Alloc slots for two children from CSpaceManager
                    let child1_slot = self.free_slots.pop().ok_or(Error::OutOfMemory)?;
                    let child2_slot = self.free_slots.pop().ok_or(Error::OutOfMemory)?;

                    let child_pages = 1 << (child_order - 12);

                    // Retype into two halves
                    current_cap.retype_untyped(child_pages, child1_slot)?;
                    current_cap.retype_untyped(child_pages, child2_slot)?;

                    let child1 = Untyped::from(child1_slot);
                    let child2 = Untyped::from(child2_slot);

                    let child_size = 1 << child_order;

                    // Put child2 into free list, marking current_cap as parent
                    self.free_lists[child_order].push((
                        child2,
                        current_paddr + child_size,
                        Some(current_cap),
                        current_parent,
                    ));

                    current_grand_parent = current_parent;
                    current_parent = Some(current_cap);
                    current_cap = child1;
                }

                return Ok((current_cap, current_paddr, current_parent, current_grand_parent));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Recursively find and revoke parent until we find one that doesn't have a parent in the buddy view
    /// or we reach the root untyped.
    fn revoke_and_merge_parent(
        &mut self,
        parent: Untyped,
        order: usize,
        paddr: usize,
        grand_parent: Option<Untyped>,
        grand_grand_parent: Option<Untyped>,
    ) {
        log!(
            "BuddyAllocator: Revoking parent cap {:?} at order {} for block at paddr {:#x}",
            parent.cap(),
            order,
            paddr
        );
        // 1. Revoke the parent to kill all children (the two buddies)
        if let Err(e) = CSPACE_CAP.revoke(parent.cap()) {
            error!("Failed to revoke parent cap {:?} during free: {:?}", parent.cap(), e);
            return;
        };
        // Use the grand_parent for the merge back into order+1
        self.add_block(parent, order + 1, paddr, grand_parent, grand_grand_parent);
    }
}

impl UntypedService for BuddyAllocator {
    fn alloc(&mut self, obj_type: CapType, flags: usize, dest: CapPtr) -> Result<usize, Error> {
        //log!("buddy: Alloc request: type={:?}, flags={}, dest={:?}", obj_type, flags, dest);
        // Calculate required order
        let pages = obj_type.pages(flags)?;
        let order = pages.next_power_of_two().ilog2() as usize + 12;

        let (untyped, paddr, _parent, _grand_parent) = self.alloc_untyped(order)?;

        // Ensure we retype the full power-of-two size to avoid leaking the remainder
        // and causing buddy merge failures when recycled.
        let alloc_pages = if obj_type == CapType::Frame || obj_type == CapType::Untyped {
            1 << (order - 12)
        } else {
            pages
        };

        match obj_type {
            CapType::Untyped => untyped.retype_untyped(alloc_pages, dest)?,
            CapType::Frame => untyped.retype_frame(alloc_pages, dest)?,
            CapType::CNode => untyped.retype_cnode(dest)?,
            CapType::PageTable => untyped.retype_pagetable(flags, dest)?,
            CapType::TCB => untyped.retype_tcb(dest)?,
            CapType::Endpoint => untyped.retype_endpoint(dest)?,
            CapType::VSpace => untyped.retype_vspace(dest)?,
            _ => return Err(Error::NotSupported),
        }

        Ok(paddr)
    }

    fn free(&mut self, slot: CapPtr) -> Result<(), Error> {
        //log!("buddy: Free request: slot={:?}", slot);
        // 1. Revoke children (kernel takes care of recursive revocation)
        CSPACE_CAP.revoke(slot)?;

        // 2. Recycle the capability
        match CSPACE_CAP.recycle(slot) {
            Ok((paddr, pages)) => {
                if pages > 0 {
                    // It's a memory-backed Untyped capability, calculate its order
                    // We use next_power_of_two to match our allocation's buddy system logic
                    let order = (pages * PGSIZE).next_power_of_two().ilog2() as usize;

                    match self.free_slots.pop() {
                        Some(next_slot) => {
                            match Untyped::from(slot).retype_untyped(pages, next_slot) {
                                Ok(_) => {
                                    self.add_block(
                                        Untyped::from(next_slot),
                                        order,
                                        paddr,
                                        None,
                                        None,
                                    );
                                }
                                Err(e) => {
                                    error!("buddy: Failed to retype free block: {:?}", e);
                                    self.free_slots.push(next_slot);
                                }
                            }
                        }
                        None => {
                            error!(
                                "buddy: Slot exhausted during free, unable to recycle untyped cap for paddr {:#x}, pages {}",
                                paddr, pages
                            );
                        }
                    }

                    // Clear the original slot after retyping the resource out of it
                    let _ = CSPACE_CAP.delete(slot);
                } else {
                    let _ = CSPACE_CAP.delete(slot);
                }
            }
            Err(e) => {
                warn!("Buddy recycle failed for slot {:?}: {:?}, deleting...", slot, e);
                let _ = CSPACE_CAP.delete(slot);
            }
        }
        self.free_slots.push(slot);
        Ok(())
    }
}

impl VSpaceProvider for BuddyAllocator {
    fn alloc_pagetable(&mut self, dest: CapPtr) -> Result<(), Error> {
        let (untyped, _, _, _) = self.alloc_untyped(12)?;
        untyped.retype_pagetable(0, dest)?;
        Ok(())
    }

    fn free_pagetable(&mut self, dest: CapPtr) -> Result<(), Error> {
        UntypedService::free(self, dest)
    }
}

impl CSpaceProvider for BuddyAllocator {
    fn alloc_cnode(&mut self, dest: CapPtr) -> Result<(), Error> {
        let order = (CNODE_PAGES * PGSIZE).ilog2() as usize;
        let (untyped, _, _, _) = self.alloc_untyped(order)?;
        untyped.retype_cnode(dest)?;
        Ok(())
    }

    fn free_cnode(&mut self, addr: CapPtr) -> Result<(), Error> {
        UntypedService::free(self, addr)
    }
}
