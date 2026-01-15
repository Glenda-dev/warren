// TODO: Resource Recycling

use glenda::cap::{CNode, CSPACE_CAP, CapPtr, CapType, Untyped};

pub struct ResourceManager {
    pub cnode: CNode, // Factotum's own CNode (Slot 0)
    pub untyped_start: usize,
    pub untyped_end: usize,
    pub next_free_slot: usize,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            cnode: CSPACE_CAP,
            untyped_start: 0,
            untyped_end: 0,
            next_free_slot: 256, // Start allocating slots from 256 (arbitrary safe zone)
        }
    }

    pub fn init(&mut self, start: usize, count: usize) {
        self.untyped_start = start;
        self.untyped_end = start + count;
    }

    pub fn alloc_slot(&mut self) -> usize {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }

    pub fn alloc_object(&mut self, obj_type: CapType, pages: usize) -> Option<CapPtr> {
        if self.untyped_start >= self.untyped_end {
            return None;
        }

        let untyped_cap = Untyped::from(CapPtr::from(self.untyped_start));
        self.untyped_start += 1;

        let dest_slot = self.alloc_slot();
        let dest_cap = CapPtr::from(dest_slot);
        let ret = untyped_cap.retype(obj_type, pages, 1, self.cnode, dest_cap, false);

        if ret == 0 { Some(dest_cap) } else { None }
    }
}
