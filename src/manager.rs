use glenda::cap::{CapPtr, CapType};

pub struct ResourceManager {
    pub cnode: CapPtr, // Factotum's own CNode (Slot 0)
    pub untyped_start: usize,
    pub untyped_end: usize,
    pub irq_start: usize,
    pub irq_end: usize,
    pub next_free_slot: usize,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            cnode: CapPtr(0),
            untyped_start: 0,
            untyped_end: 0,
            irq_start: 0,
            irq_end: 0,
            next_free_slot: 256, // Start allocating slots from 256 (arbitrary safe zone)
        }
    }

    pub fn init(&mut self, start: usize, count: usize) {
        self.untyped_start = start;
        self.untyped_end = start + count;
    }

    pub fn init_irq(&mut self, start: usize, count: usize) {
        self.irq_start = start;
        self.irq_end = start + count;
    }

    pub fn alloc_slot(&mut self) -> usize {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }

    pub fn alloc_object(&mut self, obj_type: CapType, size_bits: usize) -> Option<CapPtr> {
        if self.untyped_start >= self.untyped_end {
            return None;
        }

        let untyped_cap = CapPtr(self.untyped_start);
        self.untyped_start += 1;

        let dest_slot = self.alloc_slot();
        let dest_cap = CapPtr(dest_slot);

        let ret = untyped_cap.untyped_retype(obj_type, size_bits, 1, self.cnode, dest_slot);

        if ret == 0 { Some(dest_cap) } else { None }
    }
}
