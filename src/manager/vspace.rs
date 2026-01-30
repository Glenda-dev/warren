use super::ResourceManager;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use glenda::arch::mem::{SHIFTS, VPN_MASK};
use glenda::cap::{CNode, CapPtr, CapType, Frame, PageTable, VSpace};
use glenda::mem::Perms;

#[derive(Debug)]
enum ShadowNode {
    Table { cap: CapPtr, entries: BTreeMap<usize, Box<ShadowNode>> },
    Frame { cap: CapPtr },
}

impl ShadowNode {
    fn new_table(cap: CapPtr) -> Self {
        ShadowNode::Table { cap, entries: BTreeMap::new() }
    }
}

pub struct VSpaceManager {
    pub root: VSpace,
    shadow: BTreeMap<usize, Box<ShadowNode>>, // Top level entries
}

impl VSpaceManager {
    pub fn new(root: VSpace) -> Self {
        Self { root, shadow: BTreeMap::new() }
    }

    /// Map a given frame into the VSpace at vaddr using shadow page tables
    pub fn map_frame(
        &mut self,
        frame: Frame,
        vaddr: usize,
        perms: Perms,
        resource_mgr: &mut ResourceManager,
        dest_cnode: CNode,
        mut get_slot: impl FnMut() -> CapPtr,
    ) -> Result<(), &'static str> {
        let mut current_entries = &mut self.shadow;
        let levels = SHIFTS.len(); // e.g., 3 for SV39

        // Traverse / Create page tables down to L0
        // Levels are typically numbered L2 (Root) -> L1 -> L0
        // We iterate from Top (levels-1) down to 1
        for level in (1..levels).rev() {
            let idx = index(vaddr, level);

            if !current_entries.contains_key(&idx) {
                let slot = get_slot();
                // Allocate Intermediate PageTable
                // count: 1 page
                resource_mgr.alloc(CapType::PageTable, level, dest_cnode, slot)?;

                let pt = PageTable::from(slot); // Changed VSpace::from back to PageTable::from as it's a PageTable we are allocating

                // Map the new table.
                // The `level` argument in `map_table` generally refers to the level of the table being mapped.
                // If we are at L(level), we are creating L(level-1).
                // So target level is `level - 1`.
                let target_level = level - 1;

                if self.root.map_table(pt, vaddr, target_level) != 0 {
                    return Err("Failed to map intermediate VSpace");
                }

                current_entries.insert(idx, Box::new(ShadowNode::new_table(slot)));
            }

            let node = current_entries.get_mut(&idx).unwrap();
            match &mut **node {
                ShadowNode::Table { entries, .. } => {
                    current_entries = entries;
                }
                _ => return Err("Collision: Expected Table encountered Frame"),
            }
        }

        // Now at Level 0 (Leaf)
        let idx0 = index(vaddr, 0);
        if current_entries.contains_key(&idx0) {
            return Err("Page already mapped");
        }

        // Map Frame
        if self.root.map(frame, vaddr, perms) != 0 {
            return Err("Failed to map Frame");
        }

        // Update shadow
        current_entries.insert(idx0, Box::new(ShadowNode::Frame { cap: frame.cap() }));

        Ok(())
    }
}

fn index(vaddr: usize, level: usize) -> usize {
    (vaddr >> SHIFTS[level]) & VPN_MASK
}
