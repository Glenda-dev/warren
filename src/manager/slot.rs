use super::ResourceManager;
use glenda::cap::{CNODE_SIZE, CNode, CapPtr, CapType};
use glenda::error::Error;

const L0_DIRECT_LIMIT: usize = 64;
const L1_START_SLOT: usize = L0_DIRECT_LIMIT + 1;
const L1_SLOTS: usize = CNODE_SIZE - L1_START_SLOT; // 192

/// SlotManager manages the allocation of capability slots in Factotum's CSpace.
/// It supports multi-level CNode expansion to overcome the 256-slot limit of a single CNode.
///
/// Current Strategy: 2-level CNode hierarchy.
/// Level 0 (Root): Slots 0-255.
///   - Lower slots (e.g., 0-63) are reserved for direct capabilities.
///   - Higher slots (e.g., 64-255) are used to store capabilities to Level 1 CNodes.
pub struct SlotManager {
    root_cnode: CNode,
    next_index: usize,

    // Tracks if a Level 1 CNode is already allocated for a given Level 0 index.
    // Index 0 corresponds to L0 slot 64, Index 1 to L0 slot 65, etc.
    l1_cnodes: [bool; L1_SLOTS],
}

impl SlotManager {
    pub fn new(root: CNode, start_index: usize) -> Self {
        Self { root_cnode: root, next_index: start_index, l1_cnodes: [false; L1_SLOTS] }
    }

    /// Allocates a new slot and returns its CapPtr.
    /// If necessary, it will allocate a new intermediate CNode.
    pub fn alloc(&mut self, resource_mgr: &mut ResourceManager) -> Result<CapPtr, Error> {
        let index = self.next_index;
        self.next_index += 1;

        if index < L0_DIRECT_LIMIT {
            // Level 0 Direct Mapping
            Ok(CapPtr::from(index))
        } else {
            // Level 1 Mapping
            let relative_index = index - L0_DIRECT_LIMIT;
            let l0_idx = L1_START_SLOT + (relative_index / 256);
            let l1_idx = relative_index % 256;

            if l0_idx >= 256 {
                return Err(Error::CNodeFull);
            }

            // Ensure L1 CNode exists
            let l1_cache_idx = l0_idx - L1_START_SLOT;
            if !self.l1_cnodes[l1_cache_idx] {
                let l0_cptr = CapPtr::from(l0_idx);
                resource_mgr
                    .alloc(CapType::CNode, 1, self.root_cnode, l0_cptr)
                    .map_err(|_| Error::UntypeOOM)?;
                self.l1_cnodes[l1_cache_idx] = true;
            }

            // Construct 2-level CapPtr: l0_idx | (l1_idx << 8)
            Ok(CapPtr::from(l0_idx | (l1_idx << 8)))
        }
    }
}
