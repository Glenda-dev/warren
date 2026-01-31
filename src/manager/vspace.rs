use super::ResourceManager;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use glenda::arch::mem::{PGSIZE, SHIFTS, VPN_MASK};
use glenda::cap::{CNode, CapPtr, CapType, Frame, PageTable, VSpace};
use glenda::error::{Error, code};
use glenda::mem::Perms;

#[derive(Debug)]
enum ShadowNode {
    Table { cap: CapPtr, entries: BTreeMap<usize, Box<ShadowNode>> },
    Frame { cap: CapPtr, pages: usize, perms: Perms },
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

    pub fn setup(&self) -> Result<(), Error> {
        if self.root.setup() != code::SUCCESS {
            return Err(Error::MappingFailed);
        }
        Ok(())
    }

    /// Map a given frame into the VSpace at vaddr using shadow page tables
    pub fn map_frame(
        &mut self,
        frame: Frame,
        vaddr: usize,
        perms: Perms,
        pages: usize,
        resource_mgr: &mut ResourceManager,
        dest_cnode: CNode,
        mut get_slot: impl FnMut(&mut ResourceManager) -> Result<CapPtr, Error>,
    ) -> Result<(), Error> {
        let levels = SHIFTS.len(); // e.g., 3 for SV39

        // 1. Ensure tables exist and check for collisions
        for i in 0..pages {
            let curr_vaddr = vaddr + i * PGSIZE;

            let leaf_map = Self::ensure_path(
                &mut self.shadow,
                curr_vaddr,
                levels - 1,
                resource_mgr,
                dest_cnode,
                &mut get_slot,
                self.root,
            )?;

            // Check leaf
            let idx0 = index(curr_vaddr, 0);
            if leaf_map.contains_key(&idx0) {
                return Err(Error::MappingFailed); // Already mapped
            }
        }

        // 2. Map Frame (Kernel maps all pages if Frame cap covers them)
        if self.root.map(frame, vaddr, perms) != 0 {
            return Err(Error::MappingFailed);
        }

        // 3. Update shadow
        for i in 0..pages {
            let curr_vaddr = vaddr + i * PGSIZE;

            let leaf_map = Self::ensure_path(
                &mut self.shadow,
                curr_vaddr,
                levels - 1,
                resource_mgr,
                dest_cnode,
                &mut get_slot,
                self.root,
            )?;

            let idx0 = index(curr_vaddr, 0);
            leaf_map.insert(
                idx0,
                Box::new(ShadowNode::Frame {
                    cap: frame.cap(),
                    perms,
                    pages: if i == 0 { pages } else { 0 }, // Store size in first page
                }),
            );
        }

        Ok(())
    }

    fn ensure_path<'a>(
        entries: &'a mut BTreeMap<usize, Box<ShadowNode>>,
        vaddr: usize,
        level: usize,
        resource_mgr: &mut ResourceManager,
        dest_cnode: CNode,
        get_slot: &mut impl FnMut(&mut ResourceManager) -> Result<CapPtr, Error>,
        pivot_root: VSpace,
    ) -> Result<&'a mut BTreeMap<usize, Box<ShadowNode>>, Error> {
        let idx = index(vaddr, level);

        if level == 0 {
            return Ok(entries);
        }

        if !entries.contains_key(&idx) {
            let slot = get_slot(resource_mgr)?;
            let target_level = level - 1;
            resource_mgr
                .alloc(CapType::PageTable, target_level, dest_cnode, slot)
                .map_err(|_| Error::UntypeOOM)?;
            let pt = PageTable::from(slot);

            if pivot_root.map_table(pt, vaddr, level) != 0 {
                return Err(Error::MappingFailed);
            }
            entries.insert(idx, Box::new(ShadowNode::new_table(slot)));
        }

        let node = entries.get_mut(&idx).unwrap();
        match &mut **node {
            ShadowNode::Table { entries: sub_entries, .. } => {
                if level - 1 == 0 {
                    Ok(sub_entries)
                } else {
                    Self::ensure_path(
                        sub_entries,
                        vaddr,
                        level - 1,
                        resource_mgr,
                        dest_cnode,
                        get_slot,
                        pivot_root,
                    )
                }
            }
            _ => Err(Error::MappingFailed), // Collision
        }
    }

    pub fn mark_existing(&mut self, vaddr: usize) {
        Self::mark_existing_rec(&mut self.shadow, vaddr, SHIFTS.len() - 1);
    }

    fn mark_existing_rec(
        entries: &mut BTreeMap<usize, Box<ShadowNode>>,
        vaddr: usize,
        level: usize,
    ) {
        let idx = index(vaddr, level);
        if !entries.contains_key(&idx) {
            entries.insert(idx, Box::new(ShadowNode::new_table(CapPtr::null())));
        }

        if level > 1 {
            if let Some(node) = entries.get_mut(&idx) {
                if let ShadowNode::Table { entries: sub_entries, .. } = &mut **node {
                    Self::mark_existing_rec(sub_entries, vaddr, level - 1);
                }
            }
        }
    }

    pub fn clone_space(
        &self,
        dest_mgr: &mut VSpaceManager,
        resource_mgr: &mut ResourceManager,
        root_cnode: CNode,
        get_slot: &mut dyn FnMut(&mut ResourceManager) -> Result<CapPtr, Error>,
        src_scratch_va: usize,
        dest_scratch_va: usize,
        current_vspace: &mut VSpaceManager,
    ) -> Result<(), Error> {
        self.clone_level(
            &self.shadow,
            dest_mgr,
            resource_mgr,
            root_cnode,
            get_slot,
            0,
            SHIFTS.len() - 1,
            src_scratch_va,
            dest_scratch_va,
            current_vspace,
        )
    }

    fn clone_level(
        &self,
        entries: &BTreeMap<usize, Box<ShadowNode>>,
        dest_mgr: &mut VSpaceManager,
        resource_mgr: &mut ResourceManager,
        root_cnode: CNode,
        get_slot: &mut dyn FnMut(&mut ResourceManager) -> Result<CapPtr, Error>,
        base_vaddr: usize,
        level: usize,
        src_scratch_va: usize,
        dest_scratch_va: usize,
        current_vspace: &mut VSpaceManager,
    ) -> Result<(), Error> {
        for (&idx, node) in entries {
            let vaddr = base_vaddr | (idx << SHIFTS[level]);

            match &**node {
                ShadowNode::Table { entries: sub_entries, .. } => {
                    // Recurse
                    if level == 0 {
                        return Err(Error::MappingFailed);
                    }
                    self.clone_level(
                        sub_entries,
                        dest_mgr,
                        resource_mgr,
                        root_cnode,
                        get_slot,
                        vaddr,
                        level - 1,
                        src_scratch_va,
                        dest_scratch_va,
                        current_vspace,
                    )?;
                }
                ShadowNode::Frame { cap, perms, pages } => {
                    // Clone Frame
                    let num_pages = *pages;
                    if num_pages == 0 {
                        continue;
                    }

                    // Alloc slot
                    let new_slot = get_slot(resource_mgr)?;
                    resource_mgr
                        .alloc(CapType::Frame, 1, root_cnode, new_slot)
                        .map_err(|_| Error::UntypeOOM)?;
                    let new_frame = Frame::from(new_slot);

                    // Map both to copy
                    let src_frame = Frame::from(*cap);

                    // Map src using current_vspace
                    current_vspace.map_frame(
                        src_frame,
                        src_scratch_va,
                        Perms::READ,
                        num_pages,
                        resource_mgr,
                        root_cnode,
                        &mut *get_slot,
                    )?;

                    // Map dest using current_vspace
                    current_vspace.map_frame(
                        new_frame,
                        dest_scratch_va,
                        Perms::READ | Perms::WRITE,
                        num_pages,
                        resource_mgr,
                        root_cnode,
                        &mut *get_slot,
                    )?;

                    unsafe {
                        let total_size = num_pages * PGSIZE;
                        let src =
                            core::slice::from_raw_parts(src_scratch_va as *const u8, total_size);
                        let dest =
                            core::slice::from_raw_parts_mut(dest_scratch_va as *mut u8, total_size);
                        dest.copy_from_slice(src);
                    }

                    // Unmap
                    // current_vspace.unmap handles both kernel unmap via root (if same as VSPACE_CAP) and shadow.
                    current_vspace.unmap(src_scratch_va, num_pages);
                    current_vspace.unmap(dest_scratch_va, num_pages);

                    // Map to child
                    dest_mgr.map_frame(
                        new_frame,
                        vaddr,
                        *perms,
                        num_pages,
                        resource_mgr,
                        root_cnode,
                        &mut *get_slot,
                    )?;
                }
            }
        }
        Ok(())
    }
    pub fn unmap(&mut self, vaddr: usize, pages: usize) {
        for i in 0..pages {
            Self::unmap_rec(&mut self.shadow, vaddr + i * PGSIZE, SHIFTS.len() - 1);
        }
        self.root.unmap(vaddr, pages);
    }

    fn unmap_rec(entries: &mut BTreeMap<usize, Box<ShadowNode>>, vaddr: usize, level: usize) {
        let idx = index(vaddr, level);
        if let Some(node) = entries.get_mut(&idx) {
            match &mut **node {
                ShadowNode::Table { entries: sub_entries, .. } => {
                    // If we are at level 1, sub_entries is level 0.
                    // The item to remove is in sub_entries.
                    if level == 1 {
                        let idx0 = index(vaddr, 0);
                        sub_entries.remove(&idx0);
                    } else {
                        Self::unmap_rec(sub_entries, vaddr, level - 1);
                    }
                }
                _ => {}
            }
        }
    }
}

fn index(vaddr: usize, level: usize) -> usize {
    (vaddr >> SHIFTS[level]) & VPN_MASK
}
