use glenda::cap::{CNODE_BITS, CNODE_PAGES};
use glenda::cap::{CNode, CapPtr, CapType, Untyped};
use glenda::error::code;
use glenda::runtime::UNTYPED_SLOT;
use glenda::runtime::bootinfo::{BootInfo, UntypedRegion};

#[derive(Clone, Copy, Debug)]
pub struct UntypedBlock {
    pub cap: Untyped,
    pub desc: UntypedRegion,
}

pub struct ResourceManager {
    blocks: [Option<UntypedBlock>; 64],
}

impl ResourceManager {
    pub fn new(bootinfo: &BootInfo) -> Self {
        let mut blocks = [const { None }; 64];

        for i in 0..bootinfo.untyped_count {
            if i >= 64 {
                break;
            }
            // Slots in the Untyped CNode start at 1
            let cptr = CapPtr::from((i + 1) << CNODE_BITS | UNTYPED_SLOT.bits());
            let desc = bootinfo.untyped_list[i];

            blocks[i] = Some(UntypedBlock { cap: Untyped::from(cptr), desc });
        }

        Self { blocks }
    }

    fn get_pages(&mut self, obj_type: CapType, flags: usize) -> usize {
        match obj_type {
            CapType::Untyped => flags,
            CapType::Frame => flags,
            CapType::CNode => CNODE_PAGES,
            _ => 1,
        }
    }

    /// Allocates a kernel object of `obj_type` into `dest_slot` in `dest_cnode`.
    ///
    /// `count`: Number of physical pages to consume.
    /// The size of the object (for retype) is derived from `count * PGSIZE`.
    pub fn alloc(
        &mut self,
        obj_type: CapType,
        flags: usize,
        dest_cnode: CNode,
        dest_slot: CapPtr,
    ) -> Result<usize, &'static str> {
        let pages = self.get_pages(obj_type, flags);
        for block_opt in self.blocks.iter_mut() {
            if let Some(block) = block_opt {
                if block.desc.watermark + pages <= block.desc.pages {
                    // Try to retype
                    let ret = match obj_type {
                        CapType::Untyped => block.cap.retype_untyped(flags, dest_cnode, dest_slot),
                        CapType::TCB => block.cap.retype_tcb(dest_cnode, dest_slot),
                        CapType::PageTable => {
                            block.cap.retype_pagetable(flags, dest_cnode, dest_slot)
                        }
                        CapType::CNode => block.cap.retype_cnode(dest_cnode, dest_slot),
                        CapType::Frame => block.cap.retype_frame(flags, dest_cnode, dest_slot),
                        CapType::VSpace => block.cap.retype_vspace(dest_cnode, dest_slot),
                        CapType::Endpoint => block.cap.retype_endpoint(dest_cnode, dest_slot),
                        _ => return Err("Unsupported CapType"),
                    };

                    match ret {
                        code::SUCCESS => {
                            block.desc.watermark += pages;
                            return Ok(ret);
                        }
                        code::UNTYPE_OOM => {
                            // This block is out of memory, try next block
                            continue;
                        }
                        _ => {
                            return Err("Unknown error during retype");
                        }
                    }
                }
            }
        }

        Err("Out of Memory")
    }
}
