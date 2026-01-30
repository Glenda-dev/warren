use glenda::cap::UNTYPED_SLOT;
use glenda::cap::{CNode, CapPtr, CapType, Untyped};
use glenda::error::code;
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
            let cptr = CapPtr::new(UNTYPED_SLOT, i + 1);
            let desc = bootinfo.untyped_list[i];

            blocks[i] = Some(UntypedBlock { cap: Untyped::from(cptr), desc });
        }

        Self { blocks }
    }

    fn get_pages(&mut self, obj_type: CapType, flags: usize) -> usize {
        match obj_type {
            CapType::Untyped => flags,
            CapType::Frame => flags,
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
                        CapType::Untyped => {
                            block.cap.retype_untyped(flags, 1, dest_cnode, dest_slot)
                        }
                        CapType::TCB => block.cap.retype_tcb(1, dest_cnode, dest_slot),
                        CapType::PageTable => {
                            block.cap.retype_pagetable(flags, 1, dest_cnode, dest_slot)
                        }
                        CapType::CNode => block.cap.retype_cnode(1, dest_cnode, dest_slot),
                        CapType::Frame => block.cap.retype_frame(flags, 1, dest_cnode, dest_slot),
                        CapType::VSpace => block.cap.retype_vspace(1, dest_cnode, dest_slot),
                        CapType::Endpoint => block.cap.retype_endpoint(1, dest_cnode, dest_slot),
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
