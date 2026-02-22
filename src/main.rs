#![no_std]
#![no_main]
#![allow(dead_code)]

#[macro_use]
extern crate glenda;
extern crate alloc;

mod elf;
mod layout;
mod warren;
use crate::layout::UNTYPED_SLOT;
use crate::warren::BuddyAllocator;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CSPACE_CAP, MONITOR_CAP, MONITOR_SLOT, RECV_SLOT, REPLY_SLOT, VSPACE_CAP};
use glenda::cap::{CapPtr, CapType, Untyped};
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::mem::{BOOTINFO_VA, INITRD_VA};
use glenda::utils::BootInfo;
use glenda::utils::bootinfo;
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{
    CSpaceManager, CSpaceService, DummyProvider, UntypedService, VSpaceManager,
};
use warren::WarrenManager;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("Warren");
    log!("Starting Warren Manager...");

    // Parse BootInfo
    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    log!("{}", bootinfo);

    // Parse Initrd
    let initrd_start = INITRD_VA + bootinfo.initrd_paddr % PGSIZE;
    let initrd_size = bootinfo.initrd_size;

    // Safety check
    if initrd_size == 0 {
        panic!("Warren: Initrd info missing in BootInfo");
    }

    let initrd_slice =
        unsafe { core::slice::from_raw_parts(initrd_start as *const u8, initrd_size) };
    let initrd = Initrd::new(initrd_slice).expect("Warren: Failed to parse initrd");
    log!("Initrd parsed. Size: {} KB", initrd_size / 1024);

    // Init Resource Manager
    // let mut untyped_mgr = UntypedManager::new(bootinfo, UNTYPED_SLOT);
    let mut vspace_mgr = VSpaceManager::new(VSPACE_CAP, layout::SCRATCH_VA, layout::SCRATCH_SIZE);
    let mut cspace_mgr = CSpaceManager::new(CSPACE_CAP, 16);
    log!("Initializing Buddy Allocator...");
    // Initialize Buddy Allocator
    let mut buddy_alloc = BuddyAllocator::new();

    // Add untyped regions from BootInfo.
    // We break down each region into multiple power-of-two blocks and add them into buddy.
    let mut dummy = DummyProvider;
    for i in 0..bootinfo.untyped_count {
        if i >= bootinfo::MAX_UNTYPED_REGIONS {
            break;
        }
        let cptr = CapPtr::from((i + 1) << glenda::cap::CNODE_BITS | UNTYPED_SLOT.bits());
        let mut desc = bootinfo.untyped_list[i];
        let original_cap = Untyped::from(cptr);

        while desc.pages > 0 {
            let total_bytes = desc.pages * PGSIZE;
            let mut order = total_bytes.ilog2() as usize;
            if order > 30 {
                order = 30;
            }
            let block_pages = 1 << (order - 12);

            if let Ok(slot) = cspace_mgr.alloc(&mut dummy) {
                if original_cap.retype_untyped(block_pages, slot).is_ok() {
                    buddy_alloc.add_block(Untyped::from(slot), order, desc.start);
                    desc.start += block_pages * PGSIZE;
                    desc.pages -= block_pages;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Pre-allocate slots for Buddy Allocator internal operations (splitting)
    for _ in 0..100 {
        if let Ok(slot) = cspace_mgr.alloc(&mut dummy) {
            buddy_alloc.add_free_slot(slot);
        }
    }

    // Now buddy_alloc has 100 slots, it can handle splitting for its own provider role.
    for _ in 0..412 {
        if let Ok(slot) = cspace_mgr.alloc(&mut buddy_alloc) {
            buddy_alloc.add_free_slot(slot);
        }
    }

    // Allocated caps
    // Using buddy_alloc now
    if buddy_alloc
        .alloc(CapType::Endpoint, 0, CapPtr::concat(CSPACE_CAP.cap(), MONITOR_SLOT))
        .is_err()
    {
        log!("Failed to create endpoint");
        return 1;
    }

    // Initialize Warren Manager
    let mut manager =
        WarrenManager::new(CSPACE_CAP, &mut vspace_mgr, &mut buddy_alloc, &mut cspace_mgr, initrd);
    if let Err(e) = load_warren(&mut manager) {
        log!("Failed to load: {:?}", e);
        return 1;
    }
    manager.run().expect("Warren Manager exited");
    1
}

fn load_warren(manager: &mut WarrenManager) -> Result<(), Error> {
    manager.listen(MONITOR_CAP, REPLY_SLOT, RECV_SLOT)?;
    manager.init()?;
    Ok(())
}
