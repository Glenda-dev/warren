#![no_std]
#![no_main]
#![allow(dead_code)]

#[macro_use]
extern crate glenda;
extern crate alloc;

mod elf;
mod layout;
mod policy;
mod warren;

use alloc::vec::Vec;
use glenda::arch::mem::PGSIZE;
use glenda::cap::CapType;
use glenda::cap::{CSPACE_CAP, MONITOR_CAP, MONITOR_SLOT, RECV_SLOT, REPLY_SLOT, VSPACE_CAP};
use glenda::error::Error;
use glenda::interface::{CSpaceService, SystemService, UntypedService};
use glenda::mem::{BOOTINFO_VA, INITRD_VA};
use glenda::utils::BootInfo;
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, UntypedManager, VSpaceManager};
use policy::{Allocator, MemoryPolicy};
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
    let mut vspace_mgr = VSpaceManager::new(VSPACE_CAP, layout::SCRATCH_VA, layout::SCRATCH_SIZE);
    let mut cspace_mgr = CSpaceManager::new(CSPACE_CAP, 16);

    let mut untyped_mgr = UntypedManager::new(bootinfo, CSPACE_CAP, layout::UNTYPED_SLOT);

    // Initialize BuddyAllocator slots
    let mut free_slots = Vec::new();
    for _ in 0..layout::FULL_RESERVE {
        free_slots
            .push(cspace_mgr.alloc(&mut untyped_mgr).expect("Failed to allocate initial slot"));
    }

    log!("Initializing Memory Policy...");
    // Initialize Memory Policy with pre-allocated slots
    let mut allocator = Allocator::new(free_slots);
    allocator.init(bootinfo).expect("Warren: Failed to initialize memory policy");

    // Using allocator now
    if let Err(e) = UntypedService::alloc(&mut allocator, CapType::Endpoint, 0, MONITOR_SLOT) {
        error!("Failed to create endpoint: {:?}", e);
        return 1;
    }

    // Initialize Warren Manager
    // Note: WarrenManager still needs the cspace_mgr for other tasks
    let mut manager =
        WarrenManager::new(&mut vspace_mgr, &mut cspace_mgr, &mut allocator, CSPACE_CAP, initrd);
    if let Err(e) = load_warren(&mut manager) {
        error!("Failed to load: {:?}", e);
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
