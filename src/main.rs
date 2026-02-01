#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;

mod elf;
mod layout;
mod process;

use glenda::cap::{CSPACE_CAP, MONITOR_CAP, MONITOR_SLOT};
use glenda::cap::{CapType, VSPACE_CAP};
use glenda::error::Error;
use glenda::manager::{IResourceManager, ISystemService};
use glenda::manager::{ResourceManager, SlotManager, VSpaceManager};
use glenda::mem::BOOTINFO_VA;
use glenda::utils::bootinfo;
use glenda::utils::bootinfo::BootInfo;
use glenda::utils::initrd::Initrd;
use layout::REPLY_CAP;
use process::ProcessManager;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("Factotum: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Starting Factotum Manager...");

    // Parse BootInfo
    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    if bootinfo.magic != bootinfo::BOOTINFO_MAGIC {
        log!("Invalid BootInfo Magic: {:#x}", bootinfo.magic);
        return 1;
    }
    log!("{}", bootinfo);

    // Parse Initrd
    let initrd_start = bootinfo.initrd_start;
    let initrd_size = bootinfo.initrd_size;

    // Safety check
    if initrd_start == 0 || initrd_size == 0 {
        panic!("Factotum: Initrd info missing in BootInfo");
    }

    let initrd_slice =
        unsafe { core::slice::from_raw_parts(initrd_start as *const u8, initrd_size) };
    let initrd = Initrd::new(initrd_slice).expect("Factotum: Failed to parse initrd");
    log!("Initrd parsed. Size: {} KB", initrd_size / 1024);

    // Init Resource Manager
    let mut resource_mgr = ResourceManager::new(bootinfo);
    let mut vspace_mgr = VSpaceManager::new(VSPACE_CAP);
    let mut slot_mgr = SlotManager::new(CSPACE_CAP, 16);

    // Allocated caps
    if let Err(e) = resource_mgr.alloc(CapType::Endpoint, 0, CSPACE_CAP, MONITOR_SLOT) {
        log!("Failed to create endpoint: {:?}", e);
        return 1;
    }

    // Initialize Factotum Manager
    let mut manager =
        ProcessManager::new(CSPACE_CAP, &mut vspace_mgr, &mut resource_mgr, &mut slot_mgr, initrd);
    if let Err(e) = load_factotum(&mut manager) {
        log!("Failed to load: {:?}", e);
        return 1;
    }
    manager.run().map_err(|e| log!("Exited with error: {:?}", e)).expect("Factotum Manager failed");
    1
}

fn load_factotum(manager: &mut ProcessManager) -> Result<(), Error> {
    manager.listen(MONITOR_CAP, REPLY_CAP)?;
    manager.init()?;
    Ok(())
}
