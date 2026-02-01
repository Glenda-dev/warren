#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;

mod elf;
mod layout;
mod process;

use glenda::cap::CapType;
use glenda::cap::{CSPACE_CAP, FAULT_CAP, FAULT_SLOT};
use glenda::error::Error;
use glenda::manager::{IResourceManager, ResourceManager};
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
    // Allocated caps
    resource_mgr.alloc(CapType::Endpoint, 0, CSPACE_CAP, FAULT_SLOT).map_err(|_| Error::InvalidCap);

    // Initialize Factotum Manager
    let mut manager = ProcessManager::new(CSPACE_CAP, FAULT_CAP, REPLY_CAP, resource_mgr, initrd);

    if let Err(e) = manager.init() {
        log!("Failed to init system: {:?}", e);
        return 1;
    }

    log!("Entering main loop");
    manager.run();
}
