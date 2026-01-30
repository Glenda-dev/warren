#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;

mod bootinfo;
mod elf;
mod initrd;
mod layout;
mod manager;
mod process;

use bootinfo::BootInfo;
use glenda::cap::CSPACE_CAP;
use initrd::Initrd;
use layout::{BOOTINFO_VA, ENDPOINT_CAP, INITRD_VA};
use manager::{ProcessManager, ResourceManager};

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("Factotum: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Starting Factotum Manager...");

    // Parse Initrd
    let total_size_ptr = (INITRD_VA + 8) as *const u32;
    let total_size = unsafe { *total_size_ptr } as usize;
    let initrd_slice = unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };
    let initrd = Initrd::new(initrd_slice).expect("Factotum: Failed to parse initrd");
    log!("Initrd parsed. Size: {} KB", total_size / 1024);

    // Parse BootInfo
    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    if bootinfo.magic != bootinfo::BOOTINFO_MAGIC {
        log!("Invalid BootInfo Magic: {:#x}", bootinfo.magic);
        return 1;
    }
    log!("BootInfo parsed: {}", bootinfo);

    // Init Resource Manager
    let resource_mgr = ResourceManager::new(bootinfo);

    // Initialize Factotum Manager
    let mut manager = ProcessManager::new(CSPACE_CAP, ENDPOINT_CAP, resource_mgr, initrd);

    log!("Entering main loop");
    manager.run();
}
