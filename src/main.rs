#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda::initrd::Initrd;
use glenda::manifest::Manifest;

mod ipc;
mod layout;
mod manager;
mod process;
mod spawn;

use layout::{FACTOTUM_ENDPOINT_SLOT, INITRD_VA};
use manager::ResourceManager;
use process::ProcessManager;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("Factotum: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> ! {
    log!("Starting...");

    // Parse Initrd
    let total_size_ptr = (INITRD_VA + 8) as *const u32;
    let total_size = unsafe { *total_size_ptr } as usize;
    let initrd_slice = unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };
    let initrd = Initrd::new(initrd_slice).expect("Factotum: Failed to parse initrd");
    log!("Initrd parsed. Size: {} KB", total_size / 1024);

    let pm = ProcessManager::new();
    let rm = ResourceManager::new();
    // Find Manifest
    let manifest = if let Some(data) = initrd.get_file("manifest") {
        Manifest::parse(data).expect("Failed to parse manifest")
    } else {
        panic!("Manifest not found in initrd")
    };

    log!("Listening on endpoint {}", FACTOTUM_ENDPOINT_SLOT);

    ipc::dispatch_loop(pm, rm, manifest, initrd, initrd_slice);
}
