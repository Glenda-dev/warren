#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;

mod elf;
mod layout;
mod warren;

use crate::layout::UNTYPED_SLOT;
use glenda::cap::{CSPACE_CAP, MONITOR_CAP, MONITOR_SLOT, REPLY_SLOT, VSPACE_CAP, CapPtr};
use glenda::cap::{CapType, RECV_SLOT};
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::mem::BOOTINFO_VA;
use glenda::utils::bootinfo::BootInfo;
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, UntypedManager, UntypedService, VSpaceManager};
use warren::WarrenManager;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("{}Warren: {}{}", glenda::console::ANSI_BLUE, format_args!($($arg)*), glenda::console::ANSI_RESET);
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Starting Warren Manager...");

    // Parse BootInfo
    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    log!("{}", bootinfo);

    // Parse Initrd
    let initrd_start = bootinfo.initrd_start;
    let initrd_size = bootinfo.initrd_size;

    // Safety check
    if initrd_start == 0 || initrd_size == 0 {
        panic!("Warren: Initrd info missing in BootInfo");
    }

    let initrd_slice =
        unsafe { core::slice::from_raw_parts(initrd_start as *const u8, initrd_size) };
    let initrd = Initrd::new(initrd_slice).expect("Warren: Failed to parse initrd");
    log!("Initrd parsed. Size: {} KB", initrd_size / 1024);

    // Init Resource Manager
    let mut untyped_mgr = UntypedManager::new(bootinfo, UNTYPED_SLOT);
    let mut vspace_mgr = VSpaceManager::new(VSPACE_CAP, layout::SCRATCH_VA, layout::SCRATCH_SIZE);
    let mut cspace_mgr = CSpaceManager::new(CSPACE_CAP, 16);

    // Allocated caps
    if untyped_mgr.alloc(CapType::Endpoint, 0, CapPtr::concat(CSPACE_CAP.cap(), MONITOR_SLOT)).is_err() {
        log!("Failed to create endpoint");
        return 1;
    }

    // Initialize Warren Manager
    let mut manager =
        WarrenManager::new(CSPACE_CAP, &mut vspace_mgr, &mut untyped_mgr, &mut cspace_mgr, initrd);
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
