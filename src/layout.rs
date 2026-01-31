use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::runtime::service::{FAULT_SLOT, PLATFORM_SLOT};

/// Virtual Address where Initrd is mapped in Root Task
pub const SCRATCH_VA2: usize = SCRATCH_VA + PGSIZE;
pub const SCRATCH_VA: usize = 0x3000_0000;
pub const ENDPOINT_SLOT: CapPtr = FAULT_SLOT;
pub const PLATFORM_INFO_SLOT: CapPtr = PLATFORM_SLOT;
pub const RECV_SLOT: CapPtr = CapPtr::from(30);
pub const REPLY_SLOT: CapPtr = CapPtr::from(100);

pub const RECV_CAP: Endpoint = Endpoint::from(RECV_SLOT);
pub const ENDPOINT_CAP: Endpoint = Endpoint::from(ENDPOINT_SLOT);
pub const REPLY_CAP: Reply = Reply::from(REPLY_SLOT);

pub const INIT_NAME: &str = "nineball";
pub const DEVMGR_NAME: &str = "unicorn";
