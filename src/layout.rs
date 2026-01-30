use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, Endpoint, Reply};

/// Virtual Address where Initrd is mapped in Root Task
pub const SCRATCH_VA2: usize = SCRATCH_VA + PGSIZE;
pub const SCRATCH_VA: usize = 0x3000_0000;
pub const ENDPOINT_SLOT: usize = 10;
pub const RECV_SLOT: usize = 30;
pub const REPLY_SLOT: usize = 100;

pub const RECV_CAP: Endpoint = Endpoint::from(CapPtr::new(RECV_SLOT, 0));
pub const ENDPOINT_CAP: Endpoint = Endpoint::from(CapPtr::new(ENDPOINT_SLOT, 0));
pub const REPLY_CAP: Reply = Reply::from(CapPtr::new(REPLY_SLOT, 0));

pub const INIT_NAME: &str = "nineball";
pub const DEVMGR_NAME: &str = "unicorn";
