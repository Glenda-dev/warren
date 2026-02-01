use glenda::cap::{CapPtr, Endpoint, Reply};

pub const SCRATCH_VA: usize = 0x3000_0000;
pub const RECV_SLOT: CapPtr = CapPtr::from(30);
pub const REPLY_SLOT: CapPtr = CapPtr::from(100);

pub const RECV_CAP: Endpoint = Endpoint::from(RECV_SLOT);
pub const REPLY_CAP: Reply = Reply::from(REPLY_SLOT);

pub const INIT_NAME: &str = "nineball";
pub const DEVMGR_NAME: &str = "unicorn";
