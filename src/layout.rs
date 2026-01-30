use glenda::arch::mem::PGSIZE;
use glenda::cap::{CNode, CapPtr, Endpoint, Frame, Reply};
use glenda::mem::RES_VA_BASE;

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE + 2 * PGSIZE;
pub const BOOTINFO_VA: usize = RES_VA_BASE + PGSIZE;
pub const SCRATCH_VA: usize = RES_VA_BASE;
pub const ENDPOINT_SLOT: usize = 10;
pub const RECV_SLOT: usize = 30;
pub const REPLY_SLOT: usize = 100;

pub const RECV_CAP: Endpoint = Endpoint::from(CapPtr::new(RECV_SLOT, 0));
pub const ENDPOINT_CAP: Endpoint = Endpoint::from(CapPtr::new(ENDPOINT_SLOT, 0));
pub const REPLY_CAP: Reply = Reply::from(CapPtr::new(REPLY_SLOT, 0));
