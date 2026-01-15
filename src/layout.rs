use glenda::cap::{CapPtr, Console, Endpoint, Frame};
use glenda::mem::RES_VA_BASE;

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE;
pub const SCRATCH_VA: usize = 0x5000_0000;

pub const UTCB_SLOT: usize = 7;

/// Capability Slot for Initrd Frame
pub const INITRD_SLOT: usize = 8;

pub const ENDPOINT_SLOT: usize = 10;

// Assume this is where our endpoint is.
pub const FACTOTUM_ENDPOINT_SLOT: usize = 10;
pub const RECV_SLOT: usize = 30;

pub const UTCB_CAP: Frame = Frame::from(CapPtr::from(UTCB_SLOT));
pub const INITRD_CAP: Frame = Frame::from(CapPtr::from(INITRD_SLOT));
pub const MONITOR_CAP: Endpoint = Endpoint::from(CapPtr::from(FACTOTUM_ENDPOINT_SLOT));
pub const RECV_CAP: Endpoint = Endpoint::from(CapPtr::from(RECV_SLOT));
pub const FACTOTUM_ENDPOINT_CAP: Endpoint = Endpoint::from(CapPtr::from(FACTOTUM_ENDPOINT_SLOT));
