use glenda::mem::RES_VA_BASE;

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE;

/// Capability Slot for Console
pub const CONSOLE_SLOT: usize = 7;

/// Capability Slot for Initrd Frame
pub const INITRD_SLOT: usize = 8;

pub const ENDPOINT_SLOT: usize = 10;

// Assume this is where our endpoint is.
pub const FACTOTUM_ENDPOINT_SLOT: usize = 10;
pub const RECV_SLOT: usize = 30;
