use glenda::mem::RES_VA_BASE;

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE;

/// Capability Slot for Console
pub const CONSOLE_SLOT: usize = 6;

/// Capability Slot for Initrd Frame
pub const INITRD_SLOT: usize = 7;

// Assume this is where our endpoint is.
pub const FACTOTUM_ENDPOINT_SLOT: usize = 10;
pub const FACTOTUM_UTCB_ADDR: usize = 0x7FFF_F000;
pub const FACTOTUM_STACK_TOP: usize = 0x8000_0000;
pub const RECV_SLOT: usize = 30;
