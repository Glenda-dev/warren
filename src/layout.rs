use glenda::arch::mem::PGSIZE;

pub const SCRATCH_VA: usize = 0x3000_0000;
pub const SCRATCH_SIZE: usize = 0x100_0000; // 16MB

pub const INIT_NAME: &str = "nineball";

pub const STACK_PAGES: usize = 16; // 用户栈页面数 16 * 4KB = 64KB
pub const STACK_SIZE: usize = STACK_PAGES * PGSIZE; // 64KB
pub const HEAP_PAGES: usize = 256; // 用户堆页面数 256 * 4KB = 1MB
pub const HEAP_SIZE: usize = HEAP_PAGES * PGSIZE; // 1MB
pub const HEAP_VA: usize = 0x2000_0000; // 用户堆地址
