use glenda::arch::mem::PGSIZE;
use glenda::cap::{CNode, CapPtr, Frame, IrqHandler};

pub const SCRATCH_VA: usize = 0x3000_0000;
pub const SCRATCH_SIZE: usize = 0x100_0000; // 16MB

pub const INIT_NAME: &str = "nineball";

pub const STACK_PAGES: usize = 64; // 用户栈页面数 64 * 4KB = 256KB
pub const STACK_SIZE: usize = STACK_PAGES * PGSIZE; // 64KB

pub const BOOTINFO_SLOT: CapPtr = CapPtr::from(9);
pub const UNTYPED_SLOT: CapPtr = CapPtr::from(10);
pub const KERNEL_SLOT: CapPtr = CapPtr::from(11);
pub const IRQ_CONTROL_SLOT: CapPtr = CapPtr::from(12);
pub const CONSOLE_SLOT: CapPtr = CapPtr::from(5);

pub const BOOTINFO_CAP: Frame = Frame::from(BOOTINFO_SLOT);
pub const UNTYPED_CAP: CNode = CNode::from(UNTYPED_SLOT);
pub const CONSOLE_CAP: glenda::cap::Console = glenda::cap::Console::from(CONSOLE_SLOT);
pub const IRQ_CONTROL_CAP: IrqHandler = IrqHandler::from(IRQ_CONTROL_SLOT);
