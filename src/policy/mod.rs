pub mod arena;
pub mod buddy;

pub use arena::ArenaAllocator;
pub use buddy::BuddyAllocator as Allocator;

use glenda::cap::{CapPtr, Untyped};
use glenda::error::Error;
use glenda::interface::{CSpaceProvider, UntypedService, VSpaceProvider};
use glenda::protocol::resource::MemoryStatus;
use glenda::utils::BootInfo;

/// The MemoryPolicy trait defines the core interface for memory allocation and capability management
/// in the Warren service. It combines several sub-traits to provide a unified interface for
/// SystemContext and other components.
pub trait MemoryPolicy<'a>: UntypedService + VSpaceProvider + CSpaceProvider {
    /// Initialize the policy with boot information and system managers
    fn init(&mut self, bootinfo: &BootInfo) -> Result<(), Error>;

    /// Incrementally add untyped memory regions to the policy's management
    fn add_memory_block(&mut self, cap: Untyped, order: usize, paddr: usize);

    fn add_free_slot(&mut self, slots: CapPtr);

    fn reserve_count(&self) -> usize;

    fn status(&self) -> MemoryStatus;
}
