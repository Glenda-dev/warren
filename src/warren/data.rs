use alloc::string::String;
use alloc::vec::Vec;
use glenda::cap::{CNode, CapPtr, Frame, TCB, VSpace};
use glenda::error::Error;
use glenda::ipc::Badge;
use glenda::utils::manager::VSpaceManager;

/// Process Control Block in Warren
pub struct Process {
    pub pid: Badge,
    pub parent_pid: Badge,
    pub name: String,

    // Capabilities
    pub tcb: TCB,
    pub vspace: VSpace, // Root VSpace
    pub cnode: CNode,   // Root CNode
    pub utcb: Frame,    // UTCB

    // State
    pub state: ProcessState,
    pub exit_code: usize,
    // Manage process mappings
    pub vspace_mgr: VSpaceManager,
    pub heap_start: usize,
    pub heap_brk: usize,
    pub stack_base: usize,
    pub stack_pages: usize,

    pub allocated_slots: Vec<CapPtr>, // 记录 Warren 为此进程占用的所有槽位
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Suspended,
    Dead,
}

impl Process {
    pub fn new(
        pid: Badge,
        parent_pid: Badge,
        name: String,
        tcb: TCB,
        vspace: VSpace,
        cnode: CNode,
        utcb: Frame,
        vspace_mgr: VSpaceManager,
        stack_base: usize,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            name,
            tcb,
            vspace,
            cnode,
            utcb,
            state: ProcessState::Suspended, // Starts suspended until scheduled/loaded
            exit_code: 0,
            vspace_mgr,
            heap_start: 0,
            allocated_slots: Vec::new(),
            heap_brk: 0,
            stack_base,
            stack_pages: 0,
        }
    }

    pub fn setup_heap(&mut self, addr: usize, size: usize) -> Result<(), Error> {
        self.heap_start = addr;
        self.heap_brk = self.heap_start + size;
        Ok(())
    }
}
