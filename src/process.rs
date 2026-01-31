use crate::manager::VSpaceManager;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::cap::{CNode, CapPtr, TCB, VSpace};

/// Process Control Block in Factotum
pub struct Process {
    pub pid: usize,
    pub parent_pid: usize,
    pub name: String,

    // Capabilities
    pub tcb: TCB,
    pub vspace: VSpace, // Root VSpace
    pub cnode: CNode,   // Root CNode

    // State
    pub state: ProcessState,
    pub exit_code: usize,
    // Manage process mappings
    pub vspace_mgr: VSpaceManager,
    pub heap_start: usize,
    pub heap_brk: usize,

    pub allocated_slots: Vec<CapPtr>, // 记录 Factotum 为此进程占用的所有槽位
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
        pid: usize,
        parent_pid: usize,
        name: String,
        tcb: TCB,
        vspace: VSpace,
        cnode: CNode,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            name,
            tcb,
            vspace,
            cnode,
            state: ProcessState::Suspended, // Starts suspended until scheduled/loaded
            exit_code: 0,
            vspace_mgr: VSpaceManager::new(vspace),
            heap_start: 0,
            allocated_slots: Vec::new(),
            heap_brk: 0,
        }
    }
}
