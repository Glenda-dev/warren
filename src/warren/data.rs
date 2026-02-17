use super::thread::Thread;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::cap::{CNode, CapPtr, Frame, TCB, VSpace};
use glenda::ipc::Badge;
use glenda::utils::manager::VSpaceManager;

/// Process Control Block in Warren
pub struct Process {
    pub pid: Badge,
    pub parent_pid: Badge,
    pub name: String,

    // Capabilities
    // Threads
    pub threads: BTreeMap<usize, Thread>,
    pub next_tid: usize,

    pub vspace: VSpace, // Root VSpace
    pub cnode: CNode,   // Root CNode
    // pub utcb: Frame,    // UTCB moved to Thread

    // State
    pub state: ProcessState,
    pub exit_code: usize,
    // Manage process mappings
    pub vspace_mgr: VSpaceManager,
    pub heap_start: usize,
    pub heap_brk: usize,
    // pub stack_base: usize, // Moved to Thread
    // pub stack_pages: usize, // Moved to Thread
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
        let mut threads = BTreeMap::new();
        let main_thread = Thread::new(0, tcb, utcb, stack_base, 0); // stack_pages is 0 initially? 
        // Note: Process::new calls specify stack_pages later?
        // In previous code stack_pages was initialized to 0 in new().

        threads.insert(0, main_thread);

        Self {
            pid,
            parent_pid,
            name,
            threads,
            next_tid: 1,
            vspace,
            cnode,
            state: ProcessState::Suspended, // Starts suspended until scheduled/loaded
            exit_code: 0,
            vspace_mgr,
            heap_start: 0,
            allocated_slots: Vec::new(),
            heap_brk: 0,
            // stack_base, // removed
            // stack_pages: 0, // removed
        }
    }
}
