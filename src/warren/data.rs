use super::thread::Thread;
use crate::policy::ArenaAllocator;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::string::String;
use glenda::cap::{CNode, CapPtr, Frame, TCB, VSpace};
use glenda::utils::manager::VSpaceManager;

/// Process Control Block in Warren
pub struct Process {
    pub pid: usize,
    pub parent_pid: usize,
    pub name: String,

    // Capabilities
    // Threads
    pub threads: BTreeMap<usize, Thread>,
    pub next_tid: usize,

    pub vspace: VSpace, // Root VSpace
    pub cnode: CNode,   // Root CNode

    // State
    pub state: ProcessState,
    pub exit_code: usize,
    // Manage process mappings
    pub vspace_mgr: VSpaceManager,
    pub arena_allocator: Box<ArenaAllocator>,

    pub heap_start: usize,
    pub heap_brk: usize,

    pub image_slots: BTreeSet<CapPtr>, // 记录 ELF 加载时占用的槽位
    pub allocated_slots: BTreeSet<CapPtr>, // 记录进程级根资源槽位（如 arena 根能力）
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
        utcb: Frame,
        vspace_mgr: VSpaceManager,
        arena_allocator: Box<ArenaAllocator>,
        stack_base: usize,
    ) -> Self {
        let mut threads = BTreeMap::new();
        let main_thread = Thread::new(0, tcb, utcb, stack_base, 0);

        threads.insert(0, main_thread);

        Self {
            pid,
            parent_pid,
            name,
            threads,
            next_tid: 1,
            vspace,
            cnode,
            state: ProcessState::Suspended,
            exit_code: 0,
            vspace_mgr,
            arena_allocator,
            heap_start: 0,
            image_slots: BTreeSet::new(),
            allocated_slots: BTreeSet::new(),
            heap_brk: 0,
        }
    }
}
