use alloc::collections::BTreeMap;
use alloc::string::String;
use glenda::cap::CapPtr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Blocked, // For Futex or Join
    Dead,
}

pub struct Thread {
    pub tid: usize,
    pub tcb: CapPtr, // Capability to the TCB in Factotum's CSpace
    pub state: ThreadState,
    pub wait_tid: Option<usize>,   // If blocked on join
    pub futex_addr: Option<usize>, // If blocked on futex
}

pub struct Process {
    pub pid: usize,
    pub ppid: usize,
    pub name: String,
    pub cspace: CapPtr,
    pub vspace: CapPtr,
    pub tcb: CapPtr, // Main thread TCB
    pub threads: BTreeMap<usize, Thread>,
    pub frames: BTreeMap<usize, CapPtr>,
    pub next_tid: usize,
    // Add more fields as needed (e.g., memory regions)
}

impl Process {
    pub fn new(
        pid: usize,
        ppid: usize,
        name: String,
        cspace: CapPtr,
        vspace: CapPtr,
        tcb: CapPtr,
    ) -> Self {
        Self {
            pid,
            ppid,
            name,
            cspace,
            vspace,
            tcb,
            threads: BTreeMap::new(),
            frames: BTreeMap::new(),
            next_tid: 1,
        }
    }

    pub fn add_thread(&mut self, tcb: CapPtr) -> usize {
        let tid = self.next_tid;
        self.next_tid += 1;
        let thread =
            Thread { tid, tcb, state: ThreadState::Running, wait_tid: None, futex_addr: None };
        self.threads.insert(tid, thread);
        tid
    }

    pub fn get_thread(&self, tid: usize) -> Option<&Thread> {
        self.threads.get(&tid)
    }

    pub fn get_thread_mut(&mut self, tid: usize) -> Option<&mut Thread> {
        self.threads.get_mut(&tid)
    }

    pub fn remove_thread(&mut self, tid: usize) -> Option<Thread> {
        self.threads.remove(&tid)
    }
}

pub struct ProcessManager {
    processes: BTreeMap<usize, Process>,
    next_pid: usize,
    // Map badge (which is unique per process/thread connection) to (pid, tid)
    // For now, assuming badge == pid for simplicity as per previous code,
    // but for threads we might need a better mapping if they share the endpoint.
    // Or maybe badge encodes pid.
}

impl ProcessManager {
    pub fn new() -> Self {
        Self { processes: BTreeMap::new(), next_pid: 1 }
    }

    pub fn allocate_pid(&mut self) -> usize {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }

    pub fn add_process(&mut self, process: Process) {
        self.processes.insert(process.pid, process);
    }

    pub fn get_process(&self, pid: usize) -> Option<&Process> {
        self.processes.get(&pid)
    }

    pub fn get_process_mut(&mut self, pid: usize) -> Option<&mut Process> {
        self.processes.get_mut(&pid)
    }

    pub fn remove_process(&mut self, pid: usize) -> Option<Process> {
        self.processes.remove(&pid)
    }
}
