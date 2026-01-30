use alloc::collections::BTreeMap;
use alloc::string::ToString;
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Reply, TCB, VSpace};
use glenda::error::Error;
use glenda::ipc::MsgTag;
use glenda::ipc::utcb;
use glenda::protocol::process as proto;

use super::ResourceManager;
use crate::initrd::Initrd;
use crate::layout::REPLY_CAP;
use crate::process::{Process, ProcessState};

const REPLY_SLOT: usize = 100;

pub struct ProcessManager<'a> {
    processes: BTreeMap<usize, Process>,
    next_pid: usize,

    // Self Resources
    root_cnode: CNode,
    endpoint: Endpoint,
    reply_cap: Reply,

    resource_mgr: ResourceManager,
    initrd: Initrd<'a>,
    free_slot: usize,
}

impl<'a> ProcessManager<'a> {
    pub fn new(
        root_cnode: CNode,
        endpoint: Endpoint,
        resource_mgr: ResourceManager,
        initrd: Initrd<'a>,
    ) -> Self {
        Self {
            processes: BTreeMap::new(),
            next_pid: 1,
            root_cnode,
            endpoint,
            reply_cap: REPLY_CAP,
            resource_mgr,
            initrd,
            free_slot: 10,
        }
    }

    fn alloc_slot(&mut self) -> CapPtr {
        let slot = self.free_slot;
        self.free_slot += 1;
        CapPtr::new(slot, 0)
    }

    pub fn run(&mut self) -> ! {
        loop {
            // Receive message, putting reply cap in REPLY_SLOT
            let badge = self.endpoint.recv(REPLY_CAP.cap());

            // Get message info from UTCB
            let utcb = unsafe { utcb::get() };
            let msg_info = utcb.msg_tag;
            let label = msg_info.label();

            // Dispatch
            let result = self.dispatch(badge, label, &utcb.mrs_regs);

            // Reply
            match result {
                Ok(val) => {
                    self.reply_ok(val);
                }
                Err(e) => {
                    self.reply_err(e);
                }
            }
        }
    }

    fn reply_ok(&self, val: usize) {
        let utcb = unsafe { utcb::get() };
        utcb.mrs_regs[0] = 0; // OK
        utcb.mrs_regs[1] = val;
        let tag = MsgTag::new(0, 2);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn reply_err(&self, err: Error) {
        let utcb = unsafe { utcb::get() };
        utcb.mrs_regs[0] = err as usize;
        let tag = MsgTag::new(0, 1);
        self.reply_cap.reply(tag, [0; 7]);
    }

    fn dispatch(&mut self, _badge: usize, label: usize, _args: &[usize]) -> Result<usize, Error> {
        match label {
            proto::SPAWN => self.spawn_process("child"),
            _ => Err(Error::InvalidMethod),
        }
    }

    fn spawn_process(&mut self, name: &str) -> Result<usize, Error> {
        let pid = self.next_pid;
        self.next_pid += 1;

        // Alloc CNode
        let cnode_slot = self.alloc_slot();
        if self.resource_mgr.alloc(CapType::CNode, 64, self.root_cnode, cnode_slot).is_err() {
            // Map string/alloc error to generic error
            return Err(Error::UntypeOOM); // Placeholder for OOM
        }
        let child_cnode = CNode::from(cnode_slot);

        // Alloc VSpace (Root PageTable)
        let pd_slot = self.alloc_slot();
        if self.resource_mgr.alloc(CapType::VSpace, 0, self.root_cnode, pd_slot).is_err() {
            return Err(Error::UntypeOOM);
        }
        let child_pd = VSpace::from(pd_slot);

        // Alloc TCB
        let tcb_slot = self.alloc_slot();
        // TCB size is slightly weird, usually fits in 1 page (4KB) for seL4.
        // Assuming 1 page usage for simplicity.
        if self.resource_mgr.alloc(CapType::TCB, 1, self.root_cnode, tcb_slot).is_err() {
            return Err(Error::UntypeOOM);
        }
        let child_tcb = TCB::from(tcb_slot);

        let process = Process::new(pid, 0, name.to_string(), child_tcb, child_pd, child_cnode);

        self.processes.insert(pid, process);

        Ok(pid)
    }
}
