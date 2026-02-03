mod data;
mod fault;
mod manage;
mod memory;
mod server;
mod thread;

pub use data::*;
pub use thread::TLS;

use crate::layout::{HEAP_SIZE, HEAP_VA, STACK_SIZE};
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, Rights, TCB, VSpace};
use glenda::cap::{
    CSPACE_SLOT, KERNEL_SLOT, MMIO_SLOT, MONITOR_SLOT, PLATFORM_SLOT, TCB_SLOT, VSPACE_SLOT,
};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::manager::{CSpaceManager, ResourceManager, VSpaceManager};
use glenda::mem::Perms;
use glenda::mem::{ENTRY_VA, STACK_VA, TRAPFRAME_VA, UTCB_VA};
use glenda::utils::initrd::Initrd;

const SERVICE_PRIORITY: u8 = 252;

pub struct SystemContext<'a> {
    pub root_cnode: CNode,
    pub vspace_mgr: &'a mut VSpaceManager,
    pub resource_mgr: &'a mut ResourceManager,
    pub cspace_mgr: &'a mut CSpaceManager,
}

pub struct ProcessManager<'a> {
    processes: BTreeMap<Badge, Process>,
    pid: Badge,

    // Communication
    endpoint: Endpoint,
    reply: Reply,
    initrd: Initrd<'a>,

    // Context
    ctx: SystemContext<'a>,
    running: bool,
}

impl<'a> ProcessManager<'a> {
    pub fn new(
        root_cnode: CNode,
        vspace_mgr: &'a mut VSpaceManager,
        resource_mgr: &'a mut ResourceManager,
        cspace_mgr: &'a mut CSpaceManager,
        initrd: Initrd<'a>,
    ) -> Self {
        // Init self vspace with known regions (to populate shadow tables)
        // 1. Text/Data - Low mem 0x10000+
        vspace_mgr.mark_existing(ENTRY_VA, PGSIZE);
        // 2. Stack - High mem
        vspace_mgr.mark_existing(STACK_VA, STACK_SIZE);
        // 3. Heap
        vspace_mgr.mark_existing(HEAP_VA, HEAP_SIZE);
        // 4. UTCB
        vspace_mgr.mark_existing(UTCB_VA, PGSIZE);
        // 5. TrapFrame
        vspace_mgr.mark_existing(TRAPFRAME_VA, PGSIZE);

        Self {
            processes: BTreeMap::new(),
            pid: Badge::new(1),
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            initrd,
            ctx: SystemContext { root_cnode, vspace_mgr, resource_mgr, cspace_mgr },
            running: false,
        }
    }
    fn alloc_pid(&mut self) -> Result<Badge, Error> {
        let next = self.pid.bits().checked_add(1).ok_or(Error::OutOfSlots)?;
        self.pid = Badge::new(next);
        Ok(self.pid)
    }
    fn create(&mut self, name: &str) -> Result<Process, Error> {
        let pid = self.alloc_pid()?;

        let ep_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.root_cnode.mint(self.endpoint.cap(), ep_slot, pid, Rights::ALL)?;
        let child_endpoint = Endpoint::from(ep_slot);

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::CNode, 0, self.ctx.root_cnode, cnode_slot)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::VSpace, 0, self.ctx.root_cnode, pd_slot)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::TCB, 0, self.ctx.root_cnode, tcb_slot)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, utcb_slot)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, trapframe_slot)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let stack_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, stack_slot)?;
        let child_stack = Frame::from(stack_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;
        self.ctx.resource_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            self.ctx.root_cnode,
            kstack_slot,
        )?;
        let child_kstack = Frame::from(kstack_slot);

        child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL)?;
        child_cnode.copy(KERNEL_SLOT, KERNEL_SLOT, Rights::ALL)?;
        child_cnode.copy(PLATFORM_SLOT, PLATFORM_SLOT, Rights::ALL)?;
        child_cnode.copy(MMIO_SLOT, MMIO_SLOT, Rights::ALL)?;
        child_cnode.copy(child_endpoint.cap(), MONITOR_SLOT, Rights::ALL)?;

        // Child process vspace manager doesn't use scratch area from self, or we can give it one?
        // For now, pass 0 size to indicate no scratch area.
        let mut vspace_mgr = VSpaceManager::new(child_pd, 0, 0);
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;
        // Enable fault handler with badge=pid
        //child_tcb.set_fault_handler(child_endpoint, true)?;

        vspace_mgr.map_frame(
            child_utcb,
            UTCB_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_stack,
            STACK_VA - PGSIZE,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.setup()?;

        let mut process = Process::new(
            pid,
            Badge::null(),
            name.to_string(),
            child_tcb,
            child_pd,
            child_cnode,
            child_utcb,
            vspace_mgr,
            STACK_VA,
        );
        process.stack_pages = 1;
        process.allocated_slots.push(cnode_slot);
        process.allocated_slots.push(pd_slot);
        process.allocated_slots.push(tcb_slot);
        process.allocated_slots.push(utcb_slot);
        process.allocated_slots.push(trapframe_slot);
        process.allocated_slots.push(kstack_slot);
        process.allocated_slots.push(ep_slot);
        process.allocated_slots.push(stack_slot);
        Ok(process)
    }
}
