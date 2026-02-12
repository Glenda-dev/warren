mod data;
mod fault;
mod memory;
mod process;
mod resource;
mod server;
mod thread;

pub use data::*;
pub use thread::TLS;

use crate::layout::{BOOTINFO_SLOT, IRQ_SLOT, MMIO_SLOT, PLATFORM_SLOT, STACK_SIZE, UNTYPED_SLOT};
use crate::warren::resource::ResourceRegistry;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Frame, Reply, Rights, TCB, VSpace};
use glenda::cap::{CSPACE_SLOT, KERNEL_SLOT, MONITOR_SLOT, TCB_SLOT, VSPACE_SLOT};
use glenda::error::Error;
use glenda::ipc::{Badge, IpcRouter};
use glenda::mem::Perms;
use glenda::mem::{ENTRY_VA, HEAP_PAGES, HEAP_SIZE, HEAP_VA, STACK_VA, TRAPFRAME_VA, UTCB_VA};
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, UntypedManager, VSpaceManager};
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

const SERVICE_PRIORITY: u8 = 252;

pub struct SystemContext<'a> {
    pub root_cnode: CNode,
    pub vspace_mgr: &'a mut VSpaceManager,
    pub untyped_mgr: &'a mut UntypedManager,
    pub cspace_mgr: &'a mut CSpaceManager,
}

pub struct WarrenManager<'a> {
    processes: BTreeMap<Badge, Process>,
    pid: Badge,

    // Communication
    endpoint: Endpoint,
    reply: Reply,
    recv: CapPtr,

    // Sync
    wait_queues: BTreeMap<(Badge, usize), VecDeque<CapPtr>>,

    // Initrd
    initrd: Initrd<'a>,

    // Resources
    res: ResourceRegistry,

    // Context
    ctx: SystemContext<'a>,
    running: bool,
    router: IpcRouter<WarrenManager<'a>>,
}

impl<'a> WarrenManager<'a> {
    pub fn new(
        root_cnode: CNode,
        vspace_mgr: &'a mut VSpaceManager,
        untyped_mgr: &'a mut UntypedManager,
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
            pid: Badge::null(),
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            recv: CapPtr::null(),
            wait_queues: BTreeMap::new(),
            initrd,
            res: ResourceRegistry {
                kernel_cap: KERNEL_SLOT,
                irq_cap: IRQ_SLOT,
                mmio_cap: MMIO_SLOT,
                untyped_cap: UNTYPED_SLOT,
                bootinfo_cap: BOOTINFO_SLOT,
                platform_cap: PLATFORM_SLOT,
                endpoints: BTreeMap::new(),
            },
            ctx: SystemContext { root_cnode, vspace_mgr, untyped_mgr, cspace_mgr },
            running: false,
            router: IpcRouter::new(),
        }
    }
    fn alloc_pid(&mut self) -> Result<Badge, Error> {
        let next = self.pid.bits().checked_add(1).ok_or(Error::CNodeFull)?;
        self.pid = Badge::new(next);
        Ok(self.pid)
    }
    fn create(&mut self, name: &str) -> Result<Process, Error> {
        let pid = self.alloc_pid()?;

        let ep_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.root_cnode.mint(self.endpoint.cap(), ep_slot, pid, Rights::ALL)?;
        let child_endpoint = Endpoint::from(ep_slot);

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_cnode_dest = CapPtr::concat(self.ctx.root_cnode.cap(), cnode_slot);
        self.ctx.untyped_mgr.alloc(CapType::CNode, 0, full_cnode_dest)?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_pd_dest = CapPtr::concat(self.ctx.root_cnode.cap(), pd_slot);
        self.ctx.untyped_mgr.alloc(CapType::VSpace, 0, full_pd_dest)?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_tcb_dest = CapPtr::concat(self.ctx.root_cnode.cap(), tcb_slot);
        self.ctx.untyped_mgr.alloc(CapType::TCB, 0, full_tcb_dest)?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_utcb_dest = CapPtr::concat(self.ctx.root_cnode.cap(), utcb_slot);
        self.ctx.untyped_mgr.alloc(CapType::Frame, 1, full_utcb_dest)?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_tf_dest = CapPtr::concat(self.ctx.root_cnode.cap(), trapframe_slot);
        self.ctx.untyped_mgr.alloc(CapType::Frame, 1, full_tf_dest)?;
        let child_trapframe = Frame::from(trapframe_slot);

        let stack_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_stack_dest = CapPtr::concat(self.ctx.root_cnode.cap(), stack_slot);
        self.ctx.untyped_mgr.alloc(CapType::Frame, 1, full_stack_dest)?;
        let child_stack = Frame::from(stack_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_kstack_dest = CapPtr::concat(self.ctx.root_cnode.cap(), kstack_slot);
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            full_kstack_dest,
        )?;
        let child_kstack = Frame::from(kstack_slot);

        let heap_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        let full_heap_dest = CapPtr::concat(self.ctx.root_cnode.cap(), heap_slot);
        self.ctx.untyped_mgr.alloc(CapType::Frame, HEAP_PAGES, full_heap_dest)?;
        let child_heap = Frame::from(heap_slot);

        child_cnode.copy(child_pd.cap(), VSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_cnode.cap(), CSPACE_SLOT, Rights::ALL)?;
        child_cnode.copy(child_tcb.cap(), TCB_SLOT, Rights::ALL)?;
        child_cnode.copy(child_endpoint.cap(), MONITOR_SLOT, Rights::ALL)?;

        // Child process vspace manager doesn't use scratch area from self, or we can give it one?
        // For now, pass 0 size to indicate no scratch area.
        let mut vspace_mgr = VSpaceManager::new(child_pd, 0, 0);
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;
        // Enable fault handler with badge=pid
        child_tcb.set_fault_handler(child_endpoint, true)?;

        vspace_mgr.map_frame(
            child_utcb,
            UTCB_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_trapframe,
            TRAPFRAME_VA,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_stack,
            STACK_VA - PGSIZE,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        vspace_mgr.map_frame(
            child_heap,
            HEAP_VA,
            Perms::READ | Perms::WRITE | Perms::USER,
            HEAP_PAGES,
            self.ctx.untyped_mgr,
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
        process.heap_start = HEAP_VA;
        process.heap_brk = HEAP_VA + HEAP_SIZE;
        process.allocated_slots.push(cnode_slot);
        process.allocated_slots.push(pd_slot);
        process.allocated_slots.push(tcb_slot);
        process.allocated_slots.push(utcb_slot);
        process.allocated_slots.push(trapframe_slot);
        process.allocated_slots.push(kstack_slot);
        process.allocated_slots.push(ep_slot);
        process.allocated_slots.push(stack_slot);
        process.allocated_slots.push(heap_slot);
        Ok(process)
    }
}
