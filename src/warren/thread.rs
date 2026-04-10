use super::WarrenManager;
use crate::layout::SERVICE_PRIORITY;
use alloc::collections::btree_set::BTreeSet;
use glenda::arch::mem::KSTACK_PAGES;
use glenda::cap::{CapPtr, CapType, Endpoint, Frame, Rights, TCB};
use glenda::error::Error;
use glenda::interface::{ThreadService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::{get_trapframe_va, get_utcb_va};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TLS {
    /// ELF 文件中 TLS 初始数据模板（.tdata）的虚拟地址
    pub master_vaddr: usize,
    /// 文件中初始数据的字节大小 (p_filesz)
    pub file_size: usize,
    /// 内存中该段的总大小 (p_memsz) -> file_size + .tbss 大小
    pub mem_size: usize,
    /// 对齐要求 (p_align)
    pub align: usize,
}

impl TLS {
    pub fn new(master_vaddr: usize, file_size: usize, mem_size: usize, align: usize) -> Self {
        Self { master_vaddr, file_size, mem_size, align }
    }
}

pub struct Thread {
    pub tid: usize,
    pub tcb: TCB,
    pub utcb: Frame,
    pub stack_base: usize,
    pub stack_pages: usize,
    pub state: ThreadState,
    pub allocated_slots: BTreeSet<CapPtr>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThreadState {
    Running,
    Suspended,
    Blocked,
    Dead,
}

impl Thread {
    pub fn new(tid: usize, tcb: TCB, utcb: Frame, stack_base: usize, stack_pages: usize) -> Self {
        Self {
            tid,
            tcb,
            utcb,
            stack_base,
            stack_pages,
            state: ThreadState::Suspended,
            allocated_slots: BTreeSet::new(),
        }
    }
}

impl<'a> ThreadService for WarrenManager<'a> {
    fn thread_create(
        &mut self,
        pid: Badge,
        entry: usize,
        arg: usize,
        stack_top: usize,
        tls: usize,
    ) -> Result<usize, Error> {
        let pid = pid.bits();
        log!("Creating thread for pid: {:?}", pid);
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let tid = process.next_tid;
        process.next_tid += 1;

        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        // Allocate slots from process arena
        let (_, tcb_slot) = process.arena_allocator.alloc_cap(CapType::TCB, 0, allocator)?;
        let tcb = TCB::from(tcb_slot);

        let (_, utcb_slot) = process.arena_allocator.alloc_cap(CapType::Frame, 1, allocator)?;
        let utcb_frame = Frame::from(utcb_slot);

        let (_, trapframe_slot) =
            process.arena_allocator.alloc_cap(CapType::Frame, 1, allocator)?;
        let trapframe = Frame::from(trapframe_slot);

        let (_, kstack_slot) =
            process.arena_allocator.alloc_cap(CapType::Frame, KSTACK_PAGES, allocator)?;
        let kstack = Frame::from(kstack_slot);

        // Map UTCB and TrapFrame to unique VAs
        let utcb_vaddr = get_utcb_va(tid);
        let trapframe_vaddr = get_trapframe_va(tid);

        process.vspace_mgr.map_frame(
            utcb_frame,
            utcb_vaddr,
            Perms::READ | Perms::WRITE,
            1,
            allocator,
            cspace_mgr,
        )?;
        process.vspace_mgr.map_frame(
            trapframe,
            trapframe_vaddr,
            Perms::READ | Perms::WRITE | Perms::SUPERVISOR,
            1,
            allocator,
            cspace_mgr,
        )?;

        let faulthandler_slot = process.arena_allocator.alloc_slot()?;
        let badge = Badge::new((pid << 16) | tid);
        self.ctx.root_cnode.mint(
            self.endpoint.cap(),
            CapPtr::null(),
            faulthandler_slot,
            badge,
            Rights::ALL,
        )?;
        let fault_ep = Endpoint::from(faulthandler_slot);

        // Configure TCB
        tcb.configure(process.cnode, process.vspace, utcb_frame, trapframe, kstack)?;
        tcb.set_fault_handler(fault_ep, true)?;

        tcb.set_address(utcb_vaddr, trapframe_vaddr)?;
        // Set entrypoint
        // pc=entry, sp=stack_top, tp=tls
        tcb.set_entrypoint(entry, stack_top, tls)?;
        // Set argument (A0=arg, A1=tid)
        tcb.set_registers(&[arg, tid])?;

        tcb.set_priority(SERVICE_PRIORITY, 0)?;
        tcb.resume()?;

        let mut thread = Thread::new(tid, tcb, utcb_frame, stack_top, 0); // stack_pages unknown if user managed
        thread.allocated_slots.insert(tcb_slot);
        thread.allocated_slots.insert(utcb_slot);
        thread.allocated_slots.insert(trapframe_slot);
        thread.allocated_slots.insert(kstack_slot);

        process.threads.insert(tid, thread);

        Ok(tid)
    }
}
