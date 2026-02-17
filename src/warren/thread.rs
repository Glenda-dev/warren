use super::WarrenManager;
use crate::log;
use alloc::vec::Vec;
use glenda::arch::mem::KSTACK_PAGES;
use glenda::cap::{CapPtr, CapType, Frame, Rights, TCB};
use glenda::error::Error;
use glenda::interface::ThreadService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::{get_trapframe_va, get_utcb_va};
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

pub const SERVICE_PRIORITY: u8 = 128;

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
    pub allocated_slots: Vec<CapPtr>,
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
            allocated_slots: Vec::new(),
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
        log!("Creating thread for pid: {:?}", pid);
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let tid = process.next_tid;
        process.next_tid += 1;

        // Allocate slots
        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.buddy.alloc(
            CapType::TCB,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), tcb_slot),
        )?;
        let tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.buddy.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), utcb_slot),
        )?;
        let utcb_frame = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.buddy.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), trapframe_slot),
        )?;
        let trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.buddy.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            CapPtr::concat(self.ctx.root_cnode.cap(), kstack_slot),
        )?;
        let kstack = Frame::from(kstack_slot);

        // Map UTCB and TrapFrame to unique VAs
        let utcb_vaddr = get_utcb_va(tid);
        let trapframe_vaddr = get_trapframe_va(tid);

        process.vspace_mgr.map_frame(
            utcb_frame,
            utcb_vaddr,
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        process.vspace_mgr.map_frame(
            trapframe,
            trapframe_vaddr,
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;

        let faulthandler_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let badge = Badge::new((pid.bits() << 16) | tid);
        self.ctx.root_cnode.mint(self.endpoint.cap(), faulthandler_slot, badge, Rights::ALL)?;
        let fault_ep = glenda::cap::Endpoint::from(faulthandler_slot);

        // Configure TCB
        tcb.configure(process.cnode, process.vspace, utcb_frame, trapframe, kstack)?;
        tcb.set_fault_handler(fault_ep, true)?;

        tcb.set_address(utcb_vaddr, trapframe_vaddr)?;
        // Set entrypoint
        // pc=entry, sp=stack_top, tp=tls
        tcb.set_entrypoint(entry, stack_top, tls)?;
        // Set argument (A0=arg, A1=tid)
        tcb.set_registers(&[arg, tid])?;

        tcb.set_priority(SERVICE_PRIORITY)?;
        tcb.resume()?;

        let mut thread = Thread::new(tid, tcb, utcb_frame, stack_top, 0); // stack_pages unknown if user managed
        thread.allocated_slots.push(tcb_slot);
        thread.allocated_slots.push(utcb_slot);
        thread.allocated_slots.push(trapframe_slot);
        thread.allocated_slots.push(kstack_slot);
        thread.allocated_slots.push(faulthandler_slot);

        process.threads.insert(tid, thread);

        Ok(tid)
    }
}
