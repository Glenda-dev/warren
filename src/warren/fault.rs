use super::WarrenManager;
use crate::log;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame};
use glenda::error::Error;
use glenda::interface::{FaultService, ProcessService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::STACK_BASE;
use glenda::utils::align::align_down;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

const MAX_STACK_SIZE: usize = 8 * 1024 * 1024; // 8MB

impl<'a> FaultService for WarrenManager<'a> {
    fn page_fault(
        &mut self,
        badge: Badge,
        addr: usize,
        pc: usize,
        cause: usize,
    ) -> Result<(), Error> {
        let full_badge = badge.bits();
        let pid = Badge::new(full_badge >> 16);
        let tid = full_badge & 0xFFFF;

        // Only handle stack growth
        if addr < STACK_BASE - MAX_STACK_SIZE || addr >= STACK_BASE {
            log!(
                "PageFault outside stack: pid: {:?}, tid: {}, address={:#x}, pc={:#x}, cause={:#x}",
                pid,
                tid,
                addr,
                pc,
                cause
            );
            return self.exit(pid, 0x0b);
        }

        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let thread = process.threads.get_mut(&tid).ok_or(Error::NotFound)?;

        log!(
            "PageFault (Stack): pid: {:?}, tid: {}, address={:#x}, pc={:#x}, cause={:#x}",
            pid,
            tid,
            addr,
            pc,
            cause
        );

        // 1. Allocate Frame
        let frame_slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;

        self.ctx.buddy.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), frame_slot),
        )?;

        // 2. Map Frame
        let page_base = align_down(addr, PGSIZE);
        let perms = Perms::READ | Perms::WRITE | Perms::USER;
        let frame = Frame::from(frame_slot);

        process.vspace_mgr.map_frame(
            frame,
            page_base,
            perms,
            1,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode, // Using Warren's cnode for mapping bookkeeping
        )?;

        // 3. Record Resource
        thread.stack_pages += 1;
        thread.allocated_slots.push(frame_slot);
        log!("Solved PageFault with stack_pages: {}", thread.stack_pages);
        Ok(())
    }
    fn unknown_fault(
        &mut self,
        badge: Badge,
        cause: usize,
        value: usize,
        pc: usize,
    ) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        log!(
            "Unhandled fault: pid: {:?}, cause={:#x}, value={:#x}, pc={:#x}. Killing process.\n",
            pid,
            cause,
            value,
            pc
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
    fn access_fault(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        log!("Access Fault: pid: {:?}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn access_misaligned(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        log!("Misaligned Access: pid: {:?}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn breakpoint(&mut self, badge: Badge, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        log!("Breakpoint: pid: {:?}, pc={:#x}", pid, pc);
        // Maybe resume or handled by debugger service
        self.exit(pid, 0x05).map(|_| ())
    }

    fn illegal_instrution(&mut self, badge: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        log!("Illegal Instruction: pid: {:?}, inst={:#x}, pc={:#x}", pid, inst, pc);
        self.exit(pid, 0x04).map(|_| ())
    }

    fn handle_syscall(&mut self, badge: usize, args: glenda::ipc::MsgArgs) -> Result<(), Error> {
        let pid = Badge::new(badge >> 16);
        log!(
            "Non-Native Syscall: pid: {:?}, args=[{},{},{},{},{},{},{},{}]",
            pid,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            args[6],
            args[7]
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
}
