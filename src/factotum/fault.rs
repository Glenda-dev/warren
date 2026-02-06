use super::ProcessManager;
use crate::log;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{FaultService, ProcessService, ResourceService};
use glenda::ipc::{Badge, MsgArgs};
use glenda::mem::Perms;
use glenda::mem::STACK_VA;
use glenda::utils::align::align_down;
use glenda::utils::manager::{CSpaceService, VSpaceService};

const MAX_STACK_SIZE: usize = 8 * 1024 * 1024; // 8MB

impl<'a> FaultService for ProcessManager<'a> {
    fn page_fault(
        &mut self,
        pid: Badge,
        addr: usize,
        pc: usize,
        cause: usize,
    ) -> Result<(), Error> {
        // Only handle stack growth
        if addr < STACK_VA - MAX_STACK_SIZE || addr >= STACK_VA {
            log!(
                "PageFault outside stack: pid={}, address={:#x}, pc={:#x}, cause={:#x}",
                pid,
                addr,
                pc,
                cause
            );
            return self.exit(pid, 0x0b).map(|_| ());
        }

        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;

        log!(
            "PageFault (Stack): pid={}, address={:#x}, pc={:#x}, cause={:#x}",
            pid,
            addr,
            pc,
            cause
        );

        // 1. Allocate Frame
        let frame_slot = self.ctx.cspace_mgr.alloc(self.ctx.resource_mgr)?;

        self.ctx.resource_mgr.alloc(
            Badge::null(),
            CapType::Frame,
            1,
            self.ctx.root_cnode,
            frame_slot,
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
            self.ctx.resource_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode, // Using Factotum's cnode for mapping bookkeeping
        )?;

        // 3. Record Resource
        process.stack_pages += 1;
        process.allocated_slots.push(frame_slot);
        log!("Solved PageFault with stack_pages: {}", process.stack_pages);
        Ok(())
    }
    fn unknown_fault(
        &mut self,
        pid: Badge,
        cause: usize,
        value: usize,
        pc: usize,
    ) -> Result<(), Error> {
        log!(
            "Unhandled fault: pid={}, cause={:#x}, value={:#x}, pc={:#x}. Killing process.\n",
            pid,
            cause,
            value,
            pc
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
    fn access_fault(&mut self, pid: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        log!("Access Fault: pid={}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn access_misaligned(&mut self, pid: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        log!("Misaligned Access: pid={}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn breakpoint(&mut self, pid: Badge, pc: usize) -> Result<(), Error> {
        log!("Breakpoint: pid={}, pc={:#x}", pid, pc);
        // Maybe resume or handled by debugger service
        self.exit(pid, 0x05).map(|_| ())
    }

    fn illegal_instrution(&mut self, pid: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        log!("Illegal Instruction: pid={}, inst={:#x}, pc={:#x}", pid, inst, pc);
        self.exit(pid, 0x04).map(|_| ())
    }

    fn syscall(&mut self, pid: Badge, reg: MsgArgs) -> Result<(), Error> {
        log!(
            "Non-Native Syscall: pid={}, regs=[{},{},{},{},{},{},{},{}]",
            pid,
            reg[0],
            reg[1],
            reg[2],
            reg[3],
            reg[4],
            reg[5],
            reg[6],
            reg[7]
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
}
