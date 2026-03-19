use super::WarrenManager;
use crate::layout::MAX_STACK_SIZE;
use glenda::arch::mem::PGSIZE;
use glenda::cap::Frame;
use glenda::error::Error;
use glenda::interface::{FaultService, ProcessService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::STACK_BASE;
use glenda::utils::align::align_down;

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
            // Check if it's a scratch mapping fault (happens during ELF load or other cross-process ops)
            // Warren uses SCRATCH_VA to map child's frames.
            // If we access it before the kernel's PageTable reflects the user-mode mapping, or
            // due to some race, we might hit here.
            // But usually Warren scratch is handled synchronously.
            error!(
                "PageFault outside stack: pid: {}, tid: {}, address={:#x}, pc={:#x}, cause={:#x}",
                pid.bits(),
                tid,
                addr,
                pc,
                cause
            );
            return self.exit(pid, 0x0b);
        }

        let process = self.processes.get_mut(&pid.bits()).ok_or(Error::NotFound)?;
        let thread = process.threads.get_mut(&tid).ok_or(Error::NotFound)?;
        let allocator = &mut *self.ctx.allocator;

        // 1. Allocate Frame from process's Arena
        let (paddr, frame_slot) = process.arena_allocator.alloc(1, allocator)?;
        log!("Dynamic stack growth for pid {:?}: addr={:#x}, paddr={:#x}", pid, addr, paddr);

        // 2. Map Frame
        let page_base = align_down(addr, PGSIZE);
        let perms = Perms::READ | Perms::WRITE;
        let frame = Frame::from(frame_slot);
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        process.vspace_mgr.map_frame(frame, page_base, perms, 1, allocator, cspace_mgr)?;

        // 3. Record Resource
        thread.stack_pages += 1;
        thread.allocated_slots.insert(frame_slot);
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
        error!(
            "Unhandled fault: pid: {:?}, cause={:#x}, value={:#x}, pc={:#x}. Killing process.\n",
            pid, cause, value, pc
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
    fn access_fault(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        error!("Access Fault: pid: {:?}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn access_misaligned(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        error!("Misaligned Access: pid: {:?}, addr={:#x}, pc={:#x}", pid, addr, pc);
        self.exit(pid, 0x0b).map(|_| ())
    }
    fn breakpoint(&mut self, badge: Badge, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        warn!("Breakpoint: pid: {:?}, pc={:#x}", pid, pc);
        // Maybe resume or handled by debugger service
        self.exit(pid, 0x05).map(|_| ())
    }

    fn illegal_instruction(&mut self, badge: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        let pid = Badge::new(badge.bits() >> 16);
        error!("Illegal Instruction: pid: {:?}, inst={:#x}, pc={:#x}", pid, inst, pc);
        self.exit(pid, 0x04).map(|_| ())
    }

    fn handle_syscall(&mut self, badge: usize, args: glenda::ipc::MsgArgs) -> Result<(), Error> {
        let pid = Badge::new(badge >> 16);
        error!(
            "Non-Native Syscall: pid: {:?}, args=[{},{},{},{},{},{},{},{}]",
            pid, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]
        );
        self.exit(pid, usize::MAX).map(|_| ())
    }
}
