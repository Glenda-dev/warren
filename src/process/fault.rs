use super::ProcessManager;
use crate::log;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{CSpaceService, FaultService, ResourceService, VSpaceService};
use glenda::mem::Perms;

impl<'a> FaultService for ProcessManager<'a> {
    fn handle_page_fault(
        &mut self,
        pid: usize,
        vaddr: usize,
        error_code: usize,
    ) -> Result<(), Error> {
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;

        log!(
            "PageFault: PID={} Addr={:#x} Code={:#x}. Allocating 4K page.",
            pid,
            vaddr,
            error_code
        );

        // 1. Allocate Frame
        let frame_slot =
            match self.ctx.slot_mgr.alloc(self.ctx.resource_mgr).map_err(|_| Error::OutOfMemory)? {
                slot => slot,
            };

        if let Err(e) =
            self.ctx.resource_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, frame_slot)
        {
            log!("Failed to alloc frame for fault: {:?}", e);
            return Err(Error::OutOfMemory);
        }

        // 2. Map Frame
        let page_base = vaddr & !(PGSIZE - 1);
        let perms = Perms::READ | Perms::WRITE | Perms::USER;
        let frame = Frame::from(frame_slot);

        process.vspace_mgr.map_frame(
            frame,
            page_base,
            perms,
            1,
            self.ctx.resource_mgr,
            self.ctx.slot_mgr,
            self.ctx.root_cnode, // Using Factotum's cnode for mapping bookkeeping
        )?;

        // 3. Record Resource
        process.allocated_slots.push(frame_slot);
        Ok(())
    }
}
