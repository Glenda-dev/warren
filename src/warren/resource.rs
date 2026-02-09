use crate::WarrenManager;
use crate::log;
use alloc::string::String;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame};
use glenda::cap::{IRQ_SLOT, KERNEL_SLOT, MMIO_SLOT, UNTYPED_SLOT};
use glenda::error::Error;
use glenda::interface::{InitResourceService, ResourceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::resource::InitCap;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

pub struct InitRes {
    pub kernel_cap: CapPtr,
    pub irq_cap: CapPtr,
    pub mmio_cap: CapPtr,
    pub untyped_cap: CapPtr,
    pub bootinfo_cap: CapPtr,
}

impl<'a> ResourceService for WarrenManager<'a> {
    fn alloc(
        &mut self,
        pid: Badge,
        obj_type: CapType,
        flags: usize,
        _recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        log!("alloc: pid={}, type={:?}, flags={:#x}", pid, obj_type, flags);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(CapType::Frame, 1, self.ctx.root_cnode, slot)?;
        p.allocated_slots.push(slot);
        Ok(slot)
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid={}, cap={:?}", pid, cap);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let cnode = p.cnode;
        cnode.delete(cap)?;
        Ok(())
    }
}

impl<'a> InitResourceService for WarrenManager<'a> {
    fn get_cap(&self, _pid: Badge, cap: InitCap, _recv: CapPtr) -> Result<CapPtr, Error> {
        log!("get_cap: cap={:?}", cap);
        let cptr = match cap {
            InitCap::Kernel => KERNEL_SLOT,
            InitCap::Irq => IRQ_SLOT,
            InitCap::Mmio => MMIO_SLOT,
            InitCap::Untyped => UNTYPED_SLOT,
            _ => {
                return Err(Error::InvalidArgs);
            }
        };
        Ok(cptr)
    }

    fn map_file(&mut self, pid: Badge, name: &String, address: usize) -> Result<usize, Error> {
        log!("map_file: name={}", name);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let file = self.initrd.get_file(name.as_str()).ok_or(Error::NotFound)?;
        let len = file.len();
        let pages = (len + PGSIZE - 1) / PGSIZE;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(CapType::Frame, pages, self.ctx.root_cnode, slot)?;
        let frame = Frame::from(slot);
        let perms = Perms::READ | Perms::USER;
        p.vspace_mgr.map_frame(
            frame,
            address,
            perms,
            pages,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        Ok(address)
    }
}
