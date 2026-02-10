use crate::WarrenManager;
use crate::log;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame};
use glenda::cap::{IRQ_SLOT, KERNEL_SLOT, MMIO_SLOT, UNTYPED_SLOT};
use glenda::error::Error;
use glenda::interface::{InitResourceService, ResourceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::resource::InitCap;
use glenda::utils::align::align_up;
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
        log!("alloc: pid: {:?}, type={:?}, flags={:#x}", pid, obj_type, flags);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(obj_type, flags, self.ctx.root_cnode, slot)?;
        p.allocated_slots.push(slot);
        Ok(slot)
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid: {:?}, cap={:?}", pid, cap);
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

    fn get_file(&mut self, pid: Badge, name: &str, _recv: CapPtr) -> Result<(Frame, usize), Error> {
        log!("get_file: name={}", name);
        let _p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?;
        let len = file.len();
        let pages = align_up(len, PGSIZE) / PGSIZE;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(CapType::Frame, pages, self.ctx.root_cnode, slot)?;
        let frame = Frame::from(slot);
        let vaddr = self.ctx.vspace_mgr.map_scratch(
            frame,
            Perms::READ | Perms::WRITE | Perms::USER,
            pages,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, len);
            dst[..len].copy_from_slice(file);
        }
        self.ctx.vspace_mgr.unmap_scratch(vaddr, pages)?;
        Ok((frame, len))
    }
}
