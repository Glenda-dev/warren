use crate::WarrenManager;
use alloc::collections::btree_map::BTreeMap;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame, Rights};
use glenda::error::Error;
use glenda::interface::ResourceService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::resource::ResourceType;
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

pub struct ResourceRegistry {
    pub kernel_cap: CapPtr,
    pub irq_cap: CapPtr,
    pub mmio_cap: CapPtr,
    pub untyped_cap: CapPtr,
    pub bootinfo_cap: CapPtr,
    pub endpoints: BTreeMap<usize, CapPtr>,
}

impl<'a> ResourceService for WarrenManager<'a> {
    fn alloc(
        &mut self,
        pid: Badge,
        obj_type: CapType,
        flags: usize,
        _recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        self.do_alloc(pid, obj_type, flags).map(|(_, cap)| cap)
    }

    fn dma_alloc(
        &mut self,
        pid: Badge,
        pages: usize,
        _recv: CapPtr,
    ) -> Result<(usize, Frame), Error> {
        self.do_alloc(pid, CapType::Frame, pages).map(|(paddr, cap)| (paddr, Frame::from(cap)))
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid: {:?}, cap={:?}", pid, cap);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let cnode = p.cnode;
        cnode.delete(cap)?;
        Ok(())
    }
    fn get_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        _recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        log!("get_cap: type={:?}, id={}", cap_type, id);
        let cptr = match cap_type {
            ResourceType::Kernel => self.res.kernel_cap,
            ResourceType::Untyped => self.res.untyped_cap,
            ResourceType::Irq => {
                let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
                self.ctx.root_cnode.mint(self.res.irq_cap, slot, Badge::new(id), Rights::ALL)?;
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                p.allocated_slots.push(slot);
                slot
            }
            ResourceType::Mmio => self.res.mmio_cap,
            ResourceType::Bootinfo => self.res.bootinfo_cap,
            ResourceType::Endpoint => {
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                let ep = self.res.endpoints.get(&id).ok_or(Error::NotFound)?;
                let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
                self.ctx.root_cnode.mint(*ep, slot, pid, Rights::ALL)?;
                p.allocated_slots.push(slot);
                slot
            }
            _ => return Err(Error::InvalidArgs),
        };
        Ok(cptr)
    }

    fn register_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        recv: CapPtr,
    ) -> Result<(), Error> {
        log!("register_cap: type={:?}, id={}", cap_type, id);
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.root_cnode.move_cap(recv, slot)?;
        match cap_type {
            ResourceType::Endpoint => {
                self.res.endpoints.insert(id, slot);
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                p.allocated_slots.push(slot);
                Ok(())
            }
            _ => Err(Error::InvalidArgs),
        }
    }

    fn get_config(
        &mut self,
        pid: Badge,
        name: &str,
        _recv: CapPtr,
    ) -> Result<(Frame, usize), Error> {
        log!("get_file: name={}", name);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?;
        let len = file.len();
        let pages = align_up(len, PGSIZE) / PGSIZE;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        self.ctx.buddy.alloc(
            CapType::Frame,
            pages,
            CapPtr::concat(self.ctx.root_cnode.cap(), slot),
        )?;
        let frame = Frame::from(slot);
        let vaddr = self.ctx.vspace_mgr.map_scratch(
            frame,
            Perms::READ | Perms::WRITE | Perms::USER,
            pages,
            self.ctx.buddy,
            self.ctx.cspace_mgr,
            self.ctx.root_cnode,
        )?;
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, len);
            dst[..len].copy_from_slice(file);
        }
        self.ctx.vspace_mgr.unmap_scratch(vaddr, pages)?;
        p.allocated_slots.push(slot);
        Ok((frame, len))
    }
}

impl<'a> WarrenManager<'a> {
    fn do_alloc(
        &mut self,
        pid: Badge,
        obj_type: CapType,
        flags: usize,
    ) -> Result<(usize, CapPtr), Error> {
        log!("alloc: pid: {:?}, type={:?}, flags={:#x}", pid, obj_type, flags);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let slot = self.ctx.cspace_mgr.alloc(self.ctx.buddy)?;
        let paddr = self.ctx.buddy.alloc(
            obj_type,
            flags,
            CapPtr::concat(self.ctx.root_cnode.cap(), slot),
        )?;
        p.allocated_slots.push(slot);
        Ok((paddr, slot))
    }
}
