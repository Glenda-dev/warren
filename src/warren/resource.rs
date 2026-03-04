use crate::WarrenManager;
use alloc::collections::btree_map::BTreeMap;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame, Kernel, Rights};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::resource::ResourceType;
use glenda::utils::align::align_up;

pub struct ResourceRegistry {
    pub kernel_cap: Kernel,
    pub irq_cap: CapPtr,
    pub console_cap: CapPtr,
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
        self.do_alloc(pid, obj_type, flags)
    }

    fn dma_alloc(
        &mut self,
        pid: Badge,
        pages: usize,
        _recv: CapPtr,
    ) -> Result<(usize, Frame), Error> {
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let allocator = &mut *self.ctx.allocator;
        let (paddr, slot) = p.arena_allocator.alloc(pages, allocator)?;
        p.allocated_slots.insert(slot);
        log!("dma_alloc: pid: {:?}, paddr={:#x}, pages={}", pid, paddr, pages);
        Ok((paddr, Frame::from(slot)))
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid: {:?}, cap={:?}", pid, cap);
        Err(Error::NotSupported) // 目前不支持细粒度的自由释放，统一通过 revoke/recycle 处理
    }
    fn get_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        _recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        log!("get_cap: pid: {:?}, type={:?}, id={}", pid, cap_type, id);
        let cptr = match cap_type {
            ResourceType::Kernel => self.res.kernel_cap.cap(),
            ResourceType::Untyped => self.res.untyped_cap,
            ResourceType::Irq => {
                let allocator = &mut *self.ctx.allocator;
                let cspace_mgr = &mut *self.ctx.cspace_mgr;
                let slot = cspace_mgr.alloc(allocator)?;
                self.res.kernel_cap.get_irq(id, slot)?;
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                p.allocated_resources.insert(slot);
                slot
            }
            ResourceType::IrqControl => self.res.irq_cap,
            ResourceType::Console => self.res.console_cap,
            ResourceType::Bootinfo => self.res.bootinfo_cap,
            ResourceType::Endpoint => {
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                let ep = self.res.endpoints.get(&id).ok_or(Error::NotFound)?;
                let allocator = &mut *self.ctx.allocator;
                let cspace_mgr = &mut *self.ctx.cspace_mgr;
                let slot = cspace_mgr.alloc(allocator)?;
                self.ctx.root_cnode.mint(*ep, slot, pid, Rights::ALL)?;
                p.allocated_resources.insert(slot);
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
        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;
        let slot = cspace_mgr.alloc(allocator)?;
        self.ctx.root_cnode.move_cap(recv, slot)?;
        match cap_type {
            ResourceType::Endpoint => {
                self.res.endpoints.insert(id, slot);
                let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
                p.allocated_resources.insert(slot);
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
        let global_allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        let (_, slot) = p.arena_allocator.alloc(pages, global_allocator)?;
        let frame = Frame::from(slot);
        let vaddr = self.ctx.vspace_mgr.map_scratch(
            frame,
            Perms::READ | Perms::WRITE,
            pages,
            global_allocator,
            cspace_mgr,
        )?;
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, len);
            dst[..len].copy_from_slice(file);
        }
        self.ctx.vspace_mgr.unmap(vaddr, pages)?;
        p.allocated_slots.insert(slot);
        Ok((frame, len))
    }
}

impl<'a> WarrenManager<'a> {
    fn do_alloc(&mut self, pid: Badge, obj_type: CapType, flags: usize) -> Result<CapPtr, Error> {
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        if obj_type == CapType::Frame || obj_type == CapType::Untyped {
            let (_, slot) = p.arena_allocator.alloc(flags, allocator)?;
            p.allocated_slots.insert(slot);
            log!("alloc: pid: {:?}, type={:?}, flags={:#x}", pid, obj_type, flags);
            Ok(slot)
        } else {
            let slot = cspace_mgr.alloc(allocator)?;
            let _ = allocator.alloc(obj_type, flags, slot)?;
            p.allocated_slots.insert(slot);
            log!("alloc: pid: {:?}, type={:?}, flags={:#x}", pid, obj_type, flags);
            Ok(slot)
        }
    }
}
