use crate::WarrenManager;
use alloc::collections::btree_map::BTreeMap;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame, Kernel, Rights};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::resource::{ResourceType, WarrenStatus};
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
        recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        self.do_alloc(pid, obj_type, flags, recv)
    }

    fn dma_alloc(
        &mut self,
        pid: Badge,
        pages: usize,
        recv: CapPtr,
    ) -> Result<(usize, Frame), Error> {
        let pid = pid.bits();
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let allocator = &mut *self.ctx.allocator;
        let paddr = p.arena_allocator.alloc_into(pages, p.cnode.cap(), recv, allocator)?;
        log!("dma_alloc: pid: {:?}, paddr={:#x}, pages={}", pid, paddr, pages);
        Ok((paddr, Frame::from(recv)))
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid: {:?}, cap={:?}", pid, cap);
        Err(Error::NotSupported) // 目前不支持细粒度的自由释放，统一通过 revoke 处理
    }
    fn get_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        let pid = pid.bits();
        log!("get_cap: pid: {:?}, type={:?}, id={}", pid, cap_type, id);
        let proc_cnode = {
            let p = self.processes.get(&pid).ok_or(Error::NotFound)?;
            p.cnode.cap()
        };
        let dst_abs = CapPtr::concat(proc_cnode, recv);

        match cap_type {
            ResourceType::Kernel => {
                self.ctx.root_cnode.copy(
                    self.res.kernel_cap.cap(),
                    proc_cnode,
                    recv,
                    Rights::ALL,
                )?;
            }
            ResourceType::Untyped => {
                self.ctx.root_cnode.copy(self.res.untyped_cap, proc_cnode, recv, Rights::ALL)?;
            }
            ResourceType::Irq => {
                self.res.kernel_cap.get_irq(id, dst_abs)?;
            }
            ResourceType::IrqControl => {
                self.ctx.root_cnode.copy(self.res.irq_cap, proc_cnode, recv, Rights::ALL)?;
            }
            ResourceType::Console => {
                self.ctx.root_cnode.copy(self.res.console_cap, proc_cnode, recv, Rights::ALL)?;
            }
            ResourceType::Bootinfo => {
                self.ctx.root_cnode.copy(self.res.bootinfo_cap, proc_cnode, recv, Rights::ALL)?;
            }
            ResourceType::Endpoint => {
                let ep = self.res.endpoints.get(&id).ok_or(Error::NotFound)?;
                self.ctx.root_cnode.mint(*ep, proc_cnode, recv, Badge::new(pid), Rights::ALL)?;
            }
            _ => return Err(Error::InvalidArgs),
        };
        Ok(recv)
    }
    // TODO: Move to Nexus to support routing management
    fn register_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        cap: CapPtr,
    ) -> Result<(), Error> {
        let pid = pid.bits();
        let _ = self.processes.get(&pid).ok_or(Error::NotFound)?;
        if cap.is_null() {
            return Err(Error::InvalidArgs);
        }
        log!(
            "register_cap: pid={:?}, type={:?}, id={}, recv_window={:?}",
            pid,
            cap_type,
            id,
            cap
        );

        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        let dst_slot = cspace_mgr.alloc(allocator)?;
        if let Err(e) = self.ctx.root_cnode.transfer(cap, CapPtr::null(), dst_slot) {
            if cspace_mgr.owns_slot(dst_slot) {
                cspace_mgr.free(dst_slot);
            }
            return Err(e);
        }

        match cap_type {
            ResourceType::Endpoint => {
                if let Some(old_slot) = self.res.endpoints.insert(id, dst_slot)
                    && cspace_mgr.owns_slot(old_slot)
                {
                    let _ = self.ctx.root_cnode.revoke(old_slot);
                    if self.ctx.root_cnode.delete(old_slot).is_ok() {
                        cspace_mgr.free(old_slot);
                    }
                }
                Ok(())
            }
            _ => {
                let _ = self.ctx.root_cnode.revoke(dst_slot);
                let _ = self.ctx.root_cnode.delete(dst_slot);
                if cspace_mgr.owns_slot(dst_slot) {
                    cspace_mgr.free(dst_slot);
                }
                Err(Error::InvalidArgs)
            }
        }
    }

    fn get_config(
        &mut self,
        pid: Badge,
        name: &str,
        recv: CapPtr,
    ) -> Result<(Frame, usize), Error> {
        let pid = pid.bits();
        log!("get_file: name={}", name);
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?;
        let len = file.len();
        let pages = align_up(len, PGSIZE) / PGSIZE;
        let global_allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        p.arena_allocator.alloc_into(pages, p.cnode.cap(), recv, global_allocator)?;
        let frame = Frame::from(CapPtr::concat(p.cnode.cap(), recv));
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
        Ok((Frame::from(recv), len))
    }

    fn status(&mut self, _pid: Badge) -> Result<WarrenStatus, Error> {
        Ok(WarrenStatus { memory: self.ctx.allocator.status() })
    }
}

impl<'a> WarrenManager<'a> {
    fn do_alloc(
        &mut self,
        pid: Badge,
        obj_type: CapType,
        flags: usize,
        recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        let pid = pid.bits();
        let p = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let allocator = &mut *self.ctx.allocator;
        p.arena_allocator.alloc_cap_into(obj_type, flags, p.cnode.cap(), recv, allocator)?;
        log!("alloc: pid: {:?}, type={:?}, flags={:#x}", pid, obj_type, flags);
        Ok(recv)
    }
}
