use crate::WarrenManager;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::string::String;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Kernel, Page, Rights};
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
    pub ledger: ResourceLedger,
    pub frame_registry: PageFrameRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFrameState {
    Free,
    Anon,
    FileBacked,
    IoPinned,
    SharedMapped,
    Dirty,
    KernelInternal,
}

#[derive(Debug, Clone)]
pub struct PageFrameRecord {
    pub owner_pid: usize,
    pub pages: usize,
    pub paddr_hint: usize,
    pub state: PageFrameState,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct PageFrameRegistry {
    by_cap: BTreeMap<CapPtr, PageFrameRecord>,
}

impl PageFrameRegistry {
    pub fn register(
        &mut self,
        cap: CapPtr,
        owner_pid: usize,
        pages: usize,
        paddr_hint: usize,
        state: PageFrameState,
        source: &str,
    ) {
        self.by_cap.insert(
            cap,
            PageFrameRecord { owner_pid, pages, paddr_hint, state, source: source.into() },
        );
    }

    pub fn transition(&mut self, cap: CapPtr, new_state: PageFrameState) {
        if let Some(record) = self.by_cap.get_mut(&cap) {
            record.state = new_state;
        }
    }

    pub fn release(&mut self, cap: CapPtr) -> Option<PageFrameRecord> {
        self.by_cap.remove(&cap)
    }

    pub fn take_process(&mut self, pid: usize) -> BTreeMap<CapPtr, PageFrameRecord> {
        let caps = self
            .by_cap
            .iter()
            .filter_map(|(cap, record)| (record.owner_pid == pid).then_some(*cap))
            .collect::<alloc::vec::Vec<_>>();

        let mut out = BTreeMap::new();
        for cap in caps {
            if let Some(record) = self.by_cap.remove(&cap) {
                out.insert(cap, record);
            }
        }
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessResourceLedger {
    pub alloc_calls: usize,
    pub free_calls: usize,
    pub dma_pages: usize,
    pub internal_pages: usize,
    pub peak_live_caps: usize,
    pub alloc_by_type: BTreeMap<usize, usize>,
    pub live_caps: BTreeSet<CapPtr>,
}

impl ProcessResourceLedger {
    fn mark_live_cap(&mut self, cap: CapPtr) {
        self.live_caps.insert(cap);
        self.peak_live_caps = core::cmp::max(self.peak_live_caps, self.live_caps.len());
    }

    fn mark_cap_freed(&mut self, cap: CapPtr) {
        self.live_caps.remove(&cap);
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResourceLedger {
    pub total_alloc_calls: usize,
    pub total_free_calls: usize,
    pub total_dma_pages: usize,
    pub total_internal_pages: usize,
    per_process: BTreeMap<usize, ProcessResourceLedger>,
}

impl ResourceLedger {
    fn process_mut(&mut self, pid: usize) -> &mut ProcessResourceLedger {
        self.per_process.entry(pid).or_default()
    }

    pub fn record_alloc_slot(&mut self, pid: usize, obj_type: CapType, cap: CapPtr) {
        self.total_alloc_calls += 1;
        let p = self.process_mut(pid);
        p.alloc_calls += 1;
        *p.alloc_by_type.entry(obj_type as usize).or_insert(0) += 1;
        p.mark_live_cap(cap);
    }

    pub fn record_free_slot(&mut self, pid: usize, cap: CapPtr) {
        self.total_free_calls += 1;
        let p = self.process_mut(pid);
        p.free_calls += 1;
        p.mark_cap_freed(cap);
    }

    pub fn record_dma_alloc(&mut self, pid: usize, pages: usize) {
        self.total_dma_pages = self.total_dma_pages.saturating_add(pages);
        let p = self.process_mut(pid);
        p.dma_pages = p.dma_pages.saturating_add(pages);
    }

    pub fn record_internal_pages(&mut self, pid: usize, pages: usize) {
        self.total_internal_pages = self.total_internal_pages.saturating_add(pages);
        let p = self.process_mut(pid);
        p.internal_pages = p.internal_pages.saturating_add(pages);
    }

    pub fn take_process(&mut self, pid: usize) -> ProcessResourceLedger {
        self.per_process.remove(&pid).unwrap_or_default()
    }
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
    ) -> Result<(usize, Page), Error> {
        let pid = pid.bits();
        let (paddr, abs_recv) = {
            let p = self.state.processes.get_mut(&pid).ok_or(Error::NotFound)?;
            let allocator = &mut *self.ctx.allocator;
            let paddr = p.arena_allocator.alloc_into(pages, p.cnode.cap(), recv, allocator)?;
            (paddr, CapPtr::concat(p.cnode.cap(), recv))
        };
        self.state.res.ledger.record_alloc_slot(pid, CapType::Page, abs_recv);
        self.state.res.ledger.record_dma_alloc(pid, pages);
        self.state.res.frame_registry.register(
            abs_recv,
            pid,
            pages,
            paddr,
            PageFrameState::IoPinned,
            "dma_alloc",
        );
        Ok((paddr, Page::from(recv)))
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        let pid = pid.bits();
        let tracked = {
            let p = self.state.processes.get(&pid).ok_or(Error::NotFound)?;
            CapPtr::concat(p.cnode.cap(), cap)
        };

        let allocator = &mut *self.ctx.allocator;
        allocator.free(tracked)?;

        if let Some(p) = self.state.processes.get_mut(&pid)
            && p.arena_allocator.cspace_mgr.owns_slot(tracked)
        {
            p.arena_allocator.cspace_mgr.free(tracked);
        }

        self.state.res.ledger.record_free_slot(pid, tracked);
        if let None = self.state.res.frame_registry.release(tracked) {
            warn!("free: pid: {:?}, cap={:?} not found in frame registry", pid, tracked);
        }
        Ok(())
    }
    fn get_cap(
        &mut self,
        pid: Badge,
        cap_type: ResourceType,
        id: usize,
        recv: CapPtr,
    ) -> Result<CapPtr, Error> {
        let pid = pid.bits();
        let proc_cnode = {
            let p = self.state.processes.get(&pid).ok_or(Error::NotFound)?;
            p.cnode.cap()
        };
        let dst_abs = CapPtr::concat(proc_cnode, recv);

        match cap_type {
            ResourceType::Kernel => {
                self.ctx.root_cnode.copy(
                    self.state.res.kernel_cap.cap(),
                    proc_cnode,
                    recv,
                    Rights::ALL,
                )?;
            }
            ResourceType::Untyped => {
                self.ctx.root_cnode.copy(
                    self.state.res.untyped_cap,
                    proc_cnode,
                    recv,
                    Rights::ALL,
                )?;
            }
            ResourceType::Irq => {
                self.state.res.kernel_cap.get_irq(id, dst_abs)?;
            }
            ResourceType::IrqControl => {
                self.ctx.root_cnode.copy(self.state.res.irq_cap, proc_cnode, recv, Rights::ALL)?;
            }
            ResourceType::Console => {
                self.ctx.root_cnode.copy(
                    self.state.res.console_cap,
                    proc_cnode,
                    recv,
                    Rights::ALL,
                )?;
            }
            ResourceType::Bootinfo => {
                self.ctx.root_cnode.copy(
                    self.state.res.bootinfo_cap,
                    proc_cnode,
                    recv,
                    Rights::ALL,
                )?;
            }
            ResourceType::Endpoint => {
                let ep = self.state.res.endpoints.get(&id).ok_or(Error::NotFound)?;
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
        let _ = self.state.processes.get(&pid).ok_or(Error::NotFound)?;
        if cap.is_null() {
            return Err(Error::InvalidArgs);
        }
        log!("register_cap: pid={:?}, type={:?}, id={}, recv_window={:?}", pid, cap_type, id, cap);

        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;

        let dst_slot = cspace_mgr.alloc(allocator)?;
        if let Err(e) = self.ctx.root_cnode.transfer(cap, CapPtr::null(), dst_slot) {
            warn!(
                "register_cap: transfer into {:?} failed, skip slot recycle to avoid alias: {:?}",
                dst_slot, e
            );
            return Err(e);
        }

        match cap_type {
            ResourceType::Endpoint => {
                if let Some(old_slot) = self.state.res.endpoints.insert(id, dst_slot)
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
                let deleted_or_empty = match self.ctx.root_cnode.delete(dst_slot) {
                    Ok(()) => true,
                    Err(e) if e == Error::InvalidSlot || e == Error::InvalidCapability => true,
                    Err(e) => {
                        warn!("register_cap: cleanup delete failed for {:?}: {:?}", dst_slot, e);
                        false
                    }
                };
                if deleted_or_empty && cspace_mgr.owns_slot(dst_slot) {
                    cspace_mgr.free(dst_slot);
                }
                Err(Error::InvalidArgs)
            }
        }
    }

    fn get_config(&mut self, pid: Badge, name: &str, recv: CapPtr) -> Result<(Page, usize), Error> {
        let pid = pid.bits();
        log!("get_file: name={}", name);
        let file = self.initrd.get_file(name).ok_or(Error::NotFound)?;
        let len = file.len();
        let pages = align_up(len, PGSIZE) / PGSIZE;
        let abs_recv = {
            let p = self.state.processes.get_mut(&pid).ok_or(Error::NotFound)?;
            let global_allocator = &mut *self.ctx.allocator;
            p.arena_allocator.alloc_into(pages, p.cnode.cap(), recv, global_allocator)?;
            CapPtr::concat(p.cnode.cap(), recv)
        };
        self.state.res.ledger.record_alloc_slot(pid, CapType::Page, abs_recv);
        self.state.res.ledger.record_internal_pages(pid, pages);
        self.state.res.frame_registry.register(
            abs_recv,
            pid,
            pages,
            0,
            PageFrameState::FileBacked,
            "get_config",
        );
        let frame = Page::from(abs_recv);
        let global_allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;
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
        Ok((Page::from(recv), len))
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
        let (paddr, abs_recv) = {
            let p = self.state.processes.get_mut(&pid).ok_or(Error::NotFound)?;
            let allocator = &mut *self.ctx.allocator;
            let paddr = p.arena_allocator.alloc_cap_into(
                obj_type,
                flags,
                p.cnode.cap(),
                recv,
                allocator,
            )?;
            (paddr, CapPtr::concat(p.cnode.cap(), recv))
        };
        self.state.res.ledger.record_alloc_slot(pid, obj_type, abs_recv);
        if obj_type == CapType::Page {
            let pages = CapType::page_level_to_pages(flags).unwrap_or(1);
            self.state.res.frame_registry.register(
                abs_recv,
                pid,
                pages,
                paddr,
                PageFrameState::Anon,
                "alloc",
            );
        }
        Ok(recv)
    }

    pub(crate) fn ledger_record_internal_pages(&mut self, pid: usize, pages: usize, reason: &str) {
        self.state.res.ledger.record_internal_pages(pid, pages);
        let _ = reason;
    }

    pub(crate) fn frame_registry_register_internal(
        &mut self,
        pid: usize,
        cap: CapPtr,
        pages: usize,
        source: &str,
    ) {
        self.state.res.frame_registry.register(
            cap,
            pid,
            pages,
            0,
            PageFrameState::KernelInternal,
            source,
        );
    }

    pub(crate) fn frame_registry_release_cap(&mut self, cap: CapPtr) {
        let _ = self.state.res.frame_registry.release(cap);
    }

    pub(crate) fn frame_registry_take_process(
        &mut self,
        pid: usize,
    ) -> BTreeMap<CapPtr, PageFrameRecord> {
        self.state.res.frame_registry.take_process(pid)
    }

    pub(crate) fn frame_registry_transition(&mut self, cap: CapPtr, state: PageFrameState) {
        self.state.res.frame_registry.transition(cap, state);
    }

    pub(crate) fn ledger_take_process(&mut self, pid: usize) -> ProcessResourceLedger {
        self.state.res.ledger.take_process(pid)
    }
}
