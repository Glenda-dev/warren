use super::WarrenManager;
use super::data::Process;
use crate::layout::*;
use crate::policy::ArenaAllocator;
use alloc::boxed::Box;
use alloc::string::ToString;
use glenda::arch::mem::KSTACK_PAGES;
use glenda::cap::{CNode, CapPtr, CapType, Endpoint, Page, Rights, TCB, Untyped, VSpace};
use glenda::cap::{CONSOLE_SLOT, CSPACE_SLOT, MONITOR_SLOT, TCB_SLOT, VSPACE_SLOT};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::{HEAP_VA, STACK_BASE, get_trapframe_va, get_utcb_va};
use glenda::utils::manager::{CSpaceManager, VSpaceManager};

pub const SERVICE_PRIORITY: u8 = 128;

impl<'a> ProcessService for WarrenManager<'a> {
    fn create(&mut self, parent_pid: Badge, name: &str) -> Result<usize, Error> {
        let pid = self.alloc_pid()?;
        log!("Creating process: {}, pid: {}, parent_pid: {}", name, pid, parent_pid.bits());
        let utcb_va = get_utcb_va(0);
        let trapframe_va = get_trapframe_va(0);

        let allocator = &mut *self.ctx.allocator;
        let cspace_mgr = &mut *self.ctx.cspace_mgr;
        let mut rollback_arena: Option<Box<ArenaAllocator>> = None;
        let mut rollback_arena_cnode_slot: Option<CapPtr> = None;
        let mut rollback_arena_untyped_slot: Option<CapPtr> = None;

        let create_result: Result<Process, Error> = (|| {
            // 为进程分配 Arena 专用的 CNode 和 CSpaceManager
            let arena_cnode_slot = cspace_mgr.alloc(allocator)?;
            rollback_arena_cnode_slot = Some(arena_cnode_slot);
            allocator.alloc(CapType::CNode, 0, arena_cnode_slot)?;
            let arena_cnode = CNode::from(arena_cnode_slot);

            // 我们需要手动分配第一个二级 CNode，因为 ArenaAllocator 无法递归分配
            let mut arena_cspace_mgr = CSpaceManager::new(arena_cnode, 1);
            let first_l1_slot = CapPtr::from(1);

            // 从全局分配器预拨一块内存作为 Arena 的根 Untyped
            let arena_untyped_slot = cspace_mgr.alloc(allocator)?;
            rollback_arena_untyped_slot = Some(arena_untyped_slot);
            let arena_size_pages = 256; // 1MB 初始大小
            let arena_paddr =
                allocator.alloc(CapType::Untyped, arena_size_pages, arena_untyped_slot)?;
            let arena_untyped = Untyped::from(arena_untyped_slot);
            arena_untyped.retype_cnode(arena_cnode.cap(), first_l1_slot)?;
            arena_cspace_mgr.mark_present(1);

            rollback_arena = Some(Box::new(ArenaAllocator::new(
                arena_cspace_mgr,
                Some((arena_untyped, arena_paddr, arena_size_pages)),
                arena_size_pages,
            )));
            rollback_arena_untyped_slot = None;

            let arena_allocator = rollback_arena.as_mut().unwrap();

            let ep_slot = arena_allocator.alloc_slot()?;
            // Use pid << 16 | tid (0) for the main thread badge
            let badge = Badge::new(pid << 16);
            self.ctx.root_cnode.mint(
                self.ipc.endpoint.cap(),
                CapPtr::null(),
                ep_slot,
                badge,
                Rights::ALL,
            )?;
            let child_endpoint = Endpoint::from(ep_slot);

            let (_, cnode_slot) = arena_allocator.alloc_cap(CapType::CNode, 0, allocator)?;
            let child_cnode = CNode::from(cnode_slot);

            let (_, pd_slot) = arena_allocator.alloc_cap(CapType::VSpace, 0, allocator)?;
            let child_pd = VSpace::from(pd_slot);

            let (_, tcb_slot) = arena_allocator.alloc_cap(CapType::TCB, 0, allocator)?;
            let child_tcb = TCB::from(tcb_slot);

            // 使用 Arena 分配 UTCB, TrapFrame 等资源
            let (_, utcb_slot) = arena_allocator.alloc(1, allocator)?;
            let child_utcb = Page::from(utcb_slot);

            let (_, trapframe_slot) = arena_allocator.alloc(1, allocator)?;
            let child_trapframe = Page::from(trapframe_slot);

            let (_, kstack_slot) = arena_allocator.alloc(KSTACK_PAGES, allocator)?;
            let child_kstack = Page::from(kstack_slot);

            child_cnode.copy(child_pd.cap(), CapPtr::null(), VSPACE_SLOT, Rights::ALL)?;
            child_cnode.copy(child_cnode.cap(), CapPtr::null(), CSPACE_SLOT, Rights::ALL)?;
            child_cnode.copy(child_tcb.cap(), CapPtr::null(), TCB_SLOT, Rights::ALL)?;
            child_cnode.copy(child_endpoint.cap(), CapPtr::null(), MONITOR_SLOT, Rights::ALL)?;
            child_cnode.copy(
                self.state.res.console_cap,
                CapPtr::null(),
                CONSOLE_SLOT,
                Rights::ALL,
            )?;

            // Child process vspace manager doesn't use scratch area from self, or we can give it one?
            // For now, pass 0 size to indicate no scratch area.
            let mut vspace_mgr = VSpaceManager::new(child_pd, SCRATCH_VA, SCRATCH_SIZE);
            child_tcb.configure(
                child_cnode,
                child_pd,
                child_utcb,
                child_trapframe,
                child_kstack,
            )?;
            // Enable fault handler with badge=pid
            child_tcb.set_fault_handler(child_endpoint)?;
            child_tcb.set_address(utcb_va, trapframe_va)?;
            vspace_mgr.map_page(
                child_utcb,
                utcb_va,
                Perms::READ | Perms::WRITE,
                1,
                allocator,
                cspace_mgr,
            )?;
            vspace_mgr.map_page(
                child_trapframe,
                trapframe_va,
                Perms::READ | Perms::WRITE | Perms::SUPERVISOR,
                1,
                allocator,
                cspace_mgr,
            )?;
            vspace_mgr.setup(allocator, cspace_mgr)?;

            let mut process = Process::new(
                pid,
                parent_pid.bits() >> 16,
                name.to_string(),
                child_tcb,
                child_pd,
                child_cnode,
                child_utcb,
                vspace_mgr,
                rollback_arena.take().unwrap(),
                STACK_BASE,
            );
            process.heap_start = HEAP_VA;
            process.heap_brk = HEAP_VA;

            // 记录在父进程 CSpace 中分配的槽位，以便在进程退出时回收
            process.allocated_slots.insert(arena_cnode_slot);
            process.allocated_slots.insert(arena_untyped_slot);

            {
                let thread = process.threads.get_mut(&0).unwrap();
                thread.stack_pages = 0;
                thread.allocated_slots.insert(tcb_slot);
                thread.allocated_slots.insert(utcb_slot);
                thread.allocated_slots.insert(trapframe_slot);
                thread.allocated_slots.insert(kstack_slot);
            }

            process.parent_pid = parent_pid.bits();
            Ok(process)
        })();

        match create_result {
            Ok(process) => {
                self.state.processes.insert(pid, process);
                Ok(pid)
            }
            Err(e) => {
                warn!("Process create rollback: pid={}, err={:?}", pid, e);

                if let Some(mut arena_allocator) = rollback_arena.take() {
                    let _ = arena_allocator.release_to(allocator);
                }

                if let Some(slot) = rollback_arena_untyped_slot.take()
                    && let Err(free_err) = allocator.free(slot)
                {
                    warn!(
                        "Process create rollback: failed to free arena untyped slot {:?}: {:?}",
                        slot, free_err
                    );
                }

                if let Some(slot) = rollback_arena_cnode_slot.take()
                    && let Err(free_err) = allocator.free(slot)
                {
                    warn!(
                        "Process create rollback: failed to free arena cnode slot {:?}: {:?}",
                        slot, free_err
                    );
                }

                Err(e)
            }
        }
    }

    fn spawn(&mut self, parent_pid: Badge, path: &str) -> Result<usize, Error> {
        if self.initrd.get_file(path).is_none() {
            return Err(Error::NotFound);
        }
        let pid = self.create(parent_pid, path)?;
        log!("Spawning process: {}, pid: {}, parent_pid: {:?}", path, pid, parent_pid);
        let file = self.initrd.get_file(path).ok_or(Error::NotFound)?;
        match self.load_elf(pid, file) {
            Ok((entry, _)) => {
                let process = self.state.processes.get_mut(&pid).unwrap();
                let thread = process.threads.get_mut(&0).unwrap();
                thread.tcb.set_entrypoint(entry, STACK_BASE, 0)?;
                thread.tcb.set_address(get_utcb_va(0), get_trapframe_va(0))?;
                thread.tcb.set_priority(SERVICE_PRIORITY, 0)?;
                thread.tcb.resume()?;
                Ok(pid)
            }
            Err(e) => {
                error!("Failed to load ELF for pid {:?} at {}: {:?}", pid, path, e);
                let _ = self.exit_wrapper(Badge::new(pid), 1);
                Err(e)
            }
        }
    }

    fn exit(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        match self.exit_wrapper(pid, code) {
            Ok(_) => {}
            Err(Error::NotFound) => {
                warn!("Process not found with pid {}", pid);
            }
            Err(e) => {
                error!("Error during exit of pid {:?}: {:?}", pid, e);
            }
        }
        if pid.bits() == 1 {
            panic!("Init process exited with code: {}. Shutting down system.", code);
        }
        Ok(())
    }

    fn get_cnode(&mut self, pid: Badge, target: usize, recv: CapPtr) -> Result<CNode, Error> {
        let pid = pid.bits();
        log!("Getting cnode: pid: {}, target: {}", pid, target);
        let caller_cnode = self.state.processes.get(&pid).ok_or(Error::NotFound)?.cnode.cap();
        let p = self.state.processes.get(&target).ok_or(Error::NotFound)?;
        if p.parent_pid != pid {
            return Err(Error::PermissionDenied);
        }
        let dst_slot = {
            if recv.is_null() {
                CapPtr::null()
            } else {
                let rel = CapPtr::relative(caller_cnode, recv);
                if rel.is_null() { recv } else { rel }
            }
        };
        if dst_slot.is_null() {
            return Err(Error::InvalidArgs);
        }
        self.ctx.root_cnode.copy(p.cnode.cap(), caller_cnode, dst_slot, Rights::ALL)?;
        Ok(CNode::from(recv))
    }

    fn kill(&mut self, pid: Badge, target: usize) -> Result<(), Error> {
        let pid = pid.bits();
        if let Some(target_proc) = self.state.processes.get(&target) {
            // Allow self-kill or parent-kill
            if target_proc.parent_pid != pid && pid != target {
                log!("Permission denied for kill: pid {:?} tried to kill target {:?}", pid, target);
                return Err(Error::PermissionDenied);
            }
        } else {
            return Err(Error::NotFound);
        }

        // At this point we drop the reference to target_proc so we can mutate self
        self.exit(Badge::new(target), 0)
    }
}
