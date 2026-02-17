use super::{Process, ProcessState, WarrenManager};
use crate::layout::SCRATCH_VA;
use crate::log;
use glenda::arch::mem::{KSTACK_PAGES, PGSIZE};
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CNode, CapPtr, CapType, Frame, Rights, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::ProcessService;
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::mem::{STACK_BASE, get_trapframe_va, get_utcb_va};
use glenda::utils::manager::VSpaceManager;
use glenda::utils::manager::{CSpaceService, UntypedService, VSpaceService};

pub const SERVICE_PRIORITY: u8 = 128;

impl<'a> ProcessService for WarrenManager<'a> {
    fn spawn(&mut self, parent_pid: Badge, path: &str) -> Result<usize, Error> {
        log!("Spawning process: {}, parent_pid: {:?}", path, parent_pid);
        let file = self.initrd.get_file(path).ok_or(Error::NotFound)?.to_vec();
        let mut process = self.create(path)?;
        process.parent_pid = parent_pid;
        let pid = process.pid;
        self.processes.insert(pid, process);
        match self.load_elf(pid, &file) {
            Ok((entry, _heap)) => {
                let process = self.processes.get_mut(&pid).unwrap();
                let thread = process.threads.get_mut(&0).unwrap();
                thread.tcb.set_entrypoint(entry, STACK_BASE, 0)?;
                thread.tcb.set_address(get_utcb_va(0), get_trapframe_va(0))?;
                thread.tcb.set_priority(SERVICE_PRIORITY)?;
                thread.tcb.resume()?;
                Ok(pid.bits())
            }
            Err(e) => {
                self.processes.remove(&pid);
                Err(e)
            }
        }
    }

    fn exec(&mut self, pid: Badge, _path: &str) -> Result<(usize, usize), Error> {
        log!("Executing new ELF for pid: {:?}", pid);
        Err(Error::NotImplemented)
    }

    fn fork(&mut self, parent_pid: Badge) -> Result<usize, Error> {
        log!("Forking process, parent_pid: {:?}", parent_pid);
        let (heap_start, heap_brk, name, stack_base, stack_pages) = {
            let p = self.processes.get(&parent_pid).ok_or(Error::NotFound)?;
            let t = p.threads.get(&0).ok_or(Error::NotFound)?;
            (p.heap_start, p.heap_brk, p.name.clone(), t.stack_base, t.stack_pages)
        };

        let pid = self.alloc_pid()?;

        let cnode_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::CNode,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), cnode_slot),
        )?;
        let child_cnode = CNode::from(cnode_slot);

        let pd_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::VSpace,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), pd_slot),
        )?;
        let child_pd = VSpace::from(pd_slot);

        let tcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::TCB,
            0,
            CapPtr::concat(self.ctx.root_cnode.cap(), tcb_slot),
        )?;
        let child_tcb = TCB::from(tcb_slot);

        let utcb_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), utcb_slot),
        )?;
        let child_utcb = Frame::from(utcb_slot);

        let trapframe_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            1,
            CapPtr::concat(self.ctx.root_cnode.cap(), trapframe_slot),
        )?;
        let child_trapframe = Frame::from(trapframe_slot);

        let kstack_slot = self.ctx.cspace_mgr.alloc(self.ctx.untyped_mgr)?;
        self.ctx.untyped_mgr.alloc(
            CapType::Frame,
            KSTACK_PAGES,
            CapPtr::concat(self.ctx.root_cnode.cap(), kstack_slot),
        )?;
        let child_kstack = Frame::from(kstack_slot);

        let mut child_vspace_mgr = VSpaceManager::new(child_pd, 0, 0);
        child_vspace_mgr.setup()?;

        let root_cnode = self.ctx.root_cnode;
        let parent = self.processes.get(&parent_pid).unwrap();

        parent
            .vspace_mgr
            .clone_space(
                &mut child_vspace_mgr,
                self.ctx.untyped_mgr,
                self.ctx.cspace_mgr,
                root_cnode,
                SCRATCH_VA,
                SCRATCH_VA + PGSIZE,
                self.ctx.vspace_mgr,
            )
            .map_err(|_| Error::OutOfMemory)?;

        child_vspace_mgr.map_frame(
            child_utcb,
            get_utcb_va(0),
            Perms::READ | Perms::WRITE | Perms::USER,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;
        child_vspace_mgr.map_frame(
            child_trapframe,
            get_trapframe_va(0),
            Perms::READ | Perms::WRITE,
            1,
            self.ctx.untyped_mgr,
            self.ctx.cspace_mgr,
            root_cnode,
        )?;

        let badge = Badge::new(pid.bits() << 16);
        child_cnode.mint(self.endpoint.cap(), MONITOR_SLOT, badge, Rights::ALL)?;
        child_tcb.configure(child_cnode, child_pd, child_utcb, child_trapframe, child_kstack)?;

        let mut process = Process::new(
            pid,
            parent_pid,
            name,
            child_tcb,
            child_pd,
            child_cnode,
            child_utcb,
            child_vspace_mgr,
            stack_base,
        );
        process.heap_start = heap_start;
        process.heap_brk = heap_brk;
        {
            let thread = process.threads.get_mut(&0).unwrap();
            thread.stack_pages = stack_pages;
        }

        self.processes.insert(pid, process);
        log!("Process forked: parent_pid: {:?}, child_pid: {:?}", parent_pid, pid);
        Ok(pid.bits())
    }

    fn exit(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        if let Some(mut p) = self.processes.remove(&pid) {
            p.exit_code = code;
            p.state = ProcessState::Dead;
            for (_, thread) in p.threads.iter() {
                thread.tcb.suspend()?;
            }
            log!("Process exited with pid: {:?}, code={}", pid, code);
        } else {
            log!("Failed to find process with pid: {:?}", pid);
        }
        Ok(())
    }

    fn get_pid(&mut self, pid: Badge) -> Result<usize, Error> {
        log!("Get pid: {:?}", pid);
        Ok(pid.bits())
    }

    fn get_ppid(&mut self, pid: Badge) -> Result<usize, Error> {
        log!("Get Ppid: {:?}", pid);
        let p = self.processes.get(&pid).ok_or(Error::NotFound)?;
        let ppid = p.parent_pid;
        Ok(ppid.bits())
    }

    fn get_cnode(&mut self, pid: Badge, target: Badge, _recv: CapPtr) -> Result<CNode, Error> {
        log!("Get CNode: {}", pid);
        let p = self.processes.get(&target).ok_or(Error::NotFound)?;
        if p.parent_pid != pid {
            return Err(Error::PermissionDenied);
        }
        let cnode = p.cnode;
        Ok(cnode)
    }

    fn kill(&mut self, _pid: Badge, _target: usize) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
}
