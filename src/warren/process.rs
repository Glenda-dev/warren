use super::WarrenManager;
use glenda::cap::{CNode, CapPtr};
use glenda::error::Error;
use glenda::interface::ProcessService;
use glenda::ipc::Badge;
use glenda::mem::{STACK_BASE, get_trapframe_va, get_utcb_va};

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
            Ok((entry, _)) => {
                let process = self.processes.get_mut(&pid).unwrap();
                let thread = process.threads.get_mut(&0).unwrap();
                thread.tcb.set_entrypoint(entry, STACK_BASE, 0)?;
                thread.tcb.set_address(get_utcb_va(0), get_trapframe_va(0))?;
                thread.tcb.set_priority(SERVICE_PRIORITY, 0)?;
                thread.tcb.resume()?;
                Ok(pid.bits())
            }
            Err(e) => {
                self.processes.remove(&pid);
                Err(e)
            }
        }
    }

    fn exit(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        if pid.bits() == 1 {
            panic!("Init process exited with code: {}. Shutting down system.", code);
        }
        match self.exit_wrapper(pid, code) {
            Ok(_) => {}
            Err(e) => {
                error!("Error during exit of pid {:?}: {:?}", pid, e);
            }
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

    fn kill(&mut self, pid: Badge, target: usize) -> Result<(), Error> {
        let target_badge = Badge::new(target);
        if let Some(target_proc) = self.processes.get(&target_badge) {
            // Allow self-kill or parent-kill
            if target_proc.parent_pid != pid && pid != target_badge {
                log!("Permission denied for kill: pid {:?} tried to kill target {:?}", pid, target);
                return Err(Error::PermissionDenied);
            }
        } else {
            return Err(Error::NotFound);
        }

        // At this point we drop the reference to target_proc so we can mutate self
        self.exit(target_badge, 0)
    }
}
