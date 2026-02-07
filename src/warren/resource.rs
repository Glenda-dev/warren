use crate::ProcessManager;
use crate::log;
use alloc::boxed::Box;
use alloc::string::String;
use glenda::cap::{CNode, CapPtr, CapType};
use glenda::error::Error;
use glenda::interface::{InitResourceService, ResourceService};
use glenda::ipc::Badge;
use glenda::protocol::resource::{InitCap, InitResource};

impl ResourceService for ProcessManager<'_> {
    fn alloc(
        &mut self,
        pid: Badge,
        obj_type: CapType,
        flags: usize,
        dest_cnode: CNode,
        dest_slot: CapPtr,
    ) -> Result<(), Error> {
        log!("alloc: pid={}, type={:?}, flags={:#x}", pid, obj_type, flags);
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        unimplemented!()
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        log!("free: pid={}, cap={:?}", pid, cap);
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        unimplemented!()
    }
}

impl InitResourceService for ProcessManager<'_> {
    fn get_cap(&self, cap: InitCap) -> Result<CapPtr, Error> {
        log!("get_cap: cap={:?}", cap);
        unimplemented!()
    }

    fn get_resource(&self, res: InitResource) -> Result<Box<dyn core::any::Any>, Error> {
        log!("get_resource: res={:?}", res);
        unimplemented!()
    }

    fn get_file(&self, name: &String) -> Result<glenda::cap::Frame, Error> {
        log!("get_file: name={}", name);
        unimplemented!()
    }
}
