use crate::ProcessManager;
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
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        unimplemented!()
    }

    fn free(&mut self, pid: Badge, cap: CapPtr) -> Result<(), Error> {
        let process = self.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        unimplemented!()
    }
}

impl InitResourceService for ProcessManager<'_> {
    fn get_cap(&self, cap: InitCap) -> Result<CapPtr, Error> {
        unimplemented!()
    }

    fn get_resource(&self, res: InitResource) -> Result<Box<dyn core::any::Any>, Error> {
        unimplemented!()
    }

    fn get_file(&self, name: &String) -> Result<glenda::cap::Frame, Error> {
        unimplemented!()
    }
}
