use super::ProcessManager;
use crate::layout::INIT_NAME;
use crate::log;
use glenda::cap::{Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{FaultService, MemoryService, ProcessService, SystemService};
use glenda::ipc::proto;
use glenda::ipc::utcb;
use glenda::ipc::{MsgArgs, MsgFlags, MsgTag};

impl<'a> SystemService for ProcessManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        // Use trait interface to spawn
        self.spawn(INIT_NAME).map(|pid| {
            log!("Started init with PID: {}", pid);
        })
    }
    fn listen(&mut self, ep: Endpoint, reply: Reply) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = reply;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        loop {
            let badge = match self.endpoint.recv(self.reply.cap()) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };
            let utcb = unsafe { utcb::get() };
            let msg_info = utcb.msg_tag;
            let label = msg_info.label();
            let proto = msg_info.proto();
            let flags = msg_info.flags();
            let args = utcb.mrs_regs;

            match self.dispatch(badge, label, proto, flags, args) {
                Ok(val) => self.reply(
                    proto::GENERIC_PROTO,
                    proto::generic::REPLY,
                    MsgFlags::OK,
                    [val, 0, 0, 0, 0, 0, 0],
                )?,
                Err(e) => self.reply(
                    proto::GENERIC_PROTO,
                    proto::generic::REPLY,
                    MsgFlags::ERROR,
                    [e as usize, 0, 0, 0, 0, 0, 0],
                )?,
            }
        }
    }
    fn dispatch(
        &mut self,
        badge: usize,
        label: usize,
        proto: usize,
        _flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<usize, Error> {
        match proto {
            proto::PROCESS_PROTO => match label {
                proto::process::SPAWN_SERVICE => {
                    let name_len = msg[0];
                    let name_res = unsafe { utcb::get() }.read_str(0, name_len);
                    if let Some(name) = name_res {
                        self.spawn(&name)
                    } else {
                        Err(Error::InvalidArgs)
                    }
                }
                proto::process::FORK => self.fork(badge),
                proto::process::EXIT => self.exit(badge, msg[0]).map(|_| 0),
                proto::process::SBRK => self.brk(badge, msg[0] as isize),
                proto::process::MMAP => self.mmap(badge, &msg),
                proto::process::MUNMAP => self.munmap(badge, &msg).map(|_| 0),
                _ => Err(Error::InvalidMethod),
            },
            proto::KERNEL_PROTO => match label {
                proto::kernel::PAGE_FAULT => {
                    self.handle_page_fault(badge, msg[0], msg[1]).map(|_| 0)
                }
                _ => Err(Error::InvalidMethod),
            },
            _ => Err(Error::InvalidProtocol),
        }
    }
    fn reply(
        &mut self,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<(), Error> {
        let tag = MsgTag::new(proto, label, flags);
        self.reply.reply(tag, msg)
    }
}
