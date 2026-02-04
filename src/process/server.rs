use super::ProcessManager;
use crate::layout::INIT_NAME;
use crate::log;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{FaultService, MemoryService, ProcessService, SystemService};
use glenda::ipc::proto;
use glenda::ipc::{Badge, MsgArgs, MsgFlags, MsgTag, UTCB};

impl<'a> SystemService for ProcessManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        // Use trait interface to spawn
        self.spawn(INIT_NAME).map(|pid| {
            log!("Started init {} with PID: {}", INIT_NAME, pid);
        })
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        self.running = true;
        loop {
            if self.running == false {
                return Ok(());
            }
            match self.endpoint.recv(self.reply.cap()) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };
            let utcb = unsafe { UTCB::get() };
            let msg_info = utcb.msg_tag;
            let badge = utcb.badge;
            let label = msg_info.label();
            let proto = msg_info.proto();
            let flags = msg_info.flags();
            let args = utcb.mrs_regs;

            let res = self.dispatch(badge, label, proto, flags, args);
            match res {
                Ok(ret) => {
                    self.reply(proto::GENERIC_PROTO, proto::generic::REPLY, MsgFlags::OK, ret)?
                }
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    _ => self.reply(
                        proto::GENERIC_PROTO,
                        proto::generic::REPLY,
                        MsgFlags::ERROR,
                        [e as usize, 0, 0, 0, 0, 0, 0, 0],
                    )?,
                },
            }
        }
    }
    fn dispatch(
        &mut self,
        badge: Badge,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<MsgArgs, Error> {
        log!(
            "Received message: badge={}, label={:#x}, proto={:#x}, flags={}, msg={:?}",
            badge,
            label,
            proto,
            flags,
            msg
        );
        let ret = match proto {
            proto::PROCESS_PROTO => match label {
                proto::process::SPAWN => {
                    let name_len = msg[0];
                    let mut name_buf = alloc::vec![0u8; name_len];
                    unsafe { UTCB::get() }.read(&mut name_buf);
                    let name_res = alloc::string::String::from_utf8(name_buf).ok();
                    if let Some(name) = name_res {
                        self.spawn(&name)
                    } else {
                        Err(Error::InvalidArgs)
                    }
                }
                proto::process::FORK => self.fork(badge),
                proto::process::EXIT => self.exit(badge, msg[0]).map(|_| 0),
                proto::process::SBRK => self.brk(badge, msg[0] as isize),
                proto::process::MMAP => self.mmap(badge, msg[0], msg[1]),
                proto::process::MUNMAP => self.munmap(badge, msg[0], msg[1]).map(|_| 0),
                proto::process::INIT => self.procinit(badge),
                _ => Err(Error::InvalidMethod),
            },
            proto::KERNEL_PROTO => {
                let res = match label {
                    proto::kernel::SYSCALL => self.syscall(badge, msg),
                    proto::kernel::PAGE_FAULT => self.page_fault(badge, msg[0], msg[1], msg[2]),
                    proto::kernel::ILLEGAL_INSTRUCTION => {
                        self.illegal_instrution(badge, msg[0], msg[1])
                    }
                    proto::kernel::BREAKPOINT => self.breakpoint(badge, msg[0]),
                    proto::kernel::ACCESS_FAULT => self.access_fault(badge, msg[0], msg[1]),
                    proto::kernel::ACCESS_MISALIGNED => {
                        self.access_misaligned(badge, msg[0], msg[1])
                    }
                    _ => self.unknown_fault(badge, msg[0], msg[1], msg[2]),
                };
                if let Err(e) = res {
                    log!("Failed to handle kernel protocol: {:?}", e);
                }
                Err(Error::Success)
            }
            _ => Err(Error::InvalidProtocol),
        }?;
        Ok([ret, 0, 0, 0, 0, 0, 0, 0])
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
    fn exit() {}
}
