use super::ProcessManager;
use crate::layout::INIT_NAME;
use crate::log;
use core::mem::transmute;
use glenda::cap::{CNode, CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, InitResourceService, MemoryService, ProcessService, ResourceService,
    SystemService,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;

impl<'a> SystemService for ProcessManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        // Use trait interface to spawn
        self.spawn(Badge::null(), INIT_NAME).map(|pid| {
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
        while self.running {
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

            let res = self.dispatch(badge, msg_info);
            match res {
                Ok(_) => self.reply(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ))?,
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    Error::HasCap => self.reply(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ))?,
                    _ => {
                        let utcb = unsafe { UTCB::get() };
                        utcb.mrs_regs[0] = e as usize;
                        self.reply(MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::ERROR,
                        ))?
                    }
                },
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, badge: Badge, info: MsgTag) -> Result<(), Error> {
        let label = info.label();
        let proto = info.proto();
        let flags = info.flags();
        let utcb = unsafe { UTCB::get() };
        let msg = utcb.mrs_regs;

        log!(
            "Received message: badge={}, label={:#x}, proto={:#x}, flags={}, msg={:?}",
            badge,
            label,
            proto,
            flags,
            msg
        );

        let ret = match proto {
            protocol::PROCESS_PROTO => match label {
                protocol::process::SPAWN => Err(Error::NotImplemented),
                protocol::process::FORK => self.fork(badge),
                protocol::process::EXIT => self.exit(badge, msg[0]).map(|_| 0),
                _ => Err(Error::InvalidMethod),
            },
            protocol::RESOURCE_PROTO => match label {
                protocol::resource::ALLOC => self
                    .alloc(
                        badge,
                        unsafe { transmute(msg[0]) },
                        msg[1],
                        CNode::from(CapPtr::from(msg[2])),
                        CapPtr::from(msg[3]),
                    )
                    .map(|_| 0),
                protocol::resource::FREE => {
                    self.free(badge, unsafe { transmute(msg[0]) }).map(|_| 0)
                }
                protocol::resource::SBRK => self.brk(badge, msg[0] as isize),
                protocol::resource::MMAP => self.mmap(badge, msg[0], msg[1]),
                protocol::resource::MUNMAP => self.munmap(badge, msg[0], msg[1]).map(|_| 0),
                protocol::resource::GET_CAP => {
                    let cap = self.get_cap(unsafe { transmute(msg[0]) })?;
                    utcb.cap_transfer = cap;
                    return Err(Error::HasCap);
                }
                protocol::resource::GET_RESOURCE => Err(Error::NotImplemented),
                _ => Err(Error::InvalidMethod),
            },
            protocol::KERNEL_PROTO => {
                let res = match label {
                    protocol::kernel::SYSCALL => self.syscall(badge, &msg),
                    protocol::kernel::PAGE_FAULT => self.page_fault(badge, msg[0], msg[1], msg[2]),
                    protocol::kernel::ILLEGAL_INSTRUCTION => {
                        self.illegal_instrution(badge, msg[0], msg[1])
                    }
                    protocol::kernel::BREAKPOINT => self.breakpoint(badge, msg[0]),
                    protocol::kernel::ACCESS_FAULT => self.access_fault(badge, msg[0], msg[1]),
                    protocol::kernel::ACCESS_MISALIGNED => {
                        self.access_misaligned(badge, msg[0], msg[1])
                    }
                    _ => self.unknown_fault(badge, msg[0], msg[1], msg[2]),
                };
                if let Err(e) = res {
                    log!("Failed to handle kernel protocol: {:?}", e);
                }
                return Err(Error::Success);
            }
            _ => Err(Error::InvalidProtocol),
        }?;
        utcb.mrs_regs[0] = ret;
        Ok(())
    }
    fn reply(&mut self, info: MsgTag) -> Result<(), Error> {
        self.reply.reply(info)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
