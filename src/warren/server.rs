use super::WarrenManager;
use crate::layout::INIT_NAME;
use crate::log;
use alloc::string::ToString;
use core::mem::transmute;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, InitResourceService, MemoryService, ProcessService, ResourceService,
    SystemService,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;
use glenda::set_mrs;

impl<'a> SystemService for WarrenManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        // Use trait interface to spawn
        self.spawn(Badge::null(), INIT_NAME.to_string()).map(|pid| {
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
            let info = utcb.msg_tag;
            let badge = utcb.badge;

            let res = self.dispatch(badge, info);
            match res {
                Ok(_) => {
                    let tag = MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK,
                    );
                    self.reply(tag)?
                }
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    Error::HasCap => {
                        let tag = MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::OK | MsgFlags::HAS_CAP,
                        );
                        self.reply(tag)?
                    }
                    Error::HasBuffer => {
                        let tag = MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::OK | MsgFlags::HAS_BUFFER,
                        );
                        self.reply(tag)?
                    }
                    _ => {
                        let utcb = unsafe { UTCB::get() };
                        set_mrs!(utcb, e);
                        let tag = MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::ERROR,
                        );
                        self.reply(tag)?
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

        log!(
            "Received message: badge={}, label={:#x}, proto={:#x}, flags={}, utcb.mrs_regs={:?}",
            badge,
            label,
            proto,
            flags,
            utcb.mrs_regs
        );
        match proto {
            protocol::PROCESS_PROTO => match label {
                protocol::process::SPAWN => Err(Error::NotImplemented),
                protocol::process::FORK => {
                    let pid = self.fork(badge)?;
                    set_mrs!(utcb, pid);
                    Ok(())
                }
                protocol::process::EXIT => {
                    self.exit(badge, utcb.mrs_regs[0])?;
                    Err(Error::Success)
                }
                protocol::process::GET_CNODE => {
                    let target = Badge::new(utcb.mrs_regs[0]);
                    let cnode = self.get_cnode(badge, target)?;
                    utcb.cap_transfer = cnode.cap();
                    Err(Error::HasCap)
                }
                _ => Err(Error::InvalidMethod),
            },
            protocol::RESOURCE_PROTO => match label {
                protocol::resource::ALLOC => {
                    let cap = self.alloc(
                        badge,
                        unsafe { transmute(utcb.mrs_regs[0]) },
                        utcb.mrs_regs[1],
                    )?;
                    utcb.cap_transfer = cap;
                    Err(Error::HasCap)
                }
                protocol::resource::FREE => {
                    let cap = CapPtr::from(utcb.mrs_regs[0]);
                    self.free(badge, cap)?;
                    Ok(())
                }
                protocol::resource::SBRK => {
                    let brk = self.brk(badge, utcb.mrs_regs[0] as isize)?;
                    set_mrs!(utcb, brk);
                    Ok(())
                }
                protocol::resource::MMAP => {
                    let ret = self.mmap(badge, utcb.mrs_regs[0], utcb.mrs_regs[1])?;
                    set_mrs!(utcb, ret);
                    Ok(())
                }
                protocol::resource::MUNMAP => {
                    self.munmap(badge, utcb.mrs_regs[0], utcb.mrs_regs[1])?;
                    Ok(())
                }
                protocol::resource::GET_CAP => {
                    let cap = self.get_cap(badge, unsafe { transmute(utcb.mrs_regs[0]) })?;
                    utcb.cap_transfer = cap;
                    Err(Error::HasCap)
                }
                protocol::resource::GET_FILE => {
                    let name = utcb.read_str()?;
                    let frame = self.get_file(badge, &name)?;
                    utcb.cap_transfer = frame.cap();
                    Err(Error::HasCap)
                }
                _ => Err(Error::InvalidMethod),
            },
            protocol::KERNEL_PROTO => {
                let res = match label {
                    protocol::kernel::SYSCALL => self.syscall(badge, &utcb.mrs_regs),
                    protocol::kernel::PAGE_FAULT => {
                        self.page_fault(badge, utcb.mrs_regs[0], utcb.mrs_regs[1], utcb.mrs_regs[2])
                    }
                    protocol::kernel::ILLEGAL_INSTRUCTION => {
                        self.illegal_instrution(badge, utcb.mrs_regs[0], utcb.mrs_regs[1])
                    }
                    protocol::kernel::BREAKPOINT => self.breakpoint(badge, utcb.mrs_regs[0]),
                    protocol::kernel::ACCESS_FAULT => {
                        self.access_fault(badge, utcb.mrs_regs[0], utcb.mrs_regs[1])
                    }
                    protocol::kernel::ACCESS_MISALIGNED => {
                        self.access_misaligned(badge, utcb.mrs_regs[0], utcb.mrs_regs[1])
                    }
                    _ => self.unknown_fault(
                        badge,
                        utcb.mrs_regs[0],
                        utcb.mrs_regs[1],
                        utcb.mrs_regs[2],
                    ),
                };
                if let Err(e) = res {
                    log!("Failed to handle kernel protocol: {:?}", e);
                }
                return Err(Error::Success);
            }
            _ => Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, info: MsgTag) -> Result<(), Error> {
        self.reply.reply(info)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
