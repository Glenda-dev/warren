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
use glenda::protocol::resource::InitCap;
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
            let mut utcb = unsafe { UTCB::new() };
            utcb.set_reply_window(self.reply.cap());
            match self.endpoint.recv(&mut utcb) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };

            match self.dispatch(&mut utcb) {
                Ok(()) => {}
                Err(e) => {
                    log!("Failed to dispatch message: {:?}", e);
                    utcb.set_msg_tag(MsgTag::err());
                    utcb.set_mr(0, e as usize);
                }
            };
            self.reply(&mut utcb)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        let tag = utcb.get_msg_tag();
        let label = tag.label();
        let proto = tag.proto();
        let flags = tag.flags();
        let mrs = utcb.get_mrs();
        log!(
            "Received message: badge={}, label={:#x}, proto={:#x}, flags={}, utcb.mrs_regs={:?}",
            badge,
            label,
            proto,
            flags,
            mrs
        );
        match proto {
            protocol::PROCESS_PROTO => match label {
                protocol::process::SPAWN => Err(Error::NotImplemented),
                protocol::process::FORK => {
                    let pid = self.fork(badge)?;
                    set_mrs!(utcb, pid);
                    utcb.set_msg_tag(MsgTag::ok());
                    Ok(())
                }
                protocol::process::EXIT => {
                    self.exit(badge, mrs[0])?;
                    Ok(())
                }
                protocol::process::GET_CNODE => {
                    let target = Badge::new(mrs[0]);
                    let cnode = self.get_cnode(badge, target, CapPtr::null())?;
                    utcb.set_cap_transfer(cnode.cap());
                    utcb.set_msg_tag(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ));
                    Ok(())
                }
                _ => Err(Error::InvalidMethod),
            },
            protocol::RESOURCE_PROTO => match label {
                protocol::resource::ALLOC => {
                    let obj_type = unsafe { transmute(mrs[0]) };
                    let flags = mrs[1];
                    let recv = CapPtr::from(mrs[2]);
                    let cap = self.alloc(badge, obj_type, flags, recv)?;
                    utcb.set_cap_transfer(cap);
                    utcb.set_msg_tag(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ));
                    Ok(())
                }
                protocol::resource::FREE => {
                    let cap = CapPtr::from(mrs[0]);
                    self.free(badge, cap)?;
                    Ok(())
                }
                protocol::resource::SBRK => {
                    let brk = self.brk(badge, mrs[0] as isize)?;
                    set_mrs!(utcb, brk);
                    Ok(())
                }
                protocol::resource::MMAP => {
                    let ret = self.mmap(badge, mrs[0], mrs[1])?;
                    set_mrs!(utcb, ret);
                    Ok(())
                }
                protocol::resource::MUNMAP => {
                    self.munmap(badge, mrs[0], mrs[1])?;
                    Ok(())
                }
                protocol::resource::GET_CAP => {
                    let captype_num = mrs[0];
                    let captype = unsafe { transmute::<usize, InitCap>(captype_num) };
                    log!("Getting cap of type {} for badge {}", captype_num, badge);
                    let cap = self.get_cap(badge, captype)?;
                    utcb.set_cap_transfer(cap);
                    utcb.set_msg_tag(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ));
                    Ok(())
                }
                protocol::resource::GET_FILE => {
                    let name = unsafe { utcb.read_str()? };
                    let frame = self.get_file(badge, &name)?;
                    utcb.set_cap_transfer(frame.cap());
                    utcb.set_msg_tag(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ));
                    Ok(())
                }
                _ => Err(Error::InvalidMethod),
            },
            protocol::KERNEL_PROTO => {
                let res = match label {
                    protocol::kernel::SYSCALL => self.syscall(badge, utcb),
                    protocol::kernel::PAGE_FAULT => self.page_fault(badge, mrs[0], mrs[1], mrs[2]),
                    protocol::kernel::ILLEGAL_INSTRUCTION => {
                        self.illegal_instrution(badge, mrs[0], mrs[1])
                    }
                    protocol::kernel::BREAKPOINT => self.breakpoint(badge, mrs[0]),
                    protocol::kernel::ACCESS_FAULT => self.access_fault(badge, mrs[0], mrs[1]),
                    protocol::kernel::ACCESS_MISALIGNED => {
                        self.access_misaligned(badge, mrs[0], mrs[1])
                    }
                    _ => self.unknown_fault(badge, mrs[0], mrs[1], mrs[2]),
                };
                if let Err(e) = res {
                    log!("Failed to handle kernel protocol: {:?}", e);
                }
                Ok(())
            }
            _ => Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
