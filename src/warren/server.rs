use super::WarrenManager;
use crate::layout::INIT_NAME;
use crate::log;
use alloc::string::ToString;
use glenda::cap::{CapPtr, CapType, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, InitResourceService, MemoryService, ProcessService, ResourceService,
    SystemService,
};
use glenda::ipc::server::{handle_call, handle_cap_call};
use glenda::ipc::{Badge, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::resource::InitCap;

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
                    if e == Error::Success {
                        continue;
                    }
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

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::PROCESS_PROTO, protocol::process::SPAWN) => |_, _| Err(Error::NotImplemented),
            (protocol::PROCESS_PROTO, protocol::process::FORK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.fork(u.get_badge()))
            },
            (protocol::PROCESS_PROTO, protocol::process::EXIT) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.exit(u.get_badge(), u.get_mr(0)))
            },
            (protocol::PROCESS_PROTO, protocol::process::GET_CNODE) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.get_cnode(u.get_badge(), Badge::new(u.get_mr(0)), CapPtr::null()).map(|c| c.cap()))
            },

            (protocol::RESOURCE_PROTO, protocol::resource::ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| {
                    let obj_type = CapType::from(u.get_mr(0));
                    let flags = u.get_mr(1);
                    let recv = CapPtr::from(u.get_mr(2));
                    s.alloc(u.get_badge(), obj_type, flags, recv)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::FREE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.free(u.get_badge(), CapPtr::from(u.get_mr(0))))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::SBRK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.brk(u.get_badge(), u.get_mr(0) as isize))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.mmap(u.get_badge(), u.get_mr(0), u.get_mr(1)))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MUNMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.munmap(u.get_badge(), u.get_mr(0), u.get_mr(1)))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CAP) => |s: &mut Self, u: &mut UTCB| {
                 handle_cap_call(u, |u| {
                     let captype_num = u.get_mr(0);
                     let captype = InitCap::from(captype_num);
                     s.get_cap(u.get_badge(), captype, CapPtr::null())
                 })
            },
             (protocol::RESOURCE_PROTO, protocol::resource::MAP_FILE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str()? };
                    let name_owned = alloc::string::String::from(name);
                    let address = u.get_mr(0);
                    s.map_file(u.get_badge(), &name_owned, address)
                })
            },

            (protocol::KERNEL_PROTO, _) => |s: &mut Self, u: &mut UTCB| {
                let badge = u.get_badge();
                let mrs = u.get_mrs();
                let label = u.get_msg_tag().label();

                let res = match label {
                    protocol::kernel::SYSCALL => s.syscall(badge, u),
                    protocol::kernel::PAGE_FAULT => s.page_fault(badge, mrs[0], mrs[1], mrs[2]),
                    protocol::kernel::ILLEGAL_INSTRUCTION => {
                        s.illegal_instrution(badge, mrs[0], mrs[1])
                    }
                    protocol::kernel::BREAKPOINT => s.breakpoint(badge, mrs[0]),
                    protocol::kernel::ACCESS_FAULT => s.access_fault(badge, mrs[0], mrs[1]),
                    protocol::kernel::ACCESS_MISALIGNED => {
                        s.access_misaligned(badge, mrs[0], mrs[1])
                    }
                    _ => s.unknown_fault(badge, mrs[0], mrs[1], mrs[2]),
                };
                if let Err(e) = res {
                    log!("Failed to handle kernel protocol: {:?}", e);
                }
                Ok(())
            },
        }
    }

    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
