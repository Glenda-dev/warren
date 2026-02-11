use super::WarrenManager;
use crate::layout::INIT_NAME;
use crate::log;
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CapPtr, CapType, Endpoint, Frame, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, MemoryService, ProcessService, ResourceService, SystemService,
};
use glenda::ipc::server::{handle_call, handle_cap_call};
use glenda::ipc::{Badge, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::resource::ResourceType;
use glenda::protocol::resource::{PROCESS_ENDPOINT, RESOURCE_ENDPOINT};

impl<'a> SystemService for WarrenManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.res.endpoints.insert(PROCESS_ENDPOINT, MONITOR_SLOT);
        self.res.endpoints.insert(RESOURCE_ENDPOINT, MONITOR_SLOT);
        self.spawn(Badge::null(), INIT_NAME).map(|pid| {
            log!("Started init {} with pid: {:?}", INIT_NAME, pid);
        })
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        self.recv = recv;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() || self.recv.is_null() {
            return Err(Error::NotInitialized);
        }
        self.running = true;
        while self.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.reply.cap());
            utcb.set_recv_window(self.recv);
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
        let size = utcb.get_size();
        log!(
            "Received message: badge={}, label={:#x}, proto={:#x}, flags={}, utcb.mrs_regs={:?}, size={}",
            badge,
            label,
            proto,
            flags,
            mrs,
            size
        );

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::PROCESS_PROTO, protocol::process::SPAWN) => |s: &mut Self, u: &mut UTCB| {
                let name = unsafe {u.read_str()?};
                handle_call(u, |_| s.spawn(badge, &name))
            },
            (protocol::PROCESS_PROTO, protocol::process::FORK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |_| s.fork(badge))
            },
            (protocol::PROCESS_PROTO, protocol::process::EXIT) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.exit(badge, u.get_mr(0)))
            },
            (protocol::PROCESS_PROTO, protocol::process::EXEC) => |s: &mut Self, u: &mut UTCB| {
                    let elf_data = unsafe { core::slice::from_raw_parts(u.get_mr(0) as *const u8, u.get_mr(1)) };
                    handle_call(u, |_| s.exec(badge, elf_data))
            },
            (protocol::PROCESS_PROTO, protocol::process::GET_CNODE) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.get_cnode(badge, Badge::new(u.get_mr(0)), CapPtr::null()).map(|c| c.cap()))
            },

            (protocol::RESOURCE_PROTO, protocol::resource::ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.alloc(badge, CapType::from(u.get_mr(0)), u.get_mr(1), CapPtr::null())
                )
            },
            (protocol::RESOURCE_PROTO, protocol::resource::DMA_ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.dma_alloc(badge, u.get_mr(0), CapPtr::null()).map(
                    |(paddr, frame)|{
                        u.set_mr(0, paddr);
                        frame.cap()
                    })
                )
            },
            (protocol::RESOURCE_PROTO, protocol::resource::FREE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.free(badge, CapPtr::from(u.get_mr(0))))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::SBRK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.brk(badge, u.get_mr(0) as isize))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let frame = Frame::from(s.recv);
                    let addr = u.get_mr(1);
                    let len = u.get_mr(2);
                    s.mmap(badge, frame, addr, len)?;
                    s.ctx.root_cnode.delete(s.recv)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MUNMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.munmap(badge, u.get_mr(0), u.get_mr(1)))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CAP) => |s: &mut Self, u: &mut UTCB| {
                 handle_cap_call(u, |u| {
                     let captype_num = u.get_mr(0);
                     let captype = ResourceType::from(captype_num);
                     let id = u.get_mr(1);
                     s.get_cap(badge, captype, id, CapPtr::null())
                 })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::REGISTER_CAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let captype_num = u.get_mr(0);
                    let captype = ResourceType::from(captype_num);
                    let id = u.get_mr(1);
                    let cap = s.recv;
                    s.register_cap(badge, captype, id, cap)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CONFIG) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| {
                    let name = unsafe {u.read_str()?};
                    let (frame, len) = s.get_config(badge, &name, CapPtr::null())?;
                    u.set_mr(0, len);
                    Ok(frame.cap())
                })
            },
            (protocol::KERNEL_PROTO, _) => |s: &mut Self, u: &mut UTCB| {
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
                    panic!("Failed to handle kernel protocol: {:?}", e);
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
