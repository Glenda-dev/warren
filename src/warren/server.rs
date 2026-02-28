use super::WarrenManager;
use crate::layout::INIT_NAME;
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CapPtr, CapType, Endpoint, Frame, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, MemoryService, ProcessService, ResourceService, SystemService, ThreadService,
};
use glenda::ipc::server::{handle_call, handle_cap_call, handle_notify};
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
            self.refill_buddy();
            let _ = self.ctx.root_cnode.delete(self.recv);
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.reply.cap());
            utcb.set_recv_window(self.recv);
            match self.endpoint.recv(&mut utcb) {
                Ok(b) => b,
                Err(e) => {
                    error!("Recv error: {:?}", e);
                    continue;
                }
            };

            let badge = utcb.get_badge();
            let proto = utcb.get_msg_tag().proto();
            let label = utcb.get_msg_tag().label();
            match self.dispatch(&mut utcb) {
                Ok(()) => {}
                Err(e) => {
                    if e == Error::Success {
                        continue;
                    }
                    error!(
                        "Failed to dispatch message for {}: {:?}, proto={:#x}, label={:#x}",
                        badge, e, proto, label
                    );
                    utcb.set_msg_tag(MsgTag::err());
                    utcb.set_mr(0, e as usize);
                }
            };
            if let Err(e) = self.reply(&mut utcb) {
                // Ignore reply failures when the target process might have exited.
                // However, we still log it if it's not a common "InvalidCapability" error.
                if e != Error::InvalidCapability {
                    let b = utcb.get_badge();
                    error!("Process {} reply error: {:?}", b.bits() >> 16, e);
                }
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        let pid = Badge::new(badge.bits() >> 16);
        let tag = utcb.get_msg_tag();
        let label = tag.label();
        let mrs = utcb.get_mrs();

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::PROCESS_PROTO, protocol::process::SPAWN) => |s: &mut Self, u: &mut UTCB| {
                let name = unsafe {u.read_str()?};
                handle_call(u, |_| s.spawn(pid, &name))
            },
            (protocol::PROCESS_PROTO, protocol::process::FORK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |_| s.fork(pid))
            },
            (protocol::PROCESS_PROTO, protocol::process::EXIT) => |s: &mut Self, u: &mut UTCB| {
                handle_notify(u, |u| s.exit(pid, u.get_mr(0))) // Avoid reply since process is exiting, but indicate success to caller
            },
            (protocol::PROCESS_PROTO, protocol::process::EXEC) => |s: &mut Self, u: &mut UTCB| {
                let path = unsafe {u.read_str()?};
                handle_call(u, |_| s.exec(pid, &path))
            },
            (protocol::PROCESS_PROTO, protocol::process::THREAD_CREATE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.thread_create(pid, u.get_mr(0), u.get_mr(1), u.get_mr(2), u.get_mr(3)))
            },
            (protocol::PROCESS_PROTO, protocol::process::GET_CNODE) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.get_cnode(pid, Badge::new(u.get_mr(0)), CapPtr::null()).map(|c| c.cap()))
            },

            (protocol::RESOURCE_PROTO, protocol::resource::ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.alloc(pid, CapType::from(u.get_mr(0)), u.get_mr(1), CapPtr::null())
                )
            },
            (protocol::RESOURCE_PROTO, protocol::resource::DMA_ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| s.dma_alloc(pid, u.get_mr(0), CapPtr::null()).map(
                    |(paddr, frame)|{
                        u.set_mr(0, paddr);
                        frame.cap()
                    })
                )
            },
            (protocol::RESOURCE_PROTO, protocol::resource::FREE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.free(pid, CapPtr::from(u.get_mr(0))))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::SBRK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.brk(pid, u.get_mr(0) as isize))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let frame = Frame::from(s.recv);
                    let addr = u.get_mr(0);
                    let len = u.get_mr(1);
                    s.mmap(pid, frame, addr, len)?;
                    s.ctx.root_cnode.delete(s.recv)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::MUNMAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.munmap(pid, u.get_mr(0), u.get_mr(1)))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CAP) => |s: &mut Self, u: &mut UTCB| {
                 handle_cap_call(u, |u| {
                     let captype_num = u.get_mr(0);
                     let captype = ResourceType::from(captype_num);
                     let id = u.get_mr(1);
                     s.get_cap(pid, captype, id, CapPtr::null())
                 })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::REGISTER_CAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let captype_num = u.get_mr(0);
                    let captype = ResourceType::from(captype_num);
                    let id = u.get_mr(1);
                    let cap = s.recv;
                    s.register_cap(pid, captype, id, cap)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CONFIG) => |s: &mut Self, u: &mut UTCB| {
                handle_cap_call(u, |u| {
                    let name = unsafe {u.read_str()?};
                    let (frame, len) = s.get_config(pid, &name, CapPtr::null())?;
                    u.set_mr(0, len);
                    Ok(frame.cap())
                })
            },
            (protocol::KERNEL_PROTO, _) => |s: &mut Self, u: &mut UTCB| {
                let res = match label {
                    protocol::kernel::SYSCALL => s.handle_syscall(badge.bits(), u.get_mrs()),
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
