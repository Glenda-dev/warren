use super::WarrenManager;
use crate::layout::INIT_NAME;
use glenda::cap::MONITOR_SLOT;
use glenda::cap::{CapPtr, CapType, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{
    FaultService, ProcessService, ResourceService, SystemService, ThreadService,
};
use glenda::ipc::server::{handle_call, handle_notify};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::resource::{PROCESS_ENDPOINT, RESOURCE_ENDPOINT, ResourceType};

impl<'a> SystemService for WarrenManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.state.res.endpoints.insert(PROCESS_ENDPOINT, MONITOR_SLOT);
        self.state.res.endpoints.insert(RESOURCE_ENDPOINT, MONITOR_SLOT);
        self.spawn(Badge::null(), INIT_NAME).map(|pid| {
            log!("Started init {} with pid: {:?}", INIT_NAME, pid);
        })
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.ipc.endpoint = ep;
        self.ipc.reply = Reply::from(reply);
        self.ipc.recv = recv;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.ipc.endpoint.cap().is_null()
            || self.ipc.reply.cap().is_null()
            || self.ipc.recv.is_null()
        {
            return Err(Error::NotInitialized);
        }
        self.ipc.running = true;
        while self.ipc.running {
            self.refill_allocator();
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.ipc.reply.cap());
            utcb.set_recv_window(self.ipc.recv);
            match self.ipc.endpoint.recv(&mut utcb) {
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
                        // This path intentionally skips IPC reply (notify-style handling).
                        // If the sender used CALL, a one-shot Reply cap may still occupy
                        // our fixed reply slot and keep a stale reference to sender TCB.
                        if let Err(clean_err) = self.ctx.root_cnode.delete(self.ipc.reply.cap())
                            && clean_err != Error::InvalidCapability
                            && clean_err != Error::InvalidSlot
                        {
                            warn!(
                                "Failed to cleanup reply slot {:?}: {:?}",
                                self.ipc.reply.cap(),
                                clean_err
                            );
                        }
                        continue;
                    }
                    error!(
                        "Failed to dispatch message for {:#x}: {:?}, proto={:#x}, label={:#x}",
                        badge.bits(),
                        e,
                        proto,
                        label
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
            (protocol::PROCESS_PROTO, protocol::process::CREATE) => |s: &mut Self, u: &mut UTCB| {
                let name = unsafe { u.read_str()? };
                handle_call(u, |_| s.create(pid, &name))
            },
            (protocol::PROCESS_PROTO, protocol::process::GET_CNODE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let target = u.get_mr(0);
                    let recv = CapPtr::from(u.get_mr(1));
                    s.get_cnode(pid, target, recv).map(|c| c.cap().bits())
                })
            },
            (protocol::PROCESS_PROTO, protocol::process::SPAWN) => |s: &mut Self, u: &mut UTCB| {
                let name = unsafe {u.read_str()?};
                handle_call(u, |_| s.spawn(pid, &name))
            },
            (protocol::PROCESS_PROTO, protocol::process::EXIT) => |s: &mut Self, u: &mut UTCB| {
                handle_notify(u, |u| s.exit(pid, u.get_mr(0))) // Avoid reply since process is exiting, but indicate success to caller
            },
            (protocol::PROCESS_PROTO, protocol::process::KILL) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.kill(pid, u.get_mr(0))) // Avoid reply since process is exiting, but indicate success to caller
            },
            (protocol::PROCESS_PROTO, protocol::process::THREAD_CREATE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.thread_create(pid, u.get_mr(0), u.get_mr(1), u.get_mr(2), u.get_mr(3)))
            },

            (protocol::RESOURCE_PROTO, protocol::resource::ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let recv = CapPtr::from(u.get_mr(2));
                    s.alloc(pid, CapType::from(u.get_mr(0)), u.get_mr(1), recv)
                        .map(|cap| cap.bits())
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::DMA_ALLOC) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let pages = u.get_mr(0);
                    let recv = CapPtr::from(u.get_mr(1));
                    s.dma_alloc(pid, pages, recv).map(|(paddr, frame)| (paddr, frame.cap().bits()))
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::FREE) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.free(pid, CapPtr::from(u.get_mr(0))))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::SBRK) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| s.brk(pid, u.get_mr(0) as isize))
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CAP) => |s: &mut Self, u: &mut UTCB| {
                 handle_call(u, |u| {
                     let captype_num = u.get_mr(0);
                     let captype = ResourceType::from(captype_num);
                     let id = u.get_mr(1);
                     let recv = CapPtr::from(u.get_mr(2));
                     s.get_cap(pid, captype, id, recv).map(|cap| cap.bits())
                 })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::REGISTER_CAP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    if !u.get_msg_tag().flags().contains(MsgFlags::HAS_CAP) {
                        return Err(Error::InvalidArgs);
                    }
                    let captype_num = u.get_mr(0);
                    let captype = ResourceType::from(captype_num);
                    let id = u.get_mr(1);
                    let cap = u.get_recv_window();
                    s.register_cap(pid, captype, id, cap)
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_CONFIG) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let recv = CapPtr::from(u.get_mr(0));
                    let name = unsafe {u.read_str()?};
                    s.get_config(pid, &name, recv).map(|(frame, len)| (len, frame.cap().bits()))
                })
            },
            (protocol::RESOURCE_PROTO, protocol::resource::GET_STATUS) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |_| {
                    s.status(pid).map(|status| {
                        (status.memory.available_bytes, status.memory.total_bytes)
                    })
                })
            },
            (protocol::KERNEL_PROTO, _) => |s: &mut Self, u: &mut UTCB| {
                let res = match label {
                    protocol::kernel::SYSCALL => s.handle_syscall(badge.bits(), u.get_mrs()),
                    protocol::kernel::PAGE_FAULT => s.page_fault(badge, mrs[0], mrs[1], mrs[2]),
                    protocol::kernel::ILLEGAL_INSTRUCTION => {
                        s.illegal_instruction(badge, mrs[0], mrs[1])
                    }
                    protocol::kernel::BREAKPOINT => s.breakpoint(badge, mrs[0]),
                    protocol::kernel::ACCESS_FAULT => s.access_fault(badge, mrs[0], mrs[1]),
                    protocol::kernel::ACCESS_MISALIGNED => {
                        s.access_misaligned(badge, mrs[0], mrs[1])
                    }
                    protocol::kernel::VIRT_EXIT => {
                        s.virt_exit(badge, mrs[0], mrs[1], mrs[2], mrs[3])
                    }
                    _ => s.unknown_fault(badge, mrs[0], mrs[1], mrs[2]),
                };
                match res {
                    Ok(()) => Ok(()),
                    // Fatal kernel events (e.g. BREAKPOINT/ACCESS_FAULT after process kill)
                    // should not send IPC reply, otherwise we may wake a thread that is being torn down.
                    Err(Error::Success) => Err(Error::Success),
                    Err(e) => panic!("Failed to handle kernel protocol: {:?}", e),
                }
            },
        }
    }

    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.ipc.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.ipc.running = false;
    }
}
