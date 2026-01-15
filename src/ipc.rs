use crate::layout::{MONITOR_CAP, RECV_CAP};
use crate::log;
use crate::manager::ResourceManager;
use crate::process::{ProcessManager, ThreadState};
use crate::spawn::{
    handle_process_start_internal, handle_spawn, handle_spawn_service, handle_spawn_service_initrd,
    load_image_to_process,
};
use glenda::cap::{CapPtr, Frame, Reply, TCB, rights};
use glenda::initrd::Initrd;
use glenda::ipc::{MsgTag, UTCB};
use glenda::manifest::Manifest;
use glenda::protocol::factotum as protocol;

// Fault labels
const PAGE_FAULT: usize = 0xFFFF;
const EXCEPTION: usize = 0xFFFE;

pub fn dispatch_loop(
    mut pm: ProcessManager,
    mut rm: ResourceManager,
    manifest: Option<Manifest>,
    initrd: Initrd,
    initrd_slice: &[u8],
) -> ! {
    let endpoint = MONITOR_CAP;

    loop {
        // Prepare to receive a capability
        let utcb = UTCB::current();
        utcb.recv_window = RECV_CAP;

        // Block and wait for a message
        let badge = endpoint.recv();

        // Get the message from UTCB
        let utcb = UTCB::current();
        let tag = utcb.msg_tag;
        let label = tag.label();

        // Handle Faults
        if label == PAGE_FAULT || label == EXCEPTION {
            handle_fault(&mut pm, badge, label, utcb);
            continue;
        }

        // Check protocol label
        if label != protocol::FACTOTUM_PROTO {
            log!("Unknown protocol label: {:#x}", label);
            continue;
        }

        let method = utcb.mrs_regs[0];

        // Dispatch
        let ret = match method {
            protocol::SHARE_CAP => {
                let dest_slot = utcb.mrs_regs[1];
                let target_pid = utcb.mrs_regs[2];

                if tag.has_cap() {
                    let cap_in_recv = RECV_CAP;
                    if let Some(target_proc) = pm.get_process_mut(target_pid) {
                        let target_cnode = target_proc.cspace;
                        let ret = target_cnode.copy(cap_in_recv.cap(), dest_slot, rights::ALL);
                        ret
                    } else {
                        usize::MAX
                    }
                } else {
                    usize::MAX
                }
            }
            protocol::INIT_RESOURCES => {
                handle_init_resources(&mut rm, utcb.mrs_regs[1], utcb.mrs_regs[2])
            }
            protocol::SPAWN_SERVICE_MANIFEST => {
                let index = utcb.mrs_regs[1];
                if let Some(ref m) = manifest {
                    if index < m.service.len() {
                        let entry = &m.service[index];
                        handle_spawn_service(
                            &mut pm,
                            &mut rm,
                            &initrd,
                            initrd_slice,
                            &entry.name,
                            &entry.binary,
                        )
                    } else {
                        usize::MAX
                    }
                } else {
                    usize::MAX
                }
            }
            protocol::SPAWN => {
                let name_len = utcb.mrs_regs[1];
                let name_bytes = &utcb.ipc_buffer[utcb.head..utcb.head + name_len];
                let name = core::str::from_utf8(name_bytes).unwrap_or("unknown");
                handle_spawn(&mut pm, &mut rm, name, utcb.mrs_regs[2])
            }
            protocol::SPAWN_SERVICE => {
                let name_len = utcb.mrs_regs[1];
                let binary_len = utcb.mrs_regs[2];
                let name = core::str::from_utf8(&utcb.ipc_buffer[utcb.head..utcb.head + name_len])
                    .unwrap_or("unknown");
                let binary_name = core::str::from_utf8(
                    &utcb.ipc_buffer[utcb.head + name_len..utcb.head + name_len + binary_len],
                )
                .unwrap_or(name);
                handle_spawn_service(&mut pm, &mut rm, &initrd, initrd_slice, name, binary_name)
            }
            protocol::SPAWN_SERVICE_INITRD => {
                let name_len = utcb.mrs_regs[1];
                let binary_len = utcb.mrs_regs[2];
                let name = core::str::from_utf8(&utcb.ipc_buffer[utcb.head..utcb.head + name_len])
                    .unwrap_or("unknown");
                let binary_name = core::str::from_utf8(
                    &utcb.ipc_buffer[utcb.head + name_len..utcb.head + name_len + binary_len],
                )
                .unwrap_or(name);

                handle_spawn_service_initrd(
                    &mut pm,
                    &mut rm,
                    &initrd,
                    initrd_slice,
                    name,
                    binary_name,
                )
            }
            protocol::PROCESS_LOAD_IMAGE => handle_process_load_image(&mut pm, &mut rm, utcb),
            protocol::PROCESS_START => handle_process_start(&mut pm, utcb),
            protocol::EXIT => handle_exit(&mut pm, badge),
            protocol::GET_PID => handle_get_pid(badge),
            protocol::YIELD => handle_yield(),
            protocol::SBRK => handle_sbrk(utcb.mrs_regs[1]),
            protocol::MMAP => handle_mmap(
                utcb.mrs_regs[1],
                utcb.mrs_regs[2],
                utcb.mrs_regs[3],
                utcb.mrs_regs[4],
                utcb.mrs_regs[5],
                utcb.mrs_regs[6],
            ),
            protocol::THREAD_CREATE => handle_thread_create(&mut pm, badge, utcb),
            protocol::THREAD_EXIT => handle_thread_exit(&mut pm, badge),
            protocol::THREAD_JOIN => handle_thread_join(&mut pm, badge, utcb.mrs_regs[1]),
            protocol::FUTEX_WAIT => handle_futex_wait(
                &mut pm,
                badge,
                utcb.mrs_regs[1],
                utcb.mrs_regs[2],
                utcb.mrs_regs[3],
            ),
            protocol::FUTEX_WAKE => {
                handle_futex_wake(&mut pm, badge, utcb.mrs_regs[1], utcb.mrs_regs[2])
            }
            protocol::FORK => handle_fork(&mut pm, badge),
            _ => {
                log!("Unimplemented method: {}", method);
                usize::MAX
            }
        };

        // TODO: Reply
        unimplemented!();
        let reply_cap = Reply::from(RECV_CAP.cap());
        let reply_tag = MsgTag::new(0, 1);
        let args = [ret, 0, 0, 0, 0, 0, 0];
        reply_cap.reply(reply_tag, args);
    }
}

fn handle_init_resources(
    rm: &mut ResourceManager,
    untyped_start: usize,
    untyped_count: usize,
) -> usize {
    log!("Init resources untyped_start={} untyped_count={}", untyped_start, untyped_count);
    rm.init(untyped_start, untyped_count);
    0
}

fn handle_process_load_image(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    utcb: &UTCB,
) -> usize {
    let pid = utcb.mrs_regs[1];
    let frame_cap = Frame::from(CapPtr::from(utcb.mrs_regs[2]));
    let offset = utcb.mrs_regs[3];
    let len = utcb.mrs_regs[4];
    let load_addr = utcb.mrs_regs[5];

    load_image_to_process(pm, rm, pid, frame_cap, offset, len, load_addr)
}

fn handle_process_start(pm: &mut ProcessManager, utcb: &UTCB) -> usize {
    let pid = utcb.mrs_regs[1];
    let entry = utcb.mrs_regs[2];
    let stack = utcb.mrs_regs[3];

    handle_process_start_internal(pm, pid, entry, stack)
}

fn handle_fault(pm: &mut ProcessManager, badge: usize, label: usize, utcb: &UTCB) {
    let pid = badge;
    log!("Fault received from PID {}. Label: {:#x}", pid, label);

    if let Some(proc) = pm.get_process(pid) {
        log!("Process '{}' faulted.", proc.name);
        if label == PAGE_FAULT {
            let addr = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            log!("  Page Fault at address {:#x}, PC={:#x}", addr, pc);
        } else if label == EXCEPTION {
            let cause = utcb.mrs_regs[0];
            let val = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            log!("  Exception cause={} val={:#x} PC={:#x}", cause, val, pc);
        }
    } else {
        log!("Fault from unknown PID {}", pid);
    }

    log!("Killing process {} due to fault", pid);
    pm.remove_process(pid);
}

fn handle_exit(pm: &mut ProcessManager, badge: usize) -> usize {
    log!("EXIT requested by badge {}", badge);
    pm.remove_process(badge);
    0
}

fn handle_get_pid(badge: usize) -> usize {
    badge
}

fn handle_yield() -> usize {
    0
}

fn handle_sbrk(increment: usize) -> usize {
    log!("SBRK requested, increment: {}", increment);
    0
}

fn handle_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> usize {
    log!(
        "Factotum: MMAP requested: addr={:#x}, len={}, prot={}, flags={}, fd={}, offset={}",
        addr,
        len,
        prot,
        flags,
        fd,
        offset
    );
    0
}

fn handle_thread_create(pm: &mut ProcessManager, badge: usize, utcb: &UTCB) -> usize {
    let entry = utcb.mrs_regs[1];
    let stack = utcb.mrs_regs[2];
    let _arg = utcb.mrs_regs[3];
    let _tls = utcb.mrs_regs[4];

    log!("THREAD_CREATE from PID {}: entry={:#x}, stack={:#x}", badge, entry, stack);

    if let Some(proc) = pm.get_process_mut(badge) {
        unimplemented!();
        let tid = proc.add_thread(TCB::from(CapPtr::null()));
        return tid;
    }
    usize::MAX
}

fn handle_thread_exit(pm: &mut ProcessManager, badge: usize) -> usize {
    log!("THREAD_EXIT from PID {}", badge);
    if let Some(_proc) = pm.get_process_mut(badge) {
        log!("  (Thread exit not fully implemented without thread identification)");
    }
    0
}

fn handle_thread_join(pm: &mut ProcessManager, badge: usize, target_tid: usize) -> usize {
    log!("THREAD_JOIN from PID {} waiting for TID {}", badge, target_tid);
    if let Some(proc) = pm.get_process_mut(badge) {
        if let Some(target) = proc.get_thread(target_tid) {
            if target.state == ThreadState::Dead {
                return 0;
            }
        }
    }
    0
}

fn handle_futex_wait(
    _pm: &mut ProcessManager,
    _badge: usize,
    addr: usize,
    val: usize,
    timeout: usize,
) -> usize {
    log!("FUTEX_WAIT addr={:#x} val={} timeout={}", addr, val, timeout);
    0
}

fn handle_futex_wake(_pm: &mut ProcessManager, _badge: usize, addr: usize, count: usize) -> usize {
    log!("FUTEX_WAKE addr={:#x} count={}", addr, count);
    0
}

fn handle_fork(_pm: &mut ProcessManager, badge: usize) -> usize {
    log!("FORK requested by PID {}", badge);
    0
}
