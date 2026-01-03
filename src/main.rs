#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

use glenda::cap::{CapPtr, CapType, rights};
use glenda::console;
use glenda::initrd::Initrd;
use glenda::ipc::{MsgTag, UTCB};
use glenda::manifest::Manifest;
use glenda::protocol::factotum as protocol;

mod manager;
mod process;
mod request_cap;

use manager::ResourceManager;
use process::{ProcessManager, ThreadState};
use request_cap::handle_request_cap;

// Assume this is where our endpoint is.
const FACTOTUM_ENDPOINT_SLOT: usize = 10;
const FACTOTUM_UTCB_ADDR: usize = 0x7FFF_F000;
const FACTOTUM_STACK_TOP: usize = 0x8000_0000;
const INITRD_VA: usize = 0x3000_0000;
const RECV_SLOT: usize = 30;

// Fault labels
const PAGE_FAULT: usize = 0xFFFF;
const EXCEPTION: usize = 0xFFFE;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("Factotum: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    console::init(CapPtr(glenda::bootinfo::CONSOLE_CAP));
    log!("Starting...");

    // Map Initrd
    let initrd_cap = CapPtr(4); // Slot 4 passed by 9ball
    let my_vspace = CapPtr(1);
    if my_vspace.pagetable_map(initrd_cap, INITRD_VA, rights::READ as usize) != 0 {
        log!("Failed to map initrd");
        loop {}
    }

    // Map BootInfo
    let bootinfo_cap = CapPtr(9); // Slot 9 passed by 9ball
    if my_vspace.pagetable_map(bootinfo_cap, glenda::bootinfo::BOOTINFO_VA, rights::READ as usize)
        != 0
    {
        log!("Failed to map bootinfo");
        loop {}
    }

    // Parse Initrd
    let total_size_ptr = (INITRD_VA + 8) as *const u32;
    let total_size = unsafe { *total_size_ptr } as usize;
    let initrd_slice = unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };
    let initrd = Initrd::new(initrd_slice).expect("Factotum: Failed to parse initrd");
    log!("Initrd mapped and parsed. Size: {}", total_size);

    let mut pm = ProcessManager::new();
    let mut rm = ResourceManager::new();
    let mut manifest: Option<Manifest> = None;
    let endpoint = CapPtr(FACTOTUM_ENDPOINT_SLOT);

    log!("Listening on endpoint {}", FACTOTUM_ENDPOINT_SLOT);

    loop {
        // Prepare to receive a capability
        let utcb = UTCB::current();
        utcb.recv_window = CapPtr(RECV_SLOT);

        // Block and wait for a message
        let badge = endpoint.ipc_recv();

        // Get the message from UTCB
        let utcb = UTCB::current();
        let tag = utcb.msg_tag;
        let label = tag.label();

        // Handle Faults
        if label == PAGE_FAULT || label == EXCEPTION {
            handle_fault(&mut pm, badge, label, utcb);
            // Fault handlers usually reply to resume or kill.
            // For now, we just kill or ignore.
            // If we want to resume, we need to send a reply.
            // But handle_fault might have killed the process.
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
                    let cap_in_recv = CapPtr(RECV_SLOT);
                    if let Some(target_proc) = pm.get_process_mut(target_pid) {
                        let target_cnode = target_proc.cspace;
                        let ret = target_cnode.cnode_copy(cap_in_recv, dest_slot, rights::ALL);
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
            protocol::INIT_IRQ => handle_init_irq(&mut rm, utcb.mrs_regs[1], utcb.mrs_regs[2]),
            protocol::INIT_MANIFEST => {
                if tag.has_cap() {
                    let frame = CapPtr(RECV_SLOT);
                    // Map it temporarily to parse
                    my_vspace.pagetable_map(frame, 0x4000_0000, rights::READ as usize);
                    let data =
                        unsafe { core::slice::from_raw_parts(0x4000_0000 as *const u8, 4096) };
                    manifest = Some(Manifest::parse(data));
                    my_vspace.pagetable_unmap(0x4000_0000);
                    log!("Manifest initialized");
                    0
                } else {
                    1
                }
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
                            &initrd_slice,
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
            protocol::REQUEST_CAP => handle_request_cap(&mut pm, &mut rm, badge, utcb),
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

                let manifest_frame = if tag.has_cap() { CapPtr(RECV_SLOT) } else { CapPtr::null() };

                handle_spawn_service_initrd(
                    &mut pm,
                    &mut rm,
                    &initrd,
                    initrd_slice,
                    name,
                    binary_name,
                    manifest_frame,
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
                // Error code
                usize::MAX
            }
        };

        // Reply
        // Construct reply tag: Label 0, Length 1 (return value)
        let reply_tag = MsgTag::new(0, 1);

        let args = [ret, 0, 0, 0, 0, 0, 0];
        endpoint.ipc_reply(reply_tag, args);
    }
}

fn handle_init_resources(rm: &mut ResourceManager, start: usize, count: usize) -> usize {
    log!("Init resources start={} count={}", start, count);
    rm.init(start, count);
    0
}

fn handle_init_irq(rm: &mut ResourceManager, start: usize, count: usize) -> usize {
    log!("Init IRQ start={} count={}", start, count);
    rm.init_irq(start, count);
    0
}

fn handle_spawn(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    name: &str,
    _flags: usize,
) -> usize {
    log!("SPAWN requested for '{}'", name);

    // Allocate Resources
    let cspace = rm.alloc_object(CapType::CNode, 12).expect("OOM CNode");
    let vspace = rm.alloc_object(CapType::PageTable, 0).expect("OOM VSpace");
    let tcb = rm.alloc_object(CapType::TCB, 0).expect("OOM TCB");
    let utcb_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM UTCB Frame");
    let stack_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM Stack Frame");
    let tf_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM TF Frame");
    let kstack_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM KStack Frame");

    // Setup CSpace
    // Mint CSpace to itself
    cspace.cnode_mint(cspace, 0, 0, rights::ALL);
    cspace.cnode_mint(vspace, 1, 0, rights::ALL);
    cspace.cnode_mint(tcb, 2, 0, rights::ALL);
    cspace.cnode_mint(utcb_frame, 3, 0, rights::ALL);

    // Copy Console (Slot 8)
    cspace.cnode_copy(CapPtr(glenda::bootinfo::CONSOLE_CAP), 8, rights::ALL);

    // Mint Endpoint (Slot 10)
    cspace.cnode_mint(CapPtr(FACTOTUM_ENDPOINT_SLOT), 10, 0, rights::ALL);

    // Setup VSpace
    // Map Stack
    vspace.pagetable_map(stack_frame, FACTOTUM_STACK_TOP - 4096, rights::RW as usize);
    // Map UTCB
    vspace.pagetable_map(utcb_frame, FACTOTUM_UTCB_ADDR, rights::RW as usize);

    // Configure TCB
    tcb.tcb_configure(cspace, vspace, utcb_frame, tf_frame, kstack_frame);
    tcb.tcb_set_priority(100);

    let pid = pm.allocate_pid();

    // Badge the Endpoint for the process
    cspace.cnode_delete(10);
    cspace.cnode_mint(CapPtr(FACTOTUM_ENDPOINT_SLOT), 10, pid, rights::ALL);

    use alloc::string::ToString;
    let mut process = process::Process::new(
        pid,
        0, // TODO: Get from badge/caller
        name.to_string(),
        cspace,
        vspace,
        tcb,
    );

    process.add_thread(tcb);

    pm.add_process(process);

    log!("Spawned process {} (created)", pid);
    pid
}

fn handle_spawn_service(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    initrd: &Initrd,
    _initrd_slice: &[u8],
    name: &str,
    binary_name: &str,
) -> usize {
    log!("SPAWN_SERVICE requested for '{}' (binary: {})", name, binary_name);

    // 1. Find binary in initrd
    let entry = match initrd.entries.iter().find(|e| e.name == binary_name) {
        Some(e) => e,
        None => {
            log!("Binary '{}' not found in initrd", binary_name);
            return usize::MAX;
        }
    };

    // 2. Spawn
    let pid = handle_spawn(pm, rm, name, 0);
    if pid == usize::MAX {
        return pid;
    }

    // 3. Load Image
    // We use the Initrd Frame which is at Slot 4 in Factotum's CSpace.
    let ret = load_image_to_process(pm, rm, pid, CapPtr(4), entry.offset, entry.size, 0x10000);
    if ret != 0 {
        log!("Failed to load image for {}", name);
        return usize::MAX;
    }

    // 4. Start
    handle_process_start_internal(pm, pid, 0x10000, FACTOTUM_STACK_TOP);

    log!("Service '{}' started (PID: {})", name, pid);
    pid
}

fn handle_spawn_service_initrd(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    initrd: &Initrd,
    _initrd_slice: &[u8],
    name: &str,
    binary_name: &str,
    manifest_frame: CapPtr,
) -> usize {
    log!("SPAWN_SERVICE_INITRD requested for '{}' (binary: {})", name, binary_name);

    // 1. Find binary in initrd
    let entry = match initrd.entries.iter().find(|e| e.name == binary_name) {
        Some(e) => e,
        None => {
            log!("Binary '{}' not found in initrd", binary_name);
            return usize::MAX;
        }
    };

    // 2. Spawn
    let pid = handle_spawn(pm, rm, name, 0);
    if pid == usize::MAX {
        return pid;
    }

    // 3. Load Image
    // We use the Initrd Frame which is at Slot 4 in Factotum's CSpace.
    let ret = load_image_to_process(pm, rm, pid, CapPtr(4), entry.offset, entry.size, 0x10000);
    if ret != 0 {
        log!("Failed to load image for {}", name);
        return usize::MAX;
    }

    // 4. Pass Manifest Frame if provided
    if manifest_frame.0 != 0 {
        let process = pm.get_process_mut(pid).unwrap();
        let cnode = process.cspace;
        let vspace = process.vspace;

        // Mint into process CSpace at MANIFEST_SLOT
        cnode.cnode_mint(manifest_frame, glenda::cap::MANIFEST_SLOT, 0, rights::READ);

        // Map into process VSpace at 0x2000_0000
        vspace.pagetable_map(manifest_frame, 0x2000_0000, rights::READ as usize);
        log!("  Manifest frame passed to {} at slot {}", name, glenda::cap::MANIFEST_SLOT);
    }

    // 5. Start
    handle_process_start_internal(pm, pid, 0x10000, FACTOTUM_STACK_TOP);

    log!("Service '{}' started (PID: {})", name, pid);
    pid
}

fn load_image_to_process(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    pid: usize,
    frame_cap: CapPtr,
    offset: usize,
    len: usize,
    load_addr: usize,
) -> usize {
    if let Some(proc) = pm.get_process_mut(pid) {
        let src_va = 0x6000_0000;
        let my_vspace = CapPtr(1);

        // Map Read-Only
        my_vspace.pagetable_map(frame_cap, src_va, rights::READ as usize);

        // 2. Copy Loop
        let mut current_offset = 0;
        while current_offset < len {
            let chunk_len = core::cmp::min(4096, len - current_offset);
            let target_vaddr = load_addr + current_offset;

            let page_base = target_vaddr & !0xFFF;
            let page_offset = target_vaddr & 0xFFF;

            let dest_frame = if let Some(cap) = proc.frames.get(&page_base) {
                *cap
            } else {
                let new_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM Load Image");
                proc.vspace.pagetable_map(new_frame, page_base, rights::ALL as usize); // RWX
                proc.frames.insert(page_base, new_frame);
                new_frame
            };

            let scratch_va = 0x5000_0000;
            my_vspace.pagetable_map(dest_frame, scratch_va, rights::RW as usize);

            let src_ptr = (src_va + offset + current_offset) as *const u8;
            let dest_ptr = (scratch_va + page_offset) as *mut u8;
            let copy_len = core::cmp::min(chunk_len, 4096 - page_offset);

            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, dest_ptr, copy_len);
            }

            my_vspace.pagetable_unmap(scratch_va);
            current_offset += copy_len;
        }

        my_vspace.pagetable_unmap(src_va);
        return 0;
    }
    usize::MAX
}

fn handle_process_load_image(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    utcb: &UTCB,
) -> usize {
    let pid = utcb.mrs_regs[1];
    let frame_cap = CapPtr(utcb.mrs_regs[2]);
    let offset = utcb.mrs_regs[3];
    let len = utcb.mrs_regs[4];
    let load_addr = utcb.mrs_regs[5];

    load_image_to_process(pm, rm, pid, frame_cap, offset, len, load_addr)
}

fn handle_process_start_internal(
    pm: &mut ProcessManager,
    pid: usize,
    entry: usize,
    stack: usize,
) -> usize {
    if let Some(proc) = pm.get_process_mut(pid) {
        proc.tcb.tcb_set_registers(rights::ALL as usize, entry, stack);
        proc.tcb.tcb_resume();
        return 0;
    }
    usize::MAX
}

fn handle_process_start(pm: &mut ProcessManager, utcb: &UTCB) -> usize {
    let pid = utcb.mrs_regs[1];
    let entry = utcb.mrs_regs[2];
    let stack = utcb.mrs_regs[3];

    handle_process_start_internal(pm, pid, entry, stack)
}

fn handle_fault(pm: &mut ProcessManager, badge: usize, label: usize, utcb: &UTCB) {
    let pid = badge; // Assuming badge is PID for now
    log!("Fault received from PID {}. Label: {:#x}", pid, label);

    if let Some(proc) = pm.get_process(pid) {
        log!("Process '{}' faulted.", proc.name);
        if label == PAGE_FAULT {
            let addr = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            log!("  Page Fault at address {:#x}, PC={:#x}", addr, pc);
            // TODO: Handle lazy allocation or stack growth
        } else if label == EXCEPTION {
            let cause = utcb.mrs_regs[0];
            let val = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            log!("  Exception cause={} val={:#x} PC={:#x}", cause, val, pc);
        }
    } else {
        log!("Fault from unknown PID {}", pid);
    }

    // For now, kill the process on fault
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
    // In a real scheduler, we would manipulate priorities or timeslices.
    // Here we just return.
    0
}

fn handle_sbrk(increment: usize) -> usize {
    log!("SBRK requested, increment: {}", increment);
    // TODO: Implement SBRK
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
    // TODO: Implement MMAP
    0
}

fn handle_thread_create(pm: &mut ProcessManager, badge: usize, utcb: &UTCB) -> usize {
    let entry = utcb.mrs_regs[1];
    let stack = utcb.mrs_regs[2];
    let _arg = utcb.mrs_regs[3];
    let _tls = utcb.mrs_regs[4];

    log!("THREAD_CREATE from PID {}: entry={:#x}, stack={:#x}", badge, entry, stack);

    if let Some(proc) = pm.get_process_mut(badge) {
        // TODO:
        // 1. Allocate TCB object (need Untyped)
        // 2. Configure TCB (share VSpace/CSpace)
        // 3. Set registers (entry, stack, arg, tls)
        // 4. Resume

        // For now, just update bookkeeping
        let tid = proc.add_thread(CapPtr(0)); // Placeholder cap
        return tid;
    }
    usize::MAX
}

fn handle_thread_exit(pm: &mut ProcessManager, badge: usize) -> usize {
    log!("THREAD_EXIT from PID {}", badge);
    // We need to know WHICH thread. Assuming single thread per process for badge mapping for now,
    // or that badge implies the thread.
    // If badge == pid, we might be exiting the main thread?
    // Let's just remove the process for now as a simplification if we can't distinguish.
    // Or better:
    if let Some(_proc) = pm.get_process_mut(badge) {
        // Remove the last added thread? No, that's wrong.
        // Without thread ID in badge, we can't do this correctly.
        // Assuming the caller passed TID in arg? No, protocol says THREAD_EXIT(status).

        // Placeholder:
        log!("  (Thread exit not fully implemented without thread identification)");
    }
    0
}

fn handle_thread_join(pm: &mut ProcessManager, badge: usize, target_tid: usize) -> usize {
    log!("THREAD_JOIN from PID {} waiting for TID {}", badge, target_tid);
    if let Some(proc) = pm.get_process_mut(badge) {
        if let Some(target) = proc.get_thread(target_tid) {
            if target.state == ThreadState::Dead {
                return 0; // Already dead
            }
            // Mark current thread as blocked (need current TID)
            // ...
        }
    }
    0
}

fn handle_futex_wait(
    pm: &mut ProcessManager,
    badge: usize,
    addr: usize,
    val: usize,
    timeout: usize,
) -> usize {
    log!("FUTEX_WAIT addr={:#x} val={} timeout={}", addr, val, timeout);
    // Check value at addr (need to read user memory)
    // If match, block thread.
    0
}

fn handle_futex_wake(_pm: &mut ProcessManager, _badge: usize, addr: usize, count: usize) -> usize {
    log!("FUTEX_WAKE addr={:#x} count={}", addr, count);
    // Wake up 'count' threads waiting on addr.
    0
}

fn handle_fork(pm: &mut ProcessManager, badge: usize) -> usize {
    log!("FORK requested by PID {}", badge);
    // 1. Create new process struct
    // 2. Copy VSpace (COW)
    // 3. Copy CSpace
    // 4. Create TCB for child

    let new_pid = pm.allocate_pid();
    // ...
    new_pid
}
