#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

use glenda::cap::{CapPtr, CapType, rights};
use glenda::factotum as protocol;
use glenda::ipc::{MsgTag, UTCB};
use glenda::log;
use glenda::println;

mod manager;
mod process;

use manager::ResourceManager;
use process::{ProcessManager, ThreadState};

// Assume this is where our endpoint is.
const FACTOTUM_ENDPOINT_SLOT: usize = 10;
const FACTOTUM_UTCB_ADDR: usize = 0x7FFF_F000;
const FACTOTUM_STACK_TOP: usize = 0x8000_0000;

// Fault labels
const PAGE_FAULT: usize = 0xFFFF;
const EXCEPTION: usize = 0xFFFE;

#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    log::init(CapPtr(glenda::bootinfo::CONSOLE_CAP));
    println!("Factotum: Starting...");

    let mut pm = ProcessManager::new();
    let mut rm = ResourceManager::new();
    let endpoint = CapPtr(FACTOTUM_ENDPOINT_SLOT);

    println!("Factotum: Listening on endpoint {}", FACTOTUM_ENDPOINT_SLOT);

    loop {
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
            println!("Factotum: Unknown protocol label: {:#x}", label);
            continue;
        }

        let method = utcb.mrs_regs[0];

        // Dispatch
        let ret = match method {
            protocol::INIT_RESOURCES => {
                handle_init_resources(&mut rm, utcb.mrs_regs[1], utcb.mrs_regs[2])
            }
            protocol::SPAWN => handle_spawn(&mut pm, &mut rm, utcb),
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
                println!("Factotum: Unimplemented method: {}", method);
                // Error code
                usize::MAX
            }
        };

        // Reply
        // Construct reply tag: Label 0, Length 1 (return value)
        let reply_tag = MsgTag::new(0, 1);

        let args = [ret, 0, 0, 0, 0];
        endpoint.ipc_reply(reply_tag, &args);
    }
}

fn handle_init_resources(rm: &mut ResourceManager, start: usize, count: usize) -> usize {
    println!("Factotum: Init resources start={} count={}", start, count);
    rm.init(start, count);
    0
}

fn handle_spawn(pm: &mut ProcessManager, rm: &mut ResourceManager, utcb: &UTCB) -> usize {
    // args: [method, name_len, flags]
    let name_len = utcb.mrs_regs[1];
    let flags = utcb.mrs_regs[2];

    let ipc_buf = glenda::ipc::utcb::get_ipc_buffer();
    if name_len > ipc_buf.0.len() {
        return usize::MAX;
    }

    let name_bytes = &ipc_buf.0[0..name_len];
    let name = match core::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => return usize::MAX,
    };

    println!("Factotum: SPAWN requested for '{}', flags: {}", name, flags);

    // Allocate Resources
    let cspace = rm.alloc_object(CapType::CNode, 12).expect("OOM CNode");
    let vspace = rm.alloc_object(CapType::PageTable, 0).expect("OOM VSpace");
    let tcb = rm.alloc_object(CapType::TCB, 0).expect("OOM TCB");
    let utcb_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM UTCB Frame");
    let stack_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM Stack Frame");

    // Setup CSpace
    // Mint CSpace to itself
    cspace.cnode_mint(cspace, 0, 0, rights::ALL);
    cspace.cnode_mint(vspace, 1, 0, rights::ALL);
    cspace.cnode_mint(tcb, 2, 0, rights::ALL);

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
    tcb.tcb_configure(
        cspace,
        vspace,
        FACTOTUM_UTCB_ADDR,
        CapPtr(FACTOTUM_ENDPOINT_SLOT),
        utcb_frame,
    );
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

    println!("Factotum: Spawned process {} (created)", pid);
    pid
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

    if let Some(proc) = pm.get_process_mut(pid) {
        // 1. Map Source (Initrd) to Factotum VSpace
        // We use a fixed location for reading initrd.
        // WARNING: This assumes frame_cap is the WHOLE initrd or a large frame covering the range.
        // If it's a small frame, we might need to map multiple times or assume offset is small.
        // For now, assume it's the Initrd Frame which is large.

        let src_va = 0x6000_0000;
        let my_vspace = CapPtr(1);

        // Map Read-Only
        my_vspace.pagetable_map(frame_cap, src_va, rights::READ as usize);

        // 2. Copy Loop
        // We copy in chunks of 4KB (Page Size)
        let mut current_offset = 0;
        while current_offset < len {
            let chunk_len = core::cmp::min(4096, len - current_offset);
            let target_vaddr = load_addr + current_offset;

            // Align target_vaddr to page boundary
            let page_base = target_vaddr & !0xFFF;
            let page_offset = target_vaddr & 0xFFF;

            // Allocate Destination Frame if needed
            let dest_frame = if let Some(cap) = proc.frames.get(&page_base) {
                *cap
            } else {
                let new_frame = rm.alloc_object(CapType::Frame, 0).expect("OOM Load Image");
                proc.vspace.pagetable_map(new_frame, page_base, rights::ALL as usize); // RWX
                proc.frames.insert(page_base, new_frame);
                new_frame
            };

            // Map Dest Frame to Scratch
            let scratch_va = 0x5000_0000;
            my_vspace.pagetable_map(dest_frame, scratch_va, rights::RW as usize);

            // Copy
            let src_ptr = (src_va + offset + current_offset) as *const u8;
            let dest_ptr = (scratch_va + page_offset) as *mut u8;

            // We need to be careful not to overflow the page in destination
            let copy_len = core::cmp::min(chunk_len, 4096 - page_offset);

            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, dest_ptr, copy_len);
            }

            my_vspace.pagetable_unmap(scratch_va);

            current_offset += copy_len;
        }

        // Unmap Source
        my_vspace.pagetable_unmap(src_va);

        return 0;
    }
    usize::MAX
}

fn handle_process_start(pm: &mut ProcessManager, utcb: &UTCB) -> usize {
    let pid = utcb.mrs_regs[1];
    let entry = utcb.mrs_regs[2];
    let stack = utcb.mrs_regs[3];

    if let Some(proc) = pm.get_process(pid) {
        println!("Factotum: Starting process {} at {:#x}", pid, entry);
        proc.tcb.tcb_set_registers(rights::ALL as usize, entry, stack);
        proc.tcb.tcb_resume();
        return 0;
    }
    usize::MAX
}

fn handle_fault(pm: &mut ProcessManager, badge: usize, label: usize, utcb: &UTCB) {
    let pid = badge; // Assuming badge is PID for now
    println!("Factotum: Fault received from PID {}. Label: {:#x}", pid, label);

    if let Some(proc) = pm.get_process(pid) {
        println!("Process '{}' faulted.", proc.name);
        if label == PAGE_FAULT {
            let addr = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            println!("  Page Fault at address {:#x}, PC={:#x}", addr, pc);
            // TODO: Handle lazy allocation or stack growth
        } else if label == EXCEPTION {
            let cause = utcb.mrs_regs[0];
            let val = utcb.mrs_regs[1];
            let pc = utcb.mrs_regs[2];
            println!("  Exception cause={} val={:#x} PC={:#x}", cause, val, pc);
        }
    } else {
        println!("Fault from unknown PID {}", pid);
    }

    // For now, kill the process on fault
    println!("Factotum: Killing process {} due to fault", pid);
    pm.remove_process(pid);
}

fn handle_exit(pm: &mut ProcessManager, badge: usize) -> usize {
    println!("Factotum: EXIT requested by badge {}", badge);
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
    println!("Factotum: SBRK requested, increment: {}", increment);
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
    println!(
        "Factotum: MMAP requested: addr={:#x}, len={}, prot={}, flags={}, fd={}, offset={}",
        addr, len, prot, flags, fd, offset
    );
    // TODO: Implement MMAP
    0
}

fn handle_thread_create(pm: &mut ProcessManager, badge: usize, utcb: &UTCB) -> usize {
    let entry = utcb.mrs_regs[1];
    let stack = utcb.mrs_regs[2];
    let _arg = utcb.mrs_regs[3];
    let _tls = utcb.mrs_regs[4];

    println!("Factotum: THREAD_CREATE from PID {}: entry={:#x}, stack={:#x}", badge, entry, stack);

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
    println!("Factotum: THREAD_EXIT from PID {}", badge);
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
        println!("  (Thread exit not fully implemented without thread identification)");
    }
    0
}

fn handle_thread_join(pm: &mut ProcessManager, badge: usize, target_tid: usize) -> usize {
    println!("Factotum: THREAD_JOIN from PID {} waiting for TID {}", badge, target_tid);
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
    println!("Factotum: FUTEX_WAIT addr={:#x} val={} timeout={}", addr, val, timeout);
    // Check value at addr (need to read user memory)
    // If match, block thread.
    0
}

fn handle_futex_wake(_pm: &mut ProcessManager, _badge: usize, addr: usize, count: usize) -> usize {
    println!("Factotum: FUTEX_WAKE addr={:#x} count={}", addr, count);
    // Wake up 'count' threads waiting on addr.
    0
}

fn handle_fork(pm: &mut ProcessManager, badge: usize) -> usize {
    println!("Factotum: FORK requested by PID {}", badge);
    // 1. Create new process struct
    // 2. Copy VSpace (COW)
    // 3. Copy CSpace
    // 4. Create TCB for child

    let new_pid = pm.allocate_pid();
    // ...
    new_pid
}
