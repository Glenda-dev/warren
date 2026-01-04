use alloc::string::ToString;
use glenda::cap::{CapPtr, CapType, rights};
use glenda::initrd::Initrd;
use glenda::mem::{ENTRY_VA, PGSIZE, STACK_SIZE, STACK_VA, UTCB_VA};

use crate::layout::{CONSOLE_SLOT, FACTOTUM_ENDPOINT_SLOT};
use crate::log;
use crate::manager::ResourceManager;
use crate::process::{self, ProcessManager};

pub fn handle_spawn(
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
    cspace.cnode_copy(CapPtr(CONSOLE_SLOT), 8, rights::ALL);

    // Mint Endpoint (Slot 10)
    cspace.cnode_mint(CapPtr(FACTOTUM_ENDPOINT_SLOT), 10, 0, rights::ALL);

    // Setup VSpace
    // Map Stack
    vspace.pagetable_map(stack_frame, STACK_VA - STACK_SIZE, rights::RW as usize);
    // Map UTCB
    vspace.pagetable_map(utcb_frame, UTCB_VA, rights::RW as usize);

    // Configure TCB
    tcb.tcb_configure(cspace, vspace, utcb_frame, tf_frame, kstack_frame);
    tcb.tcb_set_priority(254); // Set high priority for Factotum

    let pid = pm.allocate_pid();

    // Badge the Endpoint for the process
    cspace.cnode_delete(10);
    cspace.cnode_mint(CapPtr(FACTOTUM_ENDPOINT_SLOT), 10, pid, rights::ALL);

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

pub fn handle_spawn_service(
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
    let ret = load_image_to_process(pm, rm, pid, CapPtr(4), entry.offset, entry.size, ENTRY_VA);
    if ret != 0 {
        log!("Failed to load image for {}", name);
        return usize::MAX;
    }

    // 4. Start
    handle_process_start_internal(pm, pid, ENTRY_VA, STACK_VA - STACK_SIZE);

    log!("Service '{}' started (PID: {})", name, pid);
    pid
}

pub fn handle_spawn_service_initrd(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    initrd: &Initrd,
    _initrd_slice: &[u8],
    name: &str,
    binary_name: &str,
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
    let ret = load_image_to_process(pm, rm, pid, CapPtr(4), entry.offset, entry.size, ENTRY_VA);
    if ret != 0 {
        log!("Failed to load image for {}", name);
        return usize::MAX;
    }

    // 5. Start
    handle_process_start_internal(pm, pid, ENTRY_VA, STACK_VA);

    log!("Service '{}' started (PID: {})", name, pid);
    pid
}

pub fn load_image_to_process(
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

            my_vspace.pagetable_unmap(scratch_va, PGSIZE);
            current_offset += copy_len;
        }

        my_vspace.pagetable_unmap(src_va, PGSIZE);
        return 0;
    }
    usize::MAX
}

pub fn handle_process_start_internal(
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
