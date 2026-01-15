use crate::layout::{FACTOTUM_ENDPOINT_CAP, INITRD_CAP, SCRATCH_VA};
use crate::log;
use crate::manager::ResourceManager;
use crate::process::{self, ProcessManager};
use alloc::string::ToString;
use glenda::cap::pagetable::{Perms, perms};
use glenda::cap::{CNode, CONSOLE_CAP, CapType, Frame, PageTable, TCB, VSPACE_CAP, rights};
use glenda::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use glenda::initrd::Initrd;
use glenda::mem::{ENTRY_VA, PGSIZE, STACK_SIZE, STACK_VA, UTCB_VA};

pub fn handle_spawn(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    name: &str,
    _flags: usize,
) -> usize {
    log!("SPAWN requested for '{}'", name);

    // Allocate Resources
    let cspace = CNode::from(rm.alloc_object(CapType::CNode, 12).expect("OOM CNode"));
    let vspace = PageTable::from(rm.alloc_object(CapType::PageTable, 0).expect("OOM VSpace"));
    let tcb = TCB::from(rm.alloc_object(CapType::TCB, 0).expect("OOM TCB"));
    let utcb_frame = Frame::from(rm.alloc_object(CapType::Frame, 0).expect("OOM UTCB Frame"));
    let stack_frame = Frame::from(rm.alloc_object(CapType::Frame, 0).expect("OOM Stack Frame"));
    let tf_frame = Frame::from(rm.alloc_object(CapType::Frame, 0).expect("OOM TF Frame"));
    let kstack_frame = Frame::from(rm.alloc_object(CapType::Frame, 0).expect("OOM KStack Frame"));

    // Setup CSpace
    // Mint CSpace to itself
    cspace.mint(cspace.cap(), 0, 0, rights::ALL);
    cspace.mint(vspace.cap(), 1, 0, rights::ALL);
    cspace.mint(tcb.cap(), 2, 0, rights::ALL);
    cspace.mint(utcb_frame.cap(), 3, 0, rights::ALL);

    // Copy Console (Slot 8)
    cspace.copy(CONSOLE_CAP.cap(), 8, rights::ALL);

    // Mint Endpoint (Slot 10)
    cspace.mint(FACTOTUM_ENDPOINT_CAP.cap(), 10, 0, rights::ALL);

    // Setup VSpace
    // Map Stack
    vspace.map(
        stack_frame,
        STACK_VA - STACK_SIZE,
        Perms::from(perms::READ | perms::WRITE | perms::USER),
    );
    // Map UTCB
    vspace.map(utcb_frame, UTCB_VA, Perms::from(perms::READ | perms::WRITE | perms::USER));

    // Configure TCB
    tcb.configure(cspace, vspace, utcb_frame, tf_frame, kstack_frame);

    let pid = pm.allocate_pid();

    // Badge the Endpoint for the process
    cspace.delete(10);
    cspace.mint(FACTOTUM_ENDPOINT_CAP.cap(), 10, pid, rights::ALL);

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
    let ret = load_image_to_process(pm, rm, pid, INITRD_CAP, entry.offset, entry.size, ENTRY_VA);
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
    let ret = load_image_to_process(pm, rm, pid, INITRD_CAP, entry.offset, entry.size, ENTRY_VA);
    if ret != 0 {
        log!("Failed to load image for {}", name);
        return usize::MAX;
    }

    // 5. Start
    handle_process_start_internal(pm, pid, ENTRY_VA, STACK_VA);

    log!("Service '{}' started (PID: {})", name, pid);
    pid
}
/// 解析 ELF 并将其段映射到目标地址空间
fn map_elf(rm: &mut ResourceManager, vspace: PageTable, elf_data: &[u8]) -> usize {
    let elf = ElfFile::new(elf_data).expect("Invalid ELF");

    for phdr in elf.program_headers() {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        log!(
            "Mapping ELF Segment: vaddr={:#x}, memsz={}, filesz={}, offset={:#x}",
            phdr.p_vaddr,
            phdr.p_memsz,
            phdr.p_filesz,
            phdr.p_offset
        );
        let vaddr = phdr.p_vaddr as usize;
        let mem_size = phdr.p_memsz as usize;
        let file_size = phdr.p_filesz as usize;
        let offset = phdr.p_offset as usize;

        let mut pms = perms::USER | perms::READ;
        if phdr.p_flags & PF_W != 0 {
            pms |= perms::WRITE;
        }
        if phdr.p_flags & PF_X != 0 {
            pms |= perms::EXECUTE;
        }

        let perms = Perms::from(pms);

        let start_page = vaddr & !(PGSIZE - 1);
        let end_page = (vaddr + mem_size + PGSIZE - 1) & !(PGSIZE - 1);

        for page_vaddr in (start_page..end_page).step_by(PGSIZE) {
            let frame = Frame::from(rm.alloc_object(CapType::Frame, 1).expect("OOM ELF Frame"));

            // 将页帧临时映射到 9ball 的 SCRATCH_VA 以便拷贝数据
            // 虽然使用了 SCRATCH_VA，但它仅作为 9ball 写入新页帧的窗口
            map_with_alloc(
                rm,
                VSPACE_CAP,
                frame,
                SCRATCH_VA,
                Perms::from(perms::READ | perms::WRITE | perms::USER),
            );
            // my_vspace.pagetable_debug_print();

            let dest_slice =
                unsafe { core::slice::from_raw_parts_mut(SCRATCH_VA as *mut u8, PGSIZE) };
            dest_slice.fill(0);

            // 直接从 elf_data (initrd 中的偏移) 拷贝到目标页帧
            let offset_in_segment = page_vaddr.saturating_sub(vaddr);
            if offset_in_segment < file_size {
                let copy_start = if page_vaddr < vaddr { vaddr - page_vaddr } else { 0 };
                let copy_len = core::cmp::min(PGSIZE - copy_start, file_size - offset_in_segment);
                let src_offset = offset + offset_in_segment + copy_start;

                dest_slice[copy_start..copy_start + copy_len]
                    .copy_from_slice(&elf_data[src_offset..src_offset + copy_len]);
            }

            // 解除 9ball 的临时映射并映射到目标进程
            VSPACE_CAP.unmap(SCRATCH_VA, 1);
            //my_vspace.pagetable_debug_print();
            map_with_alloc(rm, vspace, frame, page_vaddr, perms);
        }
    }
    elf.entry_point()
}
fn map_with_alloc(
    rm: &mut ResourceManager,
    vspace: PageTable,
    frame: Frame,
    va: usize,
    perms: Perms,
) {
    // 1. 尝试直接映射
    if vspace.map(frame, va, perms) == 0 {
        return;
    }

    // 2. 映射失败，说明缺少中间页表。
    // Sv39 布局：L2 (Root) -> L1 -> L0 -> Frame

    // ----------------------------------------------------------------
    // 步骤 A: 检查并映射 L1 Table (由 Root 表的 VPN[2] 指向)
    // ----------------------------------------------------------------
    // 分配一个页表对象
    let pt_l1 = PageTable::from(rm.alloc_object(CapType::PageTable, 1).expect("OOM PT L1"));

    // [修复] 使用 level=2，表示我们在 Root 表(L2)中安装这个新页表
    // 该页表将作为 L1 Table
    if vspace.map_table(pt_l1, va, 2) == 0 {
        // L1 Table 安装成功后，再次尝试直接映射 Frame
        if vspace.map(frame, va, perms) == 0 {
            return;
        }
    }
    // ----------------------------------------------------------------
    // 步骤 B: 检查并映射 L0 Table (由 L1 表的 VPN[1] 指向)
    // ----------------------------------------------------------------
    // 分配另一个页表对象
    let pt_l0 = PageTable::from(rm.alloc_object(CapType::PageTable, 1).expect("OOM PT L0"));

    // [修复] 使用 level=1，表示我们在 L1 表中安装这个新页表
    // 该页表将作为 L0 Table
    if vspace.map_table(pt_l0, va, 1) == 0 {
        // L0 Table 安装成功，再次尝试映射 Frame
        if vspace.map(frame, va, perms) == 0 {
            return;
        }
    } // 3. 如果还失败，说明真的无法映射
    panic!("Failed to map frame at {:#x}", va);
}

pub fn load_image_to_process(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    pid: usize,
    frame_cap: Frame,
    offset: usize,
    len: usize,
    load_addr: usize,
) -> usize {
    if let Some(proc) = pm.get_process_mut(pid) {
        let src_va = 0x6000_0000;

        // Map Read-Only
        VSPACE_CAP.map(frame_cap, src_va, Perms::from(perms::READ | perms::USER));

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
                let new_frame =
                    Frame::from(rm.alloc_object(CapType::Frame, 0).expect("OOM Load Image"));
                proc.vspace.map(
                    new_frame,
                    page_base,
                    Perms::from(perms::READ | perms::WRITE | perms::EXECUTE | perms::USER),
                ); // RWX
                proc.frames.insert(page_base, new_frame);
                new_frame
            };

            VSPACE_CAP.map(
                dest_frame,
                SCRATCH_VA,
                Perms::from(perms::READ | perms::WRITE | perms::USER),
            );

            let src_ptr = (src_va + offset + current_offset) as *const u8;
            let dest_ptr = (SCRATCH_VA + page_offset) as *mut u8;
            let copy_len = core::cmp::min(chunk_len, 4096 - page_offset);

            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, dest_ptr, copy_len);
            }

            VSPACE_CAP.unmap(SCRATCH_VA, PGSIZE);
            current_offset += copy_len;
        }

        VSPACE_CAP.unmap(src_va, PGSIZE);
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
        proc.tcb.set_registers(rights::ALL as usize, entry, stack);
        proc.tcb.set_priority(100);
        proc.tcb.resume();
        return 0;
    }
    usize::MAX
}
