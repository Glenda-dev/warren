use crate::log;
use crate::manager::ResourceManager;
use crate::process::ProcessManager;
use glenda::cap::{CapPtr, CapType, rights};
use glenda::ipc::UTCB;
use glenda::protocol::factotum as protocol;

pub fn handle_request_cap(
    pm: &mut ProcessManager,
    rm: &mut ResourceManager,
    badge: usize,
    utcb: &UTCB,
) -> usize {
    let cap_type = utcb.mrs_regs[1];
    let id = utcb.mrs_regs[2];
    let dest_slot = utcb.mrs_regs[3];
    let target_pid = utcb.mrs_regs[4];

    let pid = if target_pid == 0 { badge } else { target_pid };

    log!(
        "REQUEST_CAP type={} id={} dest={} target={} from PID {}",
        cap_type,
        id,
        dest_slot,
        pid,
        badge
    );

    // Type 1: IRQ
    if cap_type == protocol::CAP_TYPE_IRQ {
        // ... (existing IRQ logic)
        if rm.irq_start == 0 {
            log!("No IRQ caps available");
            return usize::MAX;
        }

        if id >= (rm.irq_end - rm.irq_start) {
            log!("IRQ {} out of range", id);
            return usize::MAX;
        }

        let src_slot = rm.irq_start + id;

        if let Some(proc) = pm.get_process_mut(pid) {
            let requester_cnode = proc.cspace;
            let ret = requester_cnode.cnode_copy(CapPtr(src_slot), dest_slot, rights::ALL);
            if ret != 0 {
                log!("Failed to copy cap: {}", ret);
                return usize::MAX;
            }
            return 0;
        } else {
            log!("Process {} not found", pid);
            return usize::MAX;
        }
    }
    // Type 3: Initrd
    else if cap_type == protocol::CAP_TYPE_INITRD {
        if let Some(proc) = pm.get_process_mut(pid) {
            let requester_cnode = proc.cspace;
            let ret = requester_cnode.cnode_copy(CapPtr(4), dest_slot, rights::READ);
            if ret != 0 {
                log!("Failed to copy Initrd cap: {}", ret);
                return usize::MAX;
            }
            return 0;
        }
        return usize::MAX;
    }
    // Type 2: New Endpoint
    else if cap_type == protocol::CAP_TYPE_ENDPOINT {
        if let Some(proc) = pm.get_process_mut(pid) {
            // Allocate Endpoint
            let ep_cap = rm.alloc_object(CapType::Endpoint, 0);
            if let Some(ep) = ep_cap {
                // Copy to requester
                // rm.alloc_object puts it in Factotum's CSpace at `ep.0`.
                let requester_cnode = proc.cspace;
                let ret = requester_cnode.cnode_copy(ep, dest_slot, rights::ALL);
                if ret != 0 {
                    log!("Failed to copy new endpoint: {}", ret);
                    return usize::MAX;
                }
                return 0;
            } else {
                log!("OOM allocating endpoint");
                return usize::MAX;
            }
        }
    }
    // Type 4: MMIO
    else if cap_type == protocol::CAP_TYPE_MMIO {
        let paddr = utcb.mrs_regs[5];
        let size = utcb.mrs_regs[6];

        let bootinfo =
            unsafe { &*(glenda::bootinfo::BOOTINFO_VA as *const glenda::bootinfo::BootInfo) };

        // Find Untyped that covers paddr
        let mut untyped_index = None;
        for i in 0..bootinfo.untyped_count {
            let desc = &bootinfo.untyped_list[i];
            let region_start = desc.paddr;
            let region_size = 1 << desc.size_bits;
            if paddr >= region_start && (paddr + size) <= (region_start + region_size) {
                untyped_index = Some(i);
                break;
            }
        }

        if let Some(idx) = untyped_index {
            let untyped_cap = CapPtr(rm.untyped_start + idx);
            let offset = paddr - bootinfo.untyped_list[idx].paddr;

            if let Some(proc) = pm.get_process_mut(pid) {
                let requester_cnode = proc.cspace;

                // Retype to Frame in Factotum's CSpace first
                let temp_slot = rm.alloc_slot();
                let temp_cap = CapPtr(temp_slot);

                // FLAG_NO_CLEAR = 1 << 31
                // CAP_TYPE_FRAME = 4
                let ret = untyped_cap.untyped_retype_with_offset(
                    4 | (1 << 31), // Frame | NO_CLEAR
                    (size.next_power_of_two().ilog2()) as usize, // size_bits
                    1,
                    rm.cnode,
                    temp_slot,
                    offset,
                );

                if ret != 0 {
                    log!("Failed to retype MMIO: {}", ret);
                    return usize::MAX;
                }

                // Copy to requester
                let ret = requester_cnode.cnode_copy(temp_cap, dest_slot, rights::ALL);
                if ret != 0 {
                    log!("Failed to copy MMIO cap: {}", ret);
                    return usize::MAX;
                }
                return 0;
            }
        } else {
            log!("No untyped region covers MMIO {:#x} (size {:#x})", paddr, size);
        }
        return usize::MAX;
    }

    usize::MAX
}
