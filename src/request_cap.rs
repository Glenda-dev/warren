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

    match cap_type {
        protocol::CAP_TYPE_IRQ => {
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
                0
            } else {
                log!("Process {} not found", pid);
                usize::MAX
            }
        }
        protocol::CAP_TYPE_ENDPOINT => {
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
                    0
                } else {
                    log!("OOM allocating endpoint");
                    usize::MAX
                }
            } else {
                log!("Process {} not found", pid);
                usize::MAX
            }
        }
        _ => {
            log!("Unknown capability type requested: {}", cap_type);
            usize::MAX
        }
    }
}
