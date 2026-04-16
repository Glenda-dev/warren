mod data;
mod fault;
mod memory;
mod process;
mod resource;
mod server;
mod thread;

use crate::elf::ElfFile;
use crate::elf::{PF_W, PF_X, PT_LOAD, PT_TLS};
use crate::layout::*;
use crate::policy::MemoryPolicy;
use crate::warren::resource::ResourceRegistry;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{CNode, CapPtr, Endpoint, Page, Kernel, Reply};
use glenda::cap::{CONSOLE_SLOT, CSPACE_CAP};
use glenda::error::Error;
use glenda::interface::{CSpaceService, VSpaceService};
use glenda::ipc::{Badge, IpcRouter};
use glenda::mem::Perms;
use glenda::mem::{
    ENTRY_VA, HEAP_SIZE, HEAP_VA, STACK_BASE, TRAMPOLINE_VA, get_trapframe_va, get_utcb_va,
};
use glenda::utils::align::{align_down, align_up};
use glenda::utils::initrd::Initrd;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};

pub use data::*;
pub use thread::TLS;

const SERVICE_PRIORITY: u8 = 252;
const L1_HUGE_PAGES: usize = 1 << (SHIFTS[1] - SHIFTS[0]);
const L1_HUGE_SIZE: usize = L1_HUGE_PAGES * PGSIZE;

pub struct SystemContext<'a> {
    pub vspace_mgr: &'a mut VSpaceManager,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub allocator: &'a mut dyn MemoryPolicy<'a>,
    pub root_cnode: CNode,
}

pub struct WarrenState {
    pub processes: BTreeMap<usize, Process>,
    pub pid: usize,
    pub wait_queues: BTreeMap<(usize, usize), VecDeque<CapPtr>>,
    pub res: ResourceRegistry,
}

pub struct WarrenIpc {
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
    pub running: bool,
}

pub struct WarrenManager<'a> {
    state: WarrenState,
    ipc: WarrenIpc,

    // Initrd
    initrd: Initrd<'a>,

    // Context
    ctx: SystemContext<'a>,
    router: IpcRouter<WarrenManager<'a>>,
}

impl<'a> WarrenManager<'a> {
    pub fn new(
        vspace_mgr: &'a mut VSpaceManager,
        cspace_mgr: &'a mut CSpaceManager,
        allocator: &'a mut dyn MemoryPolicy<'a>,
        root_cnode: CNode,
        initrd: Initrd<'a>,
    ) -> Self {
        // Init self vspace with known regions (to populate shadow tables)
        // 1. Text/Data - Low mem 0x10000+
        vspace_mgr.mark_existing(ENTRY_VA, PGSIZE);
        // 2. Stack - High mem
        // STACK_BASE is the top address (TRAMPOLINE_VA)
        // Stack grows down, range: [STACK_BASE - STACK_SIZE, STACK_BASE)
        vspace_mgr.mark_existing(STACK_BASE - STACK_SIZE, STACK_SIZE);
        // 3. Heap
        vspace_mgr.mark_existing(HEAP_VA, HEAP_SIZE);
        // 4. UTCB
        vspace_mgr.mark_existing(get_utcb_va(0), PGSIZE);
        // 5. TrapFrame
        vspace_mgr.mark_existing(get_trapframe_va(0), PGSIZE);
        // 6. Trampoline
        vspace_mgr.mark_existing(TRAMPOLINE_VA, PGSIZE);

        Self {
            state: WarrenState {
                processes: BTreeMap::new(),
                pid: 0,
                wait_queues: BTreeMap::new(),
                res: ResourceRegistry {
                    kernel_cap: Kernel::from(KERNEL_SLOT),
                    irq_cap: IRQ_CONTROL_SLOT,
                    console_cap: CONSOLE_SLOT,
                    untyped_cap: UNTYPED_SLOT,
                    bootinfo_cap: BOOTINFO_SLOT,
                    endpoints: BTreeMap::new(),
                },
            },
            ipc: WarrenIpc {
                endpoint: Endpoint::from(CapPtr::null()),
                reply: Reply::from(CapPtr::null()),
                recv: CapPtr::null(),
                running: false,
            },
            initrd,
            ctx: SystemContext { vspace_mgr, cspace_mgr, allocator, root_cnode },
            router: IpcRouter::new(),
        }
    }
    fn alloc_pid(&mut self) -> Result<usize, Error> {
        let next = self.state.pid.checked_add(1).ok_or(Error::OutOfMemory)?;
        self.state.pid = next;
        Ok(self.state.pid)
    }
    fn load_elf(&mut self, pid: usize, elf_data: &[u8]) -> Result<(usize, usize), Error> {
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidArgs)?;
        if elf.entry_point() == 0 {
            error!("ELF entry point is 0, aborting load");
            return Err(Error::InvalidArgs);
        }
        let mut max_vaddr = 0;
        let process = self.state.processes.get_mut(&pid).ok_or(Error::NotFound)?;
        let mut _tls = None;
        for phdr in elf.program_headers() {
            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;
            let align = phdr.p_align as usize;

            if vaddr + mem_size > max_vaddr {
                max_vaddr = vaddr + mem_size;
            }
            let mut perms = Perms::READ;
            if phdr.p_flags & PF_W != 0 {
                perms |= Perms::WRITE;
            }
            if phdr.p_flags & PF_X != 0 {
                perms |= Perms::EXECUTE;
            }

            match phdr.p_type {
                PT_LOAD => {
                    let start_page = align_down(vaddr, PGSIZE);
                    let end_page = align_up(vaddr + mem_size, PGSIZE);
                    let mut chunk_start = start_page;
                    while chunk_start < end_page {
                        let remaining_pages = (end_page - chunk_start) / PGSIZE;
                        let chunk_pages = if chunk_start % L1_HUGE_SIZE == 0
                            && remaining_pages >= L1_HUGE_PAGES
                        {
                            (remaining_pages / L1_HUGE_PAGES) * L1_HUGE_PAGES
                        } else {
                            let next_huge = align_up(chunk_start + 1, L1_HUGE_SIZE);
                            let pages_to_next_huge = if next_huge > chunk_start {
                                (next_huge - chunk_start) / PGSIZE
                            } else {
                                remaining_pages
                            };
                            core::cmp::min(remaining_pages, core::cmp::max(pages_to_next_huge, 1))
                        };

                        let global_allocator = &mut *self.ctx.allocator;
                        let cspace_mgr = &mut *self.ctx.cspace_mgr;

                        let (_, frame_cap) =
                            process.arena_allocator.alloc(chunk_pages, global_allocator)?;
                        let frame = Page::from(frame_cap);

                        process.vspace_mgr.map_page(
                            frame,
                            chunk_start,
                            perms,
                            chunk_pages,
                            global_allocator,
                            cspace_mgr,
                        )?;

                        let scratch_vaddr = self.ctx.vspace_mgr.map_scratch(
                            frame,
                            Perms::READ | Perms::WRITE,
                            chunk_pages,
                            global_allocator,
                            cspace_mgr,
                        )?;

                        let chunk_bytes = chunk_pages * PGSIZE;
                        let dest_slice = unsafe {
                            core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, chunk_bytes)
                        };
                        dest_slice.fill(0);

                        let chunk_end = chunk_start + chunk_bytes;
                        let file_region_start = vaddr;
                        let file_region_end = vaddr.saturating_add(file_size);
                        let copy_start = core::cmp::max(chunk_start, file_region_start);
                        let copy_end = core::cmp::min(chunk_end, file_region_end);

                        if copy_end > copy_start {
                            let src_off = offset + (copy_start - file_region_start);
                            let dst_off = copy_start - chunk_start;
                            let copy_len = copy_end - copy_start;
                            if src_off < elf_data.len() {
                                let actual = core::cmp::min(copy_len, elf_data.len() - src_off);
                                dest_slice[dst_off..dst_off + actual]
                                    .copy_from_slice(&elf_data[src_off..src_off + actual]);
                            }
                        }

                        self.ctx.vspace_mgr.unmap(scratch_vaddr, chunk_pages)?;
                        process.image_slots.insert(frame_cap);
                        chunk_start += chunk_bytes;
                    }
                }
                PT_TLS => {
                    _tls = Some(TLS {
                        master_vaddr: vaddr,
                        mem_size: mem_size,
                        align: align,
                        file_size: file_size,
                    });
                }
                _ => {}
            }
        }
        let ep = elf.entry_point();
        let heap = align_up(max_vaddr, PGSIZE);
        log!("Image loaded with entry_point: {:#x}, heap: {:#x}", ep, heap);
        Ok((ep, heap))
    }

    fn exit_wrapper(&mut self, pid: Badge, code: usize) -> Result<(), Error> {
        CSPACE_CAP.delete(self.ipc.reply.cap())?;
        if let Some(mut p) = self.state.processes.remove(&pid.bits()) {
            for (tid, thread) in p.threads.iter() {
                if let Err(e) = thread.tcb.suspend() {
                    warn!("Failed to suspend thread {} of pid {:?}: {:?}", tid, pid, e);
                }
            }
            p.exit_code = code;
            p.state = ProcessState::Dead;

            let sort_cleanup_slots = |slots: Vec<CapPtr>| {
                let mut ordered = slots;
                ordered.sort_by(|a, b| {
                    // Revoke children before parents: deeper cptr first.
                    b.len().cmp(&a.len()).then_with(|| b.bits().cmp(&a.bits()))
                });
                ordered
            };

            // Cleanup VSpace shadow resources first.
            let allocator = &mut *self.ctx.allocator;
            let cspace_mgr = &mut *self.ctx.cspace_mgr;
            p.vspace_mgr.drop(allocator, cspace_mgr);

            // Return process arena roots to global allocator (buddy merge path).
            let released_arena_slots = p.arena_allocator.release_to(allocator);

            for slot in released_arena_slots {
                p.allocated_slots.remove(&slot);
            }

            // Cleanup residual non-arena root slots (bootstrap/meta slots).
            let process_slots: Vec<CapPtr> =
                sort_cleanup_slots(p.allocated_slots.iter().copied().collect());
            for slot in process_slots {
                if p.arena_allocator.cspace_mgr.owns_slot(slot) {
                    continue;
                }

                if let Err(e) = self.ctx.root_cnode.revoke(slot)
                    && e != Error::InvalidSlot
                    && e != Error::InvalidCapability
                {
                    warn!("Failed to revoke process slot {:?}: {:?}", slot, e);
                }
                let deleted = match self.ctx.root_cnode.delete(slot) {
                    Ok(()) => true,
                    Err(e) => {
                        if e != Error::InvalidSlot && e != Error::InvalidCapability {
                            warn!("Failed to delete process slot {:?}: {:?}", slot, e);
                        }
                        false
                    }
                };
                if deleted && cspace_mgr.owns_slot(slot) {
                    cspace_mgr.free(slot);
                }
            }
            log!("Process exited: pid: {}, code={}", pid, code);
        } else {
            error!("Failed to find process with pid: {:?}", pid);
            return Err(Error::NotFound);
        }
        Ok(())
    }
    pub fn refill_allocator(&mut self) {
        let rev = self.ctx.allocator.reserve_count();
        if rev < LOW_RESERVE {
            warn!("Allocator reserve low: {}. Refilling...", rev);
            for _ in 0..(FULL_RESERVE - self.ctx.allocator.reserve_count()) {
                if let Ok(slot) = self.ctx.cspace_mgr.alloc(self.ctx.allocator) {
                    self.ctx.allocator.add_free_slot(slot);
                } else {
                    break;
                }
            }
        }
    }
}
