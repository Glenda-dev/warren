use core::fmt::Display;

/// Magic number to verify BootInfo validity: 'GLENDA_B'
pub const BOOTINFO_MAGIC: u32 = 0x99999999;

/// Fixed size of the BootInfo page (usually 4KB)
pub const BOOTINFO_SIZE: usize = 4096;

/// Maximum number of untyped memory regions we can describe
pub const MAX_UNTYPED_REGIONS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    /// Magic number for verification
    pub magic: u32,

    /// Platform Info Desc
    pub info_desc: MemoryRange,

    /// Number of valid entries in `untyped_list`
    pub untyped_count: usize,

    /// List of untyped memory regions available to the system
    /// The i-th entry here corresponds to the capability at `untyped.start + i`
    pub untyped_list: [UntypedRegion; MAX_UNTYPED_REGIONS],

    /// Number of valid entries in `untyped_list`
    pub mmio_count: usize,

    /// List of untyped memory regions available to the system
    /// The i-th entry here corresponds to the capability at `untyped.start + i`
    pub mmio_list: [MemoryRange; MAX_UNTYPED_REGIONS],

    /// Command line arguments passed to the kernel
    pub cmdline: [u8; 128],

    /// IRQ Handler count
    pub irq_count: usize,
}

impl Display for BootInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "BootInfo {{")?;
        writeln!(f, "    magic: {:#x},", self.magic)?;
        writeln!(
            f,
            "    info_desc: MemoryRange {{ paddr: {:#x}, size: {:#x} }},",
            self.info_desc.paddr, self.info_desc.size
        )?;

        writeln!(f, "    untyped_list: (count={}) [", self.untyped_count)?;
        for i in 0..self.untyped_count {
            if i >= MAX_UNTYPED_REGIONS {
                writeln!(f, "        ... (truncated)")?;
                break;
            }
            let region = &self.untyped_list[i];
            writeln!(
                f,
                "        {{ start: {:#x}, pages: {}, watermark: {} }},",
                region.start, region.pages, region.watermark
            )?;
        }
        writeln!(f, "    ],")?;

        writeln!(f, "    mmio_list: (count={}) [", self.mmio_count)?;
        for i in 0..self.mmio_count {
            if i >= MAX_UNTYPED_REGIONS {
                writeln!(f, "        ... (truncated)")?;
                break;
            }
            let region = &self.mmio_list[i];
            writeln!(f, "        {{ paddr: {:#x}, size: {:#x} }},", region.paddr, region.size)?;
        }
        writeln!(f, "    ],")?;

        let cmdline_str = core::str::from_utf8(&self.cmdline)
            .unwrap_or("Invalid UTF-8")
            .trim_matches(char::from(0));
        writeln!(f, "    cmdline: \"{}\",", cmdline_str)?;

        writeln!(f, "    irq_count: {},", self.irq_count)?;
        write!(f, "}}")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRange {
    /// Physical address of the memory region
    pub paddr: usize,

    /// Size of the region (2^size_bits bytes)
    pub size: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UntypedRegion {
    pub start: usize,
    pub pages: usize,
    pub watermark: usize,
}
