use core::mem::size_of;

pub const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub struct ElfFile<'a> {
    data: &'a [u8],
    header: Elf64Ehdr,
}

impl<'a> ElfFile<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < size_of::<Elf64Ehdr>() {
            return Err("Buffer too small for ELF header");
        }
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Ehdr) };
        if header.e_ident[0..4] != ELF_MAGIC {
            return Err("Invalid ELF magic");
        }
        Ok(Self { data, header })
    }

    pub fn entry_point(&self) -> usize {
        self.header.e_entry as usize
    }

    pub fn program_headers(&self) -> ProgramHeaders<'a> {
        ProgramHeaders {
            data: self.data,
            ph_off: self.header.e_phoff as usize,
            ph_num: self.header.e_phnum as usize,
            ph_size: self.header.e_phentsize as usize,
            current: 0,
        }
    }
}

pub struct ProgramHeaders<'a> {
    data: &'a [u8],
    ph_off: usize,
    ph_num: usize,
    ph_size: usize,
    current: usize,
}

impl<'a> Iterator for ProgramHeaders<'a> {
    type Item = Elf64Phdr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.ph_num {
            return None;
        }

        let off = self.ph_off + self.current * self.ph_size;
        if off + size_of::<Elf64Phdr>() > self.data.len() {
            return None;
        }

        let ph = unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(off) as *const Elf64Phdr) };
        self.current += 1;
        Some(ph)
    }
}
