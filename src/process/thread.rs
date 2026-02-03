#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TLS {
    /// ELF 文件中 TLS 初始数据模板（.tdata）的虚拟地址
    pub master_vaddr: usize,
    /// 文件中初始数据的字节大小 (p_filesz)
    pub file_size: usize,
    /// 内存中该段的总大小 (p_memsz) -> file_size + .tbss 大小
    pub mem_size: usize,
    /// 对齐要求 (p_align)
    pub align: usize,
}

impl TLS {
    pub fn new(master_vaddr: usize, file_size: usize, mem_size: usize, align: usize) -> Self {
        Self { master_vaddr, file_size, mem_size, align }
    }
}
