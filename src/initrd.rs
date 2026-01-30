use alloc::string::String;
use alloc::vec::Vec;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    RootTask = 0,
    Driver = 1,
    Server = 2,
    Test = 3,
    File = 4,
    Unknown = 255,
}

impl From<u8> for PayloadType {
    fn from(val: u8) -> Self {
        match val {
            0 => PayloadType::RootTask,
            1 => PayloadType::Driver,
            2 => PayloadType::Server,
            3 => PayloadType::Test,
            4 => PayloadType::File,
            _ => PayloadType::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub type_: PayloadType,
    pub offset: usize,
    pub size: usize,
    pub name: String,
}

pub struct Initrd<'a> {
    pub data: &'a [u8],
    pub entries: Vec<Entry>,
}

impl<'a> Initrd<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("Initrd too small");
        }

        // Parse Header
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != 0x99999999 {
            return Err("Invalid magic number");
        }

        let count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        // let total_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

        let entry_base = 16;
        let entry_size = 48;

        if data.len() < entry_base + count * entry_size {
            return Err("Initrd truncated (entries)");
        }

        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let offset = entry_base + i * entry_size;
            let type_byte = data[offset];
            let file_offset = u32::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ]) as usize;
            let file_size = u32::from_le_bytes([
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
            ]) as usize;

            // Safety check: ensure file data is within bounds
            if file_offset + file_size > data.len() {
                return Err("Initrd entry points to out-of-bounds data");
            }

            // Name parsing
            let name_bytes = &data[offset + 9..offset + 41];
            let name_len = name_bytes.iter().position(|&c| c == 0).unwrap_or(32);
            let name = core::str::from_utf8(&name_bytes[..name_len])
                .map_err(|_| "Invalid UTF-8 in name")?
                .into();

            entries.push(Entry {
                type_: PayloadType::from(type_byte),
                offset: file_offset,
                size: file_size,
                name,
            });
        }

        Ok(Self { data, entries })
    }

    pub fn get_file(&self, name: &str) -> Option<&'a [u8]> {
        for entry in &self.entries {
            if entry.name == name {
                if self.data.len() < entry.offset + entry.size {
                    return None; // Truncated data
                }
                return Some(&self.data[entry.offset..entry.offset + entry.size]);
            }
        }
        None
    }
}
