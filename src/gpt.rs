//! Shared structural GPT decoding and checksums.
use std::io;
use virtdisk::ReadAt;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
}
fn u64le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]))
}
fn guid(bytes: &[u8], offset: usize) -> [u8; 16] {
    let mut value = [0; 16];
    value.copy_from_slice(&bytes[offset..offset + 16]);
    value
}
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
        }
    }
    !value
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) disk_guid: [u8; 16],
    pub(crate) count: u32,
    pub(crate) entry_size: u32,
    pub(crate) table: Vec<u8>,
    pub(crate) raw: Vec<u8>,
    pub(crate) table_lba: u64,
}
pub(crate) fn read_header(
    source: &dyn ReadAt,
    size: u32,
    total: u64,
    current: u64,
    alternate: u64,
) -> io::Result<Header> {
    let mut block = vec![0; size as usize];
    source.read_exact_at(current * u64::from(size), &mut block)?;
    if &block[..8] != b"EFI PART" || u32le(&block, 8) != 0x0001_0000 || u32le(&block, 20) != 0 {
        return Err(invalid(
            "invalid GPT header signature, revision or reserved field",
        ));
    }
    let header_size = u32le(&block, 12) as usize;
    if !(92..=size as usize).contains(&header_size) {
        return Err(invalid("invalid GPT header size"));
    }
    let expected = u32le(&block, 16);
    let raw = block.clone();
    block[16..20].fill(0);
    if block[header_size..].iter().any(|byte| *byte != 0) {
        return Err(invalid("nonzero reserved GPT header block bytes"));
    }
    if crc32(&block[..header_size]) != expected {
        return Err(invalid("GPT header CRC mismatch"));
    }
    if u64le(&block, 24) != current || u64le(&block, 32) != alternate {
        return Err(invalid("GPT reciprocal header locations disagree"));
    }
    let first = u64le(&block, 40);
    let last = u64le(&block, 48);
    let disk_guid = guid(&block, 56);
    let table_lba = u64le(&block, 72);
    let count = u32le(&block, 80);
    let entry_size = u32le(&block, 84);
    // Bound attacker-controlled allocations before any table read.
    if count == 0
        || count > 131_072
        || entry_size < 128
        || !entry_size.is_power_of_two()
        || entry_size > 4096
    {
        return Err(invalid("unsupported GPT partition table dimensions"));
    }
    let bytes = u64::from(count) * u64::from(entry_size);
    if !(16_384..=16_777_216).contains(&bytes) {
        return Err(invalid("GPT table allocation outside supported bounds"));
    }
    let table_sectors = bytes.div_ceil(u64::from(size));
    let table_end = table_lba
        .checked_add(table_sectors)
        .ok_or_else(|| invalid("GPT table range overflow"))?;
    if first > last
        || first < 2
        || last >= total - 1
        || disk_guid == [0; 16]
        || (current == 1 && (table_lba < 2 || table_end > first))
        || (current != 1 && (table_lba <= last || table_end > current))
    {
        return Err(invalid(
            "GPT metadata intersects usable sectors or exceeds disk",
        ));
    }
    if let Some(budget) = source.budget() {
        budget.metadata(bytes)?;
    }
    let mut table = vec![0; bytes as usize];
    source.read_exact_at(table_lba * u64::from(size), &mut table)?;
    if crc32(&table) != u32le(&block, 88) {
        return Err(invalid("GPT partition array CRC mismatch"));
    }
    Ok(Header {
        first,
        last,
        disk_guid,
        count,
        entry_size,
        table,
        raw,
        table_lba,
    })
}
impl Header {
    pub(crate) fn same_contents(&self, other: &Self) -> bool {
        self.first == other.first
            && self.last == other.last
            && self.disk_guid == other.disk_guid
            && self.count == other.count
            && self.entry_size == other.entry_size
            && self.table == other.table
    }
}
