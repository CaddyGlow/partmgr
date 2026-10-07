//! Strict read-only GPT/MBR validation before exposing partition views.
//!
//! GPT requires both copies to agree; this parser never repairs a damaged disk.
//! Sector size is supplied by the caller because raw images do not encode it.
//! Layout follows UEFI 2.10 section 5.

use std::{collections::HashSet, io, sync::Arc};
use virtdisk::{DiskView, ReadAt};

/// On-disk partition table scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// GUID partition table with both copies verified.
    Gpt,
    /// Four-entry legacy master boot record.
    Mbr,
}

/// A validated occupied partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// One-based original table slot, including gaps.
    pub index: u32,
    /// Starting logical sector.
    pub first_lba: u64,
    /// Number of logical sectors.
    pub sectors: u64,
    /// GPT type GUID in on-disk mixed-endian representation, or None for MBR.
    pub type_guid: Option<[u8; 16]>,
    /// GPT unique GUID in on-disk representation.
    pub unique_guid: Option<[u8; 16]>,
    /// Legacy MBR type byte, or None for GPT.
    pub mbr_type: Option<u8>,
    /// GPT attributes, or zero for MBR.
    pub attributes: u64,
    /// GPT name as exact UTF-16 units, without trailing nulls.
    pub name: Vec<u16>,
}

/// Validated layout retaining the immutable disk reader for bounded views.
pub struct PartitionTable {
    source: Arc<dyn ReadAt>,
    sector_size: u32,
    scheme: Scheme,
    partitions: Vec<Partition>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
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
fn crc32(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
        }
    }
    !value
}

impl PartitionTable {
    /// Validate a 512-byte or 4096-byte sector disk and both GPT copies if present.
    /// Extended MBR partitions and Windows dynamic disks are unsupported.
    pub fn read(source: Arc<dyn ReadAt>, sector_size: u32) -> io::Result<Self> {
        let context = source.context();
        Self::read_inner(source, sector_size)
            .map_err(|e| context.error("validate partition table", e))
    }
    fn read_inner(source: Arc<dyn ReadAt>, sector_size: u32) -> io::Result<Self> {
        if !matches!(sector_size, 512 | 4096)
            || !source.len().is_multiple_of(u64::from(sector_size))
        {
            return Err(invalid("unsupported sector size or unaligned disk length"));
        }
        let total = source.len() / u64::from(sector_size);
        if total < 2 {
            return Err(invalid("disk is too small for a partition table"));
        }
        let mut mbr = [0; 512];
        source.read_exact_at(0, &mut mbr)?;
        if mbr[510..512] != [0x55, 0xaa] {
            return Err(invalid("missing MBR signature"));
        }
        let entries = &mbr[446..510];
        let protective = entries.chunks_exact(16).any(|entry| entry[4] == 0xee);
        let (scheme, partitions) = if protective {
            let used: Vec<_> = entries
                .chunks_exact(16)
                .filter(|entry| entry[4] != 0)
                .collect();
            if used.len() != 1
                || used[0][4] != 0xee
                || used[0][0] != 0
                || u32le(used[0], 8) != 1
                // Windows writes a saturated protective count even on smaller disks.
                // GPT usable bounds and both copies remain independently validated.
                || (u32le(used[0], 12) != u32::MAX
                    && u64::from(u32le(used[0], 12)) != (total - 1).min(u64::from(u32::MAX)))
            {
                return Err(invalid("invalid or hybrid protective MBR"));
            }
            for entry in entries.chunks_exact(16).filter(|entry| entry[4] == 0) {
                if entry.iter().any(|byte| *byte != 0) {
                    return Err(invalid("nonzero unused protective MBR entry"));
                }
            }
            (Scheme::Gpt, read_gpt(source.as_ref(), sector_size, total)?)
        } else {
            let mut partitions = Vec::new();
            for (slot, entry) in entries.chunks_exact(16).enumerate() {
                if entry[4] == 0 {
                    if entry.iter().any(|byte| *byte != 0) {
                        return Err(invalid("nonzero unused MBR entry"));
                    }
                    continue;
                }
                if !matches!(entry[0], 0 | 0x80) {
                    return Err(invalid("invalid MBR boot indicator"));
                }
                if matches!(entry[4], 0x05 | 0x0f | 0x85 | 0x42) {
                    return Err(unsupported(
                        "extended or dynamic MBR partitions are unsupported",
                    ));
                }
                let first = u64::from(u32le(entry, 8));
                let sectors = u64::from(u32le(entry, 12));
                if first == 0
                    || sectors == 0
                    || first.checked_add(sectors).is_none_or(|end| end > total)
                {
                    return Err(invalid("MBR partition exceeds disk bounds"));
                }
                partitions.push(Partition {
                    index: slot as u32 + 1,
                    first_lba: first,
                    sectors,
                    type_guid: None,
                    unique_guid: None,
                    mbr_type: Some(entry[4]),
                    attributes: 0,
                    name: Vec::new(),
                });
            }
            (Scheme::Mbr, partitions)
        };
        let mut ranges: Vec<_> = partitions
            .iter()
            .map(|p| (p.first_lba, p.first_lba + p.sectors))
            .collect();
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(invalid("overlapping partitions"));
        }
        Ok(Self {
            source,
            sector_size,
            scheme,
            partitions,
        })
    }
    /// The validated table scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
    /// All occupied entries in original table order.
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
    /// Create a bounded view using a one-based original table index.
    pub fn select(&self, index: u32) -> io::Result<DiskView> {
        let partition = self
            .partitions
            .iter()
            .find(|p| p.index == index)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "partition index not present")
            })?;
        DiskView::new(
            self.source.clone(),
            partition.first_lba * u64::from(self.sector_size),
            partition.sectors * u64::from(self.sector_size),
        )
        .map(|view| view.with_partition(index))
    }
}

#[derive(PartialEq, Eq)]
struct Header {
    first: u64,
    last: u64,
    disk_guid: [u8; 16],
    count: u32,
    entry_size: u32,
    table: Vec<u8>,
}
fn read_header(
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
    })
}
fn read_gpt(source: &dyn ReadAt, size: u32, total: u64) -> io::Result<Vec<Partition>> {
    let primary = read_header(source, size, total, 1, total - 1)?;
    let backup = read_header(source, size, total, total - 1, 1)?;
    if primary != backup {
        return Err(invalid("primary and backup GPT disagree"));
    }
    let mut partitions = Vec::new();
    let mut ids = HashSet::new();
    for (slot, entry) in primary
        .table
        .chunks_exact(primary.entry_size as usize)
        .enumerate()
    {
        let type_guid = guid(entry, 0);
        if type_guid == [0; 16] {
            continue;
        }
        let unique_guid = guid(entry, 16);
        if unique_guid == [0; 16] || !ids.insert(unique_guid) {
            return Err(invalid("missing or duplicate GPT unique partition GUID"));
        }
        // Windows LDM metadata/data are not single self-contained volumes.
        if matches!(
            type_guid,
            [
                0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34,
                0xcf, 0xb3
            ] | [
                0xa0, 0x60, 0x9b, 0xaf, 0x31, 0x14, 0x62, 0x4f, 0xbc, 0x68, 0x33, 0x11, 0x71, 0x4a,
                0x69, 0xad
            ]
        ) {
            return Err(unsupported(
                "Windows dynamic GPT partitions are unsupported",
            ));
        }
        let first = u64le(entry, 32);
        let last = u64le(entry, 40);
        if first < primary.first || last > primary.last || first > last {
            return Err(invalid("GPT partition outside usable sectors"));
        }
        let name: Vec<_> = entry[56..128]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .take_while(|c| *c != 0)
            .collect();
        partitions.push(Partition {
            index: slot as u32 + 1,
            first_lba: first,
            sectors: last - first + 1,
            type_guid: Some(type_guid),
            unique_guid: Some(unique_guid),
            mbr_type: None,
            attributes: u64le(entry, 48),
            name,
        });
    }
    Ok(partitions)
}
