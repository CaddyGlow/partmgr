//! Owned lossless partition metadata, independent of storage ownership.
//!
//! Strict inspection accepts 512/4096-byte logical sectors, GPT arrays between
//! 16 KiB and 16 MiB per copy, at most 131072 slots, and power-of-two entry sizes
//! from 128 through 4096 bytes. Both GPT copies must agree. Raw inspection retains
//! unknown header extensions, reserved attributes, and extended entry bytes for
//! forensic access; these are refused by strict validation and mutation.
//! GPT rules follow the [UEFI disk-layout specification](https://uefi.org/specs/UEFI/2.11/05_GUID_Partition_Table_Format.html).
use crate::gpt::{Header, crc32, read_header};
use std::{collections::HashSet, io};
use virtdisk::ReadAt;
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

fn read_gpt(
    source: &dyn ReadAt,
    size: u32,
    total: u64,
    mbr: Vec<u8>,
    allow_opaque: bool,
) -> io::Result<GptLayout> {
    let primary = read_header(source, size, total, 1, total - 1)?;
    let backup = read_header(source, size, total, total - 1, 1)?;
    if !allow_opaque && (u32le(&primary.raw, 12) != 92 || u32le(&backup.raw, 12) != 92) {
        return Err(unsupported("unknown GPT header extension"));
    }
    if primary.first != backup.first
        || primary.last != backup.last
        || primary.disk_guid != backup.disk_guid
        || primary.count != backup.count
        || primary.entry_size != backup.entry_size
        || primary.table != backup.table
    {
        return Err(invalid("primary and backup GPT disagree"));
    }
    let mut partitions = Vec::new();
    let mut ids = HashSet::new();
    for (slot, entry) in primary
        .table
        .chunks_exact(primary.entry_size as usize)
        .enumerate()
    {
        if !allow_opaque && entry[128..].iter().any(|b| *b != 0) {
            return Err(unsupported("nonzero reserved GPT entry extension"));
        }
        let type_guid = guid(entry, 0);
        if type_guid == [0; 16] {
            partitions.push(Entry {
                slot: slot as u32 + 1,
                raw: entry.to_vec(),
                range: None,
            });
            continue;
        }
        if !allow_opaque && u64le(entry, 48) & 0x0000_ffff_ffff_fff8 != 0 {
            return Err(unsupported("reserved GPT attribute bits"));
        }
        let unique_guid = guid(entry, 16);
        if unique_guid == [0; 16] || !ids.insert(unique_guid) {
            return Err(invalid("missing or duplicate GPT unique partition GUID"));
        }
        let first = u64le(entry, 32);
        let last = u64le(entry, 40);
        if first < primary.first || last > primary.last || first > last {
            return Err(invalid("GPT partition outside usable sectors"));
        }
        partitions.push(Entry {
            slot: slot as u32 + 1,
            raw: entry.to_vec(),
            range: Some(LbaRange::from_inclusive(first, last)?),
        });
    }
    check_overlap(partitions.iter().filter_map(|p| p.range))?;
    Ok(GptLayout {
        geometry: Geometry::new(source.len(), size)?,
        mbr,
        primary,
        backup,
        entries: partitions,
    })
}
/// Checked logical disk geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    bytes: u64,
    sector: u32,
}
impl Geometry {
    /// Construct aligned geometry with a supported logical sector size.
    pub fn new(bytes: u64, sector: u32) -> io::Result<Self> {
        if !matches!(sector, 512 | 4096)
            || !bytes.is_multiple_of(u64::from(sector))
            || bytes / u64::from(sector) < 2
        {
            return Err(invalid("invalid geometry"));
        }
        Ok(Self { bytes, sector })
    }
    /// Logical sector size in bytes.
    pub fn sector_size(self) -> u32 {
        self.sector
    }
    /// Number of logical sectors.
    pub fn sectors(self) -> u64 {
        self.bytes / u64::from(self.sector)
    }
    /// Disk length in bytes.
    pub fn bytes(self) -> u64 {
        self.bytes
    }
}
/// Nonempty half-open logical-sector range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbaRange {
    start: u64,
    end: u64,
}
impl LbaRange {
    /// Construct a nonempty exclusive-end range.
    pub fn new(start: u64, end: u64) -> io::Result<Self> {
        if start >= end {
            return Err(invalid("empty or reversed range"));
        }
        Ok(Self { start, end })
    }
    /// Convert an inclusive on-disk range without overflow.
    pub fn from_inclusive(first: u64, last: u64) -> io::Result<Self> {
        Self::new(
            first,
            last.checked_add(1)
                .ok_or_else(|| invalid("range overflow"))?,
        )
    }
    /// First logical sector.
    pub fn start(self) -> u64 {
        self.start
    }
    /// Exclusive final logical sector.
    pub fn end(self) -> u64 {
        self.end
    }
    /// Sector count.
    pub fn sectors(self) -> u64 {
        self.end - self.start
    }
}
fn check_overlap(ranges: impl Iterator<Item = LbaRange>) -> io::Result<()> {
    let mut ranges: Vec<_> = ranges.collect();
    ranges.sort_by_key(|r| r.start);
    if ranges.windows(2).any(|p| p[0].end > p[1].start) {
        return Err(invalid("overlapping partitions"));
    }
    Ok(())
}
/// Exact GPT slot bytes, including unused and extended entries.
#[derive(Clone, Debug)]
pub struct Entry {
    slot: u32,
    raw: Vec<u8>,
    range: Option<LbaRange>,
}
impl Entry {
    /// One-based on-disk slot.
    pub fn slot(&self) -> u32 {
        self.slot
    }
    /// Complete entry bytes, preserving opaque extensions.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Occupied range, or none for an unused slot.
    pub fn range(&self) -> Option<LbaRange> {
        self.range
    }
    /// All 36 name units, including terminators and invalid UTF-16.
    pub fn raw_name(&self) -> [u16; 36] {
        std::array::from_fn(|i| u16::from_le_bytes([self.raw[56 + i * 2], self.raw[57 + i * 2]]))
    }
    /// Whether this entry can be exposed as a standalone volume.
    pub fn standalone_volume(&self) -> bool {
        let t = guid(&self.raw, 0);
        self.range.is_some()
            && t != [
                0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34,
                0xcf, 0xb3,
            ]
            && t != [
                0xa0, 0x60, 0x9b, 0xaf, 0x31, 0x14, 0x62, 0x4f, 0xbc, 0x68, 0x33, 0x11, 0x71, 0x4a,
                0x69, 0xad,
            ]
    }
}
/// Validated GPT retaining both complete header sectors and arrays.
#[derive(Clone)]
pub struct GptLayout {
    geometry: Geometry,
    mbr: Vec<u8>,
    primary: Header,
    backup: Header,
    entries: Vec<Entry>,
}
impl GptLayout {
    /// Original logical geometry.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// GPT disk identity in mixed-endian disk encoding.
    pub fn disk_guid(&self) -> [u8; 16] {
        self.primary.disk_guid
    }
    /// Usable range.
    pub fn usable(&self) -> LbaRange {
        LbaRange {
            start: self.primary.first,
            end: self.primary.last + 1,
        }
    }
    /// Exact protective MBR logical sector.
    pub fn mbr_sector(&self) -> &[u8] {
        &self.mbr
    }
    /// Exact primary header logical sector.
    pub fn primary_header(&self) -> &[u8] {
        &self.primary.raw
    }
    /// Exact backup header logical sector.
    pub fn backup_header(&self) -> &[u8] {
        &self.backup.raw
    }
    /// Exact partition array.
    pub fn array(&self) -> &[u8] {
        &self.primary.table
    }
    /// Primary array LBA.
    pub fn primary_array_lba(&self) -> u64 {
        self.primary.table_lba
    }
    /// Backup array LBA.
    pub fn backup_array_lba(&self) -> u64 {
        self.backup.table_lba
    }
    /// Slot dimensions in bytes.
    pub fn entry_size(&self) -> u32 {
        self.primary.entry_size
    }
    /// Every original slot, including unused entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Whether understood header semantics allow safe mutation.
    pub fn mutation_supported(&self) -> bool {
        u32le(&self.primary.raw, 12) == 92
            && u32le(&self.backup.raw, 12) == 92
            && self.entries.iter().all(|e| {
                e.raw[128..].iter().all(|b| *b == 0)
                    && (e.range.is_none() || u64le(&e.raw, 48) & 0x0000_ffff_ffff_fff8 == 0)
            })
    }
}
/// Validated basic MBR retaining its full logical sector.
#[derive(Clone)]
pub struct MbrLayout {
    geometry: Geometry,
    raw: Vec<u8>,
    entries: Vec<MbrEntry>,
}
/// Validated occupied basic MBR entry.
#[derive(Clone, Debug)]
pub struct MbrEntry {
    slot: u32,
    raw: [u8; 16],
    range: LbaRange,
}
impl MbrEntry {
    /// Original one-based slot.
    pub fn slot(&self) -> u32 {
        self.slot
    }
    /// Exact bytes including CHS and boot flag.
    pub fn raw(&self) -> &[u8; 16] {
        &self.raw
    }
    /// Occupied range.
    pub fn range(&self) -> LbaRange {
        self.range
    }
    /// Dynamic disk entries require a separate volume manager.
    pub fn standalone_volume(&self) -> bool {
        self.raw[4] != 0x42
    }
}
impl MbrLayout {
    /// Logical geometry.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Exact MBR logical sector including boot code and sector remainder.
    pub fn sector(&self) -> &[u8] {
        &self.raw
    }
    /// Occupied entries in slot order.
    pub fn entries(&self) -> &[MbrEntry] {
        &self.entries
    }
    /// Disk signature.
    pub fn disk_signature(&self) -> u32 {
        u32le(&self.raw, 440)
    }
}
/// Owned validated table independent of any reader lifetime.
#[derive(Clone)]
pub enum DiskLayout {
    /// GUID partition table.
    Gpt(GptLayout),
    /// Basic master boot record.
    Mbr(MbrLayout),
}
impl DiskLayout {
    /// Strictly inspect borrowed storage. GPT allocations are limited to 16 MiB
    /// per copy, 131072 slots, and 4096 bytes per entry.
    pub fn inspect(source: &dyn ReadAt, sector: u32) -> io::Result<Self> {
        Self::inspect_inner(source, sector, false)
    }
    /// Inspect structurally valid metadata while retaining unsupported opaque
    /// entry extensions. Such layouts refuse all edits until separately decoded.
    pub fn inspect_raw(source: &dyn ReadAt, sector: u32) -> io::Result<Self> {
        Self::inspect_inner(source, sector, true)
    }
    fn inspect_inner(source: &dyn ReadAt, sector: u32, allow_opaque: bool) -> io::Result<Self> {
        let geometry = Geometry::new(source.len(), sector)?;
        let mut raw = vec![0; sector as usize];
        source.read_exact_at(0, &mut raw)?;
        if raw[510..512] != [0x55, 0xaa] {
            return Err(invalid("missing MBR signature"));
        }
        let slots = &raw[446..510];
        if slots.chunks_exact(16).any(|e| e[4] == 0xee) {
            let used: Vec<_> = slots.chunks_exact(16).filter(|e| e[4] != 0).collect();
            if used.len() != 1
                || used[0][0] != 0
                || u32le(used[0], 8) != 1
                || (u32le(used[0], 12) != u32::MAX
                    && u64::from(u32le(used[0], 12))
                        != (geometry.sectors() - 1).min(u64::from(u32::MAX)))
                || slots
                    .chunks_exact(16)
                    .any(|e| e[4] == 0 && e.iter().any(|b| *b != 0))
            {
                return Err(invalid("invalid protective MBR"));
            }
            return Ok(Self::Gpt(read_gpt(
                source,
                sector,
                geometry.sectors(),
                raw,
                allow_opaque,
            )?));
        }
        let mut entries = Vec::new();
        for (i, e) in slots.chunks_exact(16).enumerate() {
            if e[4] == 0 {
                if e.iter().any(|b| *b != 0) {
                    return Err(invalid("nonzero unused MBR entry"));
                }
                continue;
            }
            if matches!(e[4], 5 | 15 | 0x85) {
                return Err(unsupported("extended MBR requires EBR inspection"));
            }
            if !matches!(e[0], 0 | 0x80) {
                return Err(invalid("invalid boot flag"));
            }
            let start = u64::from(u32le(e, 8));
            let end = start + u64::from(u32le(e, 12));
            if start == 0 || end > geometry.sectors() || end > u64::from(u32::MAX) + 1 {
                return Err(invalid("MBR range outside disk"));
            }
            entries.push(MbrEntry {
                slot: i as u32 + 1,
                raw: e.try_into().expect("16 byte slot"),
                range: LbaRange::new(start, end)?,
            });
        }
        check_overlap(entries.iter().map(|e| e.range))?;
        Ok(Self::Mbr(MbrLayout {
            geometry,
            raw,
            entries,
        }))
    }
}
/// Borrowed bounded partition reader. Storage remains owned by the caller.
pub struct PartitionView<'a> {
    source: &'a dyn ReadAt,
    offset: u64,
    length: u64,
}
impl<'a> PartitionView<'a> {
    /// Bound a reader to a checked sector range.
    pub fn new(source: &'a dyn ReadAt, geometry: Geometry, range: LbaRange) -> io::Result<Self> {
        if source.len() != geometry.bytes || range.end > geometry.sectors() {
            return Err(invalid("view outside geometry"));
        }
        Ok(Self {
            source,
            offset: range.start * u64::from(geometry.sector),
            length: range.sectors() * u64::from(geometry.sector),
        })
    }
}
impl ReadAt for PartitionView<'_> {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.source.read_exact_at(self.offset + offset, out)
    }
}
impl GptLayout {
    fn update_entry(
        &mut self,
        slot: u32,
        change: impl FnOnce(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if !self.mutation_supported() {
            return Err(unsupported("unknown GPT header extension cannot be edited"));
        }
        let index = slot.checked_sub(1).ok_or_else(|| invalid("invalid slot"))? as usize;
        let mut proposed = self.entries.clone();
        let entry = proposed
            .get_mut(index)
            .ok_or_else(|| invalid("invalid slot"))?;
        if entry.range.is_some() && !entry.standalone_volume() {
            return Err(unsupported(
                "dynamic partition mutation requires a volume manager",
            ));
        }
        change(&mut entry.raw)?;
        if guid(&entry.raw, 0) != [0; 16] {
            let mut probe = entry.clone();
            probe.range = Some(LbaRange { start: 1, end: 2 });
            if !probe.standalone_volume() {
                return Err(unsupported(
                    "dynamic partition mutation requires a volume manager",
                ));
            }
        }
        let mut ids = HashSet::new();
        for e in &mut proposed {
            if guid(&e.raw, 0) == [0; 16] {
                e.range = None;
                continue;
            }
            if u64le(&e.raw, 48) & 0x0000_ffff_ffff_fff8 != 0 {
                return Err(unsupported("reserved GPT attribute bits"));
            }
            let id = guid(&e.raw, 16);
            if id == [0; 16] || !ids.insert(id) {
                return Err(invalid("nil or duplicate partition ID"));
            }
            let r = LbaRange::from_inclusive(u64le(&e.raw, 32), u64le(&e.raw, 40))?;
            if r.start < self.primary.first || r.end > self.primary.last + 1 {
                return Err(invalid("partition outside usable range"));
            }
            e.range = Some(r);
        }
        check_overlap(proposed.iter().filter_map(|e| e.range))?;
        self.entries = proposed;
        self.primary.table = self
            .entries
            .iter()
            .flat_map(|e| e.raw.iter().copied())
            .collect();
        self.backup.table = self.primary.table.clone();
        for h in [&mut self.primary, &mut self.backup] {
            h.raw[88..92].copy_from_slice(&crc32(&h.table).to_le_bytes());
            h.raw[16..20].fill(0);
            let n = u32le(&h.raw, 12) as usize;
            let crc = crc32(&h.raw[..n]);
            h.raw[16..20].copy_from_slice(&crc.to_le_bytes());
        }
        Ok(())
    }
    /// Change boundaries only; this does not resize filesystems or move data.
    pub fn set_range(&mut self, slot: u32, range: LbaRange) -> io::Result<()> {
        self.update_entry(slot, |e| {
            if guid(e, 0) == [0; 16] {
                return Err(invalid("unused slot"));
            }
            e[32..40].copy_from_slice(&range.start.to_le_bytes());
            e[40..48].copy_from_slice(&(range.end - 1).to_le_bytes());
            Ok(())
        })
    }
    /// Delete an entry. Payload bytes are untouched.
    pub fn delete(&mut self, slot: u32) -> io::Result<()> {
        self.update_entry(slot, |e| {
            e.fill(0);
            Ok(())
        })
    }
    /// Set a name without truncation, preserving unrelated bytes.
    pub fn rename(&mut self, slot: u32, name: &str) -> io::Result<()> {
        let mut n = crate::guid::GptName::from_raw([0; 36]);
        n.set(name)
            .map_err(|_| invalid("GPT name exceeds 36 UTF-16 units"))?;
        self.update_entry(slot, |e| {
            if guid(e, 0) == [0; 16] {
                return Err(invalid("unused slot"));
            }
            for (i, u) in n.raw().iter().enumerate() {
                e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
            }
            Ok(())
        })
    }
    /// Set identity and type with duplicate and nil ID validation.
    pub fn set_identity(
        &mut self,
        slot: u32,
        kind: crate::guid::Guid,
        id: crate::guid::Guid,
    ) -> io::Result<()> {
        self.update_entry(slot, |e| {
            if kind.to_gpt_bytes() == [0; 16] {
                return Err(invalid("nil partition type"));
            }
            e[..16].copy_from_slice(&kind.to_gpt_bytes());
            e[16..32].copy_from_slice(&id.to_gpt_bytes());
            Ok(())
        })
    }
    /// Replace attributes explicitly; bit helpers are available on GptAttributes.
    pub fn set_attributes(
        &mut self,
        slot: u32,
        attributes: crate::guid::GptAttributes,
    ) -> io::Result<()> {
        self.update_entry(slot, |e| {
            if guid(e, 0) == [0; 16] {
                return Err(invalid("unused slot"));
            }
            e[48..56].copy_from_slice(&attributes.bits().to_le_bytes());
            Ok(())
        })
    }
    /// Enumerate usable gaps in ascending order.
    pub fn free_space(&self) -> Vec<LbaRange> {
        let mut used: Vec<_> = self.entries.iter().filter_map(|e| e.range).collect();
        used.sort_by_key(|r| r.start);
        let mut next = self.primary.first;
        let mut gaps = Vec::new();
        for r in used {
            if next < r.start {
                gaps.push(LbaRange {
                    start: next,
                    end: r.start,
                });
            }
            next = r.end;
        }
        if next <= self.primary.last {
            gaps.push(LbaRange {
                start: next,
                end: self.primary.last + 1,
            });
        }
        gaps
    }
    /// Create a partition in a free slot using caller-provided identity.
    pub fn create(
        &mut self,
        slot: u32,
        kind: crate::guid::Guid,
        id: crate::guid::Guid,
        range: LbaRange,
    ) -> io::Result<()> {
        self.update_entry(slot, |e| {
            if guid(e, 0) != [0; 16] {
                return Err(invalid("occupied slot"));
            }
            if kind.to_gpt_bytes() == [0; 16] {
                return Err(invalid("nil partition type"));
            }
            e.fill(0);
            e[..16].copy_from_slice(&kind.to_gpt_bytes());
            e[16..32].copy_from_slice(&id.to_gpt_bytes());
            e[32..40].copy_from_slice(&range.start.to_le_bytes());
            e[40..48].copy_from_slice(&(range.end - 1).to_le_bytes());
            Ok(())
        })
    }
}
impl GptLayout {
    /// Initialize an empty GPT in memory. The caller chooses disk identity and
    /// slot dimensions; no payload or storage is touched.
    pub fn initialize(
        geometry: Geometry,
        disk_id: crate::guid::Guid,
        count: u32,
        entry_size: u32,
    ) -> io::Result<Self> {
        if disk_id.to_gpt_bytes() == [0; 16]
            || count == 0
            || count > 131072
            || !(128..=4096).contains(&entry_size)
            || !entry_size.is_power_of_two()
        {
            return Err(invalid("invalid GPT dimensions or identity"));
        }
        let bytes = u64::from(count) * u64::from(entry_size);
        if !(16384..=16777216).contains(&bytes) {
            return Err(invalid("GPT allocation limit"));
        }
        let sectors = bytes.div_ceil(u64::from(geometry.sector));
        let total = geometry.sectors();
        let first = 2 + sectors;
        let last = total
            .checked_sub(sectors + 2)
            .ok_or_else(|| invalid("disk too small"))?;
        if first > last {
            return Err(invalid("disk too small for GPT"));
        }
        let table = vec![0; bytes as usize];
        let make_header = |current: u64, alternate: u64, table_lba: u64| {
            let mut raw = vec![0; geometry.sector as usize];
            raw[..8].copy_from_slice(b"EFI PART");
            raw[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
            raw[12..16].copy_from_slice(&92u32.to_le_bytes());
            for (o, v) in [
                (24, current),
                (32, alternate),
                (40, first),
                (48, last),
                (72, table_lba),
            ] {
                raw[o..o + 8].copy_from_slice(&v.to_le_bytes());
            }
            raw[56..72].copy_from_slice(&disk_id.to_gpt_bytes());
            raw[80..84].copy_from_slice(&count.to_le_bytes());
            raw[84..88].copy_from_slice(&entry_size.to_le_bytes());
            raw[88..92].copy_from_slice(&crc32(&table).to_le_bytes());
            let crc = crc32(&raw[..92]);
            raw[16..20].copy_from_slice(&crc.to_le_bytes());
            Header {
                first,
                last,
                disk_guid: disk_id.to_gpt_bytes(),
                count,
                entry_size,
                table: table.clone(),
                raw,
                table_lba,
            }
        };
        let mut mbr = vec![0; geometry.sector as usize];
        mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
        mbr[450] = 0xee;
        mbr[447..450].copy_from_slice(&[0, 2, 0]);
        mbr[451..454].fill(0xff);
        mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
        mbr[458..462].copy_from_slice(&((total - 1).min(u64::from(u32::MAX)) as u32).to_le_bytes());
        Ok(Self {
            geometry,
            mbr,
            primary: make_header(1, total - 1, 2),
            backup: make_header(total - 1, 1, total - 1 - sectors),
            entries: (1..=count)
                .map(|slot| Entry {
                    slot,
                    raw: vec![0; entry_size as usize],
                    range: None,
                })
                .collect(),
        })
    }
    /// Find an aligned first-fit gap; alignment is expressed in logical sectors.
    pub fn place(&self, sectors: u64, alignment: u64) -> io::Result<LbaRange> {
        if sectors == 0 || alignment == 0 {
            return Err(invalid("zero size or alignment"));
        }
        for gap in self.free_space() {
            let rem = gap.start % alignment;
            let start = gap
                .start
                .checked_add(if rem == 0 { 0 } else { alignment - rem })
                .ok_or_else(|| invalid("alignment overflow"))?;
            if let Some(end) = start.checked_add(sectors)
                && end <= gap.end
            {
                return LbaRange::new(start, end);
            }
        }
        Err(invalid("no aligned free space"))
    }
}
/// Reviewable boundary change and its payload prerequisite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundaryChange {
    /// Original containing range.
    pub old: LbaRange,
    /// Proposed containing range.
    pub new: LbaRange,
    /// A managed shrink requires external filesystem completion.
    pub filesystem_shrink_required: bool,
    /// Moving the start requires independent payload movement.
    pub payload_move_required: bool,
}
impl GptLayout {
    /// Describe boundary implications before a boundary-only edit.
    pub fn describe_boundary_change(&self, slot: u32, new: LbaRange) -> io::Result<BoundaryChange> {
        let old = self
            .entries
            .iter()
            .find(|e| e.slot == slot)
            .and_then(|e| e.range)
            .ok_or_else(|| invalid("missing partition"))?;
        Ok(BoundaryChange {
            old,
            new,
            filesystem_shrink_required: new.start > old.start || new.end < old.end,
            payload_move_required: new.start != old.start,
        })
    }
}
impl MbrLayout {
    /// Initialize an empty MBR with caller-specified disk signature.
    pub fn initialize(geometry: Geometry, signature: u32) -> Self {
        let mut raw = vec![0; geometry.sector as usize];
        raw[440..444].copy_from_slice(&signature.to_le_bytes());
        raw[510..512].copy_from_slice(&[0x55, 0xaa]);
        Self {
            geometry,
            raw,
            entries: Vec::new(),
        }
    }
    fn replace(&mut self, slot: u32, raw: [u8; 16]) -> io::Result<()> {
        if !(1..=4).contains(&slot) {
            return Err(invalid("invalid MBR slot"));
        }
        if self
            .entries
            .iter()
            .any(|e| e.slot == slot && e.raw[4] == 0x42)
        {
            return Err(unsupported(
                "dynamic partition mutation requires a volume manager",
            ));
        }
        let mut proposed = self.entries.clone();
        proposed.retain(|e| e.slot != slot);
        if raw[4] != 0 {
            if !matches!(raw[0], 0 | 0x80) || matches!(raw[4], 5 | 15 | 0x85 | 0xee | 0x42) {
                return Err(unsupported("unsupported MBR entry"));
            }
            let start = u64::from(u32le(&raw, 8));
            let end = start + u64::from(u32le(&raw, 12));
            if start == 0 || end > self.geometry.sectors() || end > u64::from(u32::MAX) + 1 {
                return Err(invalid("MBR range outside disk"));
            }
            proposed.push(MbrEntry {
                slot,
                raw,
                range: LbaRange::new(start, end)?,
            });
        }
        check_overlap(proposed.iter().map(|e| e.range))?;
        proposed.sort_by_key(|e| e.slot);
        self.entries = proposed;
        let o = 446 + (slot as usize - 1) * 16;
        self.raw[o..o + 16].copy_from_slice(&raw);
        Ok(())
    }
    /// Create a basic partition without writing storage.
    pub fn create(
        &mut self,
        slot: u32,
        kind: u8,
        range: LbaRange,
        bootable: bool,
    ) -> io::Result<()> {
        if kind == 0 || self.entries.iter().any(|e| e.slot == slot) {
            return Err(invalid("invalid type or occupied slot"));
        }
        let start = u32::try_from(range.start).map_err(|_| invalid("MBR LBA exceeds 32 bits"))?;
        let sectors =
            u32::try_from(range.sectors()).map_err(|_| invalid("MBR length exceeds 32 bits"))?;
        let mut raw = [0; 16];
        raw[0] = if bootable { 0x80 } else { 0 };
        raw[1..4].fill(0xff);
        raw[4] = kind;
        raw[5..8].fill(0xff);
        raw[8..12].copy_from_slice(&start.to_le_bytes());
        raw[12..16].copy_from_slice(&sectors.to_le_bytes());
        self.replace(slot, raw)
    }
    /// Delete a partition entry without touching payload data.
    pub fn delete(&mut self, slot: u32) -> io::Result<()> {
        self.replace(slot, [0; 16])
    }
    /// Change boundaries without resizing filesystems or moving data.
    pub fn set_range(&mut self, slot: u32, range: LbaRange) -> io::Result<()> {
        let mut raw = self
            .entries
            .iter()
            .find(|e| e.slot == slot)
            .ok_or_else(|| invalid("missing partition"))?
            .raw;
        let start = u32::try_from(range.start).map_err(|_| invalid("MBR LBA exceeds 32 bits"))?;
        let count =
            u32::try_from(range.sectors()).map_err(|_| invalid("MBR count exceeds 32 bits"))?;
        raw[8..12].copy_from_slice(&start.to_le_bytes());
        raw[12..16].copy_from_slice(&count.to_le_bytes());
        self.replace(slot, raw)
    }
    /// Change type and boot flag while preserving CHS and boundaries.
    pub fn set_type(&mut self, slot: u32, kind: u8, bootable: bool) -> io::Result<()> {
        if kind == 0 {
            return Err(invalid("nil type"));
        }
        let mut raw = self
            .entries
            .iter()
            .find(|e| e.slot == slot)
            .ok_or_else(|| invalid("missing partition"))?
            .raw;
        raw[0] = if bootable { 0x80 } else { 0 };
        raw[4] = kind;
        self.replace(slot, raw)
    }
    /// Gaps excluding the MBR logical sector.
    pub fn free_space(&self) -> Vec<LbaRange> {
        let mut used: Vec<_> = self.entries.iter().map(|e| e.range).collect();
        used.sort_by_key(|r| r.start);
        let mut next = 1;
        let mut gaps = Vec::new();
        for r in used {
            if next < r.start {
                gaps.push(LbaRange {
                    start: next,
                    end: r.start,
                });
            }
            next = r.end;
        }
        if next < self.geometry.sectors() {
            gaps.push(LbaRange {
                start: next,
                end: self.geometry.sectors(),
            });
        }
        gaps
    }
}
impl Entry {
    /// Borrow a bounded standalone volume, rejecting dynamic-volume entries.
    pub fn volume_view<'a>(
        &self,
        source: &'a dyn ReadAt,
        geometry: Geometry,
    ) -> io::Result<PartitionView<'a>> {
        if !self.standalone_volume() {
            return Err(unsupported("entry is not a standalone volume"));
        }
        PartitionView::new(
            source,
            geometry,
            self.range.ok_or_else(|| invalid("unused slot"))?,
        )
    }
}
impl MbrEntry {
    /// Borrow a bounded standalone volume, rejecting LDM entries.
    pub fn volume_view<'a>(
        &self,
        source: &'a dyn ReadAt,
        geometry: Geometry,
    ) -> io::Result<PartitionView<'a>> {
        if !self.standalone_volume() {
            return Err(unsupported("entry is not a standalone volume"));
        }
        PartitionView::new(source, geometry, self.range)
    }
}
impl Entry {
    /// Typed type identity; unused entries have no type.
    pub fn type_id(&self) -> Option<crate::guid::Guid> {
        let id = crate::guid::Guid::from_gpt_bytes(guid(&self.raw, 0));
        if self.range.is_some() { Some(id) } else { None }
    }
    /// Typed unique identity; unused entries have no identity.
    pub fn unique_id(&self) -> Option<crate::guid::Guid> {
        self.range
            .map(|_| crate::guid::Guid::from_gpt_bytes(guid(&self.raw, 16)))
    }
    /// Lossless typed GPT name.
    pub fn name(&self) -> crate::guid::GptName {
        crate::guid::GptName::from_raw(self.raw_name())
    }
    /// Typed attribute bits.
    pub fn attributes(&self) -> crate::guid::GptAttributes {
        crate::guid::GptAttributes::from_bits(u64le(&self.raw, 48))
    }
}
impl GptLayout {
    /// Typed disk identity.
    pub fn disk_id(&self) -> crate::guid::Guid {
        crate::guid::Guid::from_gpt_bytes(self.disk_guid())
    }
    /// Set explicit boot code and preserve sector bytes beyond the MBR prefix.
    pub fn with_mbr_preservation(mut self, source: &[u8], boot: &[u8; 440]) -> io::Result<Self> {
        if source.len() != self.mbr.len() {
            return Err(invalid("MBR logical sector length mismatch"));
        }
        self.mbr[..440].copy_from_slice(boot);
        self.mbr[512..].copy_from_slice(&source[512..]);
        Ok(self)
    }
}
impl MbrLayout {
    /// Set explicit boot code and preserve sector bytes beyond the MBR prefix.
    pub fn with_mbr_preservation(mut self, source: &[u8], boot: &[u8; 440]) -> io::Result<Self> {
        if source.len() != self.raw.len() {
            return Err(invalid("MBR logical sector length mismatch"));
        }
        self.raw[..440].copy_from_slice(boot);
        self.raw[512..].copy_from_slice(&source[512..]);
        Ok(self)
    }
}
impl MbrLayout {
    /// Find aligned first-fit basic MBR space within 32-bit addressing limits.
    pub fn place(&self, sectors: u64, alignment: u64) -> io::Result<LbaRange> {
        if sectors == 0 || alignment == 0 {
            return Err(invalid("zero size or alignment"));
        }
        for gap in self.free_space() {
            let rem = gap.start % alignment;
            let start = gap
                .start
                .checked_add(if rem == 0 { 0 } else { alignment - rem })
                .ok_or_else(|| invalid("alignment overflow"))?;
            if let Some(end) = start.checked_add(sectors)
                && end <= gap.end
                && end <= u64::from(u32::MAX) + 1
                && sectors <= u64::from(u32::MAX)
            {
                return LbaRange::new(start, end);
            }
        }
        Err(invalid("no aligned MBR space"))
    }
    /// Describe filesystem and payload prerequisites before boundary-only changes.
    pub fn describe_boundary_change(&self, slot: u32, new: LbaRange) -> io::Result<BoundaryChange> {
        let old = self
            .entries
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| e.range)
            .ok_or_else(|| invalid("missing partition"))?;
        Ok(BoundaryChange {
            old,
            new,
            filesystem_shrink_required: new.start > old.start || new.end < old.end,
            payload_move_required: new.start != old.start,
        })
    }
}
