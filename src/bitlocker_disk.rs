//! Bounded BitLocker version-2 disk decoding. No crypto or host transport.
use crate::{
    bitlocker::{
        Error, ErrorKind, Identifier, Policy, Protector, Result, Source, invalid, resource,
        unsupported,
    },
    fs_core::Reservation,
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

pub(crate) const FULL_VOLUME_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];
const USED_SPACE_GUID: [u8; 16] = [
    0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8,
];
pub(crate) fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub(crate) fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(core::array::from_fn(|i| b[at + i]))
}
fn range(at: u64, length: u64, bound: u64) -> Result<()> {
    if at.checked_add(length).is_none_or(|end| end > bound) {
        return Err(invalid("BitLocker metadata/mapping range"));
    }
    Ok(())
}
fn overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    a < b + b_len && b < a + a_len
}

pub(crate) struct Header {
    pub(crate) sector_size: u16,
    pub(crate) offsets: [u64; 3],
    pub(crate) used_space_only: bool,
}
impl Header {
    pub(crate) fn parse(boot: &[u8; 512], length: u64) -> Result<Self> {
        if &boot[3..11] != b"-FVE-FS-" || boot[510..512] != [0x55, 0xaa] {
            return Err(invalid("BitLocker boot signature"));
        }
        if boot[160..176] != FULL_VOLUME_GUID && boot[160..176] != USED_SPACE_GUID {
            return Err(unsupported(
                "BitLocker boot envelope (requires Windows 7 or later)",
            ));
        }
        let sector_size = u16le(boot, 11);
        if !matches!(sector_size, 512 | 4096) {
            return Err(unsupported("BitLocker logical sector size"));
        }
        let offsets = core::array::from_fn(|i| u64le(boot, 176 + i * 8));
        for (i, &offset) in offsets.iter().enumerate() {
            range(offset, 65_536, length)?;
            if offset < u64::from(sector_size) || !offset.is_multiple_of(u64::from(sector_size)) {
                return Err(invalid("BitLocker metadata alignment"));
            }
            if offsets[..i]
                .iter()
                .any(|other| overlap(offset, 65_536, *other, 65_536))
            {
                return Err(invalid("overlapping BitLocker metadata regions"));
            }
        }
        Ok(Self {
            sector_size,
            offsets,
            used_space_only: boot[160..176] == USED_SPACE_GUID,
        })
    }
}

pub(crate) struct Metadata {
    data: Zeroizing<Vec<u8>>,
    entries_end: usize,
    pub(crate) identifier: Identifier,
    pub(crate) encrypted_length: u64,
    pub(crate) method: u16,
    pub(crate) current_state: u16,
    pub(crate) target_state: u16,
    pub(crate) offsets: [u64; 3],
    pub(crate) boot_offset: u64,
    boot_sectors: u32,
    _reservation: Reservation,
}

pub(crate) fn read_metadata(
    source: &dyn Source,
    at: u64,
    header: &Header,
    policy: &Policy,
) -> Result<Metadata> {
    let mut prefix = [0; 112];
    policy.read(source, at, &mut prefix)?;
    if &prefix[..8] != b"-FVE-FS-" {
        return Err(invalid("BitLocker metadata signature"));
    }
    if u16le(&prefix, 10) != 2 {
        return Err(unsupported("BitLocker metadata version"));
    }
    let size = usize::from(u16le(&prefix, 8)) * 16;
    if size < 112 || size + 8 > 65_536 {
        return Err(invalid("BitLocker metadata block size"));
    }
    if size + 8 > policy.limits.max_metadata_bytes {
        return Err(Error::new(
            ErrorKind::ResourceLimit,
            "BitLocker metadata byte limit",
        ));
    }
    let reservation = policy
        .resources
        .memory
        .reserve((size + 8) as u64)
        .map_err(resource)?;
    let mut data = Zeroizing::new(Vec::new());
    data.try_reserve_exact(size + 8)
        .map_err(|_| Error::new(ErrorKind::ResourceLimit, "metadata allocation"))?;
    data.resize(size + 8, 0);
    policy.read(source, at, &mut data)?;
    if data[..112] != prefix {
        return Err(Error::new(
            ErrorKind::SourceChanged,
            "metadata changed during read",
        ));
    }
    // Both observed validation-header versions place the CRC after size/version.
    // The optional VMK-authenticated validation payload is not an integrity claim
    // of this inspection API. Bound its declared extent to the reserved block.
    if u16le(&data, size) < 8
        || usize::from(u16le(&data, size)) > 65_536 - size
        || !matches!(u16le(&data, size + 2), 1 | 2)
        || crc32(&data[..size]) != u32le(&data, size + 4)
    {
        return Err(invalid("BitLocker metadata CRC validation"));
    }
    if u32le(&data, 68) != 1 || u32le(&data, 72) != 48 {
        return Err(unsupported("BitLocker dataset header"));
    }
    let dataset_size = u32le(&data, 64) as usize;
    let copy_size = u32le(&data, 76) as usize;
    if dataset_size < 48 || dataset_size > copy_size || copy_size > size - 64 {
        return Err(invalid("BitLocker dataset bounds"));
    }
    let entries_end = 64 + dataset_size;
    let mut count = 0;
    validate_entries(&data[112..entries_end], 1, &mut count, policy)?;
    let offsets = core::array::from_fn(|i| u64le(&data, 32 + 8 * i));
    if offsets != header.offsets {
        return Err(invalid("metadata location disagreement"));
    }
    Ok(Metadata {
        identifier: core::array::from_fn(|i| data[80 + i]),
        encrypted_length: u64le(&data, 16),
        method: u16le(&data, 100),
        current_state: u16le(&data, 12),
        target_state: u16le(&data, 14),
        offsets,
        boot_offset: u64le(&data, 56),
        boot_sectors: u32le(&data, 28),
        data,
        entries_end,
        _reservation: reservation,
    })
}

// Reflected IEEE CRC-32; bounded to a metadata block, independent of key integrity.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[derive(Clone, Copy)]
pub(crate) struct Entry<'a> {
    pub(crate) kind: u16,
    pub(crate) value: u16,
    pub(crate) version: u16,
    pub(crate) body: &'a [u8],
}
struct Entries<'a>(&'a [u8]);
impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 8 {
            return None;
        }
        let n = usize::from(u16le(self.0, 0));
        if n < 8 || n > self.0.len() {
            return None;
        }
        let entry = Entry {
            kind: u16le(self.0, 2),
            value: u16le(self.0, 4),
            version: u16le(self.0, 6),
            body: &self.0[8..n],
        };
        self.0 = &self.0[n..];
        Some(entry)
    }
}
fn validate_entries(
    mut data: &[u8],
    depth: usize,
    count: &mut usize,
    policy: &Policy,
) -> Result<()> {
    if depth > policy.limits.max_depth {
        return Err(Error::new(
            ErrorKind::ResourceLimit,
            "metadata nesting limit",
        ));
    }
    while !data.is_empty() {
        policy.resources.cancellation.check().map_err(resource)?;
        if data.len() < 8 || u16le(data, 0) == 0 {
            if data.iter().all(|byte| *byte == 0) {
                break;
            }
            return Err(invalid("truncated metadata entry"));
        }
        let size = usize::from(u16le(data, 0));
        if size < 8 || size > data.len() {
            return Err(invalid("metadata entry bounds"));
        }
        *count += 1;
        if *count > policy.limits.max_entries {
            return Err(Error::new(ErrorKind::ResourceLimit, "metadata entry limit"));
        }
        let value = u16le(data, 4);
        let body = &data[8..size];
        let nested = match value {
            3 => Some(20),
            8 => Some(28),
            9 => Some(24),
            _ => None,
        };
        let minimum = match value {
            1 => 4,
            5 => 28,
            15 => 16,
            _ => 0,
        };
        if body.len() < minimum {
            return Err(invalid("metadata value bounds"));
        }
        if let Some(skip) = nested {
            if body.len() < skip {
                return Err(invalid("metadata property header"));
            }
            if body.len() > skip {
                validate_entries(&body[skip..], depth + 1, count, policy)?;
            }
        }
        data = &data[size..];
    }
    Ok(())
}

fn unique<'a>(
    entries: impl Iterator<Item = Entry<'a>>,
    kind: u16,
    value: u16,
) -> Result<Entry<'a>> {
    let mut matches = entries.filter(|e| e.kind == kind && e.value == value);
    let entry = matches
        .next()
        .ok_or_else(|| unsupported("required BitLocker key property absent"))?;
    if matches.next().is_some() {
        return Err(invalid("duplicate BitLocker key property"));
    }
    if entry.version != 1 {
        return Err(unsupported("BitLocker key entry version"));
    }
    Ok(entry)
}
impl Metadata {
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.data == other.data
    }
    fn entries(&self) -> Entries<'_> {
        Entries(&self.data[112..self.entries_end])
    }
    pub(crate) fn agrees(&self, other: &Self) -> bool {
        self.data == other.data
    }
    pub(crate) fn protectors(&self) -> impl Iterator<Item = Protector> + '_ {
        self.entries()
            .filter(|e| e.kind == 2 && e.value == 8)
            .map(|e| Protector {
                identifier: core::array::from_fn(|i| e.body[i]),
                protection_type: u16le(e.body, 26),
            })
    }
    pub(crate) fn protector(&self, identifier: Identifier) -> Result<ProtectorEntry<'_>> {
        let mut matching = self
            .entries()
            .filter(|e| e.kind == 2 && e.value == 8 && e.body[..16] == identifier);
        let entry = matching
            .next()
            .ok_or_else(|| Error::new(ErrorKind::ProtectorNotFound, "protector identifier"))?;
        if matching.next().is_some() {
            return Err(invalid("duplicate protector identifier"));
        }
        if !matches!(entry.version, 1 | 3) {
            return Err(unsupported("VMK entry version"));
        }
        Ok(ProtectorEntry {
            protection_type: u16le(entry.body, 26),
            properties: &entry.body[28..],
        })
    }
    pub(crate) fn fvek(&self) -> Result<&[u8]> {
        Ok(unique(self.entries(), 3, 5)?.body)
    }
    pub(crate) fn boot_length(&self, sector_size: u16) -> Result<u64> {
        if self.boot_sectors == 0 || self.boot_sectors > 64 {
            return Err(unsupported("BitLocker boot-sector count"));
        }
        Ok(u64::from(self.boot_sectors) * u64::from(sector_size))
    }
    pub(crate) fn validate_mapping(&self, sector_size: u16, source_length: u64) -> Result<()> {
        let size = u64::from(sector_size);
        if self.encrypted_length == 0
            || !self.encrypted_length.is_multiple_of(size)
            || self.encrypted_length > source_length
        {
            return Err(invalid("encrypted volume length"));
        }
        let boot_length = self.boot_length(sector_size)?;
        range(self.boot_offset, boot_length, self.encrypted_length)?;
        if self.boot_offset < boot_length || !self.boot_offset.is_multiple_of(size) {
            return Err(invalid("relocated boot region"));
        }
        for &at in &self.offsets {
            range(at, 65_536, self.encrypted_length)?;
            if overlap(at, 65_536, 0, boot_length)
                || overlap(at, 65_536, self.boot_offset, boot_length)
            {
                return Err(invalid("metadata overlaps boot regions"));
            }
        }
        self.additional_reserved_region(sector_size)?;
        Ok(())
    }

    /// Decode the basic descriptor or the observed completed Windows 26200
    /// full-volume extension. Unknown trailer formats/flags remain unsupported.
    pub(crate) fn additional_reserved_region(
        &self,
        sector_size: u16,
    ) -> Result<Option<(u64, u64)>> {
        let mut descriptors = self.entries().filter(|e| e.value == 15);
        let Some(entry) = descriptors.next() else {
            return Ok(None);
        };
        if descriptors.next().is_some() {
            return Err(invalid("duplicate metadata area descriptor"));
        }
        if entry.kind != 15 || entry.version != 1 || !matches!(entry.body.len(), 16 | 92) {
            return Err(unsupported("extended metadata area descriptors"));
        }
        let body = entry.body;
        let boot_length = self.boot_length(sector_size)?;
        if u64le(body, 0) != self.boot_offset || u64le(body, 8) != boot_length {
            return Err(invalid("boot descriptor disagreement"));
        }
        if body.len() == 16 {
            return Ok(None);
        }
        // These fields are not fully specified. Accept the observed full-volume
        // profile only; in particular, never ignore conversion-log descriptors.
        if u16le(body, 16) != 5
            || u16le(body, 18) != 76
            || u32le(body, 20) != 0
            || u64le(body, 24) != 0x0a
            || u64le(body, 32) != 0
            || u32le(body, 40) != 0
            || u64le(body, 52) != 10
            || u32le(body, 60) != 0x6658
            || u64le(body, 64) != 2
            || u32le(body, 72) != 0x0201_0110
        {
            return Err(unsupported("unqualified metadata area extension"));
        }
        let physical_size = u32le(body, 48);
        if u32le(body, 44) != u32::from(sector_size)
            || !matches!(physical_size, 512 | 4096)
            || physical_size < u32::from(sector_size)
        {
            return Err(invalid("metadata area sector geometry"));
        }
        let offset = u64le(body, 76);
        let length = u64le(body, 84);
        let size = u64::from(sector_size);
        if length == 0 || !offset.is_multiple_of(size) || !length.is_multiple_of(size) {
            return Err(invalid("additional metadata region alignment"));
        }
        range(offset, length, self.encrypted_length)?;
        if overlap(offset, length, 0, boot_length)
            || overlap(offset, length, self.boot_offset, boot_length)
            || self
                .offsets
                .iter()
                .any(|&at| overlap(offset, length, at, 65_536))
        {
            return Err(invalid("additional metadata region overlap"));
        }
        Ok(Some((offset, length)))
    }
}

pub(crate) struct ProtectorEntry<'a> {
    pub(crate) protection_type: u16,
    properties: &'a [u8],
}
impl<'a> ProtectorEntry<'a> {
    pub(crate) fn salt(&self) -> Result<[u8; 16]> {
        let stretch = unique(Entries(self.properties), 0, 3)?;
        if u32le(stretch.body, 0) != 0x1000 {
            return Err(unsupported("recovery stretch algorithm"));
        }
        Ok(core::array::from_fn(|i| stretch.body[4 + i]))
    }
    pub(crate) fn encrypted_key(&self) -> Result<&'a [u8]> {
        Ok(unique(Entries(self.properties), 0, 5)?.body)
    }
    pub(crate) fn clear_key(&self) -> Result<&'a [u8]> {
        let entry = unique(Entries(self.properties), 0, 1)?;
        if entry.body.len() != 36 {
            return Err(invalid("clear-key length"));
        }
        if u32le(entry.body, 0) != 0x2000 {
            return Err(unsupported("clear-key algorithm"));
        }
        Ok(&entry.body[4..])
    }
}
