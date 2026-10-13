//! Bounded borrowed restart-table links, without type-specific entry semantics.
use super::*;

/// Independent generic-table ceilings, excluding the already assembled record.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRestartTableLimits {
    /// Maximum declared slot count.
    pub entries: usize,
    /// Maximum complete redo byte slice, including retained trailing bytes.
    pub bytes: usize,
    /// Maximum charged header, slot and free-chain steps.
    pub work: usize,
}
/// Observed dump operation only, without entry-body or replay qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogRestartTableKind {
    /// Native operation `0x1d`.
    OpenAttributes,
    /// Native operation `0x1f`.
    DirtyPages,
    /// Native operation `0x20`.
    Transactions,
}
/// One structurally validated slot, borrowed from its source-bound dump.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRestartTableEntry<'a> {
    raw: &'a [u8],
    /// Zero-based physical table slot.
    pub index: usize,
    /// Byte offset from the table prefix.
    pub offset: usize,
}
impl<'a> NtfsLogRestartTableEntry<'a> {
    /// Full entry bytes; type-specific fields remain opaque.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Exact allocated sentinel or validated next-free link.
    pub fn link(&self) -> u32 {
        le32(self.raw, 0)
    }
    /// Whether the native allocated sentinel is present.
    pub fn allocated(&self) -> bool {
        self.link() == u32::MAX
    }
}
/// Generic link/count validation for a complete source-bound redo dump.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRestartTable<'a> {
    raw: &'a [u8],
    extent: usize,
    kind: NtfsLogRestartTableKind,
    work: usize,
    /// Native bytes per slot, at least four in this structural profile.
    pub entry_bytes: u16,
    /// Declared physical slot count.
    pub capacity: u16,
    /// Declared allocated-slot count, verified against native sentinels.
    pub allocated: u16,
    /// Exact native free goal; no additional meaning inferred.
    pub free_goal: u32,
    /// First free-entry offset, or zero.
    pub first_free: u32,
    /// Last free-entry offset, or zero.
    pub last_free: u32,
}
impl<'a> NtfsLogRestartTable<'a> {
    /// Full original redo bytes, including unknown trailing bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Prefix and exactly the declared slots.
    pub fn table_bytes(&self) -> &'a [u8] {
        &self.raw[..self.extent]
    }
    /// Uninterpreted bytes after the declared table extent.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        &self.raw[self.extent..]
    }
    /// Exact six reserved prefix bytes.
    pub fn reserved_bytes(&self) -> &'a [u8] {
        &self.raw[6..12]
    }
    /// Observed operation class, without typed entry semantics.
    pub fn kind(&self) -> NtfsLogRestartTableKind {
        self.kind
    }
    /// Charged validation steps, including the header.
    pub fn work(&self) -> usize {
        self.work
    }
    /// One raw slot in constant time, without allocating or following links.
    pub fn entry(&self, index: usize) -> Option<NtfsLogRestartTableEntry<'a>> {
        let capacity = usize::from(le16(self.raw, 2));
        let entry_bytes = usize::from(le16(self.raw, 0));
        if index >= capacity {
            return None;
        }
        let offset = 24 + index * entry_bytes;
        Some(NtfsLogRestartTableEntry {
            index,
            offset,
            raw: &self.raw[offset..offset + entry_bytes],
        })
    }
    /// Always false: only generic links/counts have been checked.
    pub fn entry_semantics_supported(&self) -> bool {
        false
    }
}

/// Validate generic slots and the complete free chain without allocation or I/O.
///
/// Only dump operations 29, 31 and 32 are admitted. Names operation 30 is a
/// different variable-length array. This does not correlate checkpoint reference
/// lengths, decode entry bodies, execute undo or establish active membership.
pub fn inspect_ntfs_log_restart_table<'a>(
    record: &NtfsLogClientRecord<'a>,
    limits: NtfsLogRestartTableLimits,
    r: &Resources,
) -> Result<NtfsLogRestartTable<'a>> {
    inspect_table_with_work(record, limits, r).0
}

pub(super) fn inspect_table_with_work<'a>(
    record: &NtfsLogClientRecord<'a>,
    limits: NtfsLogRestartTableLimits,
    r: &Resources,
) -> (Result<NtfsLogRestartTable<'a>>, usize) {
    let mut work = Work {
        used: 0,
        maximum: limits.work,
    };
    let result = inspect_table_inner(record, limits, r, &mut work);
    (result, work.used)
}

fn inspect_table_inner<'a>(
    record: &NtfsLogClientRecord<'a>,
    limits: NtfsLogRestartTableLimits,
    r: &Resources,
    work: &mut Work,
) -> Result<NtfsLogRestartTable<'a>> {
    work.tick(r)?;
    // Read the protected borrowed origin, not mutable public observation fields.
    let kind = match le16(record.raw(), 0) {
        29 => NtfsLogRestartTableKind::OpenAttributes,
        31 => NtfsLogRestartTableKind::DirtyPages,
        32 => NtfsLogRestartTableKind::Transactions,
        _ => return Err(unsupported("NTFS restart table dump operation")),
    };
    let raw = record.redo();
    if raw.len() > limits.bytes {
        return Err(exhausted("NTFS restart table byte ceiling"));
    }
    if raw.len() < 24 {
        return Err(invalid("NTFS restart table prefix"));
    }
    let entry_bytes = le16(raw, 0);
    let capacity = le16(raw, 2);
    let allocated = le16(raw, 4);
    if usize::from(capacity) > limits.entries {
        return Err(exhausted("NTFS restart table entry ceiling"));
    }
    if entry_bytes < 4 || allocated > capacity {
        return Err(invalid("NTFS restart table slot geometry"));
    }
    let extent = usize::from(entry_bytes)
        .checked_mul(usize::from(capacity))
        .and_then(|bytes| bytes.checked_add(24))
        .ok_or_else(|| invalid("NTFS restart table extent overflow"))?;
    if extent > raw.len() {
        return Err(invalid("NTFS restart table slot extent"));
    }
    let slot_offset = |offset: u32| -> bool {
        let offset = offset as usize;
        offset >= 24 && offset < extent && (offset - 24).is_multiple_of(usize::from(entry_bytes))
    };
    let first_free = le32(raw, 16);
    let last_free = le32(raw, 20);
    if [first_free, last_free]
        .iter()
        .any(|off| *off != 0 && !slot_offset(*off))
    {
        return Err(invalid("NTFS restart table free head bounds"));
    }
    let mut actual_allocated = 0usize;
    for index in 0..usize::from(capacity) {
        work.tick(r)?;
        let link = le32(raw, 24 + index * usize::from(entry_bytes));
        if link == u32::MAX {
            actual_allocated += 1;
        } else if link != 0 && !slot_offset(link) {
            return Err(invalid("NTFS restart table slot link bounds"));
        }
    }
    if actual_allocated != usize::from(allocated) {
        return Err(invalid("NTFS restart table allocated count"));
    }
    let expected_free = usize::from(capacity - allocated);
    let mut offset = first_free;
    let mut count = 0usize;
    let mut tail = 0u32;
    while offset != 0 {
        work.tick(r)?;
        if count >= expected_free {
            return Err(invalid("NTFS restart table free cycle or count"));
        }
        let link = le32(raw, offset as usize);
        if link == u32::MAX {
            return Err(invalid("NTFS restart table allocated free member"));
        }
        tail = offset;
        offset = link;
        count += 1;
    }
    if count != expected_free || tail != last_free {
        return Err(invalid("NTFS restart table free membership or tail"));
    }
    r.cancellation.check()?;
    Ok(NtfsLogRestartTable {
        raw,
        extent,
        kind,
        work: work.used,
        entry_bytes,
        capacity,
        allocated,
        free_goal: le32(raw, 12),
        first_free,
        last_free,
    })
}
