//! Borrowed NTFS client restart fields, without following checkpoint tables.
use super::*;

/// Opaque checkpoint table location and declared size, without pointer validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogTableReference {
    /// Native table record LSN; zero is preserved.
    pub lsn: u64,
    /// Native table byte count; zero is preserved independently of the LSN.
    pub bytes: u32,
}

/// Structurally decoded version-1.0 NTFS client restart payload.
///
/// This client version is independent of LFS restart version. References remain
/// uninterpreted and are not checked for activity, ownership or replay readiness.
#[derive(Clone, Copy, Debug)]
pub struct NtfsClientRestart<'a> {
    raw: &'a [u8],
    /// Native client payload `(major, minor)`; admitted value is `(1, 0)`.
    pub version: (u32, u32),
    /// Native starting checkpoint LSN, not an established active-window anchor.
    pub checkpoint_start_lsn: u64,
    /// Open attribute table reference.
    pub open_attribute_table: NtfsLogTableReference,
    /// Attribute names reference.
    pub attribute_names: NtfsLogTableReference,
    /// Dirty page table reference.
    pub dirty_page_table: NtfsLogTableReference,
    /// Transaction table reference.
    pub transaction_table: NtfsLogTableReference,
    /// Signed native USN checking offset, present when at least 72 bytes exist.
    pub usn_journal_restart_offset: Option<i64>,
    /// Previous volume restart's current LSN, present at 80 bytes.
    pub last_lsn: Option<u64>,
    /// Observed cluster byte count, without geometry validation; present at 84 bytes.
    pub bytes_per_cluster: Option<u32>,
    /// Raw native USN file reference, present at 96 bytes.
    pub usn_journal_reference: Option<u64>,
    /// Signed native USN base offset, present at 104 bytes.
    pub usn_base: Option<i64>,
    /// Observed client oldest LSN at checkpoint, present at 112 bytes.
    pub oldest_lsn: Option<u64>,
}
impl<'a> NtfsClientRestart<'a> {
    /// Exact borrowed payload, including partial optional fields and unknown bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// All bytes following the mandatory 64-byte prefix, without interpretation loss.
    pub fn extension_bytes(&self) -> &'a [u8] {
        &self.raw[64..]
    }
    /// Reserved bytes 84 through 87 when the complete field is present.
    /// Partial bytes remain available through `raw()` and `extension_bytes()`.
    pub fn reserved_bytes(&self) -> Option<&'a [u8]> {
        (self.raw.len() >= 88).then(|| &self.raw[84..88])
    }
    /// Unknown bytes after the admitted 112-byte extension, if any.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        &self.raw[self.raw.len().min(112)..]
    }
}

/// Decode a complete source-bound NTFS client restart record without allocation.
///
/// Requires LFS envelope type 2 and the validated NTFS client context. Optional
/// fields are exposed only when complete; partial, reserved and trailing bytes
/// remain borrowed verbatim. Unknown client payload versions are unsupported.
/// No referenced record/table is read, and no active/recovery claim is made.
pub fn inspect_ntfs_client_restart(record: &NtfsLogRecordReport) -> Result<NtfsClientRestart<'_>> {
    let raw = record
        .payload()
        .ok_or_else(|| invalid("NTFS client restart incomplete record"))?;
    let header = record
        .header()
        .ok_or_else(|| invalid("NTFS client restart envelope missing"))?;
    let context = record
        .restart_context()
        .ok_or_else(|| invalid("NTFS client restart context missing"))?;
    if header.record_type != 2 {
        return Err(unsupported("NTFS client restart envelope type"));
    }
    if context.client_count != 1
        || context.in_use_head != 0
        || header.client_index != 0
        || Some(header.client_sequence) != context.client_sequence
    {
        return Err(invalid("NTFS client restart identity"));
    }
    if raw.len() < 64 {
        return Err(invalid("NTFS client restart mandatory prefix"));
    }
    let version = (le32(raw, 0), le32(raw, 4));
    if version != (1, 0) {
        return Err(unsupported("NTFS client restart payload version"));
    }
    let table = |lsn_at, size_at| NtfsLogTableReference {
        lsn: le64(raw, lsn_at),
        bytes: le32(raw, size_at),
    };
    Ok(NtfsClientRestart {
        raw,
        version,
        checkpoint_start_lsn: le64(raw, 8),
        open_attribute_table: table(16, 48),
        attribute_names: table(24, 52),
        dirty_page_table: table(32, 56),
        transaction_table: table(40, 60),
        usn_journal_restart_offset: (raw.len() >= 72).then(|| le64(raw, 64) as i64),
        last_lsn: (raw.len() >= 80).then(|| le64(raw, 72)),
        bytes_per_cluster: (raw.len() >= 84).then(|| le32(raw, 80)),
        usn_journal_reference: (raw.len() >= 96).then(|| le64(raw, 88)),
        usn_base: (raw.len() >= 104).then(|| le64(raw, 96) as i64),
        oldest_lsn: (raw.len() >= 112).then(|| le64(raw, 104)),
    })
}
