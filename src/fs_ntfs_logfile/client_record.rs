//! Borrowed NTFS client record envelope; operations remain opaque.
use super::*;

/// Structurally bounded native client record, without operation/replay support.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogClientRecord<'a> {
    raw: &'a [u8],
    header_end: usize,
    redo_range: (usize, usize),
    undo_range: (usize, usize),
    /// Exact native redo operation, including unknown values.
    pub redo_operation: u16,
    /// Exact native undo operation, including unknown values.
    pub undo_operation: u16,
    /// Native open-attribute-table offset, without reference validation.
    pub target_attribute: u16,
    /// Count of declared LCNs; the structural header retains one slot even if zero.
    pub lcn_count: u16,
    /// Native offset in target record.
    pub record_offset: u16,
    /// Native attribute offset.
    pub attribute_offset: u16,
    /// Native cluster-block offset, without unit interpretation.
    pub cluster_offset: u16,
    /// Exact reserved native word, without semantic interpretation.
    pub reserved: u16,
    /// Signed native target VCN, without mapping validation.
    pub target_vcn: i64,
}
impl<'a> NtfsLogClientRecord<'a> {
    /// Complete borrowed payload, including gaps and unknown bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Fixed prefix and required LCN slots, including the unused slot at count zero.
    pub fn header_bytes(&self) -> &'a [u8] {
        &self.raw[..self.header_end]
    }
    /// Exact bounded redo bytes; may be empty at the payload end.
    pub fn redo(&self) -> &'a [u8] {
        &self.raw[self.redo_range.0..self.redo_range.1]
    }
    /// Exact bounded undo bytes; may alias redo bytes.
    pub fn undo(&self) -> &'a [u8] {
        &self.raw[self.undo_range.0..self.undo_range.1]
    }
    /// Only the declared LCN bytes, without the required unused zero-count slot.
    pub fn lcn_bytes(&self) -> &'a [u8] {
        &self.raw[32..32 + usize::from(le16(self.raw, 14)) * 8]
    }
    /// One signed LCN in constant time; no allocation or unbounded traversal.
    pub fn lcn(&self, index: usize) -> Option<i64> {
        (index < usize::from(le16(self.raw, 14))).then(|| le64(self.raw, 32 + index * 8) as i64)
    }
    /// Bytes between the structural header and the earliest nonempty data range.
    /// Complete raw bytes remain available when the two ranges overlap or alias.
    pub fn padding_bytes(&self) -> &'a [u8] {
        let start = [self.redo_range, self.undo_range]
            .iter()
            .filter(|range| range.0 != range.1)
            .map(|range| range.0)
            .min()
            .unwrap_or(self.raw.len());
        &self.raw[self.header_end..start]
    }
    /// Always false: native operation values are observed, not implemented.
    pub fn operation_semantics_supported(&self) -> bool {
        false
    }
}

/// Decode the native NTFS client envelope without following targets or applying operations.
///
/// Requires a complete type-1 LFS record with validated NTFS client context.
/// Offsets and LCN framing follow the pinned Linux profile. Unknown operation
/// codes remain opaque. Data ranges can overlap and zero-length EOF ranges are
/// retained; no allocation, I/O, transaction or replay inference occurs.
pub fn inspect_ntfs_log_client_record(
    record: &NtfsLogRecordReport,
) -> Result<NtfsLogClientRecord<'_>> {
    inspect_client_record(record, false, true)
}

// Native analysis checks offsets' alignment but does NOT interpret declared
// redo/undo lengths until operation-specific consumers. Keep those raw fields
// opaque here; only native dump consumers replace the private redo body range.
fn inspect_client_record(
    record: &NtfsLogRecordReport,
    native_header_only: bool,
    selected_client_only: bool,
) -> Result<NtfsLogClientRecord<'_>> {
    let raw = record
        .payload()
        .ok_or_else(|| invalid("NTFS client envelope incomplete record"))?;
    let header = record
        .header()
        .ok_or_else(|| invalid("NTFS client envelope LFS header"))?;
    let context = record
        .restart_context()
        .ok_or_else(|| invalid("NTFS client envelope context"))?;
    if selected_client_only && header.record_type != 1 {
        return Err(unsupported("NTFS client envelope LFS type"));
    }
    if context.client_count != 1
        || context.in_use_head != 0
        || selected_client_only
            && (header.client_index != 0 || Some(header.client_sequence) != context.client_sequence)
    {
        return Err(invalid("NTFS client envelope identity"));
    }
    if raw.len() < 40 {
        return Err(invalid("NTFS client envelope fixed prefix"));
    }
    let lcn_count = le16(raw, 14);
    let header_end = usize::from(lcn_count)
        .max(1)
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or_else(|| invalid("NTFS client envelope LCN size"))?;
    if header_end > raw.len() {
        return Err(invalid("NTFS client envelope LCN bounds"));
    }
    let range = |offset_at, length_at| -> Result<(usize, usize)> {
        let start = usize::from(le16(raw, offset_at));
        let length = usize::from(le16(raw, length_at));
        if native_header_only {
            if !start.is_multiple_of(8) {
                return Err(invalid("NTFS native client data offset alignment"));
            }
            return Ok((raw.len(), raw.len()));
        }
        let end = start
            .checked_add(length)
            .ok_or_else(|| invalid("NTFS client envelope range overflow"))?;
        if !start.is_multiple_of(8) || end > raw.len() || length != 0 && start < header_end {
            return Err(invalid("NTFS client envelope data range"));
        }
        Ok((start, end))
    };
    Ok(NtfsLogClientRecord {
        raw,
        header_end,
        redo_range: range(4, 6)?,
        undo_range: range(8, 10)?,
        redo_operation: le16(raw, 0),
        undo_operation: le16(raw, 2),
        target_attribute: le16(raw, 12),
        lcn_count,
        record_offset: le16(raw, 16),
        attribute_offset: le16(raw, 18),
        cluster_offset: le16(raw, 20),
        reserved: le16(raw, 22),
        target_vcn: le64(raw, 24) as i64,
    })
}

// Pinned native checkpoint loaders use the remaining payload after redo_off for
// generic tables, and the remaining payload after lrh_length for names. Public
// redo/undo range observations retain their previous declared-length behavior.
pub(super) fn inspect_native_dump_record(
    record: &NtfsLogRecordReport,
) -> Result<NtfsLogClientRecord<'_>> {
    let mut client = inspect_native_analysis_record(record)?;
    let start = match le16(client.raw(), 0) {
        29 | 31 | 32 => usize::from(le16(client.raw(), 4)),
        30 => client.header_end,
        _ => return Err(unsupported("NTFS native checkpoint dump opcode")),
    };
    if start < client.header_end || start > client.raw().len() {
        return Err(invalid("NTFS native checkpoint body origin"));
    }
    client.redo_range = (start, client.raw().len());
    Ok(client)
}

fn target_required(op: u16) -> bool {
    let mask = [0xfc_u8, 0xfb, 0xff, 0x10, 0x06];
    op <= 34 && mask[usize::from(op >> 3)] & (1 << (op & 7)) != 0
}
pub(super) fn validate_native_analysis_header(
    header: &NtfsLogRecordHeader,
    client: &NtfsLogClientRecord<'_>,
) -> Result<()> {
    // Pinned check_log_rec685: version1.0 attr stride40; refuse table-header
    // overlaps explicitly rather than reproducing unsigned underflow admission.
    if header.transaction_id < 24 || !(header.transaction_id - 24).is_multiple_of(40) {
        return Err(invalid(
            "NTFS analysis native transaction byte-offset alignment",
        ));
    }
    if client.target_attribute == 0
        && (target_required(client.redo_operation) || target_required(client.undo_operation))
    {
        return Err(invalid("NTFS analysis native required target absent"));
    }
    if client.lcn_count != 0
        && (client.target_attribute < 24 || !(client.target_attribute - 24).is_multiple_of(40))
    {
        return Err(invalid("NTFS analysis native open-attribute alignment"));
    }
    Ok(())
}

// Header-only source-owned view for native transaction analysis; redo/undo
// slices are deliberately empty while their declarations remain in raw().
// Actual operation bodies must validate their own native ranges before use.
pub(super) fn inspect_native_analysis_record(
    record: &NtfsLogRecordReport,
) -> Result<NtfsLogClientRecord<'_>> {
    let client = inspect_client_record(record, true, true)?;
    let header = record
        .header()
        .ok_or_else(|| invalid("NTFS native analysis envelope header"))?;
    validate_native_analysis_header(header, &client)?;
    Ok(client)
}

// Native undo follows exact undo-next links without the next-client query filter.
// Physical framing and selected restart context remain validated by the caller.
pub(super) fn inspect_native_undo_record(
    record: &NtfsLogRecordReport,
) -> Result<NtfsLogClientRecord<'_>> {
    let client = inspect_client_record(record, true, false)?;
    let header = record
        .header()
        .ok_or_else(|| invalid("NTFS undo envelope header"))?;
    validate_native_analysis_header(header, &client)?;
    Ok(client)
}
