//! Borrowed allocated checkpoint entry fields, without replay or ownership claims.
use super::*;

/// One source-owned dirty-page/open-attribute link, without FILE ownership proof.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogDirtyPageOpenAttribute<'a> {
    dirty: NtfsLogDirtyPageEntry<'a>,
    open: NtfsLogOpenAttributeEntry<'a>,
    target_index: usize,
    target_offset: u32,
}
impl<'a> NtfsLogDirtyPageOpenAttribute<'a> {
    /// Original allocated dirty-page slot, including its exact raw bytes.
    pub fn dirty(&self) -> &NtfsLogDirtyPageEntry<'a> {
        &self.dirty
    }
    /// Original allocated open-attribute slot from the same checkpoint report.
    pub fn open_attribute(&self) -> &NtfsLogOpenAttributeEntry<'a> {
        &self.open
    }
    /// Zero-based open-attribute slot index derived from the original target offset.
    pub fn target_index(&self) -> usize {
        self.target_index
    }
    /// Exact original byte offset into the open-attribute table.
    pub fn target_offset(&self) -> u32 {
        self.target_offset
    }
}

/// Client-version-1.0 open attribute entry, preserving opaque native bytes.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogOpenAttributeEntry<'a> {
    raw: &'a [u8],
    /// Native index-buffer bytes, without geometry validation.
    pub bytes_per_index: u32,
    /// Raw native attribute type code.
    pub attribute_type: u32,
    /// Native FILE reference, without current FILE identity validation.
    pub file_reference: u64,
    /// Native open-record LSN, without active-window validation.
    pub open_record_lsn: u64,
}
impl<'a> NtfsLogOpenAttributeEntry<'a> {
    /// Complete native slot bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Uninterpreted native bytes 12 through 15; runtime flags are not inferred.
    pub fn opaque_flags(&self) -> &'a [u8] {
        &self.raw[12..16]
    }
    /// Serialized pointer bytes; never dereferenced or treated as disk offsets.
    pub fn pointer_bytes(&self) -> &'a [u8] {
        &self.raw[32..40]
    }
    /// Unknown slot bytes after the admitted 40-byte prefix.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        &self.raw[40..]
    }
}
/// Client-version-1.0 dirty page entry with bounded lazy native LCN access.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogDirtyPageEntry<'a> {
    raw: &'a [u8],
    lcn_end: usize,
    /// Native open-attribute-table reference, not a validated cross-reference.
    pub target_attribute: u32,
    /// Native transfer byte count, without mapping/durability interpretation.
    pub transfer_bytes: u32,
    /// Declared native LCN count; accessors use immutable original framing.
    pub lcn_count: u32,
    /// Signed native VCN, without allocation validation.
    pub target_vcn: i64,
    /// Native oldest page LSN, without chronology validation.
    pub oldest_lsn: u64,
}
impl<'a> NtfsLogDirtyPageEntry<'a> {
    /// Complete native slot bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Declared LCN bytes with bounds established by the original slot.
    pub fn lcn_bytes(&self) -> &'a [u8] {
        &self.raw[32..self.lcn_end]
    }
    /// One signed LCN in constant time; observation edits cannot alter framing.
    pub fn lcn(&self, index: usize) -> Option<i64> {
        (index < (self.lcn_end - 32) / 8).then(|| le64(self.raw, 32 + index * 8) as i64)
    }
    /// Unknown bytes following the declared LCN array.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        &self.raw[self.lcn_end..]
    }
}
/// Client-version-1.0 transaction entry; state values are observations only.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogTransactionEntry<'a> {
    raw: &'a [u8],
    /// Raw transaction state, including unknown values.
    pub state: u8,
    /// Native first LSN, without active-window validation.
    pub first_lsn: u64,
    /// Native predecessor LSN, without following the chain.
    pub previous_lsn: u64,
    /// Native undo-next LSN, without following the chain.
    pub undo_next_lsn: u64,
    /// Observed pending undo-record count.
    pub undo_records: u32,
    /// Observed pending undo byte count.
    pub undo_bytes: u32,
}
impl<'a> NtfsLogTransactionEntry<'a> {
    /// Complete native slot bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Exact three reserved bytes.
    pub fn reserved_bytes(&self) -> &'a [u8] {
        &self.raw[5..8]
    }
    /// Unknown bytes following the admitted 40-byte prefix.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        &self.raw[40..]
    }
    /// Whether the original state is in the pinned known range zero through three.
    /// This is local state-code coverage, never transaction/replay readiness.
    pub fn state_semantics_supported(&self) -> bool {
        self.raw[4] <= 3
    }
}
impl NtfsLogCheckpointDumpReport {
    /// Join one allocated dirty-page target to an allocated open-attribute slot.
    ///
    /// Returns None only when the dirty table is absent or its requested slot is
    /// free/out of range. An allocated dirty slot requires a present validated
    /// open table and an aligned in-range target referencing an allocated entry.
    /// This joins immutable bytes within one checkpoint context; it does not
    /// validate FILE ownership, attribute existence, chronology or replay safety.
    pub fn dirty_page_open_attribute(
        &self,
        index: usize,
    ) -> Result<Option<NtfsLogDirtyPageOpenAttribute<'_>>> {
        let Some(dirty) = self.dirty_page_entry(index)? else {
            return Ok(None);
        };
        let target_offset = le32(dirty.raw(), 4);
        let dump = &self.dumps()[0];
        if dump.reference().bytes == 0 || !dump.table_validated() {
            return Err(invalid("NTFS dirty page target open table unavailable"));
        }
        let client = self.dump_client(0)?;
        let table = client.redo();
        let stride = usize::from(le16(table, 0));
        let capacity = usize::from(le16(table, 2));
        let offset = usize::try_from(target_offset)
            .map_err(|_| invalid("NTFS dirty page target offset width"))?;
        if offset < 24 || !(offset - 24).is_multiple_of(stride) {
            return Err(invalid("NTFS dirty page target slot alignment"));
        }
        let target_index = (offset - 24) / stride;
        if target_index >= capacity {
            return Err(invalid("NTFS dirty page target slot bounds"));
        }
        let open = self
            .open_attribute_entry(target_index)?
            .ok_or_else(|| invalid("NTFS dirty page target references free open slot"))?;
        Ok(Some(NtfsLogDirtyPageOpenAttribute {
            dirty,
            open,
            target_index,
            target_offset,
        }))
    }
    /// Borrow one allocated open-table slot under immutable client-version-1.0 framing.
    /// Returns None for absent tables, free slots or out-of-range indices.
    pub fn open_attribute_entry(
        &self,
        index: usize,
    ) -> Result<Option<NtfsLogOpenAttributeEntry<'_>>> {
        let Some(raw) = self.allocated_table_slot(0, index)? else {
            return Ok(None);
        };
        if raw.len() < 40 {
            return Err(invalid("NTFS open attribute entry prefix"));
        }
        Ok(Some(NtfsLogOpenAttributeEntry {
            raw,
            bytes_per_index: le32(raw, 4),
            attribute_type: le32(raw, 8),
            file_reference: le64(raw, 16),
            open_record_lsn: le64(raw, 24),
        }))
    }
    /// Borrow one allocated dirty-page slot, validating only its declared LCN bounds.
    /// Returns None for absent tables, free slots or out-of-range indices.
    pub fn dirty_page_entry(&self, index: usize) -> Result<Option<NtfsLogDirtyPageEntry<'_>>> {
        let Some(raw) = self.allocated_table_slot(2, index)? else {
            return Ok(None);
        };
        if raw.len() < 32 {
            return Err(invalid("NTFS dirty page entry prefix"));
        }
        let lcn_count = le32(raw, 12);
        let lcn_end = usize::try_from(lcn_count)
            .ok()
            .and_then(|count| count.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or_else(|| invalid("NTFS dirty page LCN size"))?;
        if lcn_end > raw.len() {
            return Err(invalid("NTFS dirty page LCN bounds"));
        }
        Ok(Some(NtfsLogDirtyPageEntry {
            raw,
            lcn_end,
            target_attribute: le32(raw, 4),
            transfer_bytes: le32(raw, 8),
            lcn_count,
            target_vcn: le64(raw, 16) as i64,
            oldest_lsn: le64(raw, 24),
        }))
    }
    /// Borrow one allocated transaction slot, preserving unknown state codes.
    /// Returns None for absent tables, free slots or out-of-range indices.
    pub fn transaction_entry(&self, index: usize) -> Result<Option<NtfsLogTransactionEntry<'_>>> {
        let Some(raw) = self.allocated_table_slot(3, index)? else {
            return Ok(None);
        };
        if raw.len() < 40 {
            return Err(invalid("NTFS transaction entry prefix"));
        }
        Ok(Some(NtfsLogTransactionEntry {
            raw,
            state: raw[4],
            first_lsn: le64(raw, 8),
            previous_lsn: le64(raw, 16),
            undo_next_lsn: le64(raw, 24),
            undo_records: le32(raw, 32),
            undo_bytes: le32(raw, 36),
        }))
    }
}
