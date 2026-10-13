//! Exact record assembly, without authoritative active-window selection.
use super::*;

/// Caller-selected structural context, never an authoritative restart decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogRecordQuery {
    /// Exact native LSN to assemble.
    pub lsn: u64,
    /// Independently inspected restart slot, zero or one.
    pub restart_copy: u8,
}

/// Independent ceilings for one exact-LSN query, excluding restart inspection.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRecordLimits {
    /// Maximum physical pages retained, including a failing candidate.
    pub pages: usize,
    /// Maximum declared client payload allocation.
    pub payload_bytes: usize,
    /// Aggregate page, fixup and payload-copy work.
    pub work: usize,
}
/// Decoded LFS envelope; its client payload remains opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogRecordHeader {
    /// Exact requested LSN.
    pub this_lsn: u64,
    /// Unfollowed native client predecessor.
    pub previous_lsn: u64,
    /// Unfollowed native undo predecessor.
    pub undo_next_lsn: u64,
    /// Declared client payload bytes.
    pub payload_bytes: u32,
    /// Native client sequence.
    pub client_sequence: u16,
    /// Native client slot.
    pub client_index: u16,
    /// Supported envelope type: client record 1 or client restart 2.
    pub record_type: u32,
    /// Opaque native transaction identifier.
    pub transaction_id: u32,
    /// Native envelope flags; multipage bit 1 is interpreted and bit 4 is opaque.
    pub flags: u16,
}
/// Physical extent of a complete source-owned record, including its LFS header.
/// Page headers skipped during continuation are excluded from record bytes.
/// Physical wrap counts do not establish LSN generation or active membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogRecordExtent {
    final_byte_offset: u64,
    final_page_offset: u64,
    physical_wraps: usize,
}
impl NtfsLogRecordExtent {
    /// Inclusive stream offset of the final payload byte, or final LFS header
    /// byte when the client payload is empty. Alignment padding is excluded.
    pub fn final_byte_offset(&self) -> u64 {
        self.final_byte_offset
    }
    /// Physical stream offset of the page containing that final byte.
    pub fn final_page_offset(&self) -> u64 {
        self.final_page_offset
    }
    /// End-to-ordinary-start transitions actually traversed during assembly.
    /// This is physical provenance, never an inferred LSN sequence increment.
    pub fn physical_wraps(&self) -> usize {
        self.physical_wraps
    }
}
/// Protected source bytes supporting an exact record query.
pub struct NtfsLogRecordPage {
    offset: u64,
    raw: Vec<u8>,
    header: Option<NtfsLogPageHeader>,
    read_complete: bool,
    _reservation: Reservation,
}
impl NtfsLogRecordPage {
    /// Exact physical stream position.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Protected bytes before fixups; incomplete reads are not evidence.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Locally validated page framing, if available.
    pub fn header(&self) -> Option<&NtfsLogPageHeader> {
        self.header.as_ref()
    }
    /// Whether the entire source read completed.
    pub fn read_complete(&self) -> bool {
        self.read_complete
    }
}
/// Detailed exact query, preserving validated evidence and original failures.
pub struct NtfsLogRecordReport {
    restart: NtfsLogFileReport,
    requested_copy: Option<u8>,
    context_copy: Option<usize>,
    blocking_restart: Option<usize>,
    header: Option<NtfsLogRecordHeader>,
    extent: Option<NtfsLogRecordExtent>,
    pages: Vec<NtfsLogRecordPage>,
    payload: Vec<u8>,
    complete: bool,
    error: Option<Error>,
    source_error: Option<Error>,
    work: usize,
    _inventory: Option<Reservation>,
    _payload: Option<Reservation>,
}
impl NtfsLogRecordReport {
    /// Source-bound independently inspected restart copies.
    pub fn restart(&self) -> &NtfsLogFileReport {
        &self.restart
    }
    /// Explicitly requested slot, or None for the strict matching-copy API.
    pub fn requested_restart_copy(&self) -> Option<u8> {
        self.requested_copy
    }
    /// Validated context admitted for structural querying, never a newest-restart claim.
    pub fn restart_context(&self) -> Option<&NtfsRestartArea> {
        self.restart.copies()[self.context_copy?].area().ok()
    }
    /// Decoded envelope, retained even after a later unsupported field/failure.
    pub fn header(&self) -> Option<&NtfsLogRecordHeader> {
        self.header.as_ref()
    }
    /// Structurally assembled fixed-up client payload; never partial bytes.
    /// Page flag semantics may remain opaque; this does not establish activity.
    pub fn payload(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.payload)
    }
    /// Immutable physical endpoint after all assembly and final source guards.
    /// No successor LSN, tail selection or active membership is inferred.
    pub fn extent(&self) -> Option<&NtfsLogRecordExtent> {
        if self.complete {
            self.extent.as_ref()
        } else {
            None
        }
    }
    /// Raw physical provenance in assembly order.
    pub fn pages(&self) -> &[NtfsLogRecordPage] {
        &self.pages
    }
    /// Exact record structurally assembled and final source/cancellation guards passed.
    /// Opaque page bit `0x2` and envelope bit `0x4` retain no assigned meaning.
    pub fn complete(&self) -> bool {
        self.complete
    }
    /// Whether all structurally assembled pages have understood local flag bits.
    /// False for opaque bit `0x2` or incomplete assembly. This only describes
    /// page flags, never active-window membership or transaction semantics.
    pub fn page_flag_semantics_supported(&self) -> bool {
        self.complete
            && self.pages.iter().all(|page| {
                page.header
                    .as_ref()
                    .is_some_and(|header| header.flags & !1 == 0)
            })
    }
    /// Whether the complete LFS envelope uses only understood flag bits.
    /// Opaque bit `0x4` makes this false; page flags are reported separately.
    pub fn envelope_flag_semantics_supported(&self) -> bool {
        self.complete
            && self
                .header
                .as_ref()
                .is_some_and(|header| header.flags & !1 == 0)
    }
    /// Original stopping failure; restart errors remain in `restart()`.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.restart
            .source_error()
            .or_else(|| {
                self.blocking_restart
                    .and_then(|i| self.restart.copies()[i].area().err())
            })
            .or(self.error.as_ref())
            .or(self.source_error.as_ref())
    }
    /// Independent final source or cancellation failure.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref()
    }
    pub(super) fn retained_payload_bytes(&self) -> usize {
        if self._payload.is_some() {
            self.header.as_ref().map_or(0, |h| h.payload_bytes as usize)
        } else {
            0
        }
    }
    /// Query work charged, excluding restart work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: no active-window selection is performed.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: payload operations and transaction tables are undecoded.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
}

/// Assemble one exact LSN against matching supported source-bound restarts.
///
/// No tail replacement, successor inference, transaction interpretation or replay
/// is performed. The caller must keep source contents immutable. Equal lengths
/// cannot detect same-length mutation. Once restart evidence exists, failures
/// return a detailed incomplete report retaining prior page provenance.
pub fn inspect_logfile_record(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    lsn: u64,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    inspect_record(source, restart_limits, limits, (lsn, None), r)
}

/// Query one explicitly named source-bound restart context, without fast overlays.
/// Unselected format failures remain diagnostic; incomplete reads, I/O,
/// cancellation, source changes and resource failures block assembly.
pub fn inspect_logfile_record_in_restart(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    query: NtfsLogRecordQuery,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    inspect_record(
        source,
        restart_limits,
        limits,
        (query.lsn, Some(query.restart_copy)),
        r,
    )
}

fn inspect_record(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    query: (u64, Option<u8>),
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    inspect_record_with_work(source, restart_limits, limits, query, usize::MAX, r)
}

pub(super) fn inspect_record_with_work(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    query: (u64, Option<u8>),
    maximum_work: usize,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    inspect_envelope_with_work(source, restart_limits, limits, query, maximum_work, true, r)
}

// Private physical framing permits native forward traversal to retain and skip
// foreign clients/non-client-record envelopes. Public exact-client queries keep
// their previous identity/type admission through the strict wrapper above.
pub(super) fn inspect_physical_envelope_with_work(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    query: (u64, Option<u8>),
    maximum_work: usize,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    inspect_envelope_with_work(
        source,
        restart_limits,
        limits,
        query,
        maximum_work,
        false,
        r,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_envelope_with_work(
    source: Arc<dyn ReadAt>,
    mut restart_limits: NtfsLogFileLimits,
    mut limits: NtfsLogRecordLimits,
    query: (u64, Option<u8>),
    maximum_work: usize,
    exact_client: bool,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    restart_limits.work = restart_limits.work.min(maximum_work);
    let restart = inspect_logfile(source.clone(), restart_limits, r)?;
    limits.work = limits.work.min(maximum_work.saturating_sub(restart.work()));
    let mut report = NtfsLogRecordReport {
        restart,
        requested_copy: query.1,
        context_copy: None,
        blocking_restart: None,
        header: None,
        extent: None,
        pages: Vec::new(),
        payload: Vec::new(),
        complete: false,
        error: None,
        source_error: None,
        work: 0,
        _inventory: None,
        _payload: None,
    };
    let source_bytes = report.restart.source_bytes();
    let mut work = Work {
        used: 0,
        maximum: limits.work,
    };
    let result = assemble(
        &source,
        source_bytes,
        limits,
        query.0,
        exact_client,
        &mut report,
        &mut work,
        r,
    );
    report.error = result.err();
    report.work = work.used;
    report.source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != source_bytes)
            .then(|| Error::new(ErrorKind::StalePlan, "NTFS record source length changed"))
    });
    report.complete = report.error.is_none() && report.source_error.is_none();
    if !report.complete {
        report.extent = None;
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    source: &Arc<dyn ReadAt>,
    source_bytes: u64,
    limits: NtfsLogRecordLimits,
    lsn: u64,
    exact_client: bool,
    report: &mut NtfsLogRecordReport,
    work: &mut Work,
    r: &Resources,
) -> Result<()> {
    if report.restart.source_error().is_some() {
        return Err(invalid("NTFS exact record restart unavailable"));
    }
    let selected = usize::from(report.requested_copy.unwrap_or(0));
    if selected > 1 {
        return Err(invalid("NTFS exact record restart slot"));
    }
    for (index, copy) in report.restart.copies().iter().enumerate() {
        if let Err(error) = copy.area()
            && (report.requested_copy.is_none()
                || index == selected
                || !copy.read_complete()
                || !matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported))
        {
            report.blocking_restart = Some(index);
            return Err(invalid("NTFS exact record restart unavailable"));
        }
    }
    let a = *report.restart.copies()[selected]
        .area()
        .map_err(|_| invalid("NTFS record restart"))?;
    if report.requested_copy.is_none() {
        let b = report.restart.copies()[1]
            .area()
            .map_err(|_| invalid("NTFS record restart"))?;
        if &a != b {
            return Err(invalid("NTFS exact record ambiguous restart copies"));
        }
    }
    let first_page = match a.version {
        (1, 1) => 4u64,
        (2, 0) => 34u64,
        _ => return Err(unsupported("NTFS exact record version profile")),
    };
    report.context_copy = Some(selected);
    if a.client_count != 1 || a.in_use_head != 0 || a.client_sequence.is_none() {
        return Err(unsupported("NTFS exact record active client profile"));
    }
    let bits = 64u32
        .checked_sub(a.sequence_bits)
        .ok_or_else(|| invalid("NTFS record sequence bits"))?;
    let mask = 1u64
        .checked_shl(bits)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| invalid("NTFS record LSN mask"))?;
    let address = (lsn & mask)
        .checked_mul(8)
        .ok_or_else(|| invalid("NTFS record address overflow"))?;
    let mut position =
        usize::try_from(address % PAGE as u64).map_err(|_| invalid("NTFS record position"))?;
    if lsn == 0
        || address < first_page * PAGE as u64
        || address >= a.file_bytes
        || position < usize::from(a.page_data_offset)
        || position + 48 > PAGE
    {
        return Err(invalid("NTFS exact record address"));
    }
    let total_pages = usize::try_from(a.file_bytes / PAGE as u64 - first_page)
        .map_err(|_| exhausted("NTFS record page count"))?;
    // A record starting late in its first page can wrap and consume the prefix
    // of that same page. The available-byte bound below prevents overlap with
    // its own header, but permits N + 1 physical reads for N ordinary pages.
    let maximum_visits = total_pages
        .checked_add(1)
        .ok_or_else(|| exhausted("NTFS record page visit count"))?;
    let capacity = limits.pages.min(maximum_visits);
    let charge = (capacity as u64)
        .checked_mul(core::mem::size_of::<NtfsLogRecordPage>() as u64)
        .and_then(|v| v.checked_add(1024))
        .ok_or_else(|| exhausted("NTFS record inventory charge"))?;
    report._inventory = Some(r.memory.reserve(charge)?);
    report
        .pages
        .try_reserve_exact(capacity)
        .map_err(|_| exhausted("NTFS record inventory allocation"))?;
    if report.pages.capacity() > capacity {
        return Err(exhausted("NTFS record inventory capacity"));
    }
    let mut offset = address & !(PAGE as u64 - 1);
    let mut copied = 0usize;
    let mut physical_wraps = 0usize;
    loop {
        work.tick(r)?;
        if report.pages.len() >= capacity {
            return Err(exhausted("NTFS record page ceiling"));
        }
        if source.len() != source_bytes {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS record source length changed",
            ));
        }
        let reservation = r.memory.reserve((PAGE + 1024) as u64)?;
        let raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS record raw capacity"));
        }
        report.pages.push(NtfsLogRecordPage {
            offset,
            raw,
            header: None,
            read_complete: false,
            _reservation: reservation,
        });
        let page = report
            .pages
            .last_mut()
            .ok_or_else(|| invalid("NTFS record page missing"))?;
        source
            .read_exact_at(offset, &mut page.raw)
            .map_err(|e| Error::io("NTFS exact record page read", e))?;
        page.read_complete = true;
        work.tick(r)?;
        if &page.raw[..4] != b"RCRD" {
            return Err(unsupported("NTFS exact record page signature"));
        }
        let h = pages::frame_header(
            &page.raw,
            NtfsLogPageRole::Ordinary,
            a.page_data_offset,
            work,
            r,
        )?;
        page.header = Some(h);
        // Pinned Linux/dfir readers use the same protected page/payload layout
        // with bit 0x2 present. Its meaning is deliberately not interpreted;
        // report local semantic coverage separately from structural assembly.
        if h.flags & !3 != 0 {
            return Err(unsupported("NTFS exact record page flags"));
        }
        if h.raw_lsn_or_file_offset < lsn {
            return Err(invalid("NTFS exact record page LSN bound"));
        }
        let _scratch = r.memory.reserve(PAGE as u64)?;
        let mut decoded = page_buffer()?;
        if decoded.capacity() > PAGE {
            return Err(exhausted("NTFS record scratch capacity"));
        }
        decoded.copy_from_slice(&page.raw);
        let usa = usize::from(le16(&decoded, 4));
        for sector in 1..9 {
            work.tick(r)?;
            let trailer = sector * 512 - 2;
            decoded[trailer..trailer + 2]
                .copy_from_slice(&page.raw[usa + sector * 2..usa + sector * 2 + 2]);
        }
        if report.header.is_none() {
            let bytes = &decoded[position..position + 48];
            let header = NtfsLogRecordHeader {
                this_lsn: le64(bytes, 0),
                previous_lsn: le64(bytes, 8),
                undo_next_lsn: le64(bytes, 16),
                payload_bytes: le32(bytes, 24),
                client_sequence: le16(bytes, 28),
                client_index: le16(bytes, 30),
                record_type: le32(bytes, 32),
                transaction_id: le32(bytes, 36),
                flags: le16(bytes, 40),
            };
            report.header = Some(header);
            if header.this_lsn != lsn
                || (exact_client
                    && (header.client_index != 0
                        || Some(header.client_sequence) != a.client_sequence))
            {
                return Err(invalid("NTFS exact record LSN/client identity"));
            }
            if (exact_client && !matches!(header.record_type, 1 | 2)) || header.flags & !5 != 0 {
                return Err(unsupported("NTFS exact record envelope profile"));
            }
            let length = usize::try_from(header.payload_bytes)
                .map_err(|_| exhausted("NTFS record payload length"))?;
            let available = (a.file_bytes / PAGE as u64 - first_page)
                * (PAGE as u64 - u64::from(a.page_data_offset));
            if u64::from(header.payload_bytes) + 48 >= available {
                return Err(invalid("NTFS record exceeds available log"));
            }
            if length > limits.payload_bytes {
                return Err(exhausted("NTFS record payload ceiling"));
            }
            if header.flags & 1 == 0 && length > PAGE - position - 48 {
                return Err(invalid("NTFS record missing multipage flag"));
            }
            report._payload = Some(r.memory.reserve(length as u64)?);
            report
                .payload
                .try_reserve_exact(length)
                .map_err(|_| exhausted("NTFS record payload allocation"))?;
            if report.payload.capacity() > length {
                return Err(exhausted("NTFS record payload capacity"));
            }
            position += 48;
        }
        let length = report
            .header
            .ok_or_else(|| invalid("NTFS record header missing"))?
            .payload_bytes as usize;
        let count = (length - copied).min(PAGE - position);
        // Charge every copied byte so a large record cannot bypass the work bound.
        for _ in 0..count {
            work.tick(r)?;
        }
        report
            .payload
            .extend_from_slice(&decoded[position..position + count]);
        copied += count;
        if copied == length {
            if h.flags & 1 == 0 || h.last_end_lsn < lsn {
                return Err(invalid("NTFS record final completion evidence"));
            }
            r.cancellation.check()?;
            let final_in_page = position
                .checked_add(count)
                .and_then(|end| end.checked_sub(1))
                .ok_or_else(|| invalid("NTFS record endpoint bounds"))?;
            let final_byte_offset = offset
                .checked_add(final_in_page as u64)
                .ok_or_else(|| invalid("NTFS record endpoint overflow"))?;
            report.extent = Some(NtfsLogRecordExtent {
                final_byte_offset,
                final_page_offset: offset,
                physical_wraps,
            });
            return Ok(());
        }
        if h.raw_lsn_or_file_offset == h.last_end_lsn {
            return Err(invalid("NTFS record premature completion"));
        }
        offset += PAGE as u64;
        if offset == a.file_bytes {
            physical_wraps = physical_wraps
                .checked_add(1)
                .ok_or_else(|| invalid("NTFS record physical wrap overflow"))?;
            offset = first_page * PAGE as u64;
        }
        position = usize::from(a.page_data_offset);
    }
}

/// Exact record query bound to the resolved native `$LogFile` owner.
pub struct NtfsVolumeLogRecordReport {
    /// Source-scoped identity of base record 2.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Exact record evidence; no selected active window or recovery readiness.
    pub report: NtfsLogRecordReport,
}
/// Resolve ordinary initialized record-2 DATA and query one exact native LSN.
pub fn inspect_ntfs_logfile_record(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    lsn: u64,
    r: &Resources,
) -> Result<NtfsVolumeLogRecordReport> {
    r.cancellation.check()?;
    if restart_limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_record(Arc::new(native), restart_limits, limits, lsn, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
        report.complete = false;
    }
    Ok(NtfsVolumeLogRecordReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}

/// Resolve record-2 DATA and query an explicitly named native restart context.
/// Context selection is structural research, never authoritative tail selection.
pub fn inspect_ntfs_logfile_record_in_restart(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    restart_limits: NtfsLogFileLimits,
    limits: NtfsLogRecordLimits,
    query: NtfsLogRecordQuery,
    r: &Resources,
) -> Result<NtfsVolumeLogRecordReport> {
    r.cancellation.check()?;
    if restart_limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report =
        inspect_logfile_record_in_restart(Arc::new(native), restart_limits, limits, query, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
        report.complete = false;
    }
    Ok(NtfsVolumeLogRecordReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
