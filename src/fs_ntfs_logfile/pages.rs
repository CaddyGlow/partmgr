//! Physical RCRD inventory for the exact restart versions 1.1 and 2.0.
//! Physical page roles and local framing never establish the active log window.
use super::*;

/// Independent physical-candidate ceilings, in addition to restart inspection.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogPageLimits {
    /// Maximum candidates retained, counting both tail copies.
    pub pages: usize,
    /// Maximum raw candidate bytes retained; restart bytes and scratch are separate.
    pub retained_bytes: usize,
    /// Aggregate read/framing/fixup work for physical candidates.
    pub work: usize,
}
/// Physical location only; neither tail copy is selected as authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogPageRole {
    /// The two physical tail slots at offsets 8192 and 12288.
    TailCopy {
        /// Zero-based physical tail slot.
        index: u8,
    },
    /// One of the 32 version-2.0 recovery copies, never selected or applied.
    FastCopy {
        /// Zero-based physical slot at pages 2 through 33.
        index: u8,
    },
    /// An ordinary physical slot: page 4 for 1.1, page 34 for 2.0 and onward.
    Ordinary,
}
/// Raw candidate class, independent of local header validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogPageKind {
    /// `RCRD` signature.
    Record,
    /// Entire observed candidate is zero-filled.
    UninitializedZero,
    /// Entire observed candidate is `0xff`-filled.
    UninitializedOnes,
    /// Another signature, or an unfinished read.
    Unknown,
}
/// Fixed-up header observations after local framing checks.
/// LSNs remain opaque; transfer neighbors and generation are not validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogPageHeader {
    /// Header 08 union: LSN on ordinary/fast pages, file offset on 1.1 tail copies.
    pub raw_lsn_or_file_offset: u64,
    /// Version-2.0 fast-copy destination from offset `0x3c`, if that is the role.
    /// Its presence alone does not establish valid bounds or select the copy;
    /// inspect the observation's original error for local admission failure.
    pub fast_copy_target: Option<u32>,
    /// Whether the fast-copy destination passed alignment and usable-region bounds.
    /// False on other roles and on malformed or unchecked destinations.
    pub fast_copy_target_checked: bool,
    /// Exact page flags; only bit0 has admitted local meaning.
    pub flags: u32,
    /// Encoded pages in this transfer; no neighboring transfer is inferred.
    pub page_count: u16,
    /// Encoded one-based transfer position, locally bounded by page_count.
    pub page_position: u16,
    /// Exact next-record offset, potentially unused or stale.
    pub next_record_offset: u16,
    /// Native last-ended LSN; no active-window or chronology inference.
    pub last_end_lsn: u64,
    /// Whether next-record offset passed the conditional local bounds check.
    /// False means unvalidated/unused, never a validated payload range.
    pub next_record_offset_checked: bool,
}
/// One leased candidate, including unsupported or malformed observations.
pub struct NtfsLogPageObservation {
    offset: u64,
    role: NtfsLogPageRole,
    raw: Vec<u8>,
    read_complete: bool,
    kind: NtfsLogPageKind,
    header: Option<NtfsLogPageHeader>,
    error: Option<Error>,
    _reservation: Reservation,
}
impl NtfsLogPageObservation {
    /// Exact offset in the supplied native log stream.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Physical role without tail selection or active-log membership.
    pub fn role(&self) -> NtfsLogPageRole {
        self.role
    }
    /// Raw bytes before USA fixups; unfinished reads are not validated evidence.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Whether the complete backend candidate read finished.
    pub fn read_complete(&self) -> bool {
        self.read_complete
    }
    /// Raw signature/erasure class.
    pub fn kind(&self) -> NtfsLogPageKind {
        self.kind
    }
    /// Locally framed fixed-up fields, preserved even for unknown page flags.
    pub fn header(&self) -> Option<&NtfsLogPageHeader> {
        self.header.as_ref()
    }
    /// Original local/I/O/resource failure, including unsupported page flags.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
    /// Whether USA and local header framing passed; destination bounds are separate.
    /// Inspect `fast_copy_target_checked` for a fast-copy destination.
    pub fn framing_valid(&self) -> bool {
        self.header.is_some()
    }
    /// Whether local flag coverage is supported; never transaction coverage.
    /// Tail destinations, transfer neighbors and active membership remain unvalidated.
    pub fn semantics_supported(&self) -> bool {
        self.header.is_some() && self.error.is_none()
    }
}
enum StopReason {
    Page(usize),
    Restart(usize),
    RestartSource,
    Source,
    Global(Error),
}
/// Bounded physical observations plus their independently inspected restarts.
pub struct NtfsLogPageReport {
    restart: NtfsLogFileReport,
    pages: Vec<NtfsLogPageObservation>,
    complete: bool,
    stop: Option<StopReason>,
    source_error: Option<Error>,
    work: usize,
    retained: usize,
    _reservation: Option<Reservation>,
}
impl NtfsLogPageReport {
    /// Independently retained restart copies and their own support/failure state.
    pub fn restart(&self) -> &NtfsLogFileReport {
        &self.restart
    }
    /// Physical candidates in offset order, including local format failures.
    pub fn pages(&self) -> &[NtfsLogPageObservation] {
        &self.pages
    }
    /// Whether every declared physical slot was read/observed and final guards passed.
    /// Local malformed, erased and unsupported candidates do not imply activity
    /// and do not prevent enumeration completion.
    pub fn scan_complete(&self) -> bool {
        self.complete
    }
    /// Original error stopping enumeration, retaining its underlying I/O cause.
    pub fn stopping_error(&self) -> Option<&Error> {
        match self.stop.as_ref()? {
            StopReason::Page(index) => self.pages[*index].error(),
            StopReason::Restart(index) => self.restart.copies()[*index].area().err(),
            StopReason::RestartSource => self.restart.source_error(),
            StopReason::Source => self.source_error.as_ref(),
            StopReason::Global(error) => Some(error),
        }
    }
    /// Final cancellation or source-length guard failure, independent of prior errors.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref()
    }
    /// Physical-candidate work charged, excluding separately bounded restart work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Raw physical-candidate bytes retained, excluding restart bytes and scratch.
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    /// Always false: active-window ordering and tail selection are unimplemented.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: records, transaction tables and redo/undo are unparsed.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
}
fn stop(report: &mut NtfsLogPageReport, error: Error) {
    report.stop = Some(StopReason::Global(error));
}
/// Inventory both tail slots and ordinary physical pages without identifying activity.
///
/// Both restart areas must validate the same supported version and agree on usable file size
/// and page data offset. Other restart disagreement remains visible and is not
/// resolved by this scan. Every physical slot from 8192 to the shared usable end
/// is observed. Malformed/unsupported pages remain in the report while scanning
/// continues; I/O, cancellation, source-change and budget failures stop scanning
/// and retain all prior observations and the original failure. `Err` is limited
/// to restart preflight failures for which no leased restart report exists.
pub fn inspect_logfile_pages(
    source: Arc<dyn ReadAt>,
    restart_limits: NtfsLogFileLimits,
    page_limits: NtfsLogPageLimits,
    r: &Resources,
) -> Result<NtfsLogPageReport> {
    let restart = inspect_logfile(source.clone(), restart_limits, r)?;
    let source_bytes = restart.source_bytes();
    let mut report = NtfsLogPageReport {
        restart,
        pages: Vec::new(),
        complete: false,
        stop: None,
        source_error: None,
        work: 0,
        retained: 0,
        _reservation: None,
    };
    if report.restart.source_error().is_some() {
        report.stop = Some(StopReason::RestartSource);
        return Ok(report);
    }
    let geometry = match (
        report.restart.copies()[0].area(),
        report.restart.copies()[1].area(),
    ) {
        (Ok(a), Ok(b)) if a.version != b.version => {
            stop(
                &mut report,
                unsupported("NTFS physical log mixed version profile"),
            );
            return Ok(report);
        }
        (Ok(a), Ok(b))
            if a.version == b.version
                && a.file_bytes == b.file_bytes
                && a.page_data_offset == b.page_data_offset =>
        {
            (a.file_bytes, a.page_data_offset, a.version)
        }
        (Err(_), _) => {
            report.stop = Some(StopReason::Restart(0));
            return Ok(report);
        }
        (_, Err(_)) => {
            report.stop = Some(StopReason::Restart(1));
            return Ok(report);
        }
        _ => {
            stop(
                &mut report,
                invalid("NTFS physical log restart geometry disagreement"),
            );
            return Ok(report);
        }
    };
    if let Err(error) = r.cancellation.check() {
        stop(&mut report, error);
        return Ok(report);
    }
    if source.len() != source_bytes {
        stop(
            &mut report,
            Error::new(
                ErrorKind::StalePlan,
                "NTFS physical log source length changed",
            ),
        );
        return Ok(report);
    }
    let total = match usize::try_from(geometry.0 / PAGE as u64 - 2) {
        Ok(total) => total,
        Err(_) => {
            stop(&mut report, exhausted("NTFS physical log candidate count"));
            return Ok(report);
        }
    };
    let capacity = page_limits
        .pages
        .min(total)
        .min(page_limits.retained_bytes / PAGE);
    let charge = (capacity as u64)
        .checked_mul(crate::platform::mem::size_of::<NtfsLogPageObservation>() as u64)
        .and_then(|n| n.checked_add(2048));
    let lease = match charge
        .ok_or_else(|| exhausted("NTFS physical log inventory charge"))
        .and_then(|charge| r.memory.reserve(charge))
    {
        Ok(lease) => lease,
        Err(error) => {
            stop(&mut report, error);
            return Ok(report);
        }
    };
    if report.pages.try_reserve_exact(capacity).is_err() {
        stop(
            &mut report,
            exhausted("NTFS physical log inventory allocation"),
        );
        return Ok(report);
    }
    report._reservation = Some(lease);
    let mut work = Work {
        used: 0,
        maximum: page_limits.work,
    };
    for index in 0..total {
        if index == page_limits.pages {
            stop(&mut report, exhausted("NTFS physical log page ceiling"));
            break;
        }
        if page_limits.retained_bytes.saturating_sub(report.retained) < PAGE {
            stop(
                &mut report,
                exhausted("NTFS physical log retained-byte ceiling"),
            );
            break;
        }
        if let Err(error) = work.tick(r) {
            stop(&mut report, error);
            break;
        }
        let reservation = match r.memory.reserve((PAGE + 1024) as u64) {
            Ok(lease) => lease,
            Err(error) => {
                stop(&mut report, error);
                break;
            }
        };
        let raw = match page_buffer() {
            Ok(raw) => raw,
            Err(error) => {
                stop(&mut report, error);
                break;
            }
        };
        let offset = (index as u64 + 2) * PAGE as u64;
        let role = if geometry.2 == (2, 0) && index < 32 {
            NtfsLogPageRole::FastCopy { index: index as u8 }
        } else if geometry.2 == (1, 1) && index < 2 {
            NtfsLogPageRole::TailCopy { index: index as u8 }
        } else {
            NtfsLogPageRole::Ordinary
        };
        let mut observation = NtfsLogPageObservation {
            offset,
            role,
            raw,
            read_complete: false,
            kind: NtfsLogPageKind::Unknown,
            header: None,
            error: None,
            _reservation: reservation,
        };
        let processed = (|| {
            if source.len() != source_bytes {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS physical log source length changed",
                ));
            }
            source
                .read_exact_at(offset, &mut observation.raw)
                .map_err(|e| Error::io("NTFS physical log page read", e))?;
            observation.read_complete = true;
            work.tick(r)?;
            observation.kind = if observation.raw.iter().all(|b| *b == 0) {
                NtfsLogPageKind::UninitializedZero
            } else if observation.raw.iter().all(|b| *b == 0xff) {
                NtfsLogPageKind::UninitializedOnes
            } else if &observation.raw[..4] == b"RCRD" {
                NtfsLogPageKind::Record
            } else {
                NtfsLogPageKind::Unknown
            };
            if observation.kind != NtfsLogPageKind::Record {
                return Err(unsupported("NTFS physical log page signature/state"));
            }
            let header = frame_header(&observation.raw, role, geometry.1, &mut work, r)?;
            observation.header = Some(header);
            if let Some(target) = header.fast_copy_target {
                let target = u64::from(target);
                if !target.is_multiple_of(PAGE as u64)
                    || target < (34 * PAGE) as u64
                    || target >= geometry.0
                {
                    return Err(invalid("NTFS fast log copy destination bounds"));
                }
                if let Some(header) = observation.header.as_mut() {
                    header.fast_copy_target_checked = true;
                }
            }
            if header.flags & !1 != 0 {
                return Err(unsupported("NTFS physical log page flags"));
            }
            r.cancellation.check()?;
            Ok(())
        })();
        observation.error = processed.err();
        let fatal = observation.error().is_some_and(|error| {
            !observation.read_complete
                || !matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported)
        });
        report.retained += PAGE;
        report.pages.push(observation);
        if fatal {
            report.stop = Some(StopReason::Page(index));
            break;
        }
    }
    report.work = work.used;
    report.source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != source_bytes).then(|| {
            Error::new(
                ErrorKind::StalePlan,
                "NTFS physical log source length changed",
            )
        })
    });
    if report.source_error.is_some() && report.stop.is_none() {
        report.stop = Some(StopReason::Source);
    }
    report.complete = report.stop.is_none() && report.pages.len() == total;
    Ok(report)
}
pub(super) fn frame_header(
    raw: &[u8],
    role: NtfsLogPageRole,
    data_offset: u16,
    work: &mut Work,
    r: &Resources,
) -> Result<NtfsLogPageHeader> {
    let usa = usize::from(le16(raw, 4));
    let count = usize::from(le16(raw, 6));
    if usa < 40
        || !usa.is_multiple_of(2)
        || count != 9
        || usa + count * 2 > 510
        || usa + count * 2 > usize::from(data_offset)
        || matches!(role, NtfsLogPageRole::FastCopy { .. }) && usa + count * 2 > 60
    {
        return Err(invalid("NTFS physical log USA placement"));
    }
    let _scratch = r.memory.reserve(PAGE as u64)?;
    let mut page = page_buffer()?;
    page.copy_from_slice(raw);
    for sector in 1..count {
        work.tick(r)?;
        let trailer = sector * 512 - 2;
        if le16(&page, trailer) != le16(raw, usa) {
            return Err(invalid("NTFS torn physical log page USA"));
        }
        page[trailer..trailer + 2].copy_from_slice(&raw[usa + sector * 2..usa + sector * 2 + 2]);
    }
    let flags = le32(&page, 16);
    let page_count = le16(&page, 20);
    let page_position = le16(&page, 22);
    if page_position == 0 || page_count == 0 || page_position > page_count {
        return Err(invalid("NTFS physical log transfer bounds"));
    }
    let raw_lsn_or_file_offset = le64(&page, 8);
    let last_end_lsn = le64(&page, 32);
    let next_record_offset = le16(&page, 24);
    let next_record_offset_checked = !matches!(role, NtfsLogPageRole::TailCopy { .. })
        && flags & 1 != 0
        && raw_lsn_or_file_offset <= last_end_lsn;
    if next_record_offset_checked
        && (!next_record_offset.is_multiple_of(8)
            || next_record_offset < data_offset
            || usize::from(next_record_offset) > PAGE)
    {
        return Err(invalid("NTFS physical log next-record bounds"));
    }
    work.tick(r)?;
    Ok(NtfsLogPageHeader {
        raw_lsn_or_file_offset,
        fast_copy_target: matches!(role, NtfsLogPageRole::FastCopy { .. }).then(|| le32(&page, 60)),
        fast_copy_target_checked: false,
        flags,
        page_count,
        page_position,
        next_record_offset,
        last_end_lsn,
        next_record_offset_checked,
    })
}

/// Physical page observations bound to the resolved native `$LogFile` owner.
pub struct NtfsVolumeLogPageReport {
    /// Source-scoped identity of native base record 2.
    pub owner: crate::fs_core::ObjectId,
    /// Exact native volume flags, independently observed from the journal.
    pub volume_flags: u16,
    /// Physical headers and restart copies; no active-window or replay claim.
    pub report: NtfsLogPageReport,
}
/// Resolve record 2's ordinary initialized DATA and inventory its physical pages.
///
/// Uses the same native stream admission as [`inspect_ntfs_logfile`]. Final
/// volume source guards remain independent of the selected stream's guards.
pub fn inspect_ntfs_logfile_pages(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    restart_limits: NtfsLogFileLimits,
    page_limits: NtfsLogPageLimits,
    r: &Resources,
) -> Result<NtfsVolumeLogPageReport> {
    r.cancellation.check()?;
    if restart_limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_pages(Arc::new(native), restart_limits, page_limits, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
        report.complete = false;
        if report.stop.is_none() {
            report.stop = Some(StopReason::Source);
        }
    }
    Ok(NtfsVolumeLogPageReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
