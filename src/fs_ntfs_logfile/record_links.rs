//! Source-owned bounded observations of explicitly selected LFS links.
use super::*;

/// One native header field to follow, without inferring transaction semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogRecordLinkKind {
    /// Native client previous-LSN field.
    Previous,
    /// Native undo-next-LSN field, without executing undo.
    UndoNext,
}
/// Per-query and aggregate ceilings for one structural link walk.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRecordLinkLimits {
    /// Restart ceilings per query, also constrained by aggregate work.
    pub restart: NtfsLogFileLimits,
    /// Exact record ceilings per query, also constrained by aggregate ceilings.
    pub record: NtfsLogRecordLimits,
    /// Maximum queried records, including the anchor and failed candidates.
    pub records: usize,
    /// Retained pages, including both restart buffers on each query.
    pub pages: usize,
    /// Aggregate declared retained client payload bytes.
    pub payload_bytes: usize,
    /// Query, restart, assembly, fixed-size context and cycle-comparison work.
    pub work: usize,
}
/// Observed termination, never proof of a complete historical log window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogRecordLinkTermination {
    /// A validated record's selected link was zero and final guards passed.
    ZeroLink,
    /// A failure or ceiling prevented validated zero-link closure.
    Incomplete,
}
/// Owned traversal evidence from one source and one caller-selected restart copy.
pub struct NtfsLogRecordLinkReport {
    kind: NtfsLogRecordLinkKind,
    records: Vec<NtfsLogRecordReport>,
    pending: Option<u64>,
    error: Option<Error>,
    source_error: Option<Error>,
    failed_record: Option<usize>,
    closed: bool,
    queries: usize,
    pages: usize,
    payload_bytes: usize,
    work: usize,
    _inventory: Reservation,
}
impl NtfsLogRecordLinkReport {
    /// Selected native link field.
    pub fn kind(&self) -> NtfsLogRecordLinkKind {
        self.kind
    }
    /// Queries in traversal order, including a retained failed/context-mismatched candidate.
    pub fn records(&self) -> &[NtfsLogRecordReport] {
        &self.records
    }
    /// Target not successfully admitted when traversal stopped, including cycle targets.
    pub fn pending_next_lsn(&self) -> Option<u64> {
        self.pending
    }
    /// Whether a zero link was observed with final guards passing; not complete history.
    pub fn complete(&self) -> bool {
        self.closed && self.stopping_error().is_none()
    }
    /// Explicit structural closure status.
    pub fn termination(&self) -> NtfsLogRecordLinkTermination {
        if self.complete() {
            NtfsLogRecordLinkTermination::ZeroLink
        } else {
            NtfsLogRecordLinkTermination::Incomplete
        }
    }
    /// Original stopping error; each query additionally retains its own evidence.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.failed_record
            .and_then(|i| self.records[i].stopping_error())
            .or(self.error.as_ref())
            .or(self.source_error.as_ref())
    }
    /// Independent final source/cancellation failure.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref()
    }
    /// Queries attempted, including an attempt that produced no record report.
    pub fn queries(&self) -> usize {
        self.queries
    }
    /// Aggregate retained restart and record pages.
    pub fn pages(&self) -> usize {
        self.pages
    }
    /// Aggregate declared retained client payload bytes.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Charged query, restart, assembly, context and cycle-comparison work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: neither active membership nor complete history is established.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: following a field does not execute or analyze transactions.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
}
fn tick(
    report: &mut NtfsLogRecordLinkReport,
    limits: NtfsLogRecordLinkLimits,
    r: &Resources,
) -> Result<()> {
    r.cancellation.check()?;
    if report.work >= limits.work {
        return Err(exhausted("NTFS record link work ceiling"));
    }
    report.work += 1;
    Ok(())
}
fn query_record(
    source: &Arc<dyn ReadAt>,
    limits: NtfsLogRecordLinkLimits,
    query: NtfsLogRecordQuery,
    report: &mut NtfsLogRecordLinkReport,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    r.cancellation.check()?;
    if report.queries >= limits.records || limits.pages.saturating_sub(report.pages) < 2 {
        return Err(exhausted("NTFS record link query/page ceiling"));
    }
    tick(report, limits, r)?;
    report.queries += 1;
    let mut record_limits = limits.record;
    record_limits.pages = record_limits.pages.min(limits.pages - report.pages - 2);
    record_limits.payload_bytes = record_limits
        .payload_bytes
        .min(limits.payload_bytes.saturating_sub(report.payload_bytes));
    let record = record::inspect_record_with_work(
        source.clone(),
        limits.restart,
        record_limits,
        (query.lsn, Some(query.restart_copy)),
        limits.work - report.work,
        r,
    )?;
    report.work += record.restart().work() + record.work();
    report.pages += 2 + record.pages().len();
    report.payload_bytes += record.retained_payload_bytes();
    Ok(record)
}
/// Observe a bounded native link chain from an exact LSN, retaining partial evidence.
///
/// Zero-link closure is structural, not proof of active membership or complete
/// history. No numeric chronology, transaction-ID equality, successor or replay
/// is inferred. Every admitted record uses the same original selected restart
/// bytes and decoded client context. Caller must keep the stream immutable;
/// equal-length checks cannot detect arbitrary concurrent same-length writes.
/// Preflight failures without any record report return Err; later failures retain
/// all prior and failing queried records plus the unadmitted target LSN.
pub fn inspect_logfile_record_links(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogRecordLinkLimits,
    query: NtfsLogRecordQuery,
    kind: NtfsLogRecordLinkKind,
    r: &Resources,
) -> Result<NtfsLogRecordLinkReport> {
    r.cancellation.check()?;
    let capacity = limits.records.min(limits.pages / 2).min(limits.work);
    if capacity == 0 {
        return Err(exhausted("NTFS record link inventory ceiling"));
    }
    let charge = capacity
        .checked_mul(core::mem::size_of::<NtfsLogRecordReport>())
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or_else(|| exhausted("NTFS record link inventory size"))?;
    let reservation = r.memory.reserve(
        u64::try_from(charge).map_err(|_| exhausted("NTFS record link inventory size"))?,
    )?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(capacity)
        .map_err(|_| exhausted("NTFS record link inventory allocation"))?;
    if records.capacity() > capacity {
        return Err(exhausted("NTFS record link inventory capacity"));
    }
    let length = source.len();
    let mut report = NtfsLogRecordLinkReport {
        kind,
        records,
        pending: Some(query.lsn),
        error: None,
        source_error: None,
        failed_record: None,
        closed: false,
        queries: 0,
        pages: 0,
        payload_bytes: 0,
        work: 0,
        _inventory: reservation,
    };
    let result = (|| {
        while let Some(lsn) = report.pending {
            for i in 0..report.records.len() {
                tick(&mut report, limits, r)?;
                if report.records[i]
                    .header()
                    .is_some_and(|h| h.this_lsn == lsn)
                {
                    return Err(invalid("NTFS record link cycle"));
                }
            }
            if report.records.len() >= capacity {
                return Err(exhausted("NTFS record link inventory ceiling"));
            }
            let record = query_record(
                &source,
                limits,
                NtfsLogRecordQuery { lsn, ..query },
                &mut report,
                r,
            )?;
            report.records.push(record);
            let index = report.records.len() - 1;
            if !report.records[index].complete() {
                report.failed_record = Some(index);
                return Ok(());
            }
            // Both compared contexts are fixed-size admitted restart profiles.
            tick(&mut report, limits, r)?;
            let current = &report.records[index];
            let anchor = &report.records[0];
            let selected = usize::from(query.restart_copy);
            if current.restart_context() != anchor.restart_context()
                || current.restart().copies()[selected].raw()
                    != anchor.restart().copies()[selected].raw()
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS record link restart context changed",
                ));
            }
            // The owned header is private; callers only receive an immutable reference.
            let header = current
                .header()
                .ok_or_else(|| invalid("NTFS record link header missing"))?;
            let next = match kind {
                NtfsLogRecordLinkKind::Previous => header.previous_lsn,
                NtfsLogRecordLinkKind::UndoNext => header.undo_next_lsn,
            };
            report.pending = (next != 0).then_some(next);
            report.closed = next == 0;
        }
        Ok(())
    })();
    if let Err(error) = result {
        if report.records.is_empty() {
            return Err(error);
        }
        report.error = Some(error);
    }
    report.source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != length
            || report
                .records
                .first()
                .is_some_and(|record| record.restart().source_bytes() != length))
        .then(|| {
            Error::new(
                ErrorKind::StalePlan,
                "NTFS record link source length changed",
            )
        })
    });
    Ok(report)
}

/// Structural link observations bound to the resolved native record-2 owner.
pub struct NtfsVolumeLogRecordLinkReport {
    /// Source-scoped native base-record identity, not recovery authority.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Owned chain evidence, never active membership or undo execution.
    pub report: NtfsLogRecordLinkReport,
}
/// Resolve ordinary initialized native `$LogFile` DATA and observe selected links.
/// Final volume source/cancellation failures suppress structural closure coverage.
pub fn inspect_ntfs_logfile_record_links(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogRecordLinkLimits,
    query: NtfsLogRecordQuery,
    kind: NtfsLogRecordLinkKind,
    r: &Resources,
) -> Result<NtfsVolumeLogRecordLinkReport> {
    r.cancellation.check()?;
    if limits.restart.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_record_links(Arc::new(native), limits, query, kind, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeLogRecordLinkReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
