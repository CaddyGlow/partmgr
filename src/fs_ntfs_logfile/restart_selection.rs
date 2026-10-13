//! Caller-qualified restart candidates, separate from recoverable-tail authority.
use super::*;

/// Ordering assumptions supplied explicitly by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogRestartOrdering {
    /// Compare native current LSNs numerically, as pinned Linux does. The caller
    /// excludes sequence-counter rollover; this inspector cannot establish that
    /// historical fact from two restart pages. No modular ordering is inferred.
    NumericWithoutRollover,
}
/// Why a structural candidate was retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogRestartSelectionReason {
    /// Compatible copies have different numeric current LSNs.
    GreaterCurrentLsn,
    /// Equal current LSNs and identical fixed-up declared restart areas.
    EquivalentCopies,
    /// Only one copy passed format validation; the other's error is retained.
    SoleValidCopy,
}
/// Source-owned restart evidence and an optional caller-qualified candidate.
/// Selection is neither an active-window proof nor recovery authority.
pub struct NtfsLogRestartSelectionReport {
    restart: NtfsLogFileReport,
    ordering: NtfsLogRestartOrdering,
    selected: Option<u8>,
    reason: Option<NtfsLogRestartSelectionReason>,
    blocked_copy: Option<usize>,
    error: Option<Error>,
    source_error: Option<Error>,
    work: usize,
}
impl NtfsLogRestartSelectionReport {
    /// Both original copies, including rejected format/backend evidence.
    pub fn restart(&self) -> &NtfsLogFileReport {
        &self.restart
    }
    /// Explicit caller-supplied ordering assumption.
    pub fn ordering(&self) -> NtfsLogRestartOrdering {
        self.ordering
    }
    /// Candidate copy index, withheld on any blocking or final-guard failure.
    pub fn selected_index(&self) -> Option<u8> {
        self.stopping_error()
            .is_none()
            .then_some(self.selected)
            .flatten()
    }
    /// Immutable validated context of the candidate, without active authority.
    pub fn selected_context(&self) -> Option<&NtfsRestartArea> {
        self.selected_index()
            .and_then(|i| self.restart.copies()[usize::from(i)].area().ok())
    }
    /// Candidate rationale, withheld when selection failed.
    pub fn reason(&self) -> Option<NtfsLogRestartSelectionReason> {
        self.selected_index().and(self.reason)
    }
    /// Original blocking failure; format-only rejected-copy errors remain in restart().
    pub fn stopping_error(&self) -> Option<&Error> {
        self.blocked_copy
            .and_then(|i| self.restart.copies()[i].area().err())
            .or(self.error.as_ref())
            .or(self.restart.source_error())
            .or(self.source_error.as_ref())
    }
    /// Independent final source/cancellation failure.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref().or(self.restart.source_error())
    }
    /// Inspection plus byte-comparison work consumed.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: fast-copy preprocessing and active-tail discovery remain.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: candidate ranking does not establish recoverability.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
// Called only for successfully parsed copies: USA positions and all area bounds
// have already been validated. Substitute the original sector-trailer bytes.
fn fixed_byte(copy: &NtfsRestartCopy, at: usize) -> u8 {
    let within = at % 512;
    if within >= 510 {
        let usa = usize::from(le16(copy.raw(), 4));
        copy.raw()[usa + (at / 512 + 1) * 2 + within - 510]
    } else {
        copy.raw()[at]
    }
}
fn compare_range(
    a: &NtfsRestartCopy,
    a_start: usize,
    b: &NtfsRestartCopy,
    b_start: usize,
    length: usize,
    work: &mut Work,
    r: &Resources,
) -> Result<bool> {
    for i in 0..length {
        work.tick(r)?;
        if fixed_byte(a, a_start + i) != fixed_byte(b, b_start + i) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn rank(report: &mut NtfsLogRestartSelectionReport, work: &mut Work, r: &Resources) -> Result<()> {
    if report.restart.source_error().is_some() {
        return Ok(());
    }
    for (i, copy) in report.restart.copies().iter().enumerate() {
        if let Err(error) = copy.area()
            && (!copy.read_complete()
                || !matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported))
        {
            report.blocked_copy = Some(i);
            return Ok(());
        }
    }
    let [a, b] = report.restart.copies();
    let (aa, bb) = match (a.area(), b.area()) {
        (Ok(aa), Ok(bb)) => (aa, bb),
        (Ok(_), Err(_)) => {
            report.selected = Some(0);
            report.reason = Some(NtfsLogRestartSelectionReason::SoleValidCopy);
            return Ok(());
        }
        (Err(_), Ok(_)) => {
            report.selected = Some(1);
            report.reason = Some(NtfsLogRestartSelectionReason::SoleValidCopy);
            return Ok(());
        }
        (Err(_), Err(_)) => {
            report.blocked_copy = Some(0);
            return Ok(());
        }
    };
    work.tick(r)?;
    if aa.version != bb.version
        || aa.file_bytes != bb.file_bytes
        || aa.sequence_bits != bb.sequence_bits
        || aa.record_header_bytes != bb.record_header_bytes
        || aa.page_data_offset != bb.page_data_offset
        || aa.client_count != bb.client_count
        || aa.free_head != bb.free_head
        || aa.in_use_head != bb.in_use_head
        || aa.client_sequence != bb.client_sequence
    {
        return Err(unsupported(
            "NTFS restart candidate incompatible geometry or client",
        ));
    }
    let a_off = usize::from(le16(a.raw(), 24));
    let b_off = usize::from(le16(b.raw(), 24));
    let a_client = usize::from(le16(a.raw(), a_off + 22));
    let b_client = usize::from(le16(b.raw(), b_off + 22));
    if aa.client_count == 1
        && !compare_range(
            a,
            a_off + a_client + 16,
            b,
            b_off + b_client + 16,
            144,
            work,
            r,
        )?
    {
        return Err(if aa.current_lsn == bb.current_lsn {
            invalid("NTFS equal-LSN restart candidates conflict")
        } else {
            unsupported("NTFS restart candidate client context differs")
        });
    }
    if aa.current_lsn == bb.current_lsn {
        let a_len = usize::from(le16(a.raw(), a_off + 20));
        let b_len = usize::from(le16(b.raw(), b_off + 20));
        if a_len != b_len || !compare_range(a, a_off, b, b_off, a_len, work, r)? {
            return Err(invalid("NTFS equal-LSN restart candidates conflict"));
        }
        report.selected = Some(0);
        report.reason = Some(NtfsLogRestartSelectionReason::EquivalentCopies);
    } else {
        report.selected = Some(u8::from(bb.current_lsn > aa.current_lsn));
        report.reason = Some(NtfsLogRestartSelectionReason::GreaterCurrentLsn);
    }
    Ok(())
}
/// Inspect both source-bound restart pages and rank a compatible candidate under
/// an explicit non-rollover numeric-ordering assumption. Equal-LSN ties require
/// fixed-up declared-area equality; independently valid USA markers and bytes
/// outside those areas do not affect the tie. Copy zero breaks an equivalent tie.
/// A fully read format-invalid copy may be rejected in favor of a valid copy;
/// backend, resource, cancellation and stale-source failures never enable fallback.
/// Zero/pseudo current LSNs remain observations, not validated record addresses.
/// Keep the stream immutable: guards cannot detect arbitrary same-length changes.
pub fn inspect_logfile_restart_candidate(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogFileLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsLogRestartSelectionReport> {
    let restart = inspect_logfile(source.clone(), limits, r)?;
    let length = restart.source_bytes();
    let mut work = Work {
        used: restart.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogRestartSelectionReport {
        restart,
        ordering,
        selected: None,
        reason: None,
        blocked_copy: None,
        error: None,
        source_error: None,
        work: 0,
    };
    report.error = rank(&mut report, &mut work, r).err();
    report.work = work.used;
    report.source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != length).then(|| {
            Error::new(
                ErrorKind::StalePlan,
                "NTFS restart selection source length changed",
            )
        })
    });
    Ok(report)
}

/// Candidate evidence bound to the resolved native `$LogFile` owner.
pub struct NtfsVolumeLogRestartSelectionReport {
    /// Source-scoped base-record identity, not recovery authority.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Source-owned restart observations and caller-qualified candidate.
    pub report: NtfsLogRestartSelectionReport,
}
/// Resolve ordinary initialized native record-2 DATA and rank restart candidates.
/// Final volume source/cancellation failures suppress candidate exposure.
pub fn inspect_ntfs_logfile_restart_candidate(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogFileLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsVolumeLogRestartSelectionReport> {
    r.cancellation.check()?;
    if limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_restart_candidate(Arc::new(native), limits, ordering, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeLogRestartSelectionReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
