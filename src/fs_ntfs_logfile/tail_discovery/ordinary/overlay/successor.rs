//! Exact native successor arithmetic from a same-overlay assembled record.
use super::*;
/// Native arithmetic result; none establishes active membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogSuccessorObservation {
    /// Native inclusive-end alignment overlaps the final record byte.
    UnsupportedInclusiveAlignment,
    /// Computed native LSN is outside the source-derived numeric bounds.
    OutsideObservedBounds,
    /// Exact native next LSN; not permission to replay or assume membership.
    Candidate(u64),
}
/// Source-owned exact record and derived successor observation.
pub struct NtfsLogSuccessorReport {
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    record: NtfsLogRecordReport,
    observation: NtfsLogSuccessorObservation,
    work: usize,
}
impl NtfsLogSuccessorReport {
    /// Exact immutable overlay used for assembly and ending-page comparison.
    pub fn overlay(&self) -> &NtfsLogReadOnlyOverlay {
        &self.overlay
    }
    /// Actual assembled record, never caller-supplied extent/header evidence.
    pub fn record(&self) -> &NtfsLogRecordReport {
        &self.record
    }
    /// Native arithmetic observation, with aligned-inclusive ambiguity explicit.
    pub fn observation(&self) -> NtfsLogSuccessorObservation {
        self.observation
    }
    /// Combined record assembly, arithmetic and final repeated-guard work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false pending independently qualified complete active traversal.
    pub fn active_window_complete(&self) -> bool {
        false
    }
}
#[allow(clippy::too_many_arguments)]
fn native_successor(
    this: u64,
    start: u64,
    end: u64,
    final_page: u64,
    ending_last: u64,
    first: u64,
    file_bytes: u64,
    data_offset: u16,
    bits: u32,
    oldest: u64,
    current: u64,
) -> Result<NtfsLogSuccessorObservation> {
    let mut generation = this >> bits;
    if end <= start {
        generation = bump_generation(generation, bits)?;
    }
    let next = if this == ending_last {
        let page = if final_page + PAGE as u64 == file_bytes {
            first
        } else {
            final_page + PAGE as u64
        };
        if page == first {
            generation = bump_generation(generation, bits)?;
        }
        page.checked_add(u64::from(data_offset))
            .ok_or_else(|| invalid("NTFS successor address overflow"))?
    } else {
        // Pinned final_log_off returns an inclusive end, but next_log_lsn aligns
        // that value itself. Preserve the primary ambiguity instead of +1.
        if end.is_multiple_of(8) {
            return Ok(NtfsLogSuccessorObservation::UnsupportedInclusiveAlignment);
        }
        end.checked_add(7)
            .ok_or_else(|| invalid("NTFS successor alignment overflow"))?
            & !7
    };
    if next < first || next >= file_bytes || next % (PAGE as u64) < u64::from(data_offset) {
        return Err(unsupported(
            "NTFS successor native address outside ordinary data",
        ));
    }
    let lsn = generation
        .checked_shl(bits)
        .and_then(|n| n.checked_add(next >> 3))
        .ok_or_else(|| invalid("NTFS successor LSN overflow"))?;
    if lsn < oldest || lsn > current {
        Ok(NtfsLogSuccessorObservation::OutsideObservedBounds)
    } else if lsn <= this {
        Err(unsupported(
            "NTFS successor nonprogress under qualified numeric ordering",
        ))
    } else {
        Ok(NtfsLogSuccessorObservation::Candidate(lsn))
    }
}
/// Assemble an exact record through the sealed native overlay, then derive the
/// pinned source's successor arithmetic. The work ceiling includes every final
/// source/record comparison; callers cannot supply replacement mappings/extents.
pub fn inspect_logfile_overlay_successor(
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    restart_limits: NtfsLogFileLimits,
    record_limits: NtfsLogRecordLimits,
    lsn: u64,
    work_limit: usize,
    r: &Resources,
) -> Result<NtfsLogSuccessorReport> {
    let selection = overlay.discovery.tail.seed.selection();
    let copy = selection
        .selected_index()
        .ok_or_else(|| unsupported("NTFS successor selected restart missing"))?;
    let area = *selection
        .selected_context()
        .ok_or_else(|| unsupported("NTFS successor context missing"))?;
    let seed = overlay
        .discovery
        .tail
        .seed
        .seed()
        .ok_or_else(|| unsupported("NTFS successor seed missing"))?;
    let first = seed.ordinary_start();
    let oldest = seed.numeric_oldest_lsn();
    let current = overlay
        .discovery
        .endpoint()
        .ok_or_else(|| unsupported("NTFS successor boundary missing"))?
        .last_lsn;
    if lsn < oldest || lsn > current {
        return Err(unsupported("NTFS successor query outside observed bounds"));
    }
    let source: Arc<dyn ReadAt> = overlay.clone();
    let record = crate::fs_ntfs_logfile::record::inspect_record_with_work(
        source,
        restart_limits,
        record_limits,
        (lsn, Some(copy)),
        work_limit,
        r,
    )?;
    if !record.complete()
        || !record.page_flag_semantics_supported()
        || !record.envelope_flag_semantics_supported()
        || record.restart_context() != Some(&area)
    {
        return Err(unsupported(
            "NTFS successor incomplete exact same-context record",
        ));
    }
    let header = record
        .header()
        .ok_or_else(|| unsupported("NTFS successor header missing"))?;
    let extent = record
        .extent()
        .ok_or_else(|| unsupported("NTFS successor extent missing"))?;
    let ending = record
        .pages()
        .iter()
        .find(|p| p.offset() == extent.final_page_offset())
        .and_then(|p| p.header())
        .ok_or_else(|| unsupported("NTFS successor ending page missing"))?;
    let bits = 64u32
        .checked_sub(area.sequence_bits)
        .ok_or_else(|| invalid("NTFS successor encoding"))?;
    let mask = (1u64 << bits) - 1;
    let start = (header.this_lsn & mask)
        .checked_mul(8)
        .ok_or_else(|| invalid("NTFS successor start overflow"))?;
    let mut work = Work {
        used: record
            .restart()
            .work()
            .checked_add(record.work())
            .ok_or_else(|| exhausted("NTFS successor combined assembly work overflow"))?,
        maximum: work_limit,
    };
    charge(&mut work, 1, r)?;
    let observation = native_successor(
        header.this_lsn,
        start,
        extent.final_byte_offset(),
        extent.final_page_offset(),
        ending.raw_lsn_or_file_offset,
        first,
        area.file_bytes,
        area.page_data_offset,
        bits,
        oldest,
        current,
    )?;
    let _lease = r.memory.reserve(PAGE as u64)?;
    let mut raw = page_buffer()?;
    if raw.capacity() > PAGE {
        return Err(exhausted("NTFS successor guard capacity"));
    }
    for page in record.pages() {
        charge(&mut work, 2 * PAGE, r)?;
        overlay
            .read_exact_at(page.offset(), &mut raw)
            .map_err(|e| Error::io("NTFS successor repeated record source", e))?;
        if raw != page.raw() {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS successor record source changed",
            ));
        }
    }
    let remaining = work_limit
        .checked_sub(work.used)
        .ok_or_else(|| exhausted("NTFS successor work ceiling"))?;
    work.used = work
        .used
        .checked_add(overlay.check_source(remaining, r)?)
        .ok_or_else(|| exhausted("NTFS successor work overflow"))?;
    r.cancellation.check()?;
    Ok(NtfsLogSuccessorReport {
        overlay,
        record,
        observation,
        work: work.used,
    })
}

/// Native forward-envelope disposition, independent of payload semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogPhysicalDisposition {
    /// Matching selected CLIENT_ID and native LfsClientRecord (type 1).
    ClientRecord,
    /// Native forward iteration skips this different CLIENT_ID.
    ForeignClient,
    /// Matching client but non-type-1 envelope, retained and skipped.
    OtherEnvelope,
}
/// Retained source-owned physical assembly, including failed-step diagnostics.
pub struct NtfsLogPhysicalStep {
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    record: NtfsLogRecordReport,
    disposition: Option<NtfsLogPhysicalDisposition>,
    successor: Option<NtfsLogSuccessorObservation>,
    error: Option<Error>,
    work: usize,
}
impl NtfsLogPhysicalStep {
    /// Exact sealed overlay shared by this physical query.
    pub fn overlay(&self) -> &NtfsLogReadOnlyOverlay {
        &self.overlay
    }
    /// Actual raw/decoded record report, also retained after assembly failure.
    pub fn record(&self) -> &NtfsLogRecordReport {
        &self.record
    }
    /// Native client/type disposition when framing completed.
    pub fn disposition(&self) -> Option<NtfsLogPhysicalDisposition> {
        self.disposition
    }
    /// Exact native successor observation, absent on failed assembly/guards.
    pub fn successor(&self) -> Option<NtfsLogSuccessorObservation> {
        self.successor
    }
    /// Original assembly/source failure before any subsequent framing diagnostic.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.record
            .stopping_error()
            .or(self.record.source_error())
            .or(self.error.as_ref())
    }
    /// Combined restart, assembly, arithmetic and repeated comparison work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: structural envelopes do not establish recovery authority.
    pub fn active_window_complete(&self) -> bool {
        false
    }
}
/// Assemble a physical envelope through the sealed overlay without granting
/// matching-client payload semantics to foreign or non-type-1 envelopes.
/// Preflight failures return Err; later failures retain the actual record report.
pub fn inspect_logfile_overlay_physical_step(
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    restart_limits: NtfsLogFileLimits,
    record_limits: NtfsLogRecordLimits,
    lsn: u64,
    work_limit: usize,
    r: &Resources,
) -> Result<NtfsLogPhysicalStep> {
    let selection = overlay.discovery.tail.seed.selection();
    let copy = selection
        .selected_index()
        .ok_or_else(|| unsupported("NTFS physical restart missing"))?;
    let area = *selection
        .selected_context()
        .ok_or_else(|| unsupported("NTFS physical context missing"))?;
    let seed = overlay
        .discovery
        .tail
        .seed
        .seed()
        .ok_or_else(|| unsupported("NTFS physical seed missing"))?;
    let first = seed.ordinary_start();
    let oldest = seed.numeric_oldest_lsn();
    let current = overlay
        .discovery
        .endpoint()
        .ok_or_else(|| unsupported("NTFS physical boundary missing"))?
        .last_lsn;
    if lsn < oldest || lsn > current {
        return Err(unsupported("NTFS physical query outside observed bounds"));
    }
    let source: Arc<dyn ReadAt> = overlay.clone();
    let record = crate::fs_ntfs_logfile::record::inspect_physical_envelope_with_work(
        source,
        restart_limits,
        record_limits,
        (lsn, Some(copy)),
        work_limit,
        r,
    )?;
    let mut report = NtfsLogPhysicalStep {
        overlay,
        work: record
            .restart()
            .work()
            .checked_add(record.work())
            .ok_or_else(|| exhausted("NTFS physical combined work overflow"))?,
        record,
        disposition: None,
        successor: None,
        error: None,
    };
    let mut work = Work {
        used: report.work,
        maximum: work_limit,
    };
    let result = (|| -> Result<()> {
        if !report.record.complete() {
            return Ok(());
        }
        if !report.record.page_flag_semantics_supported()
            || !report.record.envelope_flag_semantics_supported()
            || report.record.restart_context() != Some(&area)
        {
            return Err(unsupported("NTFS physical incomplete same-context framing"));
        }
        let header = report
            .record
            .header()
            .ok_or_else(|| unsupported("NTFS physical header missing"))?;
        let extent = report
            .record
            .extent()
            .ok_or_else(|| unsupported("NTFS physical extent missing"))?;
        let ending = report
            .record
            .pages()
            .iter()
            .find(|p| p.offset() == extent.final_page_offset())
            .and_then(|p| p.header())
            .ok_or_else(|| unsupported("NTFS physical ending page missing"))?;
        let bits = 64u32
            .checked_sub(area.sequence_bits)
            .ok_or_else(|| invalid("NTFS physical encoding"))?;
        let mask = 1u64
            .checked_shl(bits)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| invalid("NTFS physical encoding mask"))?;
        let start = (header.this_lsn & mask)
            .checked_mul(8)
            .ok_or_else(|| invalid("NTFS physical start overflow"))?;
        charge(&mut work, 1, r)?;
        report.disposition = Some(
            if header.client_index != 0 || Some(header.client_sequence) != area.client_sequence {
                NtfsLogPhysicalDisposition::ForeignClient
            } else if header.record_type == 1 {
                NtfsLogPhysicalDisposition::ClientRecord
            } else {
                NtfsLogPhysicalDisposition::OtherEnvelope
            },
        );
        report.successor = Some(native_successor(
            header.this_lsn,
            start,
            extent.final_byte_offset(),
            extent.final_page_offset(),
            ending.raw_lsn_or_file_offset,
            first,
            area.file_bytes,
            area.page_data_offset,
            bits,
            oldest,
            current,
        )?);
        Ok(())
    })();
    report.error = result.err();
    // Guard every successfully observed complete raw page, including those in a
    // failed assembly. Failed read prefixes remain diagnostic rather than guards.
    let guarded = (|| -> Result<()> {
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS physical guard capacity"));
        }
        for (offset, expected) in report
            .record
            .restart()
            .copies()
            .iter()
            .filter(|p| p.read_complete())
            .map(|p| (p.offset(), p.raw()))
            .chain(
                report
                    .record
                    .pages()
                    .iter()
                    .filter(|p| p.read_complete())
                    .map(|p| (p.offset(), p.raw())),
            )
        {
            charge(&mut work, 2 * PAGE, r)?;
            report
                .overlay
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS physical repeated record source", e))?;
            r.cancellation.check()?;
            if raw != expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS physical record source changed",
                ));
            }
        }
        let remaining = work_limit
            .checked_sub(work.used)
            .ok_or_else(|| exhausted("NTFS physical work ceiling"))?;
        work.used = work
            .used
            .checked_add(report.overlay.check_source(remaining, r)?)
            .ok_or_else(|| exhausted("NTFS physical work overflow"))?;
        r.cancellation.check()
    })();
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    report.work = work.used;
    if report.stopping_error().is_some() {
        report.successor = None;
    }
    Ok(report)
}

/// Aggregate ceilings for source-owned physical oldest-to-current traversal.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogPhysicalTraversalLimits {
    /// Per-query restart ceilings; aggregate work/pages also apply.
    pub restart: NtfsLogFileLimits,
    /// Per-envelope assembly ceilings; aggregate limits also apply.
    pub record: NtfsLogRecordLimits,
    /// Maximum retained physical envelopes, including skipped/failed envelopes.
    pub queries: usize,
    /// Aggregate restart and record pages across all queries.
    pub pages: usize,
    /// Aggregate retained payload across all queries.
    pub payload_bytes: usize,
    /// Combined assembly, successor and repeated comparison work.
    pub work: usize,
}
/// Bounded physical traversal, independent of checkpoint/analysis authority.
pub struct NtfsLogPhysicalTraversalReport {
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    steps: Vec<NtfsLogPhysicalStep>,
    error: Option<Error>,
    complete: bool,
    work: usize,
    pages: usize,
    payload_bytes: usize,
    _inventory: Reservation,
}
impl NtfsLogPhysicalTraversalReport {
    /// Actual physical order, including foreign clients and non-client records.
    pub fn steps(&self) -> &[NtfsLogPhysicalStep] {
        &self.steps
    }
    /// First retained step failure, or aggregate/final source refusal.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.steps
            .iter()
            .find_map(NtfsLogPhysicalStep::stopping_error)
            .or(self.error.as_ref())
    }
    /// Structural traversal reached native out-of-range termination and guards.
    pub fn physical_traversal_complete(&self) -> bool {
        self.complete
    }
    /// Aggregate charged work, including repeated comparisons.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Aggregate restart and record page observations.
    pub fn pages(&self) -> usize {
        self.pages
    }
    /// Aggregate retained payload length.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Always false pending complete checkpoint/native qualification.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: traversal does not authorize recovery.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
/// Follow exact physical successor evidence from the sealed source's oldest
/// bound, retaining native skipped envelopes and stopping on any unsupported
/// arithmetic/framing branch. No checkpoint is selected by header sorting.
pub fn inspect_logfile_overlay_physical_traversal(
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    limits: NtfsLogPhysicalTraversalLimits,
    r: &Resources,
) -> Result<NtfsLogPhysicalTraversalReport> {
    let seed = overlay
        .discovery
        .tail
        .seed
        .seed()
        .ok_or_else(|| unsupported("NTFS traversal seed missing"))?;
    let lsn = seed.numeric_oldest_lsn();
    inspect_physical_traversal_from(overlay, limits, lsn, r)
}
// Exact native redo/undo entries use their sealed table LSN rather than oldest.
// Physical query still enforces the original source-owned client numeric range.
fn inspect_physical_traversal_from(
    overlay: Arc<NtfsLogReadOnlyOverlay>,
    limits: NtfsLogPhysicalTraversalLimits,
    mut lsn: u64,
    r: &Resources,
) -> Result<NtfsLogPhysicalTraversalReport> {
    if lsn == 0 {
        return Err(unsupported(
            "NTFS traversal zero start is not an empty-window proof",
        ));
    }
    let vector_bytes = limits
        .queries
        .checked_mul(core::mem::size_of::<NtfsLogPhysicalStep>())
        .ok_or_else(|| exhausted("NTFS traversal vector overflow"))?;
    let inventory = r.memory.reserve(
        u64::try_from(vector_bytes).map_err(|_| exhausted("NTFS traversal vector width"))?,
    )?;
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(limits.queries)
        .map_err(|_| exhausted("NTFS traversal vector allocation"))?;
    if steps.capacity() > limits.queries {
        return Err(exhausted("NTFS traversal vector capacity"));
    }
    let mut report = NtfsLogPhysicalTraversalReport {
        overlay,
        steps,
        error: None,
        complete: false,
        work: 0,
        pages: 0,
        payload_bytes: 0,
        _inventory: inventory,
    };
    let mut work = Work {
        used: 0,
        maximum: limits.work,
    };
    let scanned = (|| -> Result<bool> {
        loop {
            charge(&mut work, 1, r)?;
            if report.steps.len() >= limits.queries || limits.pages.saturating_sub(report.pages) < 2
            {
                return Err(exhausted("NTFS traversal aggregate query/page ceiling"));
            }
            let mut record_limits = limits.record;
            record_limits.pages = record_limits.pages.min(limits.pages - report.pages - 2);
            record_limits.payload_bytes = record_limits
                .payload_bytes
                .min(limits.payload_bytes.saturating_sub(report.payload_bytes));
            let remaining = limits
                .work
                .checked_sub(work.used)
                .ok_or_else(|| exhausted("NTFS traversal aggregate work"))?;
            let step = inspect_logfile_overlay_physical_step(
                report.overlay.clone(),
                limits.restart,
                record_limits,
                lsn,
                remaining,
                r,
            )?;
            work.used = work
                .used
                .checked_add(step.work())
                .ok_or_else(|| exhausted("NTFS traversal work overflow"))?;
            report.pages = report
                .pages
                .checked_add(2 + step.record.pages().len())
                .ok_or_else(|| exhausted("NTFS traversal page overflow"))?;
            report.payload_bytes = report
                .payload_bytes
                .checked_add(step.record.retained_payload_bytes())
                .ok_or_else(|| exhausted("NTFS traversal payload overflow"))?;
            let successor = step.successor();
            let failed = step.stopping_error().is_some();
            report.steps.push(step);
            if failed {
                return Ok(false);
            }
            match successor {
                Some(NtfsLogSuccessorObservation::OutsideObservedBounds) => return Ok(true),
                Some(NtfsLogSuccessorObservation::Candidate(next)) if next > lsn => lsn = next,
                Some(NtfsLogSuccessorObservation::UnsupportedInclusiveAlignment) => {
                    return Err(unsupported("NTFS traversal inclusive alignment unresolved"));
                }
                _ => {
                    return Err(unsupported(
                        "NTFS traversal successor unavailable/nonprogress",
                    ));
                }
            }
        }
    })();
    let candidate_complete = match scanned {
        Ok(complete) => complete,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    // Final re-read covers ALL previous successful observations, so later reads
    // cannot silently invalidate earlier framing evidence before completion.
    let guarded = (|| -> Result<()> {
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS traversal guard capacity"));
        }
        for step in &report.steps {
            for (offset, expected) in step
                .record
                .restart()
                .copies()
                .iter()
                .filter(|p| p.read_complete())
                .map(|p| (p.offset(), p.raw()))
                .chain(
                    step.record
                        .pages()
                        .iter()
                        .filter(|p| p.read_complete())
                        .map(|p| (p.offset(), p.raw())),
                )
            {
                charge(&mut work, 2 * PAGE, r)?;
                report
                    .overlay
                    .read_exact_at(offset, &mut raw)
                    .map_err(|e| Error::io("NTFS traversal final raw source", e))?;
                r.cancellation.check()?;
                if raw != expected {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "NTFS traversal earlier source changed",
                    ));
                }
            }
        }
        let remaining = limits
            .work
            .checked_sub(work.used)
            .ok_or_else(|| exhausted("NTFS traversal final work ceiling"))?;
        work.used = work
            .used
            .checked_add(report.overlay.check_source(remaining, r)?)
            .ok_or_else(|| exhausted("NTFS traversal final work overflow"))?;
        r.cancellation.check()
    })();
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    report.work = work.used;
    report.complete = candidate_complete && report.stopping_error().is_none();
    Ok(report)
}

mod checkpoint_analysis;
pub use checkpoint_analysis::*;

#[cfg(test)]
mod tests {
    use super::*;
    fn lsn(generation: u64, offset: u64) -> u64 {
        (generation << 16) | (offset >> 3)
    }
    #[test]
    fn inclusive_alignment_remains_explicitly_unsupported() {
        let this = lsn(9, 4 * 4096 + 64);
        assert_eq!(
            native_successor(
                this,
                4 * 4096 + 64,
                4 * 4096 + 112,
                4 * 4096,
                this + 1,
                4 * 4096,
                64 * 4096,
                64,
                16,
                0,
                u64::MAX
            )
            .unwrap(),
            NtfsLogSuccessorObservation::UnsupportedInclusiveAlignment
        );
    }
    #[test]
    fn same_page_native_alignment_and_last_record_next_page_differ() {
        let this = lsn(9, 4 * 4096 + 64);
        assert_eq!(
            native_successor(
                this,
                4 * 4096 + 64,
                4 * 4096 + 111,
                4 * 4096,
                this + 1,
                4 * 4096,
                64 * 4096,
                64,
                16,
                0,
                u64::MAX
            )
            .unwrap(),
            NtfsLogSuccessorObservation::Candidate(lsn(9, 4 * 4096 + 112))
        );
        assert_eq!(
            native_successor(
                this,
                4 * 4096 + 64,
                4 * 4096 + 111,
                4 * 4096,
                this,
                4 * 4096,
                64 * 4096,
                64,
                16,
                0,
                u64::MAX
            )
            .unwrap(),
            NtfsLogSuccessorObservation::Candidate(lsn(9, 5 * 4096 + 64))
        );
    }
    #[test]
    fn native_physical_wrap_increments_generation_and_applies_bounds() {
        let this = lsn(9, 63 * 4096 + 64);
        assert_eq!(
            native_successor(
                this,
                63 * 4096 + 64,
                63 * 4096 + 111,
                63 * 4096,
                this,
                4 * 4096,
                64 * 4096,
                64,
                16,
                0,
                u64::MAX
            )
            .unwrap(),
            NtfsLogSuccessorObservation::Candidate(lsn(10, 4 * 4096 + 64))
        );
        assert_eq!(
            native_successor(
                this,
                63 * 4096 + 64,
                63 * 4096 + 111,
                63 * 4096,
                this,
                4 * 4096,
                64 * 4096,
                64,
                16,
                0,
                this
            )
            .unwrap(),
            NtfsLogSuccessorObservation::OutsideObservedBounds
        );
    }
}
