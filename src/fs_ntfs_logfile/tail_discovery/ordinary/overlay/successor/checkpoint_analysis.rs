//! Source-selected checkpoint and structural native analysis suffix.
use super::*;
/// Selected-client restart outcome, without table/recovery qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogCheckpointSelection {
    /// Selected client's restart_lsn is zero; native read_rst_area returns none.
    NoRestartLsn,
    /// Selected restart record has zero client_data_len; native returns no payload.
    EmptyRestartPayload,
    /// Nonempty restart payload uses its own LSN because checkpoint_start is zero.
    RestartRecordAnchor,
    /// Nonzero checkpoint_start from the exact source-selected restart payload.
    PayloadCheckpointOverride,
}
/// Aggregate ceilings including the consumed traversal and any direct restart query.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogCheckpointAnalysisLimits {
    /// Per-query native restart inspection ceilings.
    pub restart: NtfsLogFileLimits,
    /// Per-query exact selected-restart record ceilings.
    pub record: NtfsLogRecordLimits,
    /// Aggregate observed pages, including traversal and direct-query restarts.
    pub pages: usize,
    /// Aggregate retained payload including traversal and direct restart.
    pub payload_bytes: usize,
    /// Combined traversal, direct query, selection and final comparison work.
    pub work: usize,
}
/// Retained physical traversal and exact source-derived checkpoint provenance.
pub struct NtfsLogCheckpointAnalysisReport {
    traversal: NtfsLogPhysicalTraversalReport,
    restart_index: Option<usize>,
    restart_query: Option<NtfsLogRecordReport>,
    pages: usize,
    payload_bytes: usize,
    anchor_index: Option<usize>,
    selection: Option<NtfsLogCheckpointSelection>,
    error: Option<Error>,
    work: usize,
}
impl NtfsLogCheckpointAnalysisReport {
    /// All actual physical steps, including native skipped envelopes/failures.
    pub fn traversal(&self) -> &NtfsLogPhysicalTraversalReport {
        &self.traversal
    }
    /// Exact selected-client restart record, absent for zero/unresolved restart LSN.
    pub fn restart_record(&self) -> Option<&NtfsLogRecordReport> {
        self.restart_query
            .as_ref()
            .or_else(|| self.restart_index.map(|i| self.traversal.steps[i].record()))
    }
    /// Provenance of the source-derived effective anchor or no-payload outcome.
    pub fn selection(&self) -> Option<NtfsLogCheckpointSelection> {
        self.selection
    }
    /// Exact visited anchor; the native analysis pass does NOT analyze this record.
    pub fn analysis_anchor(&self) -> Option<&NtfsLogRecordReport> {
        self.anchor_index.map(|i| self.traversal.steps[i].record())
    }
    /// Matching-client type-1 envelopes strictly AFTER the exact anchor, in actual
    /// physical successor order. Empty on failed selection/final source guards.
    /// Payload/opcode/table/transaction semantics remain unqualified.
    pub fn analysis_records(&self) -> impl Iterator<Item = &NtfsLogRecordReport> {
        let start = if self.stopping_error().is_none() {
            self.anchor_index
                .map_or(self.traversal.steps.len(), |i| i + 1)
        } else {
            self.traversal.steps.len()
        };
        self.traversal.steps[start..]
            .iter()
            .filter(|s| s.disposition == Some(NtfsLogPhysicalDisposition::ClientRecord))
            .map(NtfsLogPhysicalStep::record)
    }
    /// Earliest physical traversal failure, otherwise checkpoint/source refusal.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.traversal
            .stopping_error()
            .or_else(|| {
                self.restart_query
                    .as_ref()
                    .and_then(NtfsLogRecordReport::stopping_error)
            })
            .or(self.error.as_ref())
    }
    /// Whether native selected-restart lookup required a separately retained query.
    pub fn direct_restart_query(&self) -> bool {
        self.restart_query.is_some()
    }
    /// Aggregate traversal and direct-query restart/record pages.
    pub fn pages(&self) -> usize {
        self.pages
    }
    /// Aggregate traversal and direct-query retained payload.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Combined physical traversal, source checkpoint decoding and repeat work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: tables and native analysis semantics are not established.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
    /// Always false pending independently qualified full active-window evidence.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false; this report grants no recovery authority.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
/// Select checkpoint from the sealed selected client's restart_lsn and derive
/// the structural analysis suffix using native read_next-before-analysis order.
/// The work ceiling INCLUDES the consumed traversal's already charged work.
/// No header sorting, nearest-LSN selection or caller-supplied anchor is accepted.
pub fn inspect_logfile_checkpoint_analysis_from_traversal(
    traversal: NtfsLogPhysicalTraversalReport,
    limits: NtfsLogCheckpointAnalysisLimits,
    r: &Resources,
) -> NtfsLogCheckpointAnalysisReport {
    let maximum_work = limits.work;
    let mut work = Work {
        used: traversal.work,
        maximum: maximum_work,
    };
    let mut report = NtfsLogCheckpointAnalysisReport {
        pages: traversal.pages,
        payload_bytes: traversal.payload_bytes,
        traversal,
        restart_index: None,
        restart_query: None,
        anchor_index: None,
        selection: None,
        error: None,
        work: work.used,
    };
    let result = (|| -> Result<()> {
        charge(&mut work, 1, r)?;
        if report.pages > limits.pages || report.payload_bytes > limits.payload_bytes {
            return Err(exhausted(
                "NTFS checkpoint consumed traversal exceeds aggregate ceiling",
            ));
        }
        if !report.traversal.physical_traversal_complete() {
            return Err(unsupported(
                "NTFS checkpoint requires complete physical traversal",
            ));
        }
        let selection = report.traversal.overlay.discovery.tail.seed.selection();
        let context = *selection
            .selected_context()
            .ok_or_else(|| unsupported("NTFS checkpoint selected context missing"))?;
        let copy = selection
            .selected_index()
            .ok_or_else(|| unsupported("NTFS checkpoint selected copy missing"))?;
        let restart_lsn = context
            .client_restart_lsn
            .ok_or_else(|| unsupported("NTFS checkpoint selected client restart field missing"))?;
        if restart_lsn == 0 {
            report.selection = Some(NtfsLogCheckpointSelection::NoRestartLsn);
            return Ok(());
        }
        let mut restart_index = None;
        for (i, step) in report.traversal.steps.iter().enumerate() {
            charge(&mut work, 1, r)?;
            if step
                .record
                .header()
                .is_some_and(|h| h.this_lsn == restart_lsn)
            {
                restart_index = Some(i);
                break;
            }
        }
        if let Some(i) = restart_index {
            report.restart_index = Some(i);
        } else {
            // read_rst_area queries selected restart_lsn DIRECTLY, without
            // verify_client_lsn/is_lsn_in_file admission. It may precede oldest.
            charge(&mut work, 1, r)?;
            let remaining_pages = limits
                .pages
                .checked_sub(report.pages)
                .ok_or_else(|| exhausted("NTFS checkpoint aggregate pages"))?;
            if remaining_pages < 2 {
                return Err(exhausted("NTFS checkpoint direct restart page ceiling"));
            }
            let mut record_limits = limits.record;
            record_limits.pages = record_limits.pages.min(remaining_pages - 2);
            record_limits.payload_bytes = record_limits
                .payload_bytes
                .min(limits.payload_bytes.saturating_sub(report.payload_bytes));
            let remaining = maximum_work
                .checked_sub(work.used)
                .ok_or_else(|| exhausted("NTFS checkpoint direct restart work ceiling"))?;
            let source: Arc<dyn ReadAt> = report.traversal.overlay.clone();
            let query = crate::fs_ntfs_logfile::record::inspect_record_with_work(
                source,
                limits.restart,
                record_limits,
                (restart_lsn, Some(copy)),
                remaining,
                r,
            )?;
            work.used = work
                .used
                .checked_add(query.restart().work())
                .and_then(|v| v.checked_add(query.work()))
                .ok_or_else(|| exhausted("NTFS checkpoint direct restart combined work"))?;
            report.pages = report
                .pages
                .checked_add(2 + query.pages().len())
                .ok_or_else(|| exhausted("NTFS checkpoint direct restart page overflow"))?;
            report.payload_bytes = report
                .payload_bytes
                .checked_add(query.retained_payload_bytes())
                .ok_or_else(|| exhausted("NTFS checkpoint direct restart payload overflow"))?;
            report.restart_query = Some(query);
        }
        let record = report
            .restart_record()
            .ok_or_else(|| unsupported("NTFS checkpoint source-selected restart missing"))?;
        if !record.complete()
            || !record.page_flag_semantics_supported()
            || !record.envelope_flag_semantics_supported()
            || record.restart_context() != Some(&context)
        {
            return Err(unsupported(
                "NTFS checkpoint direct restart incomplete exact context",
            ));
        }
        let header = record
            .header()
            .ok_or_else(|| unsupported("NTFS checkpoint restart header missing"))?;
        if header.client_index != 0 || Some(header.client_sequence) != context.client_sequence {
            return Err(invalid("NTFS checkpoint restart selected client mismatch"));
        }
        if header.payload_bytes == 0 {
            report.selection = Some(NtfsLogCheckpointSelection::EmptyRestartPayload);
            return Ok(());
        }
        charge(&mut work, record.retained_payload_bytes(), r)?;
        let checkpoint_start =
            crate::fs_ntfs_logfile::inspect_ntfs_client_restart(record)?.checkpoint_start_lsn;
        let anchor_lsn = if checkpoint_start == 0 {
            report.selection = Some(NtfsLogCheckpointSelection::RestartRecordAnchor);
            restart_lsn
        } else {
            report.selection = Some(NtfsLogCheckpointSelection::PayloadCheckpointOverride);
            checkpoint_start
        };
        for (i, step) in report.traversal.steps.iter().enumerate() {
            charge(&mut work, 1, r)?;
            if step
                .record
                .header()
                .is_some_and(|h| h.this_lsn == anchor_lsn)
            {
                let h = step
                    .record
                    .header()
                    .ok_or_else(|| unsupported("NTFS checkpoint anchor header missing"))?;
                if h.client_index != 0 || Some(h.client_sequence) != context.client_sequence {
                    return Err(invalid("NTFS checkpoint anchor selected client mismatch"));
                }
                report.anchor_index = Some(i);
                return Ok(());
            }
        }
        Err(unsupported(
            "NTFS checkpoint anchor absent from exact physical traversal",
        ))
    })();
    report.error = result.err();
    // Decoding is performed only over retained bytes; completion still repeats
    // every complete original record observation and the sealed overlay guards.
    let guarded = (|| -> Result<()> {
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS checkpoint guard capacity"));
        }
        for record in report
            .traversal
            .steps
            .iter()
            .map(NtfsLogPhysicalStep::record)
            .chain(report.restart_query.iter())
        {
            for (offset, expected) in record
                .restart()
                .copies()
                .iter()
                .filter(|p| p.read_complete())
                .map(|p| (p.offset(), p.raw()))
                .chain(
                    record
                        .pages()
                        .iter()
                        .filter(|p| p.read_complete())
                        .map(|p| (p.offset(), p.raw())),
                )
            {
                charge(&mut work, 2 * PAGE, r)?;
                report
                    .traversal
                    .overlay
                    .read_exact_at(offset, &mut raw)
                    .map_err(|e| Error::io("NTFS checkpoint repeated record source", e))?;
                r.cancellation.check()?;
                if raw != expected {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "NTFS checkpoint earlier source changed",
                    ));
                }
            }
        }
        let remaining = maximum_work
            .checked_sub(work.used)
            .ok_or_else(|| exhausted("NTFS checkpoint combined work ceiling"))?;
        work.used = work
            .used
            .checked_add(report.traversal.overlay.check_source(remaining, r)?)
            .ok_or_else(|| exhausted("NTFS checkpoint combined work overflow"))?;
        r.cancellation.check()
    })();
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    report.work = work.used;
    report
}

mod replay_analysis;
pub use replay_analysis::*;
