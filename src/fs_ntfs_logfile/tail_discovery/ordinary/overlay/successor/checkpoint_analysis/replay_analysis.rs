//! Native-ordered source checkpoint tables and transaction dependency projection.
use super::*;
/// Aggregate ceilings, including consumed checkpoint/traversal evidence.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogReplayAnalysisLimits {
    /// Per-query/table ceilings and maximum additional checkpoint/dump queries.
    pub dumps: NtfsLogCheckpointDumpLimits,
    /// Aggregate pages including prior checkpoint/traversal evidence.
    pub pages: usize,
    /// Aggregate retained client payload including prior evidence.
    pub payload_bytes: usize,
    /// Maximum retained transaction identifiers, including initial allocated slots.
    pub transactions: usize,
    /// Maximum retained matching-client analysis record observations.
    pub records: usize,
    /// Combined prior evidence, native table loads, derivation and final guards.
    pub work: usize,
}
/// Exact structural resolution of an observed predecessor/undo link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogAnalysisLink {
    /// Native zero terminates this link.
    Zero,
    /// verify_client_lsn would stop; no target record is inferred.
    OutsideClientBounds,
    /// Exact physical traversal record index; no replay authority inferred.
    Visited(usize),
    /// Exact physical target belongs to a foreign CLIENT_ID.
    ForeignClientTarget(usize),
    /// Exact matching-client target is a non-type-1 envelope.
    NonClientEnvelope(usize),
    /// Exact matching-client record has a different transaction identifier.
    DifferentTransaction(usize),
    /// Numerically in client bounds but absent from actual physical traversal.
    MissingObservedRecord,
}
/// Source-derived native transaction fields, independent of dirty/open effects.
pub struct NtfsLogAnalysisTransaction {
    id: u32,
    allocated: bool,
    state: u8,
    first_lsn: u64,
    previous_lsn: u64,
    undo_next_lsn: u64,
    initial_slot: Option<usize>,
    first_link: NtfsLogAnalysisLink,
    previous_link: NtfsLogAnalysisLink,
    undo_link: NtfsLogAnalysisLink,
}
impl NtfsLogAnalysisTransaction {
    /// Native byte-offset transaction identifier.
    pub fn id(&self) -> u32 {
        self.id
    }
    /// Whether the native analysis prefix leaves the entry allocated.
    pub fn allocated(&self) -> bool {
        self.allocated
    }
    /// Native state0/1/2/3 after the retained analysis prefix.
    pub fn state(&self) -> u8 {
        self.state
    }
    /// First LSN from initial checkpoint or native entry allocation.
    pub fn first_lsn(&self) -> u64 {
        self.first_lsn
    }
    /// Native most recent analysis LSN for this entry.
    pub fn previous_lsn(&self) -> u64 {
        self.previous_lsn
    }
    /// Native undo-next after compensation/end-top-level handling.
    pub fn undo_next_lsn(&self) -> u64 {
        self.undo_next_lsn
    }
    /// Exact structural first-LSN dependency, with conflicts explicit.
    pub fn first_dependency(&self) -> NtfsLogAnalysisLink {
        self.first_link
    }
    /// Exact structural previous-LSN dependency, with conflicts explicit.
    pub fn previous_dependency(&self) -> NtfsLogAnalysisLink {
        self.previous_link
    }
    /// Exact structural undo-next dependency, with conflicts explicit.
    pub fn undo_dependency(&self) -> NtfsLogAnalysisLink {
        self.undo_link
    }
    /// Exact original allocated checkpoint slot, absent for new/reallocated entries.
    pub fn initial_slot(&self) -> Option<usize> {
        self.initial_slot
    }
}
/// One actual analysis record in physical successor order.
pub struct NtfsLogAnalysisRecord {
    physical_index: usize,
    transaction_index: usize,
    redo: u16,
    undo: u16,
    previous: NtfsLogAnalysisLink,
    undo_next: NtfsLogAnalysisLink,
    remaining_effects: bool,
    state_after: u8,
    allocated_after: bool,
    first_after: u64,
    undo_after: u64,
}
impl NtfsLogAnalysisRecord {
    /// Exact retained physical traversal record index.
    pub fn physical_index(&self) -> usize {
        self.physical_index
    }
    /// Source-derived transaction summary index.
    pub fn transaction_index(&self) -> usize {
        self.transaction_index
    }
    /// Actual native redo opcode.
    pub fn redo_operation(&self) -> u16 {
        self.redo
    }
    /// Actual native undo opcode.
    pub fn undo_operation(&self) -> u16 {
        self.undo
    }
    /// Structural previous-link resolution, not transaction-chain authority.
    pub fn previous(&self) -> NtfsLogAnalysisLink {
        self.previous
    }
    /// Structural undo-link resolution, not permission to execute undo.
    pub fn undo_next(&self) -> NtfsLogAnalysisLink {
        self.undo_next
    }
    /// Native state immediately after this actual analysis record.
    pub fn state_after(&self) -> u8 {
        self.state_after
    }
    /// Native allocated status immediately after this record.
    pub fn allocated_after(&self) -> bool {
        self.allocated_after
    }
    /// Native first-LSN immediately after this record.
    pub fn first_lsn_after(&self) -> u64 {
        self.first_after
    }
    /// Native undo-next immediately after this record.
    pub fn undo_next_after(&self) -> u64 {
        self.undo_after
    }
    /// Dirty/open/name/target effects still require implementation/qualification.
    pub fn remaining_effects(&self) -> bool {
        self.remaining_effects
    }
}
/// Source-owned native tables and transaction fields from an actual analysis suffix.
pub struct NtfsLogReplayAnalysisReport {
    checkpoint: NtfsLogCheckpointAnalysisReport,
    dumps: Option<NtfsLogCheckpointDumpReport>,
    transactions: Vec<NtfsLogAnalysisTransaction>,
    records: Vec<NtfsLogAnalysisRecord>,
    error: Option<Error>,
    projection_complete: bool,
    initial_dirty_pages: usize,
    initial_open_attributes: usize,
    work: usize,
    pages: usize,
    payload_bytes: usize,
    _inventory: Reservation,
}
impl NtfsLogReplayAnalysisReport {
    /// Exact source-selected checkpoint and physical analysis suffix.
    pub fn checkpoint(&self) -> &NtfsLogCheckpointAnalysisReport {
        &self.checkpoint
    }
    /// Requeried source-owned checkpoint/dumps, in native read order.
    pub fn dumps(&self) -> Option<&NtfsLogCheckpointDumpReport> {
        self.dumps.as_ref()
    }
    /// Initial allocated and subsequently observed native transaction identifiers.
    pub fn transactions(&self) -> &[NtfsLogAnalysisTransaction] {
        &self.transactions
    }
    /// Retained matching-client records in native analysis order, including prefix.
    pub fn records(&self) -> &[NtfsLogAnalysisRecord] {
        &self.records
    }
    /// Earliest original source/framing/aggregate refusal.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.checkpoint
            .stopping_error()
            .or_else(|| {
                self.dumps
                    .as_ref()
                    .and_then(NtfsLogCheckpointDumpReport::stopping_error)
            })
            .or(self.error.as_ref())
    }
    /// Number of allocated typed initial dirty slots with validated open-table links.
    pub fn initial_dirty_pages(&self) -> usize {
        self.initial_dirty_pages
    }
    /// Number of allocated typed initial open-attribute slots; FILE ownership remains unproved.
    pub fn initial_open_attributes(&self) -> usize {
        self.initial_open_attributes
    }
    /// Only transaction allocation/state/link derivation reached the suffix end.
    /// This does not cover dirty/open tables, target ownership or redo/undo safety.
    pub fn transaction_fields_complete(&self) -> bool {
        self.projection_complete
    }
    /// Combined charged prior evidence/table/projection/final comparison work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Aggregate observed restart/record pages including earlier evidence.
    pub fn pages(&self) -> usize {
        self.pages
    }
    /// Aggregate retained payload including earlier evidence.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Always false: full native dirty/open/name analysis is not complete.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
    /// Always false until the full active traversal and native evidence qualify.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false; observations do not authorize replay.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn resolve_link(
    checkpoint: &NtfsLogCheckpointAnalysisReport,
    lsn: u64,
    transaction_id: u32,
    work: &mut Work,
    r: &Resources,
) -> Result<NtfsLogAnalysisLink> {
    charge(work, 1, r)?;
    if lsn == 0 {
        return Ok(NtfsLogAnalysisLink::Zero);
    }
    let context = checkpoint
        .traversal
        .overlay
        .discovery
        .tail
        .seed
        .selection()
        .selected_context()
        .ok_or_else(|| unsupported("NTFS analysis client context missing"))?;
    let oldest = context
        .client_oldest_lsn
        .ok_or_else(|| unsupported("NTFS analysis client oldest missing"))?;
    let current = checkpoint
        .traversal
        .overlay
        .discovery
        .endpoint()
        .ok_or_else(|| unsupported("NTFS analysis endpoint missing"))?
        .last_lsn;
    if lsn < oldest || lsn > current {
        return Ok(NtfsLogAnalysisLink::OutsideClientBounds);
    }
    for (i, step) in checkpoint.traversal.steps.iter().enumerate() {
        charge(work, 1, r)?;
        if step.record.header().is_some_and(|h| h.this_lsn == lsn) {
            return Ok(
                if step.disposition == Some(NtfsLogPhysicalDisposition::ForeignClient) {
                    NtfsLogAnalysisLink::ForeignClientTarget(i)
                } else if step.disposition != Some(NtfsLogPhysicalDisposition::ClientRecord) {
                    NtfsLogAnalysisLink::NonClientEnvelope(i)
                } else if step
                    .record
                    .header()
                    .is_some_and(|h| h.transaction_id != transaction_id)
                {
                    NtfsLogAnalysisLink::DifferentTransaction(i)
                } else {
                    NtfsLogAnalysisLink::Visited(i)
                },
            );
        }
    }
    Ok(NtfsLogAnalysisLink::MissingObservedRecord)
}
/// Load native checkpoint tables and derive transaction allocation/state/link
/// fields over the exact source-owned suffix. Initial dirty/open/name effects and
/// disk target ownership are retained but are not replaced with synthetic state.
pub fn inspect_logfile_replay_analysis(
    checkpoint: NtfsLogCheckpointAnalysisReport,
    limits: NtfsLogReplayAnalysisLimits,
    r: &Resources,
) -> Result<NtfsLogReplayAnalysisReport> {
    let vector_bytes = limits
        .transactions
        .checked_mul(core::mem::size_of::<NtfsLogAnalysisTransaction>())
        .and_then(|v| {
            limits
                .records
                .checked_mul(core::mem::size_of::<NtfsLogAnalysisRecord>())
                .and_then(|n| v.checked_add(n))
        })
        .ok_or_else(|| exhausted("NTFS analysis inventory overflow"))?;
    let inventory = r.memory.reserve(
        u64::try_from(vector_bytes).map_err(|_| exhausted("NTFS analysis inventory width"))?,
    )?;
    let mut transactions = Vec::new();
    let mut records = Vec::new();
    transactions
        .try_reserve_exact(limits.transactions)
        .map_err(|_| exhausted("NTFS analysis transaction allocation"))?;
    records
        .try_reserve_exact(limits.records)
        .map_err(|_| exhausted("NTFS analysis record allocation"))?;
    if transactions.capacity() > limits.transactions || records.capacity() > limits.records {
        return Err(exhausted("NTFS analysis actual inventory capacity"));
    }
    let mut work = Work {
        used: checkpoint.work,
        maximum: limits.work,
    };
    let mut report = NtfsLogReplayAnalysisReport {
        pages: checkpoint.pages,
        payload_bytes: checkpoint.payload_bytes,
        checkpoint,
        dumps: None,
        transactions,
        records,
        error: None,
        projection_complete: false,
        initial_dirty_pages: 0,
        initial_open_attributes: 0,
        work: work.used,
        _inventory: inventory,
    };
    let result = (|| -> Result<bool> {
        charge(&mut work, 1, r)?;
        if report.checkpoint.stopping_error().is_some() {
            return Ok(false);
        }
        if report.pages > limits.pages || report.payload_bytes > limits.payload_bytes {
            return Err(exhausted("NTFS analysis consumed aggregate ceiling"));
        }
        if matches!(
            report.checkpoint.selection,
            Some(
                NtfsLogCheckpointSelection::NoRestartLsn
                    | NtfsLogCheckpointSelection::EmptyRestartPayload
            )
        ) {
            return Ok(false);
        }
        let original = report
            .checkpoint
            .restart_record()
            .ok_or_else(|| unsupported("NTFS analysis source-selected restart absent"))?;
        let lsn = original
            .header()
            .ok_or_else(|| unsupported("NTFS analysis source restart header absent"))?
            .this_lsn;
        let copy = report
            .checkpoint
            .traversal
            .overlay
            .discovery
            .tail
            .seed
            .selection()
            .selected_index()
            .ok_or_else(|| unsupported("NTFS analysis selected restart copy absent"))?;
        let mut dumps_limits = limits.dumps;
        dumps_limits.pages = dumps_limits.pages.min(limits.pages - report.pages);
        dumps_limits.payload_bytes = dumps_limits
            .payload_bytes
            .min(limits.payload_bytes - report.payload_bytes);
        dumps_limits.work = dumps_limits.work.min(limits.work.saturating_sub(work.used));
        let source: Arc<dyn ReadAt> = report.checkpoint.traversal.overlay.clone();
        let dumps = crate::fs_ntfs_logfile::checkpoint_dumps::inspect_native_checkpoint_dumps(
            source,
            dumps_limits,
            NtfsLogRecordQuery {
                lsn,
                restart_copy: copy,
            },
            (
                original
                    .restart_context()
                    .and_then(|a| a.client_oldest_lsn)
                    .ok_or_else(|| unsupported("NTFS analysis client oldest missing"))?,
                report
                    .checkpoint
                    .traversal
                    .overlay
                    .discovery
                    .endpoint()
                    .ok_or_else(|| unsupported("NTFS analysis endpoint missing"))?
                    .last_lsn,
            ),
            r,
        )?;
        work.used = work
            .used
            .checked_add(dumps.work())
            .ok_or_else(|| exhausted("NTFS analysis dump combined work"))?;
        report.pages = report
            .pages
            .checked_add(dumps.pages())
            .ok_or_else(|| exhausted("NTFS analysis dump page overflow"))?;
        report.payload_bytes = report
            .payload_bytes
            .checked_add(dumps.payload_bytes())
            .ok_or_else(|| exhausted("NTFS analysis dump payload overflow"))?;
        report.dumps = Some(dumps);
        let dumps = report
            .dumps
            .as_ref()
            .ok_or_else(|| unsupported("NTFS analysis dump evidence missing"))?;
        if !dumps.complete() {
            return Ok(false);
        }
        if dumps.checkpoint().restart_context() != original.restart_context()
            || dumps.checkpoint().payload() != original.payload()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS analysis source-selected restart changed",
            ));
        }
        for table_index in [0usize, 2] {
            if dumps.dumps()[table_index].record().is_none() {
                continue;
            }
            let client = dumps.dump_client(table_index)?;
            for i in 0..usize::from(le16(client.redo(), 2)) {
                charge(&mut work, 1, r)?;
                if table_index == 0 {
                    if dumps.open_attribute_entry(i)?.is_some() {
                        report.initial_open_attributes += 1;
                    }
                } else if let Some(joined) = dumps.dirty_page_open_attribute(i)? {
                    charge(&mut work, joined.dirty().lcn_bytes().len(), r)?;
                    report.initial_dirty_pages += 1;
                }
            }
        }
        // Initialize from EXACT allocated source transaction slots, never from
        // publicly editable observation fields supplied by callers.
        if dumps.dumps()[3].record().is_some() {
            let client = dumps.dump_client(3)?;
            if le16(client.redo(), 0) != 40 {
                return Err(unsupported("NTFS analysis transaction slot size"));
            }
            for i in 0..usize::from(le16(client.redo(), 2)) {
                charge(&mut work, 1, r)?;
                if let Some(entry) = dumps.transaction_entry(i)? {
                    if report.transactions.len() >= limits.transactions {
                        return Err(exhausted("NTFS analysis transaction ceiling"));
                    }
                    if !entry.state_semantics_supported() {
                        return Err(unsupported("NTFS analysis initial transaction state"));
                    }
                    let id = i
                        .checked_mul(40)
                        .and_then(|v| v.checked_add(24))
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or_else(|| invalid("NTFS analysis initial transaction ID"))?;
                    let first_link =
                        resolve_link(&report.checkpoint, entry.first_lsn, id, &mut work, r)?;
                    let previous_link =
                        resolve_link(&report.checkpoint, entry.previous_lsn, id, &mut work, r)?;
                    let undo_link =
                        resolve_link(&report.checkpoint, entry.undo_next_lsn, id, &mut work, r)?;
                    report.transactions.push(NtfsLogAnalysisTransaction {
                        id,
                        allocated: true,
                        state: entry.state,
                        first_lsn: entry.first_lsn,
                        previous_lsn: entry.previous_lsn,
                        undo_next_lsn: entry.undo_next_lsn,
                        initial_slot: Some(i),
                        first_link,
                        previous_link,
                        undo_link,
                    });
                }
            }
        }
        let anchor = report
            .checkpoint
            .anchor_index
            .ok_or_else(|| unsupported("NTFS analysis exact anchor absent"))?;
        for physical_index in anchor + 1..report.checkpoint.traversal.steps.len() {
            charge(&mut work, 1, r)?;
            let step = &report.checkpoint.traversal.steps[physical_index];
            if step.disposition != Some(NtfsLogPhysicalDisposition::ClientRecord) {
                continue;
            }
            if report.records.len() >= limits.records {
                return Err(exhausted("NTFS analysis record ceiling"));
            }
            let record = step.record();
            let header = record
                .header()
                .ok_or_else(|| unsupported("NTFS analysis record header missing"))?;
            let client =
                crate::fs_ntfs_logfile::client_record::inspect_native_analysis_record(record)?;
            charge(&mut work, client.raw().len(), r)?;
            let native_slot = usize::try_from((header.transaction_id - 24) / 40)
                .map_err(|_| exhausted("NTFS analysis native transaction slot width"))?;
            if native_slot >= limits.dumps.table.entries || native_slot >= usize::from(u16::MAX) {
                return Err(exhausted(
                    "NTFS analysis native transaction table extension ceiling",
                ));
            }
            let mut found = None;
            for (i, entry) in report.transactions.iter().enumerate() {
                charge(&mut work, 1, r)?;
                if entry.id == header.transaction_id {
                    found = Some(i);
                    break;
                }
            }
            let transaction_index = if let Some(i) = found {
                i
            } else {
                if report.transactions.len() >= limits.transactions {
                    return Err(exhausted("NTFS analysis transaction ceiling"));
                }
                report.transactions.push(NtfsLogAnalysisTransaction {
                    id: header.transaction_id,
                    allocated: false,
                    state: 0,
                    first_lsn: 0,
                    previous_lsn: 0,
                    undo_next_lsn: 0,
                    initial_slot: None,
                    first_link: NtfsLogAnalysisLink::Zero,
                    previous_link: NtfsLogAnalysisLink::Zero,
                    undo_link: NtfsLogAnalysisLink::Zero,
                });
                report.transactions.len() - 1
            };
            let previous = resolve_link(
                &report.checkpoint,
                header.previous_lsn,
                header.transaction_id,
                &mut work,
                r,
            )?;
            let undo_next = resolve_link(
                &report.checkpoint,
                header.undo_next_lsn,
                header.transaction_id,
                &mut work,
                r,
            )?;
            let tr = &mut report.transactions[transaction_index];
            if !tr.allocated {
                tr.allocated = true;
                tr.state = 1;
                tr.first_lsn = header.this_lsn;
                tr.initial_slot = None;
                tr.first_link = NtfsLogAnalysisLink::Visited(physical_index);
            }
            tr.previous_lsn = header.this_lsn;
            tr.previous_link = NtfsLogAnalysisLink::Visited(physical_index);
            tr.undo_link = if client.undo_operation == 1 || client.redo_operation == 24 {
                undo_next
            } else {
                NtfsLogAnalysisLink::Visited(physical_index)
            };
            tr.undo_next_lsn = if client.undo_operation == 1 {
                header.undo_next_lsn
            } else {
                header.this_lsn
            };
            match client.redo_operation {
                24 => tr.undo_next_lsn = header.undo_next_lsn,
                25 => tr.state = 2,
                26 => tr.state = 3,
                27 => tr.allocated = false,
                _ => {}
            }
            report.records.push(NtfsLogAnalysisRecord {
                physical_index,
                transaction_index,
                redo: client.redo_operation,
                undo: client.undo_operation,
                previous,
                undo_next,
                remaining_effects: !matches!(client.redo_operation, 0 | 24..=27 | 29..=32),
                state_after: tr.state,
                allocated_after: tr.allocated,
                first_after: tr.first_lsn,
                undo_after: tr.undo_next_lsn,
            });
        }
        Ok(true)
    })();
    let projected = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    let guarded = (|| -> Result<()> {
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS analysis final guard capacity"));
        }
        let previous = report
            .checkpoint
            .traversal
            .steps
            .iter()
            .map(NtfsLogPhysicalStep::record)
            .chain(report.checkpoint.restart_query.iter());
        let loaded = report.dumps.iter().flat_map(|d| {
            core::iter::once(d.checkpoint())
                .chain(d.dumps().iter().filter_map(NtfsLogCheckpointDump::record))
        });
        for record in previous.chain(loaded) {
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
                    .checkpoint
                    .traversal
                    .overlay
                    .read_exact_at(offset, &mut raw)
                    .map_err(|e| Error::io("NTFS analysis final exact source", e))?;
                r.cancellation.check()?;
                if raw != expected {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "NTFS analysis retained source changed",
                    ));
                }
            }
        }
        let remaining = limits
            .work
            .checked_sub(work.used)
            .ok_or_else(|| exhausted("NTFS analysis final combined work"))?;
        work.used = work
            .used
            .checked_add(
                report
                    .checkpoint
                    .traversal
                    .overlay
                    .check_source(remaining, r)?,
            )
            .ok_or_else(|| exhausted("NTFS analysis final guard overflow"))?;
        r.cancellation.check()
    })();
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    report.work = work.used;
    report.projection_complete = projected && report.stopping_error().is_none();
    Ok(report)
}

mod dirty_analysis;
pub use dirty_analysis::*;
