//! Native transaction-slot undo traversal; incomplete operation classes stay explicit.
use super::*;
mod mirror_finalization;
use crate::fs_ntfs_logfile::client_record::inspect_native_undo_record;
pub use mirror_finalization::*;
/// Independent finite bounds for source-owned native undo traversal.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogUndoLimits {
    /// Maximum retained allocated transaction dispositions.
    pub transactions: usize,
    /// Aggregate physical queries, page/payload storage and framing work.
    pub traversal: NtfsLogPhysicalTraversalLimits,
    /// Per-query exact consumed physical source capture.
    pub capture: crate::fs_ntfs_logfile::NtfsLogNativeContextLimits,
    /// Combined redo, undo, native effects and repeated source guards.
    pub work: usize,
}
/// One exact native transaction-table slot considered in ascending byte-offset order.
pub struct NtfsLogUndoTransaction {
    id: u32,
    initial_lsn: u64,
    active: bool,
    released: bool,
}
impl NtfsLogUndoTransaction {
    /// Source-derived physical transaction byte-offset identifier.
    pub fn id(&self) -> u32 {
        self.id
    }
    /// Exact source-derived undo-next at the end of analysis.
    pub fn initial_lsn(&self) -> u64 {
        self.initial_lsn
    }
    /// Whether native state is TransactionActive.
    pub fn active(&self) -> bool {
        self.active
    }
    /// Whether native enumeration reached the slot-release branch.
    pub fn released(&self) -> bool {
        self.released
    }
}
/// Native undo branch reached after the exact record was retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtfsLogUndoDisposition {
    /// Physical framing or client-header checks did not reach operation dispatch.
    Unresolved,
    /// Native Noop jumps directly to read_next_log_undo_action before target loading.
    Noop,
    /// Native can_skip_action branch reached after target-size preparation.
    SkippedOperation(u16),
    /// Shared native operation completed with NULL redo-LSN semantics.
    AppliedOperation(u16),
    /// Native action returned an I/O error; native read-next decides continuation.
    ActionFailed(u16),
    /// An actual operation requires the not-yet-admitted shared runtime interpreter.
    UnsupportedOperation(u16),
}
/// A retained exact undo query, including a failed assembly or native action refusal.
pub struct NtfsLogUndoStep {
    transaction: u32,
    requested_lsn: u64,
    record: Option<NtfsLogRecordReport>,
    capture: NativeReadCapture,
    disposition: NtfsLogUndoDisposition,
    action_error: Option<Error>,
}
impl NtfsLogUndoStep {
    /// Physical transaction slot whose undo chain requested this record.
    pub fn transaction(&self) -> u32 {
        self.transaction
    }
    /// Exact requested undo-next LSN; no chronological sorting is performed.
    pub fn requested_lsn(&self) -> u64 {
        self.requested_lsn
    }
    /// Exact reached native dispatch branch, independent of query completion.
    pub fn disposition(&self) -> NtfsLogUndoDisposition {
        self.disposition
    }
    /// Native action error retained independently from native undo control flow.
    /// A successful read-next overwrites this error instead of aborting undo.
    pub fn action_error(&self) -> Option<&Error> {
        self.action_error.as_ref()
    }
    /// Actual retained physical envelope, including partial framing failures.
    pub fn record(&self) -> Option<&NtfsLogRecordReport> {
        self.record.as_ref()
    }
}
/// Source-owned undo prefix with all original redo effects and consumed observations.
pub struct NtfsLogUndoReport {
    redo: NtfsLogRedoReport,
    transactions: Vec<NtfsLogUndoTransaction>,
    steps: Vec<NtfsLogUndoStep>,
    error: Option<Error>,
    complete: bool,
    work: usize,
    _transaction_lease: Reservation,
    _step_lease: Reservation,
}
impl NtfsLogUndoReport {
    /// Original runtime state and native redo shadow effects.
    pub fn redo(&self) -> &NtfsLogRedoReport {
        &self.redo
    }
    /// Actual ascending physical transaction-slot enumeration.
    pub fn transactions(&self) -> &[NtfsLogUndoTransaction] {
        &self.transactions
    }
    /// Exact linked undo queries in their native execution order.
    pub fn steps(&self) -> &[NtfsLogUndoStep] {
        &self.steps
    }
    /// Original failure retained at the first unsupported or failed native step.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error
            .as_ref()
            .or_else(|| self.redo.stopping_error())
            .or_else(|| {
                self.steps
                    .iter()
                    .filter_map(|s| s.record.as_ref())
                    .find_map(|r| r.stopping_error())
            })
    }
    /// Whether all allocated slots and admitted undo operations reached native release.
    pub fn admitted_undo_complete(&self) -> bool {
        self.complete
    }
    /// Aggregate work including all preceding source-owned analysis and redo.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Native traversal alone does not qualify the full active window.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// No durable writer or recovery authority is granted.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn in_client_interval(lsn: u64, oldest: u64, current: u64) -> bool {
    lsn != 0 && lsn >= oldest && lsn <= current
}
fn guard_undo(report: &NtfsLogUndoReport, w: &mut Work, r: &Resources) -> Result<()> {
    repeat(&report.redo, w, r)?;
    let context = report.redo.input.input.analysis().context();
    let overlay = &report
        .redo
        .input
        .input
        .analysis()
        .replay()
        .checkpoint()
        .traversal()
        .overlay;
    for step in &report.steps {
        charge(w, step.capture.work()?, r)?;
        step.capture.check(context, r)?;
        let Some(record) = &step.record else {
            continue;
        };
        for (offset, expected) in record
            .restart()
            .copies()
            .iter()
            .filter(|c| c.read_complete())
            .map(|c| (c.offset(), c.raw()))
            .chain(
                record
                    .pages()
                    .iter()
                    .filter(|p| p.read_complete())
                    .map(|p| (p.offset(), p.raw())),
            )
        {
            charge(
                w,
                expected
                    .len()
                    .checked_mul(3)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| exhausted("NTFS undo repeated raw work"))?,
                r,
            )?;
            let _lease = r.memory.reserve(expected.len() as u64)?;
            let mut raw = bytes(expected.len())?;
            overlay
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS undo repeated raw source", e))?;
            r.cancellation.check()?;
            if raw != expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS undo consumed raw source changed",
                ));
            }
        }
    }
    r.cancellation.check()
}
// fslog.c add_allocated_vcns mutates the copied native header even for
// can_skip_action classes. The earlier run lookup/alignment branch performs
// no map mutation; source LCNs are not inserted by this native undo loop.
fn extend_undo_target(
    runtime: &mut [NtfsLogRuntimeTarget],
    client: &crate::fs_ntfs_logfile::NtfsLogClientRecord<'_>,
    cluster: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    if client.lcn_count == 0 {
        return Ok(());
    }
    let mut winner = None;
    for (index, target) in runtime.iter().enumerate() {
        charge(w, 1, r)?;
        if target.slot == u32::from(client.target_attribute) {
            winner = Some(index);
            break;
        }
    }
    let index = winner.ok_or_else(|| unsupported("NTFS undo source runtime target unavailable"))?;
    let target = &mut runtime[index];
    let raw = &mut target.raw;
    let nonresident = *raw
        .get(8)
        .ok_or_else(|| invalid("NTFS undo native target header"))?
        != 0;
    let minimum = if nonresident { 64 } else { 20 };
    if raw.len() < minimum {
        return Err(invalid("NTFS undo native target sizes unavailable"));
    }
    let vcn = u64::try_from(client.target_vcn)
        .map_err(|_| unsupported("NTFS undo negative target VCN configuration"))?;
    let mut size = vcn
        .checked_add(1)
        .and_then(|n| n.checked_mul(cluster))
        .ok_or_else(|| unsupported("NTFS undo native size overflow"))?;
    for ordinal in 0..client.lcn_count {
        charge(w, if nonresident { 25 } else { 5 }, r)?;
        if nonresident {
            if size > le64(raw, 48) {
                for offset in [40usize, 48, 56] {
                    raw[offset..offset + 8].copy_from_slice(&size.to_le_bytes());
                }
            }
        } else if size > u64::from(le32(raw, 16)) {
            // Native cpu_to_le32 keeps the low word of the u64 size.
            raw[16..20].copy_from_slice(&(size as u32).to_le_bytes());
        }
        if ordinal + 1 != client.lcn_count {
            size = size
                .checked_add(cluster)
                .ok_or_else(|| unsupported("NTFS undo native size progression overflow"))?;
        }
    }
    Ok(())
}
/// Follow native allocated-slot undo chains using exact retained physical queries.
///
/// Native Noop is modeled before any target access. Other operation classes
/// remain explicit refusals until their shared FILE/index/bitmap interpreter is
/// wired for NULL redo-LSN semantics. Such refusals never release the transaction
/// or permit mirror finalization. No caller-selected owner, geometry or LSN seed
/// supplies authority; all entries come from the retained native analysis.
pub fn inspect_logfile_native_undo(
    redo: NtfsLogRedoReport,
    limits: NtfsLogUndoLimits,
    r: &Resources,
) -> Result<NtfsLogUndoReport> {
    let (transactions, transaction_lease) = vector(limits.transactions, r)?;
    let (steps, step_lease) = vector(limits.traversal.queries, r)?;
    let mut w = Work {
        used: redo.work(),
        maximum: limits.work,
    };
    charge(&mut w, 0, r)?;
    let mut report = NtfsLogUndoReport {
        redo,
        transactions,
        steps,
        error: None,
        complete: false,
        work: w.used,
        _transaction_lease: transaction_lease,
        _step_lease: step_lease,
    };
    let result = (|| -> Result<bool> {
        guard_undo(&report, &mut w, r)?;
        if !report.redo.admitted_redo_complete() {
            return Ok(false);
        }
        let analysis = report.redo.input.input.analysis();
        let overlay = analysis.replay().checkpoint().traversal().overlay.clone();
        let selection = overlay.discovery.tail.seed.selection();
        let selected = selection
            .selected_index()
            .ok_or_else(|| unsupported("NTFS undo restart selection missing"))?;
        let area = *selection
            .selected_context()
            .ok_or_else(|| unsupported("NTFS undo restart context missing"))?;
        let oldest = area
            .client_oldest_lsn
            .ok_or_else(|| unsupported("NTFS undo client oldest missing"))?;
        let current = overlay
            .discovery
            .endpoint()
            .ok_or_else(|| unsupported("NTFS undo endpoint missing"))?
            .last_lsn;
        let mut framing_work = 0usize;
        let mut pages = 0usize;
        let mut payload = 0usize;
        let mut previous_id = None;
        loop {
            // enum_rstbl walks physical slots. Analysis vector insertion order is
            // not native slot order, so choose the smallest remaining allocated ID.
            let mut winner = None;
            for (index, transaction) in analysis.replay().transactions().iter().enumerate() {
                charge(&mut w, 1, r)?;
                if transaction.allocated()
                    && previous_id.is_none_or(|id| transaction.id() > id)
                    && winner.is_none_or(|i: usize| {
                        transaction.id() < analysis.replay().transactions()[i].id()
                    })
                {
                    winner = Some(index);
                }
            }
            let Some(index) = winner else {
                return Ok(true);
            };
            let transaction = &analysis.replay().transactions()[index];
            if report.transactions.len() == limits.transactions {
                return Err(exhausted("NTFS undo transaction ceiling"));
            }
            previous_id = Some(transaction.id());
            let entry = report.transactions.len();
            report.transactions.push(NtfsLogUndoTransaction {
                id: transaction.id(),
                initial_lsn: transaction.undo_next_lsn(),
                active: transaction.state() == 1,
                released: false,
            });
            if transaction.state() != 1 || transaction.undo_next_lsn() == 0 {
                report.transactions[entry].released = true;
                continue;
            }
            let mut lsn = transaction.undo_next_lsn();
            if !in_client_interval(lsn, oldest, current) {
                return Err(invalid(
                    "NTFS native initial undo LSN outside client interval",
                ));
            }
            let chain_start = report.steps.len();
            loop {
                charge(&mut w, 1, r)?;
                for old in &report.steps[chain_start..] {
                    charge(&mut w, 1, r)?;
                    if old.requested_lsn == lsn {
                        return Err(unsupported(
                            "NTFS native undo cycle exceeds supported finite traversal",
                        ));
                    }
                }
                if report.steps.len() == limits.traversal.queries
                    || limits.traversal.pages.saturating_sub(pages) < 2
                {
                    return Err(exhausted("NTFS undo aggregate query/page ceiling"));
                }
                let mut record_limits = limits.traversal.record;
                record_limits.pages = record_limits.pages.min(limits.traversal.pages - pages - 2);
                record_limits.payload_bytes = record_limits
                    .payload_bytes
                    .min(limits.traversal.payload_bytes.saturating_sub(payload));
                charge(&mut w, limits.capture.work, r)?;
                let remaining = limits
                    .work
                    .checked_sub(w.used)
                    .ok_or_else(|| exhausted("NTFS undo framing work"))?
                    .min(
                        limits
                            .traversal
                            .work
                            .checked_sub(framing_work)
                            .ok_or_else(|| exhausted("NTFS undo aggregate framing work"))?,
                    );
                let (query, capture) =
                    analysis
                        .context()
                        .capture_native_reads(limits.capture, r, || {
                            let source: Arc<dyn ReadAt> = overlay.clone();
                            crate::fs_ntfs_logfile::record::inspect_physical_envelope_with_work(
                                source,
                                limits.traversal.restart,
                                record_limits,
                                (lsn, Some(selected)),
                                remaining,
                                r,
                            )
                        })?;
                // Retain the completed capture before inspecting any result or
                // performing charged work. Late failures cannot erase consumed IO.
                let query_error;
                let record = match query {
                    Ok(record) => {
                        query_error = None;
                        Some(record)
                    }
                    Err(error) => {
                        query_error = Some(error);
                        None
                    }
                };
                report.steps.push(NtfsLogUndoStep {
                    transaction: transaction.id(),
                    requested_lsn: lsn,
                    record,
                    capture,
                    disposition: NtfsLogUndoDisposition::Unresolved,
                    action_error: None,
                });
                if let Some(error) = query_error {
                    return Err(error);
                }
                let record = report
                    .steps
                    .last()
                    .expect("retained undo step")
                    .record
                    .as_ref()
                    .expect("successful assembly");
                let record_work = record
                    .restart()
                    .work()
                    .checked_add(record.work())
                    .ok_or_else(|| exhausted("NTFS undo record work"))?;
                framing_work = framing_work
                    .checked_add(record_work)
                    .filter(|n| *n <= limits.traversal.work)
                    .ok_or_else(|| exhausted("NTFS undo aggregate framing work"))?;
                charge(&mut w, record_work, r)?;
                pages = pages
                    .checked_add(2 + record.pages().len())
                    .ok_or_else(|| exhausted("NTFS undo page count"))?;
                payload = payload
                    .checked_add(record.retained_payload_bytes())
                    .ok_or_else(|| exhausted("NTFS undo payload count"))?;
                if !record.complete() {
                    return Ok(false);
                }
                if record.restart_context() != Some(&area)
                    || !record.page_flag_semantics_supported()
                    || !record.envelope_flag_semantics_supported()
                {
                    return Err(unsupported(
                        "NTFS undo same-context physical framing incomplete",
                    ));
                }
                let client = inspect_native_undo_record(record)?;
                // Pinned undo tests Noop BEFORE loading the target or extending
                // attributes. Other skipped classes still need those side effects.
                let next = record
                    .header()
                    .ok_or_else(|| invalid("NTFS undo retained header missing"))?
                    .undo_next_lsn;
                let source_lsn = record
                    .header()
                    .ok_or_else(|| invalid("NTFS undo envelope header"))?
                    .this_lsn;
                let operation = client.undo_operation;
                let target_vcn = client.target_vcn;
                let cluster_offset = client.cluster_offset;
                if operation != 0 {
                    // Unlike Noop, can_skip_action is tested only after the
                    // target's resident/nonresident size extension. Keep those
                    // runtime mutations even when actual action dispatch refuses.
                    extend_undo_target(
                        &mut report.redo.runtime,
                        &client,
                        analysis.context().geometry().cluster_bytes(),
                        &mut w,
                        r,
                    )?;
                }
                let disposition = if operation == 0 {
                    NtfsLogUndoDisposition::Noop
                } else if skip(operation) {
                    NtfsLogUndoDisposition::SkippedOperation(operation)
                } else {
                    NtfsLogUndoDisposition::AppliedOperation(operation)
                };
                let mut action_error = None;
                if matches!(operation, 2 | 3) {
                    let geometry = analysis.context().geometry();
                    let vcn = u64::try_from(target_vcn)
                        .map_err(|_| unsupported("NTFS undo FILE negative target VCN"))?;
                    let vbo = vcn
                        .checked_mul(geometry.cluster_bytes())
                        .and_then(|n| n.checked_add(u64::from(cluster_offset) << 9))
                        .ok_or_else(|| unsupported("NTFS undo FILE virtual byte overflow"))?;
                    let number = vbo / geometry.record_bytes() as u64;
                    let mut loaded = false;
                    for file in &report.redo.files {
                        charge(&mut w, 1, r)?;
                        loaded |= file.number == number && file.cached && file.loaded;
                    }
                    if !loaded || report.redo.mirror.is_none() {
                        return Err(unsupported(
                            "NTFS undo FILE source cache/mirror admission unavailable",
                        ));
                    }
                    let record_lsn = source_lsn;
                    let mutation = if operation == 2 {
                        let origin = usize::from(le16(client.raw(), 8));
                        let length = usize::from(le16(client.raw(), 10));
                        let data = client
                            .raw()
                            .get(origin..origin + length)
                            .ok_or_else(|| unsupported("NTFS initialize undo payload range"))?;
                        native_file::Mutation::Initialize {
                            offset: usize::from(client.record_offset),
                            data,
                        }
                    } else {
                        native_file::Mutation::Deallocate
                    };
                    let action = native_file::apply(
                        analysis.context(),
                        report
                            .redo
                            .capture
                            .iter()
                            .chain(report.steps.iter().map(|step| &step.capture)),
                        &mut report.redo.files,
                        &mut report.redo.fragments,
                        vbo,
                        true,
                        mutation,
                        &mut report.redo.dirty_volume,
                        record_lsn,
                        None,
                        report.redo.limits,
                        &mut w,
                        r,
                    );
                    let written = matches!(&action, Ok(true));
                    if let Err(error) = action {
                        if error.kind != ErrorKind::Io {
                            return Err(error);
                        }
                        action_error = Some(error);
                    }
                    if written
                        && action_error.is_none()
                        && let Some(mirror) = &mut report.redo.mirror
                    {
                        mirror.pending |= number < mirror.records;
                    }
                } else if matches!(operation, 8 | 21 | 22) {
                    let mut target_index = None;
                    for (index, target) in report.redo.runtime.iter().enumerate() {
                        charge(&mut w, 1, r)?;
                        if target.slot == u32::from(client.target_attribute) {
                            target_index = Some(index);
                            break;
                        }
                    }
                    let target_index = target_index
                        .ok_or_else(|| unsupported("NTFS undo nonresident target unavailable"))?;
                    let origin = usize::from(le16(client.raw(), 8));
                    let length = usize::from(le16(client.raw(), 10));
                    let action = apply_nonresident(
                        analysis.context(),
                        &report.redo.runtime[target_index],
                        &mut report.redo.fragments,
                        &mut report.redo.dirty_volume,
                        report
                            .redo
                            .capture
                            .iter()
                            .chain(report.steps.iter().map(|step| &step.capture)),
                        &client,
                        operation,
                        source_lsn,
                        origin,
                        length,
                        report.redo.limits,
                        &mut w,
                        r,
                    );
                    if let Err(error) = action {
                        if error.kind != ErrorKind::Io {
                            return Err(error);
                        }
                        action_error = Some(error);
                    }
                } else if !skip(operation) {
                    report
                        .steps
                        .last_mut()
                        .expect("retained undo step")
                        .disposition = NtfsLogUndoDisposition::UnsupportedOperation(operation);
                    return Err(unsupported(
                        "NTFS native undo target/runtime operation effects not yet implemented",
                    ));
                }
                let step = report.steps.last_mut().expect("retained undo step");
                step.disposition = if action_error.is_some() {
                    NtfsLogUndoDisposition::ActionFailed(operation)
                } else {
                    disposition
                };
                step.action_error = action_error;
                if !in_client_interval(next, oldest, current) {
                    report.transactions[entry].released = true;
                    break;
                }
                lsn = next;
            }
        }
    })();
    let candidate = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    if let Err(error) = guard_undo(&report, &mut w, r) {
        report.error.get_or_insert(error);
    }
    report.complete = candidate && report.stopping_error().is_none();
    report.work = w.used;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_undo_interval_is_inclusive_and_zero_is_not_a_query() {
        assert!(!in_client_interval(0, 0, 10));
        assert!(!in_client_interval(4, 5, 10));
        assert!(in_client_interval(5, 5, 10));
        assert!(in_client_interval(10, 5, 10));
        assert!(!in_client_interval(11, 5, 10));
    }
}
