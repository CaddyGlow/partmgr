//! Source-owned checkpoint reference loading without active-window selection.
use super::*;

/// Per-operation and aggregate ceilings for a checkpoint and its four dumps.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogCheckpointDumpLimits {
    /// Per-query restart ceilings, additionally constrained by aggregate work.
    pub restart: NtfsLogFileLimits,
    /// Per-query record ceilings, additionally constrained by aggregate ceilings.
    pub record: NtfsLogRecordLimits,
    /// Per-table ceilings, additionally constrained by aggregate work.
    pub table: NtfsLogRestartTableLimits,
    /// Maximum queries, including the checkpoint.
    pub queries: usize,
    /// Aggregate retained pages, including two restart buffers for each query.
    pub pages: usize,
    /// Aggregate reserved client payload bytes, excluding protected page buffers.
    pub payload_bytes: usize,
    /// Aggregate query, restart, assembly and generic-table validation work.
    pub work: usize,
}
/// Expected checkpoint reference role, without typed body semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogCheckpointDumpKind {
    /// Redo operation 29.
    OpenAttributes,
    /// Redo operation 30; names array bytes remain opaque.
    AttributeNames,
    /// Redo operation 31.
    DirtyPages,
    /// Redo operation 32.
    Transactions,
}
/// One original checkpoint reference and its retained query evidence.
pub struct NtfsLogCheckpointDump {
    kind: NtfsLogCheckpointDumpKind,
    reference: NtfsLogTableReference,
    record: Option<NtfsLogRecordReport>,
    bytes_match: Option<bool>,
    table_validated: bool,
}
impl NtfsLogCheckpointDump {
    /// Reference role from immutable checkpoint bytes.
    pub fn kind(&self) -> NtfsLogCheckpointDumpKind {
        self.kind
    }
    /// Original reference when the parent report has `references_available()`.
    /// Otherwise these are zero placeholders; zero-byte references are not queried.
    pub fn reference(&self) -> NtfsLogTableReference {
        self.reference
    }
    /// Retained query, including a failed candidate, if attempted.
    pub fn record(&self) -> Option<&NtfsLogRecordReport> {
        self.record.as_ref()
    }
    /// Whether checkpoint bytes equal the bounded redo length, when available.
    /// A mismatch is an observation, not a universal corruption judgment.
    pub fn reference_bytes_match(&self) -> Option<bool> {
        self.bytes_match
    }
    /// Whether generic table links/counts passed; always false for names arrays.
    pub fn table_validated(&self) -> bool {
        self.table_validated
    }
}
enum Stop {
    Checkpoint,
    Dump(usize),
    Global(Error),
}
/// Owned checkpoint and partial dump evidence from one immutable source context.
pub struct NtfsLogCheckpointDumpReport {
    checkpoint: NtfsLogRecordReport,
    native_body: bool,
    native_bounds: Option<(u64, u64)>,
    references_available: bool,
    dumps: [NtfsLogCheckpointDump; 4],
    stop: Option<Stop>,
    source_error: Option<Error>,
    queries: usize,
    pages: usize,
    payload_bytes: usize,
    work: usize,
}
impl NtfsLogCheckpointDumpReport {
    pub(super) fn dump_client(&self, index: usize) -> Result<NtfsLogClientRecord<'_>> {
        let record = self.dumps[index]
            .record
            .as_ref()
            .ok_or_else(|| invalid("NTFS dump client source record missing"))?;
        if self.native_body {
            client_record::inspect_native_dump_record(record)
        } else {
            inspect_ntfs_log_client_record(record)
        }
    }
    pub(super) fn allocated_table_slot(
        &self,
        dump_index: usize,
        index: usize,
    ) -> Result<Option<&[u8]>> {
        let checkpoint = inspect_ntfs_client_restart(&self.checkpoint)?;
        if (le32(checkpoint.raw(), 0), le32(checkpoint.raw(), 4)) != (1, 0) {
            return Err(unsupported("NTFS checkpoint entry client version"));
        }
        let dump = &self.dumps[dump_index];
        if dump.reference.bytes == 0 {
            return Ok(None);
        }
        if !dump.table_validated {
            return Err(invalid("NTFS checkpoint entry table not validated"));
        }
        let client = self.dump_client(dump_index)?;
        let raw = client.redo();
        let size = usize::from(le16(raw, 0));
        let capacity = usize::from(le16(raw, 2));
        if index >= capacity {
            return Ok(None);
        }
        let start = 24 + index * size;
        let entry = &raw[start..start + size];
        if le32(entry, 0) != u32::MAX {
            return Ok(None);
        }
        Ok(Some(entry))
    }
    /// Original checkpoint query, including its independently retained restarts.
    pub fn checkpoint(&self) -> &NtfsLogRecordReport {
        &self.checkpoint
    }
    /// Whether all four references were decoded from the original checkpoint.
    /// False distinguishes unavailable references from decoded zero-byte entries.
    pub fn references_available(&self) -> bool {
        self.references_available
    }
    /// Four references in open attributes, names, dirty pages, transaction order.
    pub fn dumps(&self) -> &[NtfsLogCheckpointDump; 4] {
        &self.dumps
    }
    /// All nonempty references loaded and admitted structurally with final guards.
    /// Does not imply exact reference-length matches, names bodies or recovery.
    pub fn complete(&self) -> bool {
        self.stop.is_none() && self.source_error.is_none()
    }
    /// Original failure, retaining backend errors in partial record reports.
    pub fn stopping_error(&self) -> Option<&Error> {
        match self.stop.as_ref() {
            Some(Stop::Checkpoint) => self.checkpoint.stopping_error(),
            Some(Stop::Dump(i)) => self.dumps[*i]
                .record
                .as_ref()
                .and_then(|r| r.stopping_error()),
            Some(Stop::Global(error)) => Some(error),
            None => self.source_error.as_ref(),
        }
    }
    /// Final source-length/cancellation failure, independent of earlier failures.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref()
    }
    /// Queries charged, including attempts failing before a record report exists.
    pub fn queries(&self) -> usize {
        self.queries
    }
    /// Retained restart and candidate pages.
    pub fn pages(&self) -> usize {
        self.pages
    }
    /// Reserved client payload bytes retained across owned reports.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Aggregate charged work, including each repeated restart inspection.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: caller-selected context does not identify an active window.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: typed table bodies and transaction replay remain unimplemented.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
}

struct Counters {
    queries: usize,
    pages: usize,
    payload: usize,
    work: usize,
}
fn query_record(
    source: &Arc<dyn ReadAt>,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    used: &mut Counters,
    r: &Resources,
) -> Result<NtfsLogRecordReport> {
    r.cancellation.check()?;
    if used.queries >= limits.queries
        || limits.pages.saturating_sub(used.pages) < 2
        || used.work >= limits.work
    {
        return Err(exhausted(
            "NTFS checkpoint aggregate query/page/work ceiling",
        ));
    }
    used.queries += 1;
    used.work += 1;
    let mut record_limits = limits.record;
    record_limits.pages = record_limits.pages.min(limits.pages - used.pages - 2);
    record_limits.payload_bytes = record_limits
        .payload_bytes
        .min(limits.payload_bytes.saturating_sub(used.payload));
    let report = record::inspect_record_with_work(
        source.clone(),
        limits.restart,
        record_limits,
        (query.lsn, Some(query.restart_copy)),
        limits.work - used.work,
        r,
    )?;
    used.work += report.restart().work() + report.work();
    used.pages += 2 + report.pages().len();
    used.payload += report.retained_payload_bytes();
    Ok(report)
}

/// Load a source-bound checkpoint and each nonempty referenced dump in one context.
///
/// The caller must maintain immutable source contents throughout. Equal-length
/// guards cannot universally detect concurrent writes; selected restart bytes
/// and decoded context must remain identical across repeated queries. No fast
/// copy is overlaid. Preflight failures without checkpoint evidence return Err;
/// subsequent failures retain the checkpoint and prior/failed dump reports.
pub fn inspect_logfile_checkpoint_dumps(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    r: &Resources,
) -> Result<NtfsLogCheckpointDumpReport> {
    inspect_checkpoint_dumps_ordered(source, limits, query, [0, 1, 2, 3], false, None, r)
}

// Pinned process_log loads transaction, dirty, names and open dumps in this
// order before analysis. Public structural caller-selected loader is unchanged.
pub(super) fn inspect_native_checkpoint_dumps(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    bounds: (u64, u64),
    r: &Resources,
) -> Result<NtfsLogCheckpointDumpReport> {
    inspect_checkpoint_dumps_ordered(source, limits, query, [3, 2, 1, 0], true, Some(bounds), r)
}
#[allow(clippy::too_many_arguments)]
fn inspect_checkpoint_dumps_ordered(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    order: [usize; 4],
    native_body: bool,
    native_bounds: Option<(u64, u64)>,
    r: &Resources,
) -> Result<NtfsLogCheckpointDumpReport> {
    let source_bytes = source.len();
    let mut used = Counters {
        queries: 0,
        pages: 0,
        payload: 0,
        work: 0,
    };
    let checkpoint = query_record(&source, limits, query, &mut used, r)?;
    let empty = |kind| NtfsLogCheckpointDump {
        kind,
        reference: NtfsLogTableReference { lsn: 0, bytes: 0 },
        record: None,
        bytes_match: None,
        table_validated: false,
    };
    let mut report = NtfsLogCheckpointDumpReport {
        checkpoint,
        native_body,
        native_bounds,
        references_available: false,
        dumps: [
            empty(NtfsLogCheckpointDumpKind::OpenAttributes),
            empty(NtfsLogCheckpointDumpKind::AttributeNames),
            empty(NtfsLogCheckpointDumpKind::DirtyPages),
            empty(NtfsLogCheckpointDumpKind::Transactions),
        ],
        stop: None,
        source_error: None,
        queries: 0,
        pages: 0,
        payload_bytes: 0,
        work: 0,
    };
    if !report.checkpoint.complete() {
        report.stop = Some(Stop::Checkpoint);
    } else if let Err(error) = load_dumps(&source, limits, query, order, &mut report, &mut used, r)
        && report.stop.is_none()
    {
        report.stop = Some(Stop::Global(error));
    }
    report.source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != source_bytes || report.checkpoint.restart().source_bytes() != source_bytes)
            .then(|| {
                Error::new(
                    ErrorKind::StalePlan,
                    "NTFS checkpoint source length changed",
                )
            })
    });
    report.queries = used.queries;
    report.pages = used.pages;
    report.payload_bytes = used.payload;
    report.work = used.work;
    Ok(report)
}
#[allow(clippy::too_many_arguments)]
fn load_dumps(
    source: &Arc<dyn ReadAt>,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    order: [usize; 4],
    report: &mut NtfsLogCheckpointDumpReport,
    used: &mut Counters,
    r: &Resources,
) -> Result<()> {
    let checkpoint = inspect_ntfs_client_restart(&report.checkpoint)?;
    // Private immutable payload, never caller-mutable public observation fields.
    let raw = checkpoint.raw();
    for (i, dump) in report.dumps.iter_mut().enumerate() {
        dump.reference = NtfsLogTableReference {
            lsn: le64(raw, 16 + i * 8),
            bytes: le32(raw, 48 + i * 4),
        };
    }
    report.references_available = true;
    for i in order {
        r.cancellation.check()?;
        let reference = report.dumps[i].reference;
        if reference.bytes == 0 {
            continue;
        }
        if reference.lsn == 0 {
            return Err(invalid("NTFS nonempty checkpoint reference has zero LSN"));
        }
        if let Some((oldest, current)) = report.native_bounds
            && (reference.lsn < oldest || reference.lsn > current)
        {
            return Err(invalid("NTFS native checkpoint dump outside client bounds"));
        }
        let record = query_record(
            source,
            limits,
            NtfsLogRecordQuery {
                lsn: reference.lsn,
                ..query
            },
            used,
            r,
        )?;
        let dump = &mut report.dumps[i];
        dump.record = Some(record);
        let record = dump
            .record
            .as_ref()
            .ok_or_else(|| invalid("NTFS dump query evidence missing"))?;
        if !record.complete() {
            report.stop = Some(Stop::Dump(i));
            return Ok(());
        }
        let selected = usize::from(query.restart_copy);
        if record.restart_context() != report.checkpoint.restart_context()
            || record.restart().copies()[selected].raw()
                != report.checkpoint.restart().copies()[selected].raw()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS checkpoint restart context changed",
            ));
        }
        let client = if report.native_body {
            client_record::inspect_native_dump_record(record)?
        } else {
            inspect_ntfs_log_client_record(record)?
        };
        if le16(client.raw(), 0) != 29 + i as u16 {
            return Err(invalid("NTFS checkpoint dump operation mismatch"));
        }
        dump.bytes_match = Some(client.redo().len() as u64 == u64::from(reference.bytes));
        if i != 1 {
            let mut table_limits = limits.table;
            table_limits.work = table_limits.work.min(limits.work.saturating_sub(used.work));
            let (table, charged) = restart_table::inspect_table_with_work(&client, table_limits, r);
            used.work += charged;
            let table = table?;
            if report.native_body {
                r.cancellation.check()?;
                used.work = used
                    .work
                    .checked_add(1)
                    .filter(|n| *n <= limits.work)
                    .ok_or_else(|| exhausted("NTFS native restart table prefix work"))?;
                if usize::from(table.entry_bytes)
                    .checked_add(24)
                    .is_none_or(|minimum| minimum > client.redo().len())
                {
                    return Err(invalid("NTFS native restart table lacks one physical slot"));
                }
            }
            dump.table_validated = true;
        }
    }
    Ok(())
}

/// Source-owned checkpoint dump evidence bound to native `$LogFile` record 2.
pub struct NtfsVolumeCheckpointDumpReport {
    /// Source-scoped identity of the native base record.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Owned structural dump evidence, without recovery readiness.
    pub report: NtfsLogCheckpointDumpReport,
}
/// Resolve ordinary initialized record-2 DATA and load one checkpoint's dumps.
/// Uses the same native-map admission and immutable-source contract as record queries.
pub fn inspect_ntfs_logfile_checkpoint_dumps(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogCheckpointDumpLimits,
    query: NtfsLogRecordQuery,
    r: &Resources,
) -> Result<NtfsVolumeCheckpointDumpReport> {
    r.cancellation.check()?;
    if limits.restart.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_checkpoint_dumps(Arc::new(native), limits, query, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeCheckpointDumpReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
