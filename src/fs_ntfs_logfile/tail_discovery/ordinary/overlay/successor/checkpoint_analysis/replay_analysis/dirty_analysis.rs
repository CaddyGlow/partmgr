//! Source-native geometry and dirty-page analysis, without target/recovery authority.
use super::*;
use crate::fs_ntfs_logfile::NtfsLogNativeAnalysisContext;
mod open_analysis;
pub use open_analysis::*;
mod target_intents;
pub use target_intents::*;
/// Bounded native dirty-table storage and combined analysis work.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogDirtyAnalysisLimits {
    /// Maximum physical native restart-table slots, including free slots.
    pub entries: usize,
    /// Maximum LCN cells per native dirty slot.
    pub lcns: usize,
    /// Combined prior replay evidence, dirty derivation and all final guards.
    pub work: usize,
}
/// Retained native dirty state plus its complete source-owned input evidence.
pub struct NtfsLogDirtyAnalysisReport {
    context: NtfsLogNativeAnalysisContext,
    replay: NtfsLogReplayAnalysisReport,
    table: Vec<u8>,
    open: Option<OpenState>,
    processed: usize,
    error: Option<Error>,
    complete: bool,
    work: usize,
    _lease: Reservation,
}
impl NtfsLogDirtyAnalysisReport {
    /// Retained source-owned native-volume context and exact physical guards.
    pub fn context(&self) -> &NtfsLogNativeAnalysisContext {
        &self.context
    }
    /// Original checkpoint, suffix, transaction fields and source observations.
    pub fn replay(&self) -> &NtfsLogReplayAnalysisReport {
        &self.replay
    }
    /// Derived native restart-table bytes, including exact physical slot/free order.
    pub fn dirty_table_bytes(&self) -> &[u8] {
        &self.table
    }
    /// Source-derived open attributes/names, when the combined pass was requested.
    pub fn open_attributes(&self) -> Option<&OpenState> {
        self.open.as_ref()
    }
    /// Successfully modeled selected-client suffix records before any refusal.
    pub fn processed_records(&self) -> usize {
        self.processed
    }
    /// Original derivation or repeated-source failure.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error.as_ref().or_else(|| self.replay.stopping_error())
    }
    /// Whether all admitted dirty fields reached the exact suffix end and guards.
    pub fn dirty_fields_complete(&self) -> bool {
        self.complete
    }
    /// Aggregate work including prior replay evidence.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Dirty fields alone do not qualify a complete analysis pass.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
    /// Native active-window qualification remains unavailable.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// No target mapping, provisional target or redo/undo execution authority.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn slots(b: &[u8]) -> usize {
    if b.is_empty() {
        0
    } else {
        usize::from(le16(b, 2))
    }
}
fn offset(b: &[u8], i: usize) -> usize {
    24 + i * usize::from(le16(b, 0))
}
fn allocated(b: &[u8], i: usize) -> bool {
    le32(b, offset(b, i)) == u32::MAX
}
fn find(b: &[u8], attribute: u32, vcn: u64, w: &mut Work, r: &Resources) -> Result<Option<usize>> {
    for i in 0..slots(b) {
        charge(w, 1, r)?;
        let at = offset(b, i);
        if !allocated(b, i) || le32(b, at + 4) != attribute {
            continue;
        }
        let first = le64(b, at + 16);
        let end = first
            .checked_add(u64::from(le32(b, at + 12)))
            .ok_or_else(|| unsupported("NTFS dirty VCN interval overflow"))?;
        if vcn >= first && vcn < end {
            return Ok(Some(at));
        }
    }
    Ok(None)
}
fn free(b: &mut [u8], at: usize) -> Result<()> {
    let last = le32(b, 20);
    let first = le32(b, 16);
    if at < u32::MAX as usize && (at as u32) < le32(b, 12) {
        put32(b, at, first);
        put32(b, 16, at as u32);
        if last == 0 {
            put32(b, 20, at as u32);
        }
    } else {
        if last != 0 {
            put32(b, last as usize, at as u32);
        } else {
            put32(b, 16, at as u32);
        }
        put32(b, 20, at as u32);
        put32(b, at, 0);
    }
    let total = le16(b, 4)
        .checked_sub(1)
        .ok_or_else(|| invalid("NTFS dirty allocated count"))?;
    put16(b, 4, total);
    Ok(())
}
fn initialize(
    b: &mut Vec<u8>,
    stride: usize,
    count: usize,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let bytes = 24usize
        .checked_add(
            stride
                .checked_mul(count)
                .ok_or_else(|| exhausted("NTFS dirty table size"))?,
        )
        .ok_or_else(|| exhausted("NTFS dirty table size"))?;
    charge(w, bytes, r)?;
    b.resize(bytes, 0);
    put16(
        b,
        0,
        u16::try_from(stride).map_err(|_| unsupported("NTFS dirty slot width"))?,
    );
    put16(b, 2, count as u16);
    put32(b, 12, u32::MAX);
    put32(b, 16, 24);
    put32(b, 20, (24 + (count - 1) * stride) as u32);
    for i in 0..count - 1 {
        put32(b, 24 + i * stride, (24 + (i + 1) * stride) as u32);
    }
    Ok(())
}
fn allocate(b: &mut Vec<u8>, maximum: usize, w: &mut Work, r: &Resources) -> Result<usize> {
    if le32(b, 16) == 0 {
        let old = b.len();
        let oldcount = slots(b);
        let stride = usize::from(le16(b, 0));
        let count = oldcount
            .checked_add(16)
            .filter(|n| *n <= maximum && *n <= usize::from(u16::MAX))
            .ok_or_else(|| exhausted("NTFS dirty native extension slots"))?;
        charge(w, 16 * stride, r)?;
        b.resize(24 + count * stride, 0);
        put16(b, 2, count as u16);
        put32(b, 12, u32::MAX);
        put32(b, 16, old as u32);
        put32(b, 20, (24 + (count - 1) * stride) as u32);
        for i in oldcount..count - 1 {
            put32(b, 24 + i * stride, (24 + (i + 1) * stride) as u32);
        }
    }
    let at = le32(b, 16) as usize;
    let next = le32(b, at);
    put32(b, 16, next);
    if next == 0 {
        put32(b, 20, 0);
    }
    let stride = usize::from(le16(b, 0));
    charge(w, stride, r)?;
    b[at..at + stride].fill(0);
    put32(b, at, u32::MAX);
    let total = le16(b, 4)
        .checked_add(1)
        .ok_or_else(|| unsupported("NTFS dirty allocated count overflow"))?;
    put16(b, 4, total);
    Ok(at)
}
fn normalize(table: &mut [u8], cluster: u64, work: &mut Work, r: &Resources) -> Result<()> {
    let count = slots(table);
    if cluster > PAGE as u64 {
        for i in 0..count {
            charge(work, 1, r)?;
            if !allocated(table, i) {
                continue;
            }
            let at = offset(table, i);
            for j in i + 1..count {
                charge(work, 1, r)?;
                if !allocated(table, j) {
                    continue;
                }
                let next = offset(table, j);
                if le32(table, at + 4) == le32(table, next + 4)
                    && le64(table, at + 16) == le64(table, next + 16)
                {
                    let oldest = le64(table, at + 24).min(le64(table, next + 24));
                    put64(table, at + 24, oldest);
                    free(table, next)?;
                }
            }
        }
    }
    Ok(())
}
fn delete_range(b: &mut [u8], first: u64, last: u64, w: &mut Work, r: &Resources) -> Result<()> {
    for i in 0..slots(b) {
        charge(w, 1, r)?;
        if !allocated(b, i) {
            continue;
        }
        let at = offset(b, i);
        for j in 0..le32(b, at + 12) as usize {
            charge(w, 1, r)?;
            let pos = at + 32 + j * 8;
            let lcn = le64(b, pos);
            if lcn >= first && lcn <= last {
                put64(b, pos, 0);
            }
        }
    }
    Ok(())
}
fn update_class(op: u16) -> bool {
    matches!(op,2..=9|11..=22|33|34|37)
}
fn apply(
    b: &mut Vec<u8>,
    client: &crate::fs_ntfs_logfile::NtfsLogClientRecord<'_>,
    lsn: u64,
    cluster: u64,
    limits: NtfsLogDirtyAnalysisLimits,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let op = client.redo_operation;
    let vcn = client.target_vcn as u64;
    if update_class(op) {
        let at = match find(b, u32::from(client.target_attribute), vcn, w, r)? {
            Some(at) => at,
            None => {
                let lcns = if b.is_empty() {
                    (PAGE as u64 / cluster).max(1) as usize
                } else {
                    (usize::from(le16(b, 0)) - 32) / 8
                };
                if lcns == 0 || !lcns.is_power_of_two() || lcns > limits.lcns {
                    return Err(unsupported("NTFS dirty native page LCN geometry"));
                }
                if b.is_empty() {
                    if limits.entries < 32 {
                        return Err(exhausted("NTFS dirty initial32slots"));
                    }
                    initialize(b, 32 + 8 * lcns, 32, w, r)?;
                }
                let at = allocate(b, limits.entries, w, r)?;
                put32(b, at + 4, u32::from(client.target_attribute));
                put32(
                    b,
                    at + 8,
                    u32::try_from(
                        (lcns as u64)
                            .checked_mul(cluster)
                            .ok_or_else(|| unsupported("NTFS dirty transfer overflow"))?,
                    )
                    .map_err(|_| unsupported("NTFS dirty transfer width"))?,
                );
                put32(b, at + 12, lcns as u32);
                put64(b, at + 16, vcn & !((lcns as u64) - 1));
                put64(b, at + 24, lsn);
                at
            }
        };
        let start = vcn
            .checked_sub(le64(b, at + 16))
            .ok_or_else(|| invalid("NTFS dirty copy VCN"))?;
        let end = start
            .checked_add(u64::from(client.lcn_count))
            .filter(|end| *end <= u64::from(le32(b, at + 12)))
            .ok_or_else(|| unsupported("NTFS dirty LCN copy exceeds native slot"))?;
        let _ = end;
        charge(w, client.lcn_bytes().len(), r)?;
        let at =
            at + 32 + usize::try_from(start).map_err(|_| unsupported("NTFS dirty copy index"))? * 8;
        b[at..at + client.lcn_bytes().len()].copy_from_slice(client.lcn_bytes());
    } else if op == 10 {
        let raw = client.raw();
        let start = usize::from(le16(raw, 4));
        let length = usize::from(le16(raw, 6));
        let ranges = length / 16;
        if ranges == 0 {
            return Ok(());
        }
        let end = start
            .checked_add(ranges * 16)
            .filter(|end| *end <= raw.len())
            .ok_or_else(|| invalid("NTFS dirty delete ranges"))?;
        if ranges != 0 && start < client.header_bytes().len() {
            return Err(unsupported("NTFS dirty delete header overlap"));
        }
        for range in raw[start..end].chunks_exact(16) {
            charge(w, 1, r)?;
            let first = le64(range, 0);
            let count = le64(range, 8);
            let last = first
                .checked_add(count)
                .and_then(|n| n.checked_sub(1))
                .filter(|_| count != 0)
                .ok_or_else(|| unsupported("NTFS dirty delete inclusive overflow"))?;
            delete_range(b, first, last, w, r)?;
        }
    } else if op == 23 {
        if let Some(at) = find(b, u32::from(client.target_attribute), vcn, w, r)? {
            let j = vcn - le64(b, at + 16);
            let pos = at + 32 + j as usize * 8;
            charge(w, 1, r)?;
            if le64(b, pos) != 0 {
                if client.lcn_count == 0 {
                    return Err(unsupported("NTFS dirty hotfix missing declared LCN"));
                }
                put64(b, pos, le64(client.lcn_bytes(), 0));
            }
        }
    } else if op == 28 {
        return Err(unsupported("NTFS open/name effects not yet projected"));
    } else if !matches!(op,0|1|24..=27|29..=32) {
        return Err(unsupported("NTFS dirty unknown operation effects"));
    }
    Ok(())
}

/// Derive dirty-page state using the geometry of the SAME source-owned volume.
///
/// A report from a different logfile handle is refused even with equal bytes.
/// Native table slots and free ordering are retained, with bounded extension.
/// Open/name and provisional target effects remain explicitly unsupported.
pub fn inspect_logfile_native_dirty_analysis(
    context: NtfsLogNativeAnalysisContext,
    replay: NtfsLogReplayAnalysisReport,
    limits: NtfsLogDirtyAnalysisLimits,
    r: &Resources,
) -> Result<NtfsLogDirtyAnalysisReport> {
    inspect_combined(context, replay, limits, None, r)
}
fn inspect_combined(
    context: NtfsLogNativeAnalysisContext,
    replay: NtfsLogReplayAnalysisReport,
    limits: NtfsLogDirtyAnalysisLimits,
    open_limits: Option<NtfsLogOpenAnalysisLimits>,
    r: &Resources,
) -> Result<NtfsLogDirtyAnalysisReport> {
    r.cancellation.check()?;
    if !Arc::ptr_eq(
        &context.logfile_source(),
        &replay.checkpoint.traversal.overlay.source,
    ) {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS dirty native logfile source mismatch",
        ));
    }
    if limits.entries > usize::from(u16::MAX) || limits.lcns > (usize::from(u16::MAX) - 32) / 8 {
        return Err(exhausted("NTFS dirty native table encoding limits"));
    }
    let maximum = limits
        .entries
        .checked_mul(
            32usize
                .checked_add(
                    limits
                        .lcns
                        .checked_mul(8)
                        .ok_or_else(|| exhausted("NTFS dirty table bytes"))?,
                )
                .ok_or_else(|| exhausted("NTFS dirty table bytes"))?,
        )
        .and_then(|n| n.checked_add(24))
        .filter(|n| *n <= u32::MAX as usize)
        .ok_or_else(|| exhausted("NTFS dirty table bytes"))?;
    let lease = r.memory.reserve(maximum as u64)?;
    let mut table = Vec::new();
    table
        .try_reserve_exact(maximum)
        .map_err(|_| exhausted("NTFS dirty table allocation"))?;
    if table.capacity() > maximum {
        return Err(exhausted("NTFS dirty table capacity"));
    }
    let mut work = Work {
        used: replay.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogDirtyAnalysisReport {
        context,
        replay,
        table,
        open: None,
        processed: 0,
        error: None,
        complete: false,
        work: work.used,
        _lease: lease,
    };
    let result = (|| -> Result<bool> {
        charge(&mut work, report.context.source_guard_work()?, r)?;
        report.context.check_source(r)?;
        if !report.replay.transaction_fields_complete() {
            return Ok(false);
        }
        let cluster = report.context.geometry().cluster_bytes();
        if let Some(open_limits) = open_limits {
            report.open = Some(OpenState::load(&report.replay, open_limits, &mut work, r)?);
        }
        if let Some(dumps) = report
            .replay
            .dumps
            .as_ref()
            .filter(|d| d.dumps()[2].record().is_some())
        {
            let client = dumps.dump_client(2)?;
            let raw = client.redo();
            let stride = usize::from(le16(raw, 0));
            let count = usize::from(le16(raw, 2));
            if stride < 32 || stride > 32 + 8 * limits.lcns || count > limits.entries {
                return Err(exhausted("NTFS initial dirty slot limits"));
            }
            let size = 24 + stride * count;
            charge(&mut work, size, r)?;
            report.table.extend_from_slice(&raw[..size]);
            for i in 0..count {
                charge(&mut work, 1, r)?;
                if !allocated(&report.table, i) {
                    continue;
                }
                let at = offset(&report.table, i);
                let lcns = le32(&report.table, at + 12) as usize;
                if 32usize
                    .checked_add(
                        lcns.checked_mul(8)
                            .ok_or_else(|| invalid("NTFS initial dirty LCNs"))?,
                    )
                    .is_none_or(|end| end > stride)
                {
                    return Err(invalid("NTFS initial dirty LCNs"));
                }
                le64(&report.table, at + 16)
                    .checked_add(lcns as u64)
                    .ok_or_else(|| unsupported("NTFS initial dirty VCN overflow"))?;
            }
            normalize(&mut report.table, cluster, &mut work, r)?;
        }
        for observed in &report.replay.records {
            charge(&mut work, 1, r)?;
            let record = report.replay.checkpoint.traversal.steps[observed.physical_index].record();
            let client =
                crate::fs_ntfs_logfile::client_record::inspect_native_analysis_record(record)?;
            charge(&mut work, client.raw().len(), r)?;
            let lsn = record
                .header()
                .ok_or_else(|| invalid("NTFS dirty record header"))?
                .this_lsn;
            if client.redo_operation == 28 && report.open.is_some() {
                report
                    .open
                    .as_mut()
                    .ok_or_else(|| invalid("NTFS open state missing"))?
                    .apply(&client, &mut work, r)?;
            } else {
                apply(
                    &mut report.table,
                    &client,
                    lsn,
                    cluster,
                    limits,
                    &mut work,
                    r,
                )?;
            }
            report.processed += 1;
        }
        Ok(true)
    })();
    let done = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    let guarded = guard_report(&report, &mut work, r);
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    report.work = work.used;
    report.complete = done && report.error.is_none();
    Ok(report)
}

fn guard_report(report: &NtfsLogDirtyAnalysisReport, work: &mut Work, r: &Resources) -> Result<()> {
    charge(work, PAGE, r)?;
    let _lease = r.memory.reserve(PAGE as u64)?;
    let mut raw = page_buffer()?;
    if raw.capacity() > PAGE {
        return Err(exhausted("NTFS dirty final guard capacity"));
    }
    let previous = report
        .replay
        .checkpoint
        .traversal
        .steps
        .iter()
        .map(NtfsLogPhysicalStep::record)
        .chain(report.replay.checkpoint.restart_query.iter());
    let loaded = report.replay.dumps.iter().flat_map(|d| {
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
            charge(work, 2 * PAGE, r)?;
            report
                .replay
                .checkpoint
                .traversal
                .overlay
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS dirty final exact source", e))?;
            r.cancellation.check()?;
            if raw != expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS dirty retained log source changed",
                ));
            }
        }
    }
    let remaining = work
        .maximum
        .checked_sub(work.used)
        .ok_or_else(|| exhausted("NTFS dirty final combined work"))?;
    work.used = work
        .used
        .checked_add(
            report
                .replay
                .checkpoint
                .traversal
                .overlay
                .check_source(remaining, r)?,
        )
        .ok_or_else(|| exhausted("NTFS dirty guard work overflow"))?;
    charge(work, report.context.source_guard_work()?, r)?;
    report.context.check_source(r)?;
    r.cancellation.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    #[test]
    fn native_large_cluster_normalization_keeps_first_lcns_and_frees_duplicate_by_goal() {
        let r = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        for cluster in [512, 8192] {
            let mut table = Vec::with_capacity(144);
            let mut work = Work {
                used: 0,
                maximum: 10000,
            };
            initialize(&mut table, 40, 3, &mut work, &r).unwrap();
            for (lsn, lcn) in [(90, 100), (20, 200)] {
                let at = allocate(&mut table, 3, &mut work, &r).unwrap();
                put32(&mut table, at + 4, 24);
                put32(&mut table, at + 12, 1);
                put64(&mut table, at + 16, 7);
                put64(&mut table, at + 24, lsn);
                put64(&mut table, at + 32, lcn);
            }
            normalize(&mut table, cluster, &mut work, &r).unwrap();
            if cluster == 512 {
                assert_eq!(le16(&table, 4), 2);
                assert_eq!(le64(&table, 48), 90);
            } else {
                assert_eq!(le16(&table, 4), 1);
                assert_eq!(le64(&table, 48), 20);
                assert_eq!(le64(&table, 56), 100);
                assert_eq!(le32(&table, 16), 64);
                assert_eq!(le32(&table, 64), 104);
                assert_eq!(le32(&table, 20), 104);
            }
        }
    }
    #[test]
    fn mostly_free_delete_scan_has_exact_finite_work_and_cancellation() {
        let resources = || Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let r = resources();
        let mut table = Vec::with_capacity(24 + 512 * 40);
        let mut build = Work {
            used: 0,
            maximum: 1 << 20,
        };
        initialize(&mut table, 40, 512, &mut build, &r).unwrap();
        let last = 24 + 511 * 40;
        put32(&mut table, last, u32::MAX);
        put32(&mut table, last + 12, 1);
        put64(&mut table, last + 32, 100);
        let original = table.clone();
        let mut below = Work {
            used: 0,
            maximum: 512,
        };
        assert_eq!(
            delete_range(&mut table, 100, 100, &mut below, &r)
                .unwrap_err()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(below.used, 512);
        assert_eq!(
            table, original,
            "refusal precedes final allocated LCN change"
        );
        let mut exact = Work {
            used: 0,
            maximum: 513,
        };
        delete_range(&mut table, 100, 100, &mut exact, &r).unwrap();
        assert_eq!(exact.used, 513);
        assert_eq!(le64(&table, last + 32), 0);
        // All slots free: the old skipped-slot loop performed no charge/check.
        let r = resources();
        let mut free = Vec::with_capacity(24 + 512 * 40);
        initialize(&mut free, 40, 512, &mut build, &r).unwrap();
        let before = free.clone();
        r.cancellation.cancel();
        let mut work = Work {
            used: 0,
            maximum: 512,
        };
        assert_eq!(
            delete_range(&mut free, 100, 100, &mut work, &r)
                .unwrap_err()
                .kind,
            ErrorKind::Cancelled
        );
        assert_eq!(work.used, 0);
        assert_eq!(free, before);
    }
}
