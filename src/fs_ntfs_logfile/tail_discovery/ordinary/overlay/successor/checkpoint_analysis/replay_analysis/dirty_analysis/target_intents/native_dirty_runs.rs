//! Native source-ordered dirty LCN projection; no allocation or replay authority.
use super::*;
mod redo_analysis;
use crate::fs_ntfs_logfile::NtfsLogNativeRun;
pub use redo_analysis::*;
/// Finite derived native-map storage and combined work ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogDirtyRunLimits {
    /// Maximum retained target observations.
    pub targets: usize,
    /// Maximum normalized runs per target, including source runs and splits.
    pub runs: usize,
    /// Combined input evidence, derivation, and repeated exact-source work.
    pub work: usize,
}
/// Derived in-memory native target mapping, retaining its original source evidence.
pub struct NtfsLogDirtyTargetRuns {
    slot: u32,
    shared_file: Option<u64>,
    runs: Vec<NtfsLogNativeRun>,
    sizes: Option<[u64; 3]>,
    _lease: Reservation,
}
impl NtfsLogDirtyTargetRuns {
    /// Exact source open-table slot offset.
    pub fn open_slot_offset(&self) -> u32 {
        self.slot
    }
    /// Native source runs after dirty-table single-cluster replacements.
    pub fn runs(&self) -> &[NtfsLogNativeRun] {
        &self.runs
    }
    /// Native alloc/data/valid sizes; resident attributes have no such fields.
    pub fn nonresident_sizes(&self) -> Option<[u64; 3]> {
        self.sizes
    }
}
/// Source-bound dirty mapping derivation with original failure and partial state.
pub struct NtfsLogDirtyRunReport {
    input: NtfsLogTargetIntentReport,
    targets: Vec<NtfsLogDirtyTargetRuns>,
    redo_lsn: Option<u64>,
    complete: bool,
    error: Option<Error>,
    work: usize,
    _lease: Reservation,
}
impl NtfsLogDirtyRunReport {
    /// Complete retained source inputs and original target lookup observations.
    pub fn input(&self) -> &NtfsLogTargetIntentReport {
        &self.input
    }
    /// Derived target maps in original allocated open-slot order.
    pub fn targets(&self) -> &[NtfsLogDirtyTargetRuns] {
        &self.targets
    }
    /// Native numeric redo-start candidate, including zero when no suffix exists.
    pub fn redo_lsn(&self) -> Option<u64> {
        self.redo_lsn
    }
    /// Whether admitted map derivation and all repeated guards reached their end.
    pub fn dirty_runs_complete(&self) -> bool {
        self.complete
    }
    /// Original source, unsupported class, resource, or cancellation failure.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error.as_ref().or_else(|| self.input.stopping_error())
    }
    /// Combined consumed work, including retained earlier analysis.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Mapping derivation does not qualify a complete native active window.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// No writer, allocation, or recovery authority is provided.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn vector<T>(maximum: usize, r: &Resources) -> Result<(Vec<T>, Reservation)> {
    let bytes = maximum
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| exhausted("NTFS dirty run storage"))?;
    let lease = r.memory.reserve(bytes as u64)?;
    let mut v = Vec::new();
    v.try_reserve_exact(maximum)
        .map_err(|_| exhausted("NTFS dirty run allocation"))?;
    if v.capacity() > maximum {
        return Err(exhausted("NTFS dirty run capacity"));
    }
    Ok((v, lease))
}
fn push(v: &mut Vec<NtfsLogNativeRun>, value: NtfsLogNativeRun, maximum: usize) -> Result<()> {
    if v.len() == maximum {
        return Err(exhausted("NTFS dirty normalized run ceiling"));
    }
    v.push(value);
    Ok(())
}
fn mapped_lcn(
    map: &[NtfsLogNativeRun],
    vcn: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<Option<u64>> {
    for run in map {
        charge(w, 1, r)?;
        if vcn >= run.vcn && vcn - run.vcn < run.clusters {
            return run
                .lcn
                .map(|lcn| {
                    lcn.checked_add(vcn - run.vcn)
                        .ok_or_else(|| unsupported("NTFS dirty mapped LCN overflow"))
                })
                .transpose();
        }
    }
    Ok(None)
}
fn merge(
    map: &mut Vec<NtfsLogNativeRun>,
    scratch: &mut Vec<NtfsLogNativeRun>,
    vcn: u64,
    lcn: u64,
    maximum: usize,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    scratch.clear();
    let stop = vcn
        .checked_add(1)
        .ok_or_else(|| unsupported("NTFS dirty VCN overflow"))?;
    let new = NtfsLogNativeRun {
        vcn,
        lcn: Some(lcn),
        clusters: 1,
    };
    let mut inserted = false;
    for old in map.iter().copied() {
        charge(w, 1, r)?;
        let end = old
            .vcn
            .checked_add(old.clusters)
            .ok_or_else(|| unsupported("NTFS dirty source run overflow"))?;
        if end <= vcn {
            push(scratch, old, maximum)?;
            continue;
        }
        if old.vcn >= stop {
            if !inserted {
                push(scratch, new, maximum)?;
                inserted = true;
            }
            push(scratch, old, maximum)?;
            continue;
        }
        if old.vcn < vcn {
            push(
                scratch,
                NtfsLogNativeRun {
                    clusters: vcn - old.vcn,
                    ..old
                },
                maximum,
            )?;
        }
        if !inserted {
            push(scratch, new, maximum)?;
            inserted = true;
        }
        if end > stop {
            let physical = old
                .lcn
                .map(|n| {
                    n.checked_add(stop - old.vcn)
                        .ok_or_else(|| unsupported("NTFS dirty LCN overflow"))
                })
                .transpose()?;
            push(
                scratch,
                NtfsLogNativeRun {
                    vcn: stop,
                    lcn: physical,
                    clusters: end - stop,
                },
                maximum,
            )?;
        }
    }
    if !inserted {
        push(scratch, new, maximum)?;
    }
    let mut out = 0usize;
    for i in 0..scratch.len() {
        charge(w, 1, r)?;
        let next = scratch[i];
        let joins = out > 0
            && scratch[out - 1].vcn.checked_add(scratch[out - 1].clusters) == Some(next.vcn)
            && match (scratch[out - 1].lcn, next.lcn) {
                (None, None) => true,
                (Some(a), Some(b)) => a.checked_add(scratch[out - 1].clusters) == Some(b),
                _ => false,
            };
        if joins {
            scratch[out - 1].clusters = scratch[out - 1]
                .clusters
                .checked_add(next.clusters)
                .ok_or_else(|| unsupported("NTFS dirty coalesced run overflow"))?;
        } else {
            scratch[out] = next;
            out += 1;
        }
    }
    scratch.truncate(out);
    core::mem::swap(map, scratch);
    Ok(())
}
fn guards(input: &NtfsLogTargetIntentReport, w: &mut Work, r: &Resources) -> Result<()> {
    for target in input.targets() {
        charge(w, target.physical_work()?, r)?;
        target.check_source(r)?;
    }
    guard_report(input.analysis(), w, r)
}
/// Derive native dirty-table LCN overrides from sealed source targets and geometry.
/// Provisional maps remain in-memory intents and never authorize disk allocation.
pub fn inspect_logfile_native_dirty_runs(
    input: NtfsLogTargetIntentReport,
    limits: NtfsLogDirtyRunLimits,
    r: &Resources,
) -> Result<NtfsLogDirtyRunReport> {
    r.cancellation.check()?;
    let (targets, lease) = vector(limits.targets, r)?;
    let mut work = Work {
        used: input.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogDirtyRunReport {
        input,
        targets,
        redo_lsn: None,
        complete: false,
        error: None,
        work: work.used,
        _lease: lease,
    };
    let result = (|| -> Result<bool> {
        guards(&report.input, &mut work, r)?;
        if !report.input.target_observations_complete() {
            return Ok(false);
        }
        for evidence in report.input.targets() {
            charge(&mut work, 1, r)?;
            if report.targets.len() == limits.targets {
                return Err(exhausted("NTFS dirty target ceiling"));
            }
            let raw = if let Some(i) = evidence.selected_occurrence() {
                &evidence
                    .attributes()
                    .ok_or_else(|| unsupported("NTFS native winner attributes unavailable"))?[i]
                    .raw[..]
            } else {
                evidence
                    .provisional_attribute()
                    .ok_or_else(|| unsupported("NTFS dirty target has no native attribute"))?
            };
            let sizes = if raw.get(8) == Some(&1) {
                if raw.len() < 64 {
                    return Err(unsupported("NTFS dirty nonresident header"));
                }
                Some([le64(raw, 40), le64(raw, 48), le64(raw, 56)])
            } else {
                None
            };
            let (mut runs, lease) = vector(limits.runs, r)?;
            for source in evidence.native_runs().unwrap_or(&[]) {
                charge(&mut work, 1, r)?;
                push(&mut runs, *source, limits.runs)?;
            }
            report.targets.push(NtfsLogDirtyTargetRuns {
                slot: evidence.open_slot_offset(),
                shared_file: (evidence.selected_occurrence().is_some()
                    && !evidence.is_directory()
                    && evidence.attribute_type() == 0x80
                    && evidence.name().is_empty())
                .then_some(evidence.file_reference()),
                runs,
                sizes,
                _lease: lease,
            });
        }
        let (mut scratch, _scratch_lease) = vector(limits.runs, r)?;
        let analysis = report.input.analysis();
        let geometry = analysis.context().geometry();
        let cluster = geometry.cluster_bytes();
        let volume_clusters = geometry.volume_bytes() / cluster;
        let mft_prefix = (geometry.record_bytes() as u64)
            .checked_mul(4)
            .ok_or_else(|| unsupported("NTFS dirty MFT prefix overflow"))?;
        let open = analysis
            .open_attributes()
            .ok_or_else(|| unsupported("NTFS dirty open table unavailable"))?
            .table_bytes();
        let dirty = analysis.dirty_table_bytes();
        let mut redo = analysis
            .replay()
            .checkpoint()
            .analysis_records()
            .next()
            .and_then(|record| record.header())
            .map_or(0, |h| h.this_lsn);
        for i in 0..slots(dirty) {
            charge(&mut work, 1, r)?;
            if !allocated(dirty, i) {
                continue;
            }
            let at = offset(dirty, i);
            let oldest = le64(dirty, at + 24);
            if oldest != 0 && oldest < redo {
                redo = oldest;
            }
            let target = le32(dirty, at + 4) as usize;
            let stride = if open.is_empty() {
                0
            } else {
                usize::from(le16(open, 0))
            };
            if target < 24
                || stride == 0
                || !(target - 24).is_multiple_of(stride)
                || (target - 24) / stride >= slots(open)
            {
                return Err(unsupported("NTFS dirty target is not a source open slot"));
            }
            if le32(open, target) != u32::MAX {
                continue;
            }
            let mut index = None;
            for (j, candidate) in report.targets.iter().enumerate() {
                charge(&mut work, 1, r)?;
                if candidate.slot as usize == target {
                    index = Some(j);
                    break;
                }
            }
            let index =
                index.ok_or_else(|| unsupported("NTFS allocated dirty target unavailable"))?;
            let count = le32(dirty, at + 12) as usize;
            if count
                .checked_mul(8)
                .and_then(|n| n.checked_add(32))
                .is_none_or(|n| n > usize::from(le16(dirty, 0)))
            {
                return Err(unsupported("NTFS dirty LCN extent"));
            }
            for cell in 0..count {
                charge(&mut work, 1, r)?;
                let vcn = le64(dirty, at + 16)
                    .checked_add(cell as u64)
                    .ok_or_else(|| unsupported("NTFS dirty VCN addition"))?;
                let size = vcn
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(cluster))
                    .ok_or_else(|| unsupported("NTFS dirty byte-size overflow"))?;
                let lcn = le64(dirty, at + 32 + cell * 8);
                if lcn == 0 {
                    continue;
                }
                let number = le64(open, target + 16) & 0x0000_ffff_ffff_ffff;
                if number <= 1 && le32(open, target + 8) == 0x80 && size < mft_prefix {
                    continue;
                }
                if lcn >= volume_clusters {
                    return Err(unsupported("NTFS dirty LCN outside source volume"));
                }
                if vcn >= (1u64 << 32) || lcn >= (1u64 << 32) {
                    return Err(unsupported("NTFS native dirty cluster-width configuration"));
                }
                let shared_file = report.targets[index].shared_file;
                if report.targets[index].sizes.is_none() {
                    return Err(unsupported(
                        "NTFS resident dirty target native union semantics",
                    ));
                }
                // Native OpenAttr owns a kmemdup header but may reference the
                // shared inode file.run. Propagate the map, not copied sizes.
                let already_mapped =
                    mapped_lcn(&report.targets[index].runs, vcn, &mut work, r)? == Some(lcn);
                for j in 0..report.targets.len() {
                    charge(&mut work, 1, r)?;
                    if !already_mapped
                        && (j == index
                            || shared_file.is_some()
                                && report.targets[j].shared_file == shared_file)
                    {
                        merge(
                            &mut report.targets[j].runs,
                            &mut scratch,
                            vcn,
                            lcn,
                            limits.runs,
                            &mut work,
                            r,
                        )?;
                    }
                }
                let sizes = report.targets[index]
                    .sizes
                    .as_mut()
                    .expect("checked native sizes");
                if size > sizes[0] {
                    *sizes = [size; 3];
                }
            }
        }
        for transaction in analysis.replay().transactions() {
            charge(&mut work, 1, r)?;
            let first = transaction.first_lsn();
            if transaction.allocated() && first != 0 && first < redo {
                redo = first;
            }
        }
        report.redo_lsn = Some(redo);
        Ok(true)
    })();
    let done = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    if let Err(error) = guards(&report.input, &mut work, r) {
        report.error.get_or_insert(error);
    }
    report.complete = done && report.stopping_error().is_none();
    report.work = work.used;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn physical(map: &[NtfsLogNativeRun], v: u64) -> Option<Option<u64>> {
        map.iter()
            .find(|run| v >= run.vcn && v - run.vcn < run.clusters)
            .map(|run| run.lcn.map(|lcn| lcn + v - run.vcn))
    }
    #[test]
    fn source_ordered_dirty_replacements_match_independent_cluster_model() {
        let r = resources();
        let (mut map, map_lease) = vector(32, &r).unwrap();
        let (mut scratch, scratch_lease) = vector(32, &r).unwrap();
        map.push(NtfsLogNativeRun {
            vcn: 2,
            lcn: Some(20),
            clusters: 8,
        });
        map.push(NtfsLogNativeRun {
            vcn: 12,
            lcn: None,
            clusters: 4,
        });
        let mut expected = [None; 20];
        for (v, entry) in expected.iter_mut().enumerate().take(10).skip(2) {
            *entry = Some(Some(20 + v as u64 - 2));
        }
        for entry in &mut expected[12..16] {
            *entry = Some(None);
        }
        let mut w = Work {
            used: 0,
            maximum: 10000,
        };
        for (v, l) in [(5, 100), (3, 99), (5, 98), (10, 29), (13, 50), (19, 70)] {
            merge(&mut map, &mut scratch, v, l, 32, &mut w, &r).unwrap();
            expected[v as usize] = Some(Some(l));
            for (v, expected) in expected.iter().enumerate() {
                assert_eq!(physical(&map, v as u64), *expected);
            }
        }
        drop((map, scratch, map_lease, scratch_lease));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn exact_merge_work_and_one_below_preserve_original_on_refusal() {
        let r = resources();
        let initial = NtfsLogNativeRun {
            vcn: 0,
            lcn: Some(100),
            clusters: 8,
        };
        let (mut map, lease) = vector(8, &r).unwrap();
        let (mut scratch, scratch_lease) = vector(8, &r).unwrap();
        map.push(initial);
        let mut w = Work {
            used: 0,
            maximum: 1000,
        };
        merge(&mut map, &mut scratch, 4, 500, 8, &mut w, &r).unwrap();
        let exact = w.used;
        map.clear();
        map.push(initial);
        let mut w = Work {
            used: 0,
            maximum: exact,
        };
        merge(&mut map, &mut scratch, 4, 500, 8, &mut w, &r).unwrap();
        map.clear();
        map.push(initial);
        let mut w = Work {
            used: 0,
            maximum: exact - 1,
        };
        assert_eq!(
            merge(&mut map, &mut scratch, 4, 500, 8, &mut w, &r)
                .unwrap_err()
                .kind,
            crate::fs_core::ErrorKind::BudgetExhausted
        );
        assert_eq!(map.as_slice(), &[initial]);
        r.cancellation.cancel();
        assert_eq!(
            merge(&mut map, &mut scratch, 4, 500, 8, &mut w, &r)
                .unwrap_err()
                .kind,
            crate::fs_core::ErrorKind::Cancelled
        );
        drop((map, scratch, lease, scratch_lease));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn same_native_middle_mapping_requires_no_split_capacity() {
        let r = resources();
        let (mut map, lease) = vector(1, &r).unwrap();
        map.push(NtfsLogNativeRun {
            vcn: 0,
            lcn: Some(100),
            clusters: 8,
        });
        let mut w = Work {
            used: 0,
            maximum: 1,
        };
        assert_eq!(mapped_lcn(&map, 4, &mut w, &r).unwrap(), Some(104));
        assert_eq!(w.used, 1);
        assert_eq!(map.capacity(), 1);
        let mut below = Work {
            used: 0,
            maximum: 0,
        };
        assert_eq!(
            mapped_lcn(&map, 4, &mut below, &r).unwrap_err().kind,
            crate::fs_core::ErrorKind::BudgetExhausted
        );
        drop((map, lease));
        assert_eq!(r.memory.used(), 0);
    }
}
