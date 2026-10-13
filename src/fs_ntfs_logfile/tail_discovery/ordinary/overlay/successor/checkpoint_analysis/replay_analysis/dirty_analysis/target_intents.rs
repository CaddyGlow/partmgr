//! Source-owned target and provisional-intent enumeration in native open-slot order.
use super::*;
mod native_dirty_runs;
use crate::fs_ntfs::NtfsStreamLimits;
use crate::fs_ntfs_logfile::{NtfsLogNativeContextLimits, NtfsLogNativeTargetEvidence};
pub use native_dirty_runs::*;
/// Independent target lookup capture and aggregate analysis ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogTargetIntentLimits {
    /// Maximum allocated open-slot target observations retained.
    pub targets: usize,
    /// Per-target exact consumed physical-read/byte/work ceilings.
    pub capture: NtfsLogNativeContextLimits,
    /// Source-owned native attribute-list resolution ceilings.
    pub streams: NtfsStreamLimits,
    /// Combined prior analysis, target lookups and ALL repeated source guards.
    pub work: usize,
}
/// Retained source-owned target observations, including mandatory provisional branches.
pub struct NtfsLogTargetIntentReport {
    analysis: NtfsLogDirtyAnalysisReport,
    targets: Vec<NtfsLogNativeTargetEvidence>,
    error: Option<Error>,
    enumerated: bool,
    work: usize,
    _lease: Reservation,
}
impl NtfsLogTargetIntentReport {
    /// Original source-owned native checkpoint/dirty/open/name analysis.
    pub fn analysis(&self) -> &NtfsLogDirtyAnalysisReport {
        &self.analysis
    }
    /// Target observations in exact allocated open-slot enumeration order.
    pub fn targets(&self) -> &[NtfsLogNativeTargetEvidence] {
        &self.targets
    }
    /// Original incomplete lookup, guard, resource or cancellation cause.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error
            .as_ref()
            .or_else(|| self.analysis.stopping_error())
            .or_else(|| self.targets.iter().find_map(|t| t.stopping_error()))
    }
    /// Whether bounded target observation enumeration reached the source table end.
    /// This does not prove native winner selection, run validity or target ownership.
    pub fn target_observations_complete(&self) -> bool {
        self.enumerated
    }
    /// Combined retained evidence work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Existing/provisional target observations do not authorize recovery.
    pub fn recovery_complete(&self) -> bool {
        false
    }
    /// Full native analysis and active membership qualification remain incomplete.
    pub fn active_window_complete(&self) -> bool {
        false
    }
}
/// Enumerate actual existing and provisional target branches from sealed open slots.
///
/// Missing FILE/attribute observations retain source evidence and never manufacture
/// ObjectId, allocated FILE/attribute/index records, initialized bytes or writes.
pub fn inspect_logfile_native_target_intents(
    analysis: NtfsLogDirtyAnalysisReport,
    limits: NtfsLogTargetIntentLimits,
    r: &Resources,
) -> Result<NtfsLogTargetIntentReport> {
    r.cancellation.check()?;
    let bytes = limits
        .targets
        .checked_mul(core::mem::size_of::<NtfsLogNativeTargetEvidence>())
        .ok_or_else(|| exhausted("NTFS target evidence inventory"))?;
    let lease = r.memory.reserve(bytes as u64)?;
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(limits.targets)
        .map_err(|_| exhausted("NTFS target evidence allocation"))?;
    if targets.capacity() > limits.targets {
        return Err(exhausted("NTFS target evidence capacity"));
    }
    let mut work = Work {
        used: analysis.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogTargetIntentReport {
        analysis,
        targets,
        error: None,
        enumerated: false,
        work: work.used,
        _lease: lease,
    };
    let result = (|| -> Result<bool> {
        guard_report(&report.analysis, &mut work, r)?;
        if !report.analysis.dirty_fields_complete() {
            return Ok(false);
        }
        let open = report.analysis.open.as_ref().ok_or_else(|| {
            unsupported("NTFS target intents require completed source open/name effects")
        })?;
        let table = open.table_bytes();
        for i in 0..slots(table) {
            charge(&mut work, 1, r)?;
            if !allocated(table, i) {
                continue;
            }
            if report.targets.len() == limits.targets {
                return Err(exhausted("NTFS target observation ceiling"));
            }
            let at = offset(table, i);
            let reference = le64(table, at + 16);
            let kind = le32(table, at + 8);
            let units = usize::from(table[at + 14]);
            let rawname = open.name_bytes(i).unwrap_or(&[]);
            if units
                .checked_mul(2)
                .is_none_or(|bytes| bytes > rawname.len())
            {
                return Err(unsupported("NTFS target native name bytes unavailable"));
            }
            charge(&mut work, units + 1, r)?;
            charge(&mut work, 64 + (units * 2).next_multiple_of(8), r)?;
            let _scratch = r.memory.reserve((units * 2) as u64)?;
            let mut name = Vec::new();
            name.try_reserve_exact(units)
                .map_err(|_| exhausted("NTFS target name scratch"))?;
            if name.capacity() > units {
                return Err(exhausted("NTFS target name scratch capacity"));
            }
            name.extend(
                rawname[..units * 2]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]])),
            );
            let native_work = limits
                .streams
                .work
                .checked_mul(2)
                .and_then(|n| n.checked_add(limits.streams.attributes.checked_mul(units + 1)?))
                .ok_or_else(|| exhausted("NTFS target resolver work"))?;
            // Prepay the COMPLETE finite physical capture and repeated guard
            // envelopes before native I/O; actual consumed evidence stays retained.
            let capture_work = limits
                .capture
                .work
                .checked_mul(2)
                .and_then(|n| n.checked_add(native_work))
                .ok_or_else(|| exhausted("NTFS target prepaid work"))?;
            charge(&mut work, capture_work, r)?;
            let evidence = report.analysis.context.inspect_target(
                (
                    u32::try_from(at)
                        .map_err(|_| unsupported("NTFS target open offset encoding"))?,
                    reference,
                    kind,
                ),
                &name,
                limits.streams,
                limits.capture,
                r,
            )?;
            let failed = evidence.stopping_error().is_some();
            report.targets.push(evidence);
            if failed {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    let enumerated = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    let guarded = (|| -> Result<()> {
        for target in &report.targets {
            charge(&mut work, target.physical_work()?, r)?;
            target.check_source(r)?;
        }
        guard_report(&report.analysis, &mut work, r)
    })();
    if let Err(error) = guarded {
        report.error.get_or_insert(error);
    }
    // Preserve the original lookup cause while retaining its captured raw evidence.
    if report.error.is_none() && report.targets.iter().any(|t| t.stopping_error().is_some()) {
        report.enumerated = false;
    } else {
        report.enumerated = enumerated && report.stopping_error().is_none();
    }
    report.work = work.used;
    Ok(report)
}
