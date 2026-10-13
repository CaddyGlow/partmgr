//! Independent FAT-copy differences and chain branches, including inactive copies.
//! Copy zero is a comparison baseline, never a historical authority.
use crate::{
    forensics::{
        ByteRange, CoordinateSpace, CoverageEvent, CoverageKind, ScanControl, ScanLimits,
        ScanOutcome, StopReason,
    },
    forensics_fat::{
        FatAllocationKind, FatAllocationObservation, FatForensics, allocation_kind, decode_entry,
        entry_position,
    },
    fs_core::Resources,
    io::{self, ReadAt},
};
use alloc::vec::Vec;

/// Exact same-cluster evidence from two independently read FAT copies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatCopyDifferenceObservation {
    /// Copy-zero comparison evidence, including packed overlap/reserved bits.
    pub baseline: FatAllocationObservation,
    /// Independently read nonzero copy, including inactive FAT32 copies.
    pub other: FatAllocationObservation,
    /// Meaningful decoded values disagree, independent of reserved raw bits.
    pub meaningful_difference: bool,
    /// Original backing bytes disagree; adjacent FAT12 entries share these bytes.
    pub raw_difference: bool,
}
/// One transition in an independently followed FAT-copy chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatCopyChainObservation {
    /// Zero-based transition within this copy's chain.
    pub step: u32,
    /// Selected copy entry at the current cluster.
    pub entry: FatAllocationObservation,
    /// Copy zero at the same cluster, independently read for a nonzero copy.
    pub baseline: FatAllocationObservation,
    /// This transition returns to an earlier cluster in this same copy's chain.
    pub cycle_to: Option<u32>,
}

struct Work<'a> {
    limits: ScanLimits,
    resources: &'a Resources,
    control: &'a dyn ScanControl,
    read: u64,
    output: u64,
    records: u64,
}
impl Work<'_> {
    fn check(&self) -> Result<(), StopReason> {
        if self.control.cancelled() || self.resources.cancellation.check().is_err() {
            Err(StopReason::Cancelled)
        } else {
            Ok(())
        }
    }
    fn read(
        &mut self,
        volume: &FatForensics,
        copy: u8,
        cluster: u32,
    ) -> Result<FatAllocationObservation, StopReason> {
        self.check()?;
        if self.records >= self.limits.records {
            return Err(StopReason::ResourceLimit("records"));
        }
        let g = volume.geometry();
        let (relative, length) = entry_position(g.family(), cluster);
        if length > self.limits.read_bytes.saturating_sub(self.read) {
            return Err(StopReason::ResourceLimit("read_bytes"));
        }
        let offset = g.fat_offset() + u64::from(copy) * g.fat_bytes() + relative;
        let mut raw = [0; 4];
        self.records += 1;
        self.read += length;
        volume
            .source()
            .read_exact_at(offset, &mut raw[..length as usize])
            .map_err(|error| {
                if volume.source().check_stability().is_err() {
                    StopReason::SourceStability(error)
                } else {
                    StopReason::Io(error)
                }
            })?;
        let value = decode_entry(g.family(), cluster, raw);
        Ok(FatAllocationObservation {
            source_id: volume.source().id(),
            copy,
            cluster,
            offset,
            raw,
            raw_length: length as u8,
            value,
            kind: allocation_kind(g.family(), cluster, value, g.cluster_count()),
        })
    }
    fn deliver<T>(
        &mut self,
        observation: T,
        ordinal: u64,
        outcome: &mut ScanOutcome,
        visitor: &mut dyn FnMut(T) -> io::Result<bool>,
    ) -> Result<(), StopReason> {
        self.check()?;
        let size = core::mem::size_of::<T>() as u64;
        if size > self.limits.output_bytes.saturating_sub(self.output) {
            return Err(StopReason::ResourceLimit("output_bytes"));
        }
        let proceed = visitor(observation).map_err(StopReason::DeliveryFailed)?;
        self.output += size;
        outcome.observations += 1;
        outcome.last_delivered = Some(ordinal + 1);
        if !proceed {
            return Err(StopReason::CallerStop);
        }
        self.check()
    }
}
fn cover(
    outcome: &mut ScanOutcome,
    offset: u64,
    length: u64,
    kind: CoverageKind,
    visitor: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
) -> Result<(), StopReason> {
    if length == 0 {
        return Ok(());
    }
    visitor(CoverageEvent {
        range: ByteRange { offset, length },
        kind,
    })
    .map_err(StopReason::DeliveryFailed)?;
    outcome.coverage_events += 1;
    outcome.advance(offset + length);
    Ok(())
}
impl FatForensics {
    /// Compare each addressable entry against copy zero. Emit only raw or decoded
    /// disagreements; coverage also includes equal comparisons. Limits count every
    /// independent backing read, including overlapping packed FAT12 entry bytes.
    pub fn scan_fat_copy_differences(
        &self,
        limits: ScanLimits,
        resources: &Resources,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatCopyDifferenceObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> ScanOutcome {
        let entries = u64::from(self.geometry().cluster_count()) + 2;
        let copies = self.geometry().fat_count();
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: entries * u64::from(copies.saturating_sub(1)),
            },
            "fat-copy-comparison-entry-ordinals",
        )
        .with_coordinate_space(CoordinateSpace::EntryOrdinals)
        .with_source_id(self.source().id());
        let memory = core::mem::size_of::<FatCopyDifferenceObservation>() as u64;
        let mut work = Work {
            limits,
            resources,
            control,
            read: 0,
            output: 0,
            records: 0,
        };
        let run = (|| {
            work.check()?;
            self.source()
                .check_stability()
                .map_err(StopReason::SourceStability)?;
            if copies <= 1 {
                return Ok(());
            }
            if memory > limits.memory_bytes {
                return Err(StopReason::ResourceLimit("memory_bytes"));
            }
            let _reservation = resources
                .memory
                .reserve(memory)
                .map_err(|_| StopReason::ResourceLimit("shared memory"))?;
            for copy in 1..copies {
                for cluster in 0..self.geometry().cluster_count() + 2 {
                    let ordinal = u64::from(copy - 1) * entries + u64::from(cluster);
                    let baseline = work.read(self, 0, cluster)?;
                    let other = work.read(self, copy, cluster)?;
                    let meaningful_difference = baseline.value != other.value;
                    let raw_difference = baseline.raw != other.raw;
                    if meaningful_difference || raw_difference {
                        work.deliver(
                            FatCopyDifferenceObservation {
                                baseline,
                                other,
                                meaningful_difference,
                                raw_difference,
                            },
                            ordinal,
                            &mut outcome,
                            visitor,
                        )?;
                    }
                    cover(&mut outcome, ordinal, 1, CoverageKind::Inspected, coverage)?;
                }
            }
            work.check()
        })();
        if let Err(reason) = run {
            outcome.stop_reason = reason;
            report_unreadable(&mut outcome, coverage);
        }
        outcome
    }
    /// Follow every FAT copy independently from an explicit data-cluster start.
    /// Domain cells are copy-major transition ordinals. A reached terminal marks
    /// the unused per-copy suffix skipped; exhausting the bound while still linked
    /// is incomplete. A cycle is explicit terminal evidence, never replayed data.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit chain bounds and independent resource controls"
    )]
    pub fn scan_fat_copy_chains(
        &self,
        first_cluster: u32,
        maximum_transitions: u32,
        limits: ScanLimits,
        resources: &Resources,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatCopyChainObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> ScanOutcome {
        let g = self.geometry();
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: u64::from(maximum_transitions) * u64::from(g.fat_count()),
            },
            "fat-independent-copy-chain-transition-ordinals",
        )
        .with_coordinate_space(CoordinateSpace::EntryOrdinals)
        .with_source_id(self.source().id());
        let memory = u64::from(maximum_transitions) * 4
            + core::mem::size_of::<FatCopyChainObservation>() as u64;
        let mut work = Work {
            limits,
            resources,
            control,
            read: 0,
            output: 0,
            records: 0,
        };
        let run = (|| {
            work.check()?;
            self.source()
                .check_stability()
                .map_err(StopReason::SourceStability)?;
            if !(2..=g.cluster_count() + 1).contains(&first_cluster) {
                return Err(StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "FAT chain start is outside data cluster domain",
                )));
            }
            if maximum_transitions == 0 {
                return Err(StopReason::ResourceLimit("chain transitions"));
            }
            if memory > limits.memory_bytes {
                return Err(StopReason::ResourceLimit("memory_bytes"));
            }
            let _reservation = resources
                .memory
                .reserve(memory)
                .map_err(|_| StopReason::ResourceLimit("shared memory"))?;
            let mut seen = Vec::new();
            seen.try_reserve_exact(maximum_transitions as usize)
                .map_err(|_| StopReason::ResourceLimit("memory allocation"))?;
            for copy in 0..g.fat_count() {
                seen.clear();
                let mut cluster = first_cluster;
                let base = u64::from(copy) * u64::from(maximum_transitions);
                let mut terminated = false;
                for step in 0..maximum_transitions {
                    seen.push(cluster);
                    let entry = work.read(self, copy, cluster)?;
                    let baseline = if copy == 0 {
                        entry.clone()
                    } else {
                        work.read(self, 0, cluster)?
                    };
                    let next = match entry.kind {
                        FatAllocationKind::Next(next) => Some(next),
                        _ => None,
                    };
                    let cycle_to = next.filter(|next| seen.contains(next));
                    work.deliver(
                        FatCopyChainObservation {
                            step,
                            entry,
                            baseline,
                            cycle_to,
                        },
                        base + u64::from(step),
                        &mut outcome,
                        visitor,
                    )?;
                    cover(
                        &mut outcome,
                        base + u64::from(step),
                        1,
                        CoverageKind::Inspected,
                        coverage,
                    )?;
                    if next.is_none() || cycle_to.is_some() {
                        cover(
                            &mut outcome,
                            base + u64::from(step) + 1,
                            u64::from(maximum_transitions - step - 1),
                            CoverageKind::Skipped,
                            coverage,
                        )?;
                        terminated = true;
                        break;
                    }
                    cluster = next.ok_or(StopReason::UnsupportedProfile)?;
                }
                if !terminated {
                    return Err(StopReason::ResourceLimit("chain transitions"));
                }
            }
            work.check()
        })();
        if let Err(reason) = run {
            outcome.stop_reason = reason;
            report_unreadable(&mut outcome, coverage);
        }
        outcome
    }
}
fn report_unreadable(
    outcome: &mut ScanOutcome,
    coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
) {
    if matches!(outcome.stop_reason, StopReason::Io(_)) && outcome.unvisited.length != 0 {
        match coverage(CoverageEvent {
            range: ByteRange {
                offset: outcome.unvisited.offset,
                length: 1,
            },
            kind: CoverageKind::Unreadable,
        }) {
            Ok(()) => outcome.coverage_events += 1,
            Err(error) => outcome.stop_reason = StopReason::DeliveryFailed(error),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::{
        forensics::{AcquisitionLease, ForensicSource, NeverCancel, SourceIdentity},
        fs_core::{Budget, Cancellation},
        fs_fat::FatFamily,
    };
    use alloc::sync::Arc;
    struct Bytes(Vec<u8>);
    impl ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let bytes = self
                .0
                .get(offset as usize..offset as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            out.copy_from_slice(bytes);
            Ok(())
        }
    }
    fn fixture(family: FatFamily) -> FatForensics {
        let (sectors, fat_sectors, reserved, root) = match family {
            FatFamily::Fat12 => (2880usize, 9u16, 1u16, 224u16),
            FatFamily::Fat16 => (8192, 32, 1, 224),
            FatFamily::Fat32 => (70000, 540, 32, 0),
        };
        let mut bytes = vec![0; sectors * 512];
        bytes[11..13].copy_from_slice(&512u16.to_le_bytes());
        bytes[13] = 1;
        bytes[14..16].copy_from_slice(&reserved.to_le_bytes());
        bytes[16] = 2;
        bytes[17..19].copy_from_slice(&root.to_le_bytes());
        bytes[21] = 0xf8;
        if family == FatFamily::Fat32 {
            bytes[32..36].copy_from_slice(&(sectors as u32).to_le_bytes());
            bytes[36..40].copy_from_slice(&u32::from(fat_sectors).to_le_bytes());
            bytes[40..42].copy_from_slice(&0x81u16.to_le_bytes()); // Copy one active.
            bytes[44..48].copy_from_slice(&2u32.to_le_bytes());
            bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
        } else {
            bytes[19..21].copy_from_slice(&(sectors as u16).to_le_bytes());
            bytes[22..24].copy_from_slice(&fat_sectors.to_le_bytes());
        }
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        for copy in 0..2usize {
            let base = usize::from(reserved) * 512 + copy * usize::from(fat_sectors) * 512;
            match family {
                FatFamily::Fat12 => {
                    // Copy zero: 2->3->END. Copy one: 2->4->2 (cycle).
                    bytes[base + 3..base + 6].copy_from_slice(if copy == 0 {
                        &[3, 0xf0, 0xff]
                    } else {
                        &[4, 0, 0]
                    });
                    if copy == 1 {
                        bytes[base + 6..base + 8].copy_from_slice(&[2, 0]);
                    }
                }
                FatFamily::Fat16 => {
                    bytes[base + 4..base + 6]
                        .copy_from_slice(&(if copy == 0 { 3u16 } else { 4 }).to_le_bytes());
                    bytes[base + 6..base + 8].copy_from_slice(&0xffffu16.to_le_bytes());
                    bytes[base + 8..base + 10].copy_from_slice(&2u16.to_le_bytes());
                }
                FatFamily::Fat32 => {
                    bytes[base + 8..base + 12].copy_from_slice(
                        &(if copy == 0 { 0xa0000003u32 } else { 0xb0000004 }).to_le_bytes(),
                    );
                    bytes[base + 12..base + 16].copy_from_slice(&0x0fffffffu32.to_le_bytes());
                    bytes[base + 16..base + 20].copy_from_slice(&2u32.to_le_bytes());
                }
            }
        }
        let length = bytes.len() as u64;
        FatForensics::open(
            ForensicSource::new(
                Arc::new(Bytes(bytes)),
                SourceIdentity {
                    acquisition: "fixture".into(),
                    source: "independent FAT copies".into(),
                    stability_provider: "owned bytes".into(),
                },
                Arc::new(AcquisitionLease::default()),
                ByteRange { offset: 0, length },
                vec![],
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    #[test]
    fn divergent_packed_fixed_and_inactive_copies_follow_independent_chains() {
        for family in [FatFamily::Fat12, FatFamily::Fat16, FatFamily::Fat32] {
            let volume = fixture(family);
            let resources = resources();
            let mut observations = vec![];
            let mut coverage = vec![];
            let outcome = volume.scan_fat_copy_chains(
                2,
                4,
                ScanLimits::default(),
                &resources,
                &NeverCancel,
                &mut |event| {
                    observations.push(event);
                    Ok(true)
                },
                &mut |event| {
                    coverage.push(event);
                    Ok(())
                },
            );
            assert!(outcome.is_complete(), "{:?}", outcome.stop_reason);
            assert_eq!(
                observations
                    .iter()
                    .map(|event| (event.entry.copy, event.entry.cluster))
                    .collect::<Vec<_>>(),
                vec![(0, 2), (0, 3), (1, 2), (1, 4)]
            );
            assert_eq!(observations[3].cycle_to, Some(2));
            assert_eq!(observations[2].baseline.value, 3);
            assert_eq!(observations[2].entry.value, 4);
            assert!(
                coverage
                    .iter()
                    .any(|event| event.kind == CoverageKind::Skipped)
            );
            assert_eq!(outcome.source_id, Some(volume.source().id()));
            let mut differences = vec![];
            let outcome = volume.scan_fat_copy_differences(
                ScanLimits::default(),
                &resources,
                &NeverCancel,
                &mut |event| {
                    differences.push(event);
                    Ok(true)
                },
                &mut |_| Ok(()),
            );
            assert!(outcome.is_complete());
            let disagreement = differences
                .iter()
                .find(|event| event.other.cluster == 2)
                .unwrap();
            assert!(disagreement.meaningful_difference && disagreement.raw_difference);
            assert_ne!(disagreement.baseline.offset, disagreement.other.offset);
        }
    }
    #[test]
    fn exact_chain_ceilings_and_failed_delivery_retain_typed_progress() {
        let volume = fixture(FatFamily::Fat12);
        let resources = resources();
        let exact = ScanLimits {
            records: 6,
            read_bytes: 12,
            output_bytes: 4 * core::mem::size_of::<FatCopyChainObservation>() as u64,
            memory_bytes: 1024,
        };
        let outcome = volume.scan_fat_copy_chains(
            2,
            2,
            exact,
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(outcome.is_complete(), "{:?}", outcome.stop_reason);
        let mut delivered = 0;
        let outcome = volume.scan_fat_copy_chains(
            2,
            2,
            exact,
            &resources,
            &NeverCancel,
            &mut |_| {
                delivered += 1;
                if delivered == 2 {
                    Err(io::Error::other("sink"))
                } else {
                    Ok(true)
                }
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::DeliveryFailed(_)));
        assert_eq!(outcome.observations, 1);
        assert_eq!(outcome.unvisited.offset, 1);
        let outcome = volume.scan_fat_copy_chains(
            2,
            2,
            exact,
            &resources,
            &NeverCancel,
            &mut |_| {
                resources.cancellation.cancel();
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        assert_eq!(outcome.observations, 1);
    }
    #[test]
    fn missing_copy_evidence_emits_an_unreadable_comparison_without_equal_claims() {
        let original = fixture(FatFamily::Fat12);
        let length = original.source().len();
        let missing = original.geometry().fat_offset() + original.geometry().fat_bytes();
        let source = ForensicSource::new(
            Arc::new(original.source().clone()),
            SourceIdentity {
                acquisition: "gap".into(),
                source: "missing copy bytes".into(),
                stability_provider: "owned bytes".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange { offset: 0, length },
            vec![ByteRange {
                offset: missing,
                length: 2,
            }],
        )
        .unwrap();
        let volume = FatForensics::open(source).unwrap();
        let mut coverage = vec![];
        let outcome = volume.scan_fat_copy_differences(
            ScanLimits::default(),
            &resources(),
            &NeverCancel,
            &mut |_| panic!("unavailable pair has no comparison"),
            &mut |event| {
                coverage.push(event);
                Ok(())
            },
        );
        assert!(matches!(outcome.stop_reason, StopReason::Io(_)));
        assert_eq!(outcome.observations, 0);
        assert_eq!(outcome.unvisited, outcome.domain);
        assert_eq!(
            coverage,
            vec![CoverageEvent {
                range: ByteRange {
                    offset: 0,
                    length: 1
                },
                kind: CoverageKind::Unreadable
            }]
        );
    }
    #[test]
    fn cancellation_and_shared_budget_stop_before_the_first_comparison() {
        let volume = fixture(FatFamily::Fat12);
        let resources = resources();
        resources.cancellation.cancel();
        let outcome = volume.scan_fat_copy_differences(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("cancelled"),
            &mut |_| panic!("not read"),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        let resources = Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        };
        let outcome = volume.scan_fat_copy_differences(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("no memory"),
            &mut |_| panic!("not read"),
        );
        assert!(matches!(
            outcome.stop_reason,
            StopReason::ResourceLimit("shared memory")
        ));
    }
    #[test]
    fn resource_and_bound_failures_stop_without_promoting_prefix_to_completion() {
        let volume = fixture(FatFamily::Fat12);
        for (limits, ceiling) in [
            (
                ScanLimits {
                    records: 0,
                    ..ScanLimits::default()
                },
                "records",
            ),
            (
                ScanLimits {
                    read_bytes: 0,
                    ..ScanLimits::default()
                },
                "read_bytes",
            ),
            (
                ScanLimits {
                    output_bytes: 0,
                    ..ScanLimits::default()
                },
                "output_bytes",
            ),
            (
                ScanLimits {
                    memory_bytes: 0,
                    ..ScanLimits::default()
                },
                "memory_bytes",
            ),
        ] {
            let outcome = volume.scan_fat_copy_chains(
                2,
                2,
                limits,
                &resources(),
                &NeverCancel,
                &mut |_| panic!("ceiling precedes delivery"),
                &mut |_| Ok(()),
            );
            assert!(
                matches!(outcome.stop_reason, StopReason::ResourceLimit(actual) if actual == ceiling)
            );
        }
        let outcome = volume.scan_fat_copy_chains(
            2,
            1,
            ScanLimits::default(),
            &resources(),
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            outcome.stop_reason,
            StopReason::ResourceLimit("chain transitions")
        ));
        assert_eq!(outcome.observations, 1);
    }
}
