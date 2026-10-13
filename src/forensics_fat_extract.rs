//! Metadata-assisted FAT candidate maps. Deleted aliases identify candidates,
//! never authenticated historical content; contiguous reconstruction is explicit.
use crate::{
    forensics::{ByteRange, CoverageEvent, ScanControl, ScanLimits, ScanOutcome, StopReason},
    forensics_extract::{ExtractionKind, ExtractionRange, ReuseEvidence},
    forensics_fat::{
        FatAllocationKind, FatForensics, FatOwnershipObservation, FatSlotKind, FatSlotObservation,
    },
    fs_core::{Reservation, Resources},
    fs_fat::FatFamily,
    io::{self, ReadAt},
};
use alloc::vec::Vec;

/// How a deleted alias with a cleared chain may supply additional candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatRecoveryPolicy {
    /// Follow retained current chain transitions; missing suffixes stay unavailable.
    RetainedChain,
    /// Explicitly hypothesize consecutive clusters after a lost transition.
    ContiguousHypothesis,
}
/// Per-range metadata qualifications independent of the extracted-byte digest.
#[derive(Clone, Debug)]
pub struct FatCandidateRange {
    /// Streaming extractor map entry.
    pub extraction: ExtractionRange,
    /// Current selected-copy FAT entry; unavailable evidence remains `None`.
    pub allocation: Option<FatAllocationKind>,
    /// Complete current namespace ownership coverage.
    pub ownership_complete: bool,
    /// The full owner scan actually observed this live alias claiming this range.
    pub selected_owner_observed: bool,
    /// An observed conflicting alias offset; `Some(None)` means FAT32 root.
    pub conflicting_owner: Option<Option<u64>>,
    /// The physical assignment uses the opt-in contiguous reconstruction hypothesis.
    pub contiguous_hypothesis: bool,
}
/// Bounded map retaining shared memory and independent mapping/ownership outcomes.
pub struct FatCandidateMap {
    ranges: Vec<FatCandidateRange>,
    source: crate::forensics::ForensicSource,
    _reservation: Option<Reservation>,
    /// Raw source slot; preserves native name, timestamps and lost first alias byte.
    pub slot: FatSlotObservation,
    /// Logical file length from the raw alias.
    pub length: u64,
    /// Whether the alias is deleted; complete extraction cannot authenticate history.
    pub deleted: bool,
    /// Current namespace traversal actually reached the selected live alias.
    /// False with incomplete ownership coverage means unknown membership.
    pub selected_alias_observed: bool,
    /// Mapping traversal outcome. An incomplete map must not be extracted as complete.
    pub mapping: ScanOutcome,
    /// Independent complete/current owner coverage, or its causal stop reason.
    pub ownership: Option<ScanOutcome>,
}
impl FatCandidateMap {
    /// Stable source bound to the raw alias and every candidate range.
    pub fn source(&self) -> &crate::forensics::ForensicSource {
        &self.source
    }
    /// Ordered range evidence; unavailable suffixes are explicit.
    pub fn ranges(&self) -> &[FatCandidateRange] {
        &self.ranges
    }
}

/// Build a bounded live-file or deleted-alias map from raw FAT metadata.
/// Arbitrary slack, labels, directories and LFN fragments are rejected. The
/// selected FAT copy is the BPB active copy, or copy zero for mirrored volumes;
/// divergent copies must be independently retained by the allocation inventory.
pub fn map_fat_candidate(
    volume: &FatForensics,
    slot: FatSlotObservation,
    policy: FatRecoveryPolicy,
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
    coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
) -> FatCandidateMap {
    let length = u64::from(u32::from_le_bytes([
        slot.raw[28],
        slot.raw[29],
        slot.raw[30],
        slot.raw[31],
    ]));
    let deleted = slot.kind == FatSlotKind::DeletedAlias;
    let mut result = FatCandidateMap {
        ranges: Vec::new(),
        source: volume.source().clone(),
        _reservation: None,
        slot,
        length,
        deleted,
        selected_alias_observed: false,
        mapping: ScanOutcome::new(ByteRange { offset: 0, length }, "fat-alias-candidate-map")
            .with_coordinate_space(crate::forensics::CoordinateSpace::LogicalStreamBytes)
            .with_source_id(volume.source().id()),
        ownership: None,
    };
    let invalid = |message| {
        StopReason::InvalidBootstrap(io::Error::new(io::ErrorKind::InvalidInput, message))
    };
    if result
        .slot
        .source_id
        .is_some_and(|source| source != volume.source().id())
    {
        result.mapping.stop_reason = invalid("alias belongs to a different forensic source view");
        return result;
    }
    if result.slot.post_terminator
        || !matches!(
            result.slot.kind,
            FatSlotKind::File | FatSlotKind::DeletedAlias
        )
        || result.slot.raw[11] & 0xd8 != 0
    {
        result.mapping.stop_reason = invalid("slot is not a supported live/deleted file alias");
        return result;
    }
    if control.cancelled() || resources.cancellation.check().is_err() {
        result.mapping.stop_reason = StopReason::Cancelled;
        return result;
    }
    if let Err(error) = volume.source().check_stability() {
        result.mapping.stop_reason = StopReason::SourceStability(error);
        return result;
    }
    let geometry = volume.geometry();
    let cluster_bytes = geometry.cluster_bytes();
    let clusters = length.div_ceil(cluster_bytes);
    let memory = 32u64.saturating_add(clusters.saturating_mul(
        (core::mem::size_of::<FatCandidateRange>() + core::mem::size_of::<u32>()) as u64,
    ));
    if clusters > limits.records {
        result.mapping.stop_reason = StopReason::ResourceLimit("records");
        return result;
    }
    if memory > limits.memory_bytes {
        result.mapping.stop_reason = StopReason::ResourceLimit("memory_bytes");
        return result;
    }
    if !result.slot.offset.is_multiple_of(32)
        || !result.slot.directory_offset.is_multiple_of(32)
        || ByteRange::checked(result.slot.offset, 32, geometry.volume_bytes()).is_err()
    {
        result.mapping.stop_reason = invalid("alias slot is unaligned or outside the FAT volume");
        return result;
    }
    if limits.read_bytes < 32 {
        result.mapping.stop_reason = StopReason::ResourceLimit("read_bytes");
        return result;
    }
    result._reservation = match resources.memory.reserve(memory) {
        Ok(reservation) => Some(reservation),
        Err(_) => {
            result.mapping.stop_reason = StopReason::ResourceLimit("shared memory");
            return result;
        }
    };
    let mut seen = Vec::new();
    if result.ranges.try_reserve_exact(clusters as usize).is_err()
        || seen.try_reserve_exact(clusters as usize).is_err()
    {
        result.mapping.stop_reason = StopReason::ResourceLimit("memory allocation");
        return result;
    }
    let mut actual_slot = [0; 32];
    if let Err(error) = volume
        .source()
        .read_exact_at(result.slot.offset, &mut actual_slot)
    {
        result.mapping.stop_reason = if volume.source().check_stability().is_err() {
            StopReason::SourceStability(error)
        } else {
            StopReason::Io(error)
        };
        return result;
    }
    if actual_slot != result.slot.raw
        || FatSlotObservation::decode(
            result.slot.offset,
            result.slot.directory_offset,
            actual_slot,
            false,
        )
        .kind
            != result.slot.kind
    {
        result.mapping.stop_reason = invalid("slot bytes differ from stable source evidence");
        return result;
    }
    result.slot.source_id = Some(volume.source().id());
    let low = u32::from(u16::from_le_bytes([
        result.slot.raw[26],
        result.slot.raw[27],
    ]));
    let high = u32::from(u16::from_le_bytes([
        result.slot.raw[20],
        result.slot.raw[21],
    ]));
    if (geometry.family() != FatFamily::Fat32 && high != 0) || high & 0xf000 != 0 {
        result.mapping.stop_reason = invalid("invalid alias high cluster word");
        return result;
    }
    let mut cluster = if geometry.family() == FatFamily::Fat32 {
        (high << 16) | low
    } else {
        low
    };
    let copy = geometry.active_fat().unwrap_or(0);
    let mut inferred = false;
    for index in 0..clusters {
        if control.cancelled() || resources.cancellation.check().is_err() {
            result.mapping.stop_reason = StopReason::Cancelled;
            return result;
        }
        let logical = index * cluster_bytes;
        let take = (length - logical).min(cluster_bytes);
        if cluster < 2 || cluster > geometry.cluster_count() + 1 || seen.contains(&cluster) {
            result.ranges.push(FatCandidateRange {
                extraction: ExtractionRange {
                    logical: ByteRange {
                        offset: logical,
                        length: length - logical,
                    },
                    kind: ExtractionKind::Unavailable,
                    reuse: ReuseEvidence::Unknown,
                },
                allocation: None,
                ownership_complete: false,
                selected_owner_observed: false,
                conflicting_owner: None,
                contiguous_hypothesis: false,
            });
            result.mapping.stop_reason = invalid("missing, cyclic or out-of-range candidate chain");
            return result;
        }
        let read_size = if geometry.family() == FatFamily::Fat32 {
            4
        } else {
            2
        };
        if 32 + (index + 1) * read_size > limits.read_bytes {
            result.mapping.stop_reason = StopReason::ResourceLimit("read_bytes");
            return result;
        }
        if (index + 1) * core::mem::size_of::<FatCandidateRange>() as u64 > limits.output_bytes {
            result.mapping.stop_reason = StopReason::ResourceLimit("output_bytes");
            return result;
        }
        seen.push(cluster);
        let value = match volume.read_allocation_value(copy, cluster) {
            Ok(value) => value,
            Err(error) => {
                result.mapping.stop_reason = match volume.source().check_stability() {
                    Ok(()) => StopReason::Io(error),
                    Err(_) => StopReason::SourceStability(error),
                };
                return result;
            }
        };
        let allocation = volume.classify_allocation(cluster, value);
        let offset = geometry.data_offset() + u64::from(cluster - 2) * cluster_bytes;
        result.ranges.push(FatCandidateRange {
            extraction: ExtractionRange {
                logical: ByteRange {
                    offset: logical,
                    length: take,
                },
                kind: ExtractionKind::Data(offset),
                reuse: ReuseEvidence::Unknown,
            },
            allocation: Some(allocation),
            ownership_complete: false,
            selected_owner_observed: false,
            conflicting_owner: None,
            contiguous_hypothesis: inferred,
        });
        result.mapping.observations += 1;
        if let Err(error) = coverage(CoverageEvent {
            range: ByteRange {
                offset: logical,
                length: take,
            },
            kind: crate::forensics::CoverageKind::Inspected,
        }) {
            result.mapping.stop_reason = StopReason::DeliveryFailed(error);
            return result;
        }
        result.mapping.coverage_events += 1;
        result.mapping.advance(logical + take);
        if !deleted
            && ((index + 1 == clusters && allocation != FatAllocationKind::End)
                || (index + 1 < clusters && !matches!(allocation, FatAllocationKind::Next(_))))
        {
            result.mapping.stop_reason = invalid("live file chain does not match declared length");
            return result;
        }
        cluster = match allocation {
            FatAllocationKind::Next(next) if !inferred => next,
            FatAllocationKind::Free
                if deleted && policy == FatRecoveryPolicy::ContiguousHypothesis =>
            {
                inferred = true;
                cluster + 1
            }
            _ if inferred => cluster + 1,
            _ => 0,
        };
    }
    // Full current owner coverage is independent from candidate chain traversal.
    // Retain observed conflicts even when owner enumeration later stops.
    let entry_bytes = if geometry.family() == FatFamily::Fat32 {
        4
    } else {
        2
    };
    let ownership_limits = ScanLimits {
        records: limits.records.saturating_sub(clusters),
        read_bytes: limits
            .read_bytes
            .saturating_sub(32 + clusters * entry_bytes),
        output_bytes: limits
            .output_bytes
            .saturating_sub(clusters * core::mem::size_of::<FatCandidateRange>() as u64),
        memory_bytes: limits.memory_bytes.saturating_sub(memory),
    };
    let ownership = volume.scan_ownership(
        ownership_limits,
        resources,
        control,
        &mut |observation| {
            if let FatOwnershipObservation::LiveAlias { alias_offset, .. } = &observation
                && *alias_offset == result.slot.offset
            {
                result.selected_alias_observed = true;
            }
            if let FatOwnershipObservation::Owner {
                cluster,
                alias_offset,
                ..
            } = observation
            {
                for (index, candidate_cluster) in seen.iter().enumerate() {
                    if *candidate_cluster == cluster
                        && (deleted || alias_offset != Some(result.slot.offset))
                    {
                        result.ranges[index].conflicting_owner = Some(alias_offset);
                    } else if *candidate_cluster == cluster
                        && !deleted
                        && alias_offset == Some(result.slot.offset)
                    {
                        result.ranges[index].selected_owner_observed = true;
                    }
                }
            }
            Ok(true)
        },
        &mut |_| Ok(()),
    );
    let complete = ownership.namespace_complete
        && ownership.allocation_complete
        && ownership.scan.is_complete();
    for range in &mut result.ranges {
        range.ownership_complete = complete;
        range.extraction.reuse = if range.conflicting_owner.is_some() {
            ReuseEvidence::ConflictingOwner
        } else if !complete {
            ReuseEvidence::Unknown
        } else if range.allocation == Some(FatAllocationKind::Free) {
            ReuseEvidence::CurrentlyFree
        } else if !deleted && range.selected_owner_observed {
            ReuseEvidence::SelectedLiveOwner
        } else {
            ReuseEvidence::AllocatedOwnerUnknown
        };
    }
    if !deleted
        && complete
        && (!result.selected_alias_observed
            || result
                .ranges
                .iter()
                .any(|range| !range.selected_owner_observed))
    {
        result.mapping.stop_reason =
            invalid("alias was not observed in the current live namespace");
    }
    result.ownership = Some(ownership.scan);
    result
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::forensics::{AcquisitionLease, ForensicSource, NeverCancel, SourceIdentity};
    use crate::forensics_extract::{ExtractionEvent, extract_ranges};
    use alloc::sync::Arc;
    struct Image(Vec<u8>);
    impl ReadAt for Image {
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
    fn fixture(deleted: bool) -> (Vec<u8>, FatSlotObservation) {
        let mut bytes = alloc::vec![0; 2880 * 512];
        bytes[11..13].copy_from_slice(&512u16.to_le_bytes());
        bytes[13] = 1;
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[16] = 2;
        bytes[17..19].copy_from_slice(&224u16.to_le_bytes());
        bytes[19..21].copy_from_slice(&2880u16.to_le_bytes());
        bytes[21] = 0xf8;
        bytes[22..24].copy_from_slice(&9u16.to_le_bytes());
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut raw = [0; 32];
        raw[..11].copy_from_slice(b"FILE    BIN");
        raw[11] = 0x20;
        raw[26..28].copy_from_slice(&2u16.to_le_bytes());
        raw[28..32].copy_from_slice(&700u32.to_le_bytes());
        if deleted {
            raw[0] = 0xe5;
        } else {
            bytes[515] = 4;
            bytes[518..520].copy_from_slice(&[0xff, 0x0f]);
        }
        let root = 19 * 512;
        bytes[root..root + 32].copy_from_slice(&raw);
        bytes[33 * 512..34 * 512].fill(b'A');
        let second = if deleted { 34 } else { 35 };
        bytes[second * 512..second * 512 + 188].fill(b'B');
        let fat = bytes[512..512 + 9 * 512].to_vec();
        bytes[512 + 9 * 512..512 + 18 * 512].copy_from_slice(&fat);
        (
            bytes,
            FatSlotObservation::decode(root as u64, 0, raw, false),
        )
    }
    fn volume(bytes: Vec<u8>) -> FatForensics {
        let length = bytes.len() as u64;
        FatForensics::open(
            ForensicSource::new(
                Arc::new(Image(bytes)),
                SourceIdentity {
                    acquisition: "test".into(),
                    source: "literal-fat12".into(),
                    stability_provider: "lease".into(),
                },
                Arc::new(AcquisitionLease::default()),
                ByteRange { offset: 0, length },
                alloc::vec![],
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn resources() -> Resources {
        Resources {
            memory: crate::fs_core::Budget::new(1 << 20),
            cancellation: crate::fs_core::Cancellation::default(),
        }
    }
    #[test]
    fn fragmented_live_candidate_extracts_independent_known_bytes() {
        let (bytes, slot) = fixture(false);
        let volume = volume(bytes);
        let resources = resources();
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(map.mapping.is_complete());
        assert!(
            map.ranges()
                .iter()
                .all(|range| range.extraction.reuse == ReuseEvidence::SelectedLiveOwner)
        );
        let ranges: Vec<_> = map.ranges().iter().map(|range| range.extraction).collect();
        let mut output = Vec::new();
        let result = extract_ranges(
            volume.source(),
            map.length,
            &ranges,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |event| {
                if let ExtractionEvent::Bytes { bytes, .. } = event {
                    output.extend_from_slice(bytes);
                }
                Ok(())
            },
        );
        assert!(result.scan.is_complete());
        assert_eq!(output.len(), 700);
        assert_eq!(
            result.prefix_sha256,
            [
                0x02, 0xe9, 0xde, 0x1f, 0x81, 0x7f, 0x2e, 0x6a, 0x4e, 0x85, 0x17, 0x01, 0xea, 0xd0,
                0x74, 0x55, 0x31, 0x84, 0x4c, 0xe1, 0xc9, 0xb5, 0x33, 0xe6, 0x60, 0xe1, 0xdb, 0x2f,
                0x85, 0x4b, 0x45, 0xce
            ]
        );
        assert_eq!(&output[..512], &[b'A'; 512]);
        assert_eq!(&output[512..], &[b'B'; 188]);
    }
    #[test]
    fn deleted_cleared_chain_requires_explicit_contiguous_hypothesis() {
        let (bytes, slot) = fixture(true);
        let volume = volume(bytes);
        let resources = resources();
        let retained = map_fat_candidate(
            &volume,
            slot.clone(),
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(!retained.mapping.is_complete());
        assert!(matches!(
            retained.ranges()[1].extraction.kind,
            ExtractionKind::Unavailable
        ));
        let hypothesized = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::ContiguousHypothesis,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(hypothesized.mapping.is_complete());
        assert!(hypothesized.deleted);
        assert!(hypothesized.ranges()[1].contiguous_hypothesis);
        assert!(
            hypothesized
                .ranges()
                .iter()
                .all(|range| range.extraction.reuse == ReuseEvidence::CurrentlyFree)
        );
    }
    #[test]
    fn overwritten_deleted_slot_cannot_supply_a_stale_recovery_map() {
        let (mut bytes, slot) = fixture(true);
        let offset = slot.offset as usize;
        bytes[offset..offset + 11].copy_from_slice(b"REUSED  BIN");
        bytes[offset + 26..offset + 28].copy_from_slice(&4u16.to_le_bytes());
        let volume = volume(bytes);
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::ContiguousHypothesis,
            ScanLimits::default(),
            &resources(),
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(matches!(
            map.mapping.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        assert!(map.ranges().is_empty());
    }
    #[test]
    fn a_raw_live_alias_in_slack_cannot_be_promoted_to_live_namespace() {
        let (mut bytes, mut slot) = fixture(false);
        let actual = slot.raw;
        bytes[slot.offset as usize..slot.offset as usize + 32].fill(0);
        slot.offset += 32;
        bytes[slot.offset as usize..slot.offset as usize + 32].copy_from_slice(&actual);
        let volume = volume(bytes);
        let resources = resources();
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(matches!(
            map.mapping.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        assert!(
            map.ranges()
                .iter()
                .all(|range| !range.selected_owner_observed)
        );
    }
    #[test]
    fn mirrored_allocation_conflict_cannot_become_currently_free_recovery() {
        let (mut bytes, slot) = fixture(true);
        bytes[512 + 9 * 512 + 3..512 + 9 * 512 + 5].copy_from_slice(&[0xff, 0x0f]);
        let volume = volume(bytes);
        let resources = resources();
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::ContiguousHypothesis,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(map.mapping.is_complete());
        assert!(
            map.ranges().iter().all(|range| !range.ownership_complete
                && range.extraction.reuse == ReuseEvidence::Unknown)
        );
    }
    #[test]
    fn record_and_shared_memory_ceilings_precede_alias_reads() {
        let (bytes, slot) = fixture(false);
        let length = bytes.len() as u64;
        let source = ForensicSource::new(
            Arc::new(Image(bytes)),
            SourceIdentity {
                acquisition: "test".into(),
                source: "unavailable-alias".into(),
                stability_provider: "lease".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange { offset: 0, length },
            vec![ByteRange {
                offset: slot.offset,
                length: 32,
            }],
        )
        .unwrap();
        let volume = FatForensics::open(source).unwrap();
        let map = map_fat_candidate(
            &volume,
            slot.clone(),
            FatRecoveryPolicy::RetainedChain,
            ScanLimits {
                records: 0,
                ..ScanLimits::default()
            },
            &resources(),
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(matches!(
            map.mapping.stop_reason,
            StopReason::ResourceLimit("records")
        ));
        let empty_budget = Resources {
            memory: crate::fs_core::Budget::new(0),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &empty_budget,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(matches!(
            map.mapping.stop_reason,
            StopReason::ResourceLimit("shared memory")
        ));
    }
    #[test]
    fn empty_live_alias_requires_namespace_membership_even_without_extents() {
        for in_slack in [false, true] {
            let (mut bytes, mut slot) = fixture(false);
            slot.raw[20..22].fill(0);
            slot.raw[26..32].fill(0);
            let root = slot.offset as usize;
            if in_slack {
                bytes[root..root + 32].fill(0);
                slot.offset += 32;
                slot.directory_offset += 32;
            }
            let offset = slot.offset as usize;
            bytes[offset..offset + 32].copy_from_slice(&slot.raw);
            let volume = volume(bytes);
            let map = map_fat_candidate(
                &volume,
                slot,
                FatRecoveryPolicy::RetainedChain,
                ScanLimits::default(),
                &resources(),
                &NeverCancel,
                &mut |_| Ok(()),
            );
            assert!(map.ranges().is_empty());
            assert!(map.ownership.as_ref().unwrap().is_complete());
            if in_slack {
                assert!(matches!(
                    map.mapping.stop_reason,
                    StopReason::InvalidBootstrap(_)
                ));
            } else {
                assert!(map.mapping.is_complete());
            }
        }
    }
    #[test]
    fn identical_bytes_in_a_distinct_source_view_cannot_rebind_an_alias() {
        let (bytes, mut slot) = fixture(false);
        let original = volume(bytes.clone());
        slot.source_id = Some(original.source().id());
        let distinct = volume(bytes);
        let map = map_fat_candidate(
            &distinct,
            slot.clone(),
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &resources(),
            &NeverCancel,
            &mut |_| panic!("foreign view must be rejected before reading evidence"),
        );
        assert!(matches!(
            map.mapping.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        assert!(map.ranges().is_empty());
        assert!(map.ownership.is_none());
        let cloned = FatForensics::open(original.source().clone()).unwrap();
        let map = map_fat_candidate(
            &cloned,
            slot,
            FatRecoveryPolicy::RetainedChain,
            ScanLimits::default(),
            &resources(),
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(map.mapping.is_complete());
        assert_eq!(map.mapping.source_id, Some(original.source().id()));
    }
    #[test]
    fn interrupted_owner_scan_keeps_candidate_reuse_unknown() {
        let (bytes, slot) = fixture(true);
        let volume = volume(bytes);
        let resources = resources();
        let map = map_fat_candidate(
            &volume,
            slot,
            FatRecoveryPolicy::ContiguousHypothesis,
            ScanLimits {
                records: 2,
                ..ScanLimits::default()
            },
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(map.mapping.is_complete());
        assert!(
            map.ranges().iter().all(|range| !range.ownership_complete
                && range.extraction.reuse == ReuseEvidence::Unknown)
        );
    }
}
