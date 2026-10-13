//! Read-only FAT evidence inventory. Raw slots remain evidence even when deleted,
//! malformed, or beyond a directory terminator. No recovered name is authenticated.
use crate::fs_fat::FatFamily;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use crate::platform::prelude::*;

/// Classification of a raw directory slot, independent of its location in slack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatSlotKind {
    /// First-byte zero directory terminator.
    Terminator,
    /// Deleted long filename fragment; ordinal and first byte have been lost.
    DeletedLongName,
    /// Deleted alias; its original first byte is unavailable.
    DeletedAlias,
    /// Native UTF-16 long filename fragment, not a validated reconstructed name.
    LongName,
    /// Volume label.
    Label,
    /// Short directory alias.
    Directory,
    /// Short file alias.
    File,
}
/// Lossless directory observation. Offsets are volume-relative, never container offsets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatSlotObservation {
    /// Exact forensic source view; detached raw decoding has no bound source.
    pub source_id: Option<crate::forensics::SourceId>,
    /// Volume-relative byte position of this exact 32-byte slot.
    pub offset: u64,
    /// Logical byte position within the selected directory chain.
    pub directory_offset: u64,
    /// Complete original slot including native timestamps and unknown fields.
    pub raw: [u8; 32],
    /// Raw slot classification without namespace validation.
    pub kind: FatSlotKind,
    /// True only after an earlier zero terminator in this directory.
    pub post_terminator: bool,
}
impl FatSlotObservation {
    /// Classify bytes without treating post-terminator entries as namespace members.
    pub fn decode(
        offset: u64,
        directory_offset: u64,
        raw: [u8; 32],
        post_terminator: bool,
    ) -> Self {
        let kind = match (raw[0], raw[11]) {
            (0, _) => FatSlotKind::Terminator,
            (0xe5, 0x0f) => FatSlotKind::DeletedLongName,
            (0xe5, _) => FatSlotKind::DeletedAlias,
            (_, 0x0f) => FatSlotKind::LongName,
            (_, attributes) if attributes & 8 != 0 => FatSlotKind::Label,
            (_, attributes) if attributes & 0x10 != 0 => FatSlotKind::Directory,
            _ => FatSlotKind::File,
        };
        Self {
            source_id: None,
            offset,
            directory_offset,
            raw,
            kind,
            post_terminator,
        }
    }
    /// Native units of one LFN fragment, including terminator and padding units.
    /// Deleted fragment association and ordering require separate inference.
    pub fn long_name_units(&self) -> Option<[u16; 13]> {
        if !matches!(
            self.kind,
            FatSlotKind::LongName | FatSlotKind::DeletedLongName
        ) {
            return None;
        }
        let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        Some(positions.map(|i| u16::from_le_bytes([self.raw[i], self.raw[i + 1]])))
    }
    /// Alias bytes, with a deleted first byte retained as 0xe5 rather than guessed.
    pub fn alias(&self) -> Option<[u8; 11]> {
        if matches!(
            self.kind,
            FatSlotKind::LongName | FatSlotKind::DeletedLongName | FatSlotKind::Terminator
        ) {
            return None;
        }
        let mut result = [0; 11];
        result.copy_from_slice(&self.raw[..11]);
        Some(result)
    }
}
/// Meaning of one FAT value. Allocation does not establish current ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatAllocationKind {
    /// Zero entry.
    Free,
    /// Link to another addressable cluster.
    Next(u32),
    /// End-of-chain marker.
    End,
    /// Bad-cluster marker.
    Bad,
    /// Reserved marker or reserved FAT index zero/one.
    Reserved,
    /// Non-marker value outside addressable data clusters.
    OutOfRange,
}
/// One independently read FAT copy entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatAllocationObservation {
    /// Exact forensic source view; this token is not a content digest.
    pub source_id: crate::forensics::SourceId,
    /// FAT copy, including inactive FAT32 copies.
    pub copy: u8,
    /// Cluster index; zero and one are retained as reserved entries.
    pub cluster: u32,
    /// Exact backing byte position. Adjacent FAT12 entries overlap.
    pub offset: u64,
    /// Original two or four bytes, including FAT32 high reserved bits.
    pub raw: [u8; 4],
    /// Valid backing byte count.
    pub raw_length: u8,
    /// Decoded meaningful allocation value.
    pub value: u32,
    /// Classification against validated BPB cluster bounds.
    pub kind: FatAllocationKind,
}
pub(crate) fn allocation_kind(
    family: FatFamily,
    cluster: u32,
    value: u32,
    count: u32,
) -> FatAllocationKind {
    if cluster < 2 {
        return FatAllocationKind::Reserved;
    }
    let reserved = match family {
        FatFamily::Fat12 => 0xff0,
        FatFamily::Fat16 => 0xfff0,
        FatFamily::Fat32 => 0x0fff_fff0,
    };
    if value == 0 {
        FatAllocationKind::Free
    } else if value == reserved + 7 {
        FatAllocationKind::Bad
    } else if value >= reserved + 8 {
        FatAllocationKind::End
    } else if value >= reserved || value == 1 {
        FatAllocationKind::Reserved
    } else if value > count + 1 {
        FatAllocationKind::OutOfRange
    } else {
        FatAllocationKind::Next(value)
    }
}

use crate::{
    forensics::{
        ByteRange, CoverageEvent, CoverageKind, ForensicSource, ScanControl, ScanLimits,
        ScanOutcome, StopReason,
    },
    fs_fat::{FatGeometry, FatVolume},
    io::{self, ReadAt},
};
use alloc::sync::Arc;

/// Stable FAT reader retaining the original BPB independently of decoded geometry.
pub struct FatForensics {
    source: ForensicSource,
    volume: FatVolume,
    boot: [u8; 512],
}
impl FatForensics {
    /// Validate FAT geometry without applying namespace or allocation audit policy.
    pub fn open(source: ForensicSource) -> io::Result<Self> {
        let mut boot = [0; 512];
        source.read_exact_at(0, &mut boot)?;
        let volume = FatVolume::open(Arc::new(source.clone()))?;
        Ok(Self {
            source,
            volume,
            boot,
        })
    }
    /// Original bootstrap bytes including unrecognized and reserved fields.
    pub fn boot_sector(&self) -> &[u8; 512] {
        &self.boot
    }
    /// Validated BPB geometry in volume-relative bytes.
    pub fn geometry(&self) -> &FatGeometry {
        self.volume.geometry()
    }
    /// Acquisition identity and logical region translations.
    pub fn source(&self) -> &ForensicSource {
        &self.source
    }
    /// Inspect an explicit slot-aligned directory region, including all slack.
    /// This does not infer that an arbitrary caller-selected region is a directory.
    pub fn scan_directory_region(
        &self,
        range: ByteRange,
        limits: ScanLimits,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatSlotObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> ScanOutcome {
        let mut outcome =
            ScanOutcome::new(range, "fat-raw-directory-region").with_source_id(self.source.id());
        if !range.offset.is_multiple_of(32)
            || !range.length.is_multiple_of(32)
            || ByteRange::checked(range.offset, range.length, self.geometry().volume_bytes())
                .is_err()
        {
            outcome.stop_reason = StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unaligned or out-of-volume FAT directory region",
            ));
            return outcome;
        }
        let mut terminated = false;
        for logical in (0..range.length).step_by(32) {
            if let Some(reason) = boundary_stop(
                limits,
                control,
                outcome.observations,
                32,
                core::mem::size_of::<FatSlotObservation>() as u64,
            ) {
                outcome.stop_reason = reason;
                return outcome;
            }
            let offset = range.offset + logical;
            let mut raw = [0; 32];
            if let Err(error) = self.source.read_exact_at(offset, &mut raw) {
                record_read_failure(
                    &self.source,
                    error,
                    ByteRange { offset, length: 32 },
                    &mut outcome,
                    coverage,
                );
                return outcome;
            }
            let mut slot = FatSlotObservation::decode(offset, logical, raw, terminated);
            slot.source_id = Some(self.source.id());
            terminated |= slot.kind == FatSlotKind::Terminator;
            match visitor(slot) {
                Err(error) => {
                    outcome.stop_reason = StopReason::DeliveryFailed(error);
                    return outcome;
                }
                Ok(proceed) => {
                    outcome.observations += 1;
                    outcome.last_delivered = Some(offset + 32);
                    if let Err(error) = coverage(CoverageEvent {
                        range: ByteRange { offset, length: 32 },
                        kind: CoverageKind::Inspected,
                    }) {
                        outcome.stop_reason = StopReason::DeliveryFailed(error);
                        return outcome;
                    }
                    outcome.coverage_events += 1;
                    outcome.advance(offset + 32);
                    if !proceed {
                        outcome.stop_reason = StopReason::CallerStop;
                        return outcome;
                    }
                }
            }
        }
        if control.cancelled() {
            outcome.stop_reason = StopReason::Cancelled;
        }
        outcome
    }
    pub(crate) fn read_allocation_value(&self, copy: u8, cluster: u32) -> io::Result<u32> {
        self.volume.read_fat_entry(copy, cluster)
    }
    pub(crate) fn classify_allocation(&self, cluster: u32, value: u32) -> FatAllocationKind {
        allocation_kind(
            self.geometry().family(),
            cluster,
            value,
            self.geometry().cluster_count(),
        )
    }
    /// Inspect every addressable entry of every FAT copy, including reserved entries.
    /// Raw bytes preserve packed FAT12 overlap and FAT32 reserved high bits.
    /// Coverage is in entry ordinals (copy-major), not byte offsets; observations
    /// separately retain the exact volume byte positions.
    pub fn scan_allocation(
        &self,
        limits: ScanLimits,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatAllocationObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> ScanOutcome {
        let g = self.geometry();
        let entries = u64::from(g.cluster_count()) + 2;
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: entries * u64::from(g.fat_count()),
            },
            "fat-all-copies-entry-ordinals",
        )
        .with_coordinate_space(crate::forensics::CoordinateSpace::EntryOrdinals)
        .with_source_id(self.source.id());
        for copy in 0..g.fat_count() {
            for cluster in 0..g.cluster_count() + 2 {
                let ordinal = u64::from(copy) * entries + u64::from(cluster);
                let (relative, count) = entry_position(g.family(), cluster);
                if let Some(reason) = boundary_stop(
                    limits,
                    control,
                    outcome.observations,
                    count,
                    core::mem::size_of::<FatAllocationObservation>() as u64,
                ) {
                    outcome.stop_reason = reason;
                    return outcome;
                }
                let offset = g.fat_offset() + u64::from(copy) * g.fat_bytes() + relative;
                let mut raw = [0; 4];
                if let Err(error) = self
                    .source
                    .read_exact_at(offset, &mut raw[..count as usize])
                {
                    record_read_failure(
                        &self.source,
                        error,
                        ByteRange {
                            offset: ordinal,
                            length: 1,
                        },
                        &mut outcome,
                        coverage,
                    );
                    return outcome;
                }
                let value = decode_entry(g.family(), cluster, raw);
                let observation = FatAllocationObservation {
                    source_id: self.source.id(),
                    copy,
                    cluster,
                    offset,
                    raw,
                    raw_length: count as u8,
                    value,
                    kind: allocation_kind(g.family(), cluster, value, g.cluster_count()),
                };
                match visitor(observation) {
                    Err(error) => {
                        outcome.stop_reason = StopReason::DeliveryFailed(error);
                        return outcome;
                    }
                    Ok(proceed) => {
                        outcome.observations += 1;
                        outcome.last_delivered = Some(ordinal + 1);
                        if let Err(error) = coverage(CoverageEvent {
                            range: ByteRange {
                                offset: ordinal,
                                length: 1,
                            },
                            kind: CoverageKind::Inspected,
                        }) {
                            outcome.stop_reason = StopReason::DeliveryFailed(error);
                            return outcome;
                        }
                        outcome.coverage_events += 1;
                        outcome.advance(ordinal + 1);
                        if !proceed {
                            outcome.stop_reason = StopReason::CallerStop;
                            return outcome;
                        }
                    }
                }
            }
        }
        if control.cancelled() {
            outcome.stop_reason = StopReason::Cancelled;
        }
        outcome
    }
}
pub(crate) fn entry_position(family: FatFamily, cluster: u32) -> (u64, u64) {
    let n = u64::from(cluster);
    match family {
        FatFamily::Fat12 => (n + n / 2, 2),
        FatFamily::Fat16 => (n * 2, 2),
        FatFamily::Fat32 => (n * 4, 4),
    }
}
pub(crate) fn decode_entry(family: FatFamily, cluster: u32, raw: [u8; 4]) -> u32 {
    match family {
        FatFamily::Fat12 => {
            let word = u32::from(u16::from_le_bytes([raw[0], raw[1]]));
            if cluster & 1 == 0 {
                word & 0xfff
            } else {
                word >> 4
            }
        }
        FatFamily::Fat16 => u32::from(u16::from_le_bytes([raw[0], raw[1]])),
        FatFamily::Fat32 => u32::from_le_bytes(raw) & 0x0fff_ffff,
    }
}
fn boundary_stop(
    limits: ScanLimits,
    control: &dyn ScanControl,
    done: u64,
    read_size: u64,
    output_size: u64,
) -> Option<StopReason> {
    if control.cancelled() {
        Some(StopReason::Cancelled)
    } else if done >= limits.records {
        Some(StopReason::ResourceLimit("records"))
    } else if limits.memory_bytes < read_size.max(output_size) {
        Some(StopReason::ResourceLimit("memory_bytes"))
    } else if done
        .checked_add(1)
        .and_then(|n| n.checked_mul(read_size))
        .is_none_or(|bytes| bytes > limits.read_bytes)
    {
        Some(StopReason::ResourceLimit("read_bytes"))
    } else if done
        .checked_add(1)
        .and_then(|n| n.checked_mul(output_size))
        .is_none_or(|bytes| bytes > limits.output_bytes)
    {
        Some(StopReason::ResourceLimit("output_bytes"))
    } else {
        None
    }
}
fn record_read_failure(
    source: &ForensicSource,
    error: io::Error,
    range: ByteRange,
    outcome: &mut ScanOutcome,
    coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
) {
    outcome.stop_reason = match source.check_stability() {
        Err(_) => StopReason::SourceStability(error),
        Ok(()) => StopReason::Io(error),
    };
    match coverage(CoverageEvent {
        range,
        kind: CoverageKind::Unreadable,
    }) {
        Ok(()) => outcome.coverage_events += 1,
        Err(error) => outcome.stop_reason = StopReason::DeliveryFailed(error),
    }
}

/// Terminal evidence for a chain in one explicitly selected FAT copy.
#[derive(Debug)]
pub enum FatChainEnd {
    /// End-of-chain marker reached.
    End,
    /// A cluster was revisited; the repeated cluster is not delivered twice.
    Cycle(u32),
    /// Chain stopped at a free, bad, reserved or out-of-range value.
    Invalid {
        /// Cluster whose FAT entry supplied the invalid transition.
        cluster: u32,
        /// Original decoded FAT value.
        value: u32,
    },
    /// Traversal stopped before establishing a terminal chain fact.
    Unknown,
}
/// Bounded directory-chain traversal result; validity and traversal completion differ.
#[derive(Debug)]
pub struct FatDirectoryChainOutcome {
    /// Shared terminal traversal state in logical directory byte coordinates.
    pub scan: ScanOutcome,
    /// Chain terminal evidence, independent of directory entry validity.
    pub chain: FatChainEnd,
}
impl FatForensics {
    /// Scan a selected FAT copy's directory chain, retaining deleted slots and slack.
    /// The requested domain is `maximum_clusters * cluster_bytes`; a chain that
    /// ends early emits a skipped suffix rather than claiming those bytes inspected.
    /// Cycles are explicit evidence. No alternative FAT copy is silently selected.
    #[expect(
        clippy::too_many_arguments,
        reason = "independent resource, visitor and source boundaries"
    )]
    pub fn scan_directory_chain(
        &self,
        first_cluster: u32,
        copy: u8,
        maximum_clusters: u32,
        limits: ScanLimits,
        resources: &crate::fs_core::Resources,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatSlotObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> FatDirectoryChainOutcome {
        let bytes = self.geometry().cluster_bytes();
        let domain = ByteRange {
            offset: 0,
            length: u64::from(maximum_clusters) * bytes,
        };
        let mut result = FatDirectoryChainOutcome {
            scan: ScanOutcome::new(domain, "fat-directory-chain-logical-bytes")
                .with_coordinate_space(crate::forensics::CoordinateSpace::LogicalStreamBytes)
                .with_source_id(self.source.id()),
            chain: FatChainEnd::Unknown,
        };
        if copy >= self.geometry().fat_count() {
            result.scan.stop_reason = StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FAT copy out of bounds",
            ));
            return result;
        }
        if control.cancelled() || resources.cancellation.check().is_err() {
            result.scan.stop_reason = StopReason::Cancelled;
            return result;
        }
        let memory = u64::from(maximum_clusters) * 4;
        if memory.saturating_add(core::mem::size_of::<FatSlotObservation>() as u64)
            > limits.memory_bytes
        {
            result.scan.stop_reason = StopReason::ResourceLimit("memory_bytes");
            return result;
        }
        let _reservation = match resources.memory.reserve(memory) {
            Ok(reservation) => reservation,
            Err(_) => {
                result.scan.stop_reason = StopReason::ResourceLimit("shared memory");
                return result;
            }
        };
        let mut seen = alloc::vec::Vec::new();
        if seen.try_reserve_exact(maximum_clusters as usize).is_err() {
            result.scan.stop_reason = StopReason::ResourceLimit("memory allocation");
            return result;
        }
        let mut cluster = first_cluster;
        let mut terminated = false;
        let mut read_bytes = 0u64;
        let mut logical = 0u64;
        loop {
            if control.cancelled() || resources.cancellation.check().is_err() {
                result.scan.stop_reason = StopReason::Cancelled;
                return result;
            }
            if cluster < 2 || cluster > self.geometry().cluster_count() + 1 {
                result.chain = FatChainEnd::Invalid {
                    cluster,
                    value: cluster,
                };
                break;
            }
            if seen.contains(&cluster) {
                result.chain = FatChainEnd::Cycle(cluster);
                break;
            }
            if seen.len() >= maximum_clusters as usize {
                result.scan.stop_reason = StopReason::ResourceLimit("directory clusters");
                return result;
            }
            seen.push(cluster);
            let base = self.geometry().data_offset() + u64::from(cluster - 2) * bytes;
            for within in (0..bytes).step_by(32) {
                if resources.cancellation.check().is_err() {
                    result.scan.stop_reason = StopReason::Cancelled;
                    return result;
                }
                if let Some(reason) = boundary_stop(
                    limits,
                    control,
                    result.scan.observations,
                    32,
                    core::mem::size_of::<FatSlotObservation>() as u64,
                ) {
                    result.scan.stop_reason = reason;
                    return result;
                }
                if read_bytes.saturating_add(32) > limits.read_bytes {
                    result.scan.stop_reason = StopReason::ResourceLimit("read_bytes");
                    return result;
                }
                let mut raw = [0; 32];
                if let Err(error) = self.source.read_exact_at(base + within, &mut raw) {
                    record_read_failure(
                        &self.source,
                        error,
                        ByteRange {
                            offset: logical,
                            length: 32,
                        },
                        &mut result.scan,
                        coverage,
                    );
                    return result;
                }
                read_bytes += 32;
                let mut slot = FatSlotObservation::decode(base + within, logical, raw, terminated);
                slot.source_id = Some(self.source.id());
                terminated |= slot.kind == FatSlotKind::Terminator;
                let proceed = match visitor(slot) {
                    Ok(proceed) => proceed,
                    Err(error) => {
                        result.scan.stop_reason = StopReason::DeliveryFailed(error);
                        return result;
                    }
                };
                result.scan.observations += 1;
                result.scan.last_delivered = Some(logical + 32);
                if let Err(error) = coverage(CoverageEvent {
                    range: ByteRange {
                        offset: logical,
                        length: 32,
                    },
                    kind: CoverageKind::Inspected,
                }) {
                    result.scan.stop_reason = StopReason::DeliveryFailed(error);
                    return result;
                }
                result.scan.coverage_events += 1;
                logical += 32;
                result.scan.advance(logical);
                if !proceed {
                    result.scan.stop_reason = StopReason::CallerStop;
                    return result;
                }
            }
            if control.cancelled() || resources.cancellation.check().is_err() {
                result.scan.stop_reason = StopReason::Cancelled;
                return result;
            }
            let (_, count) = entry_position(self.geometry().family(), cluster);
            if read_bytes.saturating_add(count) > limits.read_bytes {
                result.scan.stop_reason = StopReason::ResourceLimit("read_bytes");
                return result;
            }
            let value = match self.volume.read_fat_entry(copy, cluster) {
                Ok(value) => value,
                Err(error) => {
                    record_read_failure(
                        &self.source,
                        error,
                        ByteRange {
                            offset: logical,
                            length: 0,
                        },
                        &mut result.scan,
                        coverage,
                    );
                    return result;
                }
            };
            read_bytes += count;
            match allocation_kind(
                self.geometry().family(),
                cluster,
                value,
                self.geometry().cluster_count(),
            ) {
                FatAllocationKind::Next(next) => cluster = next,
                FatAllocationKind::End => {
                    result.chain = FatChainEnd::End;
                    break;
                }
                _ => {
                    result.chain = FatChainEnd::Invalid { cluster, value };
                    break;
                }
            }
        }
        if result.scan.unvisited.length > 0 {
            match coverage(CoverageEvent {
                range: result.scan.unvisited,
                kind: CoverageKind::Skipped,
            }) {
                Ok(()) => {
                    result.scan.coverage_events += 1;
                    result.scan.advance(domain.length);
                }
                Err(error) => result.scan.stop_reason = StopReason::DeliveryFailed(error),
            }
        }
        result
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::forensics::{AcquisitionLease, NeverCancel, SourceIdentity};
    struct Image(alloc::vec::Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let data = self
                .0
                .get(offset as usize..offset as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            out.copy_from_slice(data);
            Ok(())
        }
    }
    fn fixture() -> (alloc::vec::Vec<u8>, usize) {
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
        (bytes, 19 * 512)
    }
    fn open(bytes: alloc::vec::Vec<u8>) -> FatForensics {
        let len = bytes.len() as u64;
        FatForensics::open(
            ForensicSource::new(
                Arc::new(Image(bytes)),
                SourceIdentity {
                    acquisition: "fixture".into(),
                    source: "memory".into(),
                    stability_provider: "held".into(),
                },
                Arc::new(AcquisitionLease::default()),
                ByteRange {
                    offset: 0,
                    length: len,
                },
                alloc::vec![],
            )
            .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn deleted_lfn_and_post_terminator_are_lossless() {
        let (mut bytes, root) = fixture();
        bytes[root] = 0xe5;
        bytes[root + 11] = 0x0f;
        bytes[root + 1..root + 3].copy_from_slice(&0xd800u16.to_le_bytes());
        bytes[root + 32] = 0xe5;
        bytes[root + 32 + 11] = 0x20;
        bytes[root + 96] = b'A';
        bytes[root + 96 + 11] = 0x10;
        let volume = open(bytes);
        let mut slots = alloc::vec::Vec::new();
        let mut coverage = alloc::vec::Vec::new();
        let outcome = volume.scan_directory_region(
            ByteRange {
                offset: root as u64,
                length: 128,
            },
            ScanLimits::default(),
            &NeverCancel,
            &mut |slot| {
                slots.push(slot);
                Ok(true)
            },
            &mut |event| {
                coverage.push(event);
                Ok(())
            },
        );
        assert!(outcome.is_complete());
        assert_eq!(slots[0].kind, FatSlotKind::DeletedLongName);
        assert_eq!(slots[0].long_name_units().unwrap()[0], 0xd800);
        assert_eq!(slots[1].alias().unwrap()[0], 0xe5);
        assert!(!slots[2].post_terminator);
        assert!(slots[3].post_terminator);
        assert_eq!(slots[3].offset, root as u64 + 96);
        assert_eq!(coverage.len(), 4);
    }
    #[test]
    fn broken_lfn_fields_remain_raw_fragments_without_reconstructed_aliases() {
        let (mut bytes, root) = fixture();
        let mut fragment = [0xff; 32];
        fragment[0] = 0x47; // Missing ordinals one through six.
        fragment[11] = 0x0f;
        fragment[12] = 9; // Invalid native LFN type.
        fragment[13] = 0xa5; // No matching short alias checksum.
        fragment[26..28].copy_from_slice(&7u16.to_le_bytes());
        fragment[1..3].copy_from_slice(&0xdc00u16.to_le_bytes());
        bytes[root..root + 32].copy_from_slice(&fragment);
        let volume = open(bytes);
        let mut observations = alloc::vec::Vec::new();
        let outcome = volume.scan_directory_region(
            ByteRange {
                offset: root as u64,
                length: 64,
            },
            ScanLimits::default(),
            &NeverCancel,
            &mut |slot| {
                observations.push(slot);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(outcome.is_complete());
        assert_eq!(observations[0].raw, fragment);
        assert_eq!(observations[0].kind, FatSlotKind::LongName);
        assert_eq!(observations[0].long_name_units().unwrap()[0], 0xdc00);
        assert_eq!(observations[0].alias(), None);
        assert_eq!(observations[1].kind, FatSlotKind::Terminator);
    }
    #[test]
    fn fat12_copy_values_remain_independent_and_raw() {
        let (mut bytes, _) = fixture();
        bytes[515..518].copy_from_slice(&[0xbc, 0x3a, 0x12]);
        bytes[512 + 9 * 512 + 3..512 + 9 * 512 + 6].copy_from_slice(&[0, 0, 0]);
        let volume = open(bytes);
        let mut values = alloc::vec::Vec::new();
        let outcome = volume.scan_allocation(
            ScanLimits::default(),
            &NeverCancel,
            &mut |entry| {
                if entry.cluster == 2 || entry.cluster == 3 {
                    values.push(entry);
                }
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(outcome.is_complete());
        assert_eq!(values[0].value, 0xabc);
        assert_eq!(values[1].value, 0x123);
        assert_eq!(values[2].value, 0);
        assert_eq!(values[0].offset + 1, values[1].offset);
    }
    #[test]
    fn no_work_and_delivery_failure_are_incomplete() {
        let (bytes, root) = fixture();
        let volume = open(bytes);
        let range = ByteRange {
            offset: root as u64,
            length: 32,
        };
        let zero = volume.scan_directory_region(
            range,
            ScanLimits {
                records: 0,
                ..ScanLimits::default()
            },
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            zero.stop_reason,
            StopReason::ResourceLimit("records")
        ));
        assert_eq!(zero.observations, 0);
        assert_eq!(zero.unvisited, range);
        let failed = volume.scan_directory_region(
            range,
            ScanLimits::default(),
            &NeverCancel,
            &mut |_| Err(io::Error::other("sink")),
            &mut |_| Ok(()),
        );
        assert!(matches!(failed.stop_reason, StopReason::DeliveryFailed(_)));
        assert!(!failed.is_complete());
    }
    #[test]
    fn directory_cycle_is_evidence_and_does_not_repeat_slots() {
        let (mut bytes, _) = fixture();
        bytes[515..517].copy_from_slice(&[2, 0]);
        let volume = open(bytes);
        let resources = crate::fs_core::Resources {
            memory: crate::fs_core::Budget::new(4096),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let result = volume.scan_directory_chain(
            2,
            0,
            4,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(result.chain, FatChainEnd::Cycle(2)));
        assert_eq!(result.scan.observations, 16);
        assert!(result.scan.is_complete());
    }
    #[test]
    fn ownership_cross_links_and_orphans_require_complete_namespace() {
        let (mut bytes, root) = fixture();
        bytes[515..518].copy_from_slice(&[0xff, 0xff, 0xff]);
        for index in 0..2 {
            let at = root + index * 32;
            bytes[at..at + 11].fill(b' ');
            bytes[at] = b'A' + index as u8;
            bytes[at + 11] = 0x20;
            bytes[at + 26..at + 28].copy_from_slice(&2u16.to_le_bytes());
            bytes[at + 28..at + 32].copy_from_slice(&1u32.to_le_bytes());
        }
        let fat = bytes[512..512 + 9 * 512].to_vec();
        bytes[512 + 9 * 512..512 + 18 * 512].copy_from_slice(&fat);
        let resources = crate::fs_core::Resources {
            memory: crate::fs_core::Budget::new(1 << 20),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let mut observations = alloc::vec::Vec::new();
        let volume = open(bytes.clone());
        let result = volume.scan_ownership(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |item| {
                observations.push(item);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(result.namespace_complete && result.allocation_complete);
        assert!(
            observations
                .iter()
                .any(|item| matches!(item, FatOwnershipObservation::CrossLink { cluster: 2, .. }))
        );
        assert!(
            observations
                .iter()
                .any(|item| matches!(item, FatOwnershipObservation::Orphan { cluster: 3, .. }))
        );
        bytes[515] = 0;
        bytes[516] &= 0xf0;
        let fat = bytes[512..512 + 9 * 512].to_vec();
        bytes[512 + 9 * 512..512 + 18 * 512].copy_from_slice(&fat);
        observations.clear();
        let result = open(bytes).scan_ownership(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |item| {
                observations.push(item);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(!result.namespace_complete);
        assert!(result.allocation_complete);
        assert!(
            !observations
                .iter()
                .any(|item| matches!(item, FatOwnershipObservation::Orphan { .. }))
        );
    }
    #[test]
    fn fat32_root_chain_keeps_slack_across_cluster_boundaries() {
        let mut bytes = alloc::vec![0; 70000 * 512];
        bytes[11..13].copy_from_slice(&512u16.to_le_bytes());
        bytes[13] = 1;
        bytes[14..16].copy_from_slice(&32u16.to_le_bytes());
        bytes[16] = 2;
        bytes[21] = 0xf8;
        bytes[32..36].copy_from_slice(&70000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&600u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&2u32.to_le_bytes());
        bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
        bytes[50..52].copy_from_slice(&6u16.to_le_bytes());
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        bytes[32 * 512 + 8..32 * 512 + 12].copy_from_slice(&3u32.to_le_bytes());
        bytes[32 * 512 + 12..32 * 512 + 16].copy_from_slice(&0xafff_ffffu32.to_le_bytes());
        let data = (32 + 1200) * 512;
        bytes[data + 512] = b'X';
        bytes[data + 512 + 11] = 0x20;
        let volume = open(bytes);
        let resources = crate::fs_core::Resources {
            memory: crate::fs_core::Budget::new(4096),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let mut slots = alloc::vec::Vec::new();
        let result = volume.scan_directory_chain(
            2,
            0,
            2,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |slot| {
                slots.push(slot);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(result.chain, FatChainEnd::End));
        assert!(result.scan.is_complete());
        assert_eq!(slots[16].offset, data as u64 + 512);
        assert_eq!(slots[16].directory_offset, 512);
        assert!(slots[16].post_terminator);
    }
    #[test]
    fn mirrored_disagreement_keeps_ownership_unknown_and_preserves_source_scope() {
        let (mut bytes, _) = fixture();
        bytes[515..517].copy_from_slice(&[0xff, 0x0f]);
        let volume = open(bytes);
        let resources = crate::fs_core::Resources {
            memory: crate::fs_core::Budget::new(1 << 20),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let mut observations = Vec::new();
        let result = volume.scan_ownership(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |item| {
                observations.push(item);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(result.scan.is_complete() && result.allocation_complete);
        assert!(!result.namespace_complete);
        assert_eq!(result.scan.source_id, Some(volume.source().id()));
        assert!(observations.iter().any(|item| matches!(item, FatOwnershipObservation::MirrorDisagreement { source_id, cluster: 2, copy: 1, selected_value: 0xfff, other_value: 0 } if *source_id == volume.source().id())));
        assert!(
            !observations
                .iter()
                .any(|item| matches!(item, FatOwnershipObservation::Orphan { .. }))
        );
    }
    #[test]
    fn nonintegral_fixed_root_profile_is_explicitly_rejected() {
        let (mut bytes, _) = fixture();
        bytes[17..19].copy_from_slice(&17u16.to_le_bytes());
        let length = bytes.len() as u64;
        let source = ForensicSource::new(
            Arc::new(Image(bytes)),
            SourceIdentity {
                acquisition: "fixture".into(),
                source: "nonintegral-root".into(),
                stability_provider: "held".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange { offset: 0, length },
            vec![],
        )
        .unwrap();
        match FatForensics::open(source) {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("integral fixed root"));
            }
            Ok(_) => panic!("unsupported root profile must be explicit"),
        }
    }
    #[test]
    fn malformed_alias_and_length_mismatch_cannot_establish_orphans() {
        for malformed_alias in [true, false] {
            let (mut bytes, root) = fixture();
            bytes[515..518].copy_from_slice(&[0xff, 0xff, 0xff]);
            bytes[root..root + 11].copy_from_slice(if malformed_alias {
                b".          "
            } else {
                b"FILE    BIN"
            });
            bytes[root + 11] = 0x20;
            bytes[root + 26..root + 28].copy_from_slice(&2u16.to_le_bytes());
            bytes[root + 28..root + 32].copy_from_slice(&600u32.to_le_bytes());
            let volume = open(bytes);
            let resources = crate::fs_core::Resources {
                memory: crate::fs_core::Budget::new(1 << 20),
                cancellation: crate::fs_core::Cancellation::default(),
            };
            let mut observations = Vec::new();
            let result = volume.scan_ownership(
                ScanLimits::default(),
                &resources,
                &NeverCancel,
                &mut |item| {
                    observations.push(item);
                    Ok(true)
                },
                &mut |_| Ok(()),
            );
            assert!(!result.namespace_complete);
            assert!(result.allocation_complete);
            assert!(
                !observations
                    .iter()
                    .any(|item| matches!(item, FatOwnershipObservation::Orphan { .. }))
            );
            if !malformed_alias {
                assert!(observations.iter().any(|item| matches!(
                    item,
                    FatOwnershipObservation::LengthMismatch {
                        expected_clusters: 2,
                        observed_clusters: 1,
                        ..
                    }
                )));
            }
        }
    }
    #[test]
    fn chain_cancellation_after_final_slot_precedes_fat_metadata_read() {
        let (bytes, _) = fixture();
        let length = bytes.len() as u64;
        struct Bytes(Vec<u8>);
        impl ReadAt for Bytes {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
                out.copy_from_slice(&self.0[offset as usize..offset as usize + out.len()]);
                Ok(())
            }
        }
        let source = ForensicSource::new(
            Arc::new(Bytes(bytes)),
            SourceIdentity {
                acquisition: "fixture".into(),
                source: "missing FAT".into(),
                stability_provider: "held".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange { offset: 0, length },
            vec![ByteRange {
                offset: 515,
                length: 2,
            }],
        )
        .unwrap();
        let volume = FatForensics::open(source).unwrap();
        let resources = crate::fs_core::Resources {
            memory: crate::fs_core::Budget::new(4096),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let mut seen = 0;
        let result = volume.scan_directory_chain(
            2,
            0,
            1,
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |_| {
                seen += 1;
                if seen == 16 {
                    resources.cancellation.cancel();
                }
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(result.scan.stop_reason, StopReason::Cancelled));
        assert!(matches!(result.chain, FatChainEnd::Unknown));
        assert_eq!(result.scan.observations, 16);
    }
    #[test]
    fn cancellation_from_last_directory_delivery_is_terminal() {
        let (bytes, root) = fixture();
        let volume = open(bytes);
        let cancelled = core::sync::atomic::AtomicBool::new(false);
        let outcome = volume.scan_directory_region(
            ByteRange {
                offset: root as u64,
                length: 32,
            },
            ScanLimits::default(),
            &cancelled,
            &mut |_| {
                cancelled.store(true, core::sync::atomic::Ordering::Release);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        assert_eq!(outcome.observations, 1);
        assert_eq!(outcome.unvisited.length, 0);
    }
    #[test]
    fn fat16_fixed_root_preserves_raw_timestamp_edges() {
        let (mut bytes, _) = fixture();
        bytes.resize(10000 * 512, 0);
        bytes[17..19].copy_from_slice(&512u16.to_le_bytes());
        bytes[19..21].copy_from_slice(&10000u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&40u16.to_le_bytes());
        let root = 81 * 512;
        bytes[root] = 0xe5;
        bytes[root + 11] = 0x20;
        bytes[root + 13..root + 20].copy_from_slice(&[199, 0xff, 0xff, 0, 0, 0xff, 0xff]);
        let volume = open(bytes);
        assert_eq!(volume.geometry().family(), FatFamily::Fat16);
        assert_eq!(volume.geometry().root_offset(), Some(root as u64));
        let mut raw = None;
        let outcome = volume.scan_directory_region(
            ByteRange {
                offset: root as u64,
                length: 32,
            },
            ScanLimits::default(),
            &NeverCancel,
            &mut |slot| {
                raw = Some(slot.raw);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(outcome.is_complete());
        assert_eq!(&raw.unwrap()[13..20], &[199, 0xff, 0xff, 0, 0, 0xff, 0xff]);
    }
}

/// Current namespace ownership evidence; never a historical reuse claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FatOwnershipObservation {
    /// A validated live alias was reached in the current namespace, even when empty.
    LiveAlias {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Alias slot volume byte offset, distinct from cluster coordinates.
        alias_offset: u64,
    },
    /// Current live alias chain claims a cluster.
    Owner {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Claimed data cluster.
        cluster: u32,
        /// Alias slot volume byte offset; FAT32 root uses `None`.
        alias_offset: Option<u64>,
    },
    /// Two current alias chains claim the same data cluster.
    CrossLink {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Shared cluster.
        cluster: u32,
        /// First observed alias, or FAT32 root.
        first: Option<u64>,
        /// Additional observed alias, or FAT32 root.
        second: Option<u64>,
    },
    /// Allocation has no observed live owner after a complete namespace scan.
    Orphan {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Allocated data cluster.
        cluster: u32,
        /// Current selected-copy allocation value.
        value: u32,
    },
    /// Mirrored current FAT copies disagree; ownership conclusions stay unknown.
    MirrorDisagreement {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Data cluster whose allocation entries differ.
        cluster: u32,
        /// Differing FAT copy compared against copy zero.
        copy: u8,
        /// Current copy-zero meaningful value.
        selected_value: u32,
        /// Differing meaningful value, excluding FAT32 reserved high bits.
        other_value: u32,
    },
    /// A live alias chain length disagrees with its declared file length.
    LengthMismatch {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Alias slot volume byte offset.
        alias_offset: u64,
        /// Alias's first cluster, in the ownership outcome coordinate space.
        cluster: u32,
        /// Clusters required by the declared byte length.
        expected_clusters: u64,
        /// Distinct valid clusters actually visited in its chain.
        observed_clusters: u64,
    },
    /// A chain cycles or stops at an invalid marker; ownership remains incomplete.
    InvalidChain {
        /// Exact forensic source view; this token is not a content digest.
        source_id: crate::forensics::SourceId,
        /// Alias slot, or FAT32 root.
        alias_offset: Option<u64>,
        /// Cluster at the invalid transition or repeated cluster.
        cluster: u32,
    },
}
/// Ownership completion independently identifies namespace and allocation coverage.
#[derive(Debug)]
pub struct FatOwnershipOutcome {
    /// Overall bounded traversal, in data-cluster ordinal coordinates.
    pub scan: ScanOutcome,
    /// Every reachable live directory was inspected, including chain validation.
    pub namespace_complete: bool,
    /// Every current selected-copy data allocation entry was inspected.
    pub allocation_complete: bool,
}
impl FatForensics {
    /// Inventory current live namespace ownership with tolerant chain diagnostics.
    /// Deleted slots, LFN fragments and post-terminator bytes never claim ownership.
    /// Orphans are emitted only when every reachable directory and live chain was
    /// fully inspected. An invalid chain suppresses all orphan conclusions.
    /// `limits.records` bounds slots, chain transitions and allocation entries
    /// together; scratch allocation is reserved from the shared budget.
    pub fn scan_ownership(
        &self,
        limits: ScanLimits,
        resources: &crate::fs_core::Resources,
        control: &dyn ScanControl,
        visitor: &mut dyn FnMut(FatOwnershipObservation) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> FatOwnershipOutcome {
        let g = self.geometry();
        let count = g.cluster_count() as usize;
        let mut result = FatOwnershipOutcome {
            scan: ScanOutcome::new(
                ByteRange {
                    offset: 2,
                    length: count as u64,
                },
                "fat-current-ownership-cluster-ordinals",
            )
            .with_coordinate_space(crate::forensics::CoordinateSpace::ClusterOrdinals)
            .with_source_id(self.source.id()),
            namespace_complete: false,
            allocation_complete: false,
        };
        if control.cancelled() || resources.cancellation.check().is_err() {
            result.scan.stop_reason = StopReason::Cancelled;
            return result;
        }
        // The dense owner map, per-chain epochs, and bounded directory queue
        // reserve their maximum storage before reading any evidence.
        let memory = (count as u64 + 2).saturating_mul(80);
        if memory > limits.memory_bytes {
            result.scan.stop_reason = StopReason::ResourceLimit("memory_bytes");
            return result;
        }
        let _reservation = match resources.memory.reserve(memory) {
            Ok(reservation) => reservation,
            Err(_) => {
                result.scan.stop_reason = StopReason::ResourceLimit("shared memory");
                return result;
            }
        };
        let mut owners = alloc::vec::Vec::new();
        let mut epochs = alloc::vec::Vec::new();
        let mut directories = alloc::vec::Vec::new();
        let mut allocation = alloc::vec::Vec::new();
        if allocation.try_reserve_exact(count + 2).is_err()
            || owners.try_reserve_exact(count + 2).is_err()
            || epochs.try_reserve_exact(count + 2).is_err()
            || directories.try_reserve_exact(count + 1).is_err()
        {
            result.scan.stop_reason = StopReason::ResourceLimit("memory allocation");
            return result;
        }
        owners.resize(count + 2, None::<Option<u64>>);
        epochs.resize(count + 2, 0u64);
        allocation.resize(count + 2, 0u32);
        directories.push((g.root_cluster(), None));
        let mut state = OwnershipWork {
            limits,
            resources,
            control,
            records: 0,
            read_bytes: 0,
            output_bytes: 0,
        };
        let mut epoch = 0u64;
        let mut valid = true;
        let copy = g.active_fat().unwrap_or(0);
        // Inspect all current mirrored entries before making any orphan claim.
        // The additional four-byte map fits the reserved 80 bytes per cluster.
        for cluster in 2..g.cluster_count() + 2 {
            let (_, size) = entry_position(g.family(), cluster);
            if let Err(reason) = state.boundary(size) {
                result.scan.stop_reason = reason;
                return result;
            }
            let value = match self.volume.read_fat_entry(copy, cluster) {
                Ok(value) => value,
                Err(error) => {
                    record_read_failure(
                        &self.source,
                        error,
                        ByteRange {
                            offset: u64::from(cluster),
                            length: 1,
                        },
                        &mut result.scan,
                        coverage,
                    );
                    return result;
                }
            };
            allocation[cluster as usize] = value;
            if g.active_fat().is_none() {
                for other_copy in 1..g.fat_count() {
                    if let Err(reason) = state.boundary(size) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    let other_value = match self.volume.read_fat_entry(other_copy, cluster) {
                        Ok(value) => value,
                        Err(error) => {
                            record_read_failure(
                                &self.source,
                                error,
                                ByteRange {
                                    offset: u64::from(cluster),
                                    length: 1,
                                },
                                &mut result.scan,
                                coverage,
                            );
                            return result;
                        }
                    };
                    if value != other_value {
                        valid = false;
                        if let Err(reason) = deliver_owner(
                            FatOwnershipObservation::MirrorDisagreement {
                                source_id: self.source.id(),
                                cluster,
                                copy: other_copy,
                                selected_value: value,
                                other_value,
                            },
                            &mut state,
                            &mut result.scan,
                            visitor,
                        ) {
                            result.scan.stop_reason = reason;
                            return result;
                        }
                    }
                }
            }
            if let Err(error) = coverage(CoverageEvent {
                range: ByteRange {
                    offset: u64::from(cluster),
                    length: 1,
                },
                kind: CoverageKind::Inspected,
            }) {
                result.scan.stop_reason = StopReason::DeliveryFailed(error);
                return result;
            }
            result.scan.coverage_events += 1;
        }
        result.allocation_complete = true;
        while let Some((start, alias)) = directories.pop() {
            if let Some(first) =
                start.filter(|first| *first >= 2 && *first <= g.cluster_count() + 1)
                && let Some(previous) = owners[first as usize]
            {
                valid = false;
                if let Err(reason) = deliver_owner(
                    FatOwnershipObservation::CrossLink {
                        source_id: self.source.id(),
                        cluster: first,
                        first: previous,
                        second: alias,
                    },
                    &mut state,
                    &mut result.scan,
                    visitor,
                ) {
                    result.scan.stop_reason = reason;
                    return result;
                }
                continue;
            }

            let mut regions = alloc::vec::Vec::new();
            if regions.try_reserve_exact(count + 1).is_err() {
                result.scan.stop_reason = StopReason::ResourceLimit("memory allocation");
                return result;
            }
            // Region vector is included by the conservative 80-byte-per-cluster reservation.
            if let Some(first) = start {
                epoch += 1;
                let mut cluster = first;
                loop {
                    if let Err(reason) = state.boundary(0) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    if cluster < 2
                        || cluster > g.cluster_count() + 1
                        || epochs[cluster as usize] == epoch
                    {
                        valid = false;
                        if let Err(reason) = deliver_owner(
                            FatOwnershipObservation::InvalidChain {
                                source_id: self.source.id(),
                                alias_offset: alias,
                                cluster,
                            },
                            &mut state,
                            &mut result.scan,
                            visitor,
                        ) {
                            result.scan.stop_reason = reason;
                            return result;
                        }
                        break;
                    }
                    epochs[cluster as usize] = epoch;
                    if let Some(first_owner) = owners[cluster as usize] {
                        if let Err(reason) = deliver_owner(
                            FatOwnershipObservation::CrossLink {
                                source_id: self.source.id(),
                                cluster,
                                first: first_owner,
                                second: alias,
                            },
                            &mut state,
                            &mut result.scan,
                            visitor,
                        ) {
                            result.scan.stop_reason = reason;
                            return result;
                        }
                        // A directory reached through another alias must not recursively
                        // enumerate itself forever; its claimed chain is still observed.
                    } else {
                        owners[cluster as usize] = Some(alias);
                    }
                    if let Err(reason) = deliver_owner(
                        FatOwnershipObservation::Owner {
                            source_id: self.source.id(),
                            cluster,
                            alias_offset: alias,
                        },
                        &mut state,
                        &mut result.scan,
                        visitor,
                    ) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    regions.push((
                        g.data_offset() + u64::from(cluster - 2) * g.cluster_bytes(),
                        g.cluster_bytes(),
                    ));
                    let size = 0;
                    if let Err(reason) = state.boundary(size) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    let value = allocation[cluster as usize];
                    match allocation_kind(g.family(), cluster, value, g.cluster_count()) {
                        FatAllocationKind::Next(next) => cluster = next,
                        FatAllocationKind::End => break,
                        _ => {
                            valid = false;
                            if let Err(reason) = deliver_owner(
                                FatOwnershipObservation::InvalidChain {
                                    source_id: self.source.id(),
                                    alias_offset: alias,
                                    cluster,
                                },
                                &mut state,
                                &mut result.scan,
                                visitor,
                            ) {
                                result.scan.stop_reason = reason;
                                return result;
                            }
                            break;
                        }
                    }
                }
            } else {
                // The BPB counts namespace entries, while root_bytes rounds to
                // sectors. Padding after a full nonaligned fixed root is slack.
                let root_entries = u16::from_le_bytes([self.boot[17], self.boot[18]]);
                regions.push((g.root_offset().unwrap_or(0), u64::from(root_entries) * 32));
            }
            let mut terminated = false;
            for (base, length) in regions {
                for within in (0..length).step_by(32) {
                    if let Err(reason) = state.boundary(32) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    let mut raw = [0; 32];
                    if let Err(error) = self.source.read_exact_at(base + within, &mut raw) {
                        result.scan.stop_reason = read_stop(&self.source, error);
                        return result;
                    }
                    let slot = FatSlotObservation::decode(base + within, within, raw, terminated);
                    terminated |= slot.kind == FatSlotKind::Terminator;
                    if terminated
                        || !matches!(slot.kind, FatSlotKind::File | FatSlotKind::Directory)
                    {
                        continue;
                    }
                    let low = u16::from_le_bytes([raw[26], raw[27]]) as u32;
                    let high = u16::from_le_bytes([raw[20], raw[21]]) as u32;
                    let first = if g.family() == FatFamily::Fat32 {
                        (high << 16) | low
                    } else {
                        low
                    };
                    if raw[11] & 0xc0 != 0
                        || (g.family() != FatFamily::Fat32 && high != 0)
                        || (g.family() == FatFamily::Fat32 && high & 0xf000 != 0)
                    {
                        valid = false;
                        continue;
                    }

                    if raw[0] == b'.' {
                        let dot = &raw[..11] == b".          "
                            && slot.kind == FatSlotKind::Directory
                            && start == Some(first);
                        let parent = &raw[..11] == b"..         "
                            && slot.kind == FatSlotKind::Directory
                            && start.is_some()
                            && (first == 0 || (2..=g.cluster_count() + 1).contains(&first));
                        if !dot && !parent {
                            valid = false;
                        }
                        continue;
                    }
                    if !short_alias_valid(&raw[..11]) {
                        valid = false;
                        continue;
                    }
                    if slot.kind == FatSlotKind::Directory && raw[28..32] != [0; 4] {
                        valid = false;
                        continue;
                    }
                    if let Err(reason) = deliver_owner(
                        FatOwnershipObservation::LiveAlias {
                            source_id: self.source.id(),
                            alias_offset: slot.offset,
                        },
                        &mut state,
                        &mut result.scan,
                        visitor,
                    ) {
                        result.scan.stop_reason = reason;
                        return result;
                    }
                    if first == 0 && slot.kind == FatSlotKind::File && raw[28..32] == [0; 4] {
                        continue;
                    }
                    if slot.kind == FatSlotKind::Directory {
                        if directories.len() >= count {
                            valid = false;
                            continue;
                        }
                        directories.push((Some(first), Some(slot.offset)));
                    } else {
                        epoch += 1;
                        let mut cluster = first;
                        let mut chain_clusters = 0u64;
                        loop {
                            let size = 0;
                            if let Err(reason) = state.boundary(size) {
                                result.scan.stop_reason = reason;
                                return result;
                            }
                            if cluster < 2
                                || cluster > g.cluster_count() + 1
                                || epochs[cluster as usize] == epoch
                            {
                                valid = false;
                                if let Err(reason) = deliver_owner(
                                    FatOwnershipObservation::InvalidChain {
                                        source_id: self.source.id(),
                                        alias_offset: Some(slot.offset),
                                        cluster,
                                    },
                                    &mut state,
                                    &mut result.scan,
                                    visitor,
                                ) {
                                    result.scan.stop_reason = reason;
                                    return result;
                                }
                                break;
                            }
                            epochs[cluster as usize] = epoch;
                            chain_clusters += 1;
                            if let Some(first_owner) = owners[cluster as usize] {
                                if let Err(reason) = deliver_owner(
                                    FatOwnershipObservation::CrossLink {
                                        source_id: self.source.id(),
                                        cluster,
                                        first: first_owner,
                                        second: Some(slot.offset),
                                    },
                                    &mut state,
                                    &mut result.scan,
                                    visitor,
                                ) {
                                    result.scan.stop_reason = reason;
                                    return result;
                                }
                            } else {
                                owners[cluster as usize] = Some(Some(slot.offset));
                            }
                            if let Err(reason) = deliver_owner(
                                FatOwnershipObservation::Owner {
                                    source_id: self.source.id(),
                                    cluster,
                                    alias_offset: Some(slot.offset),
                                },
                                &mut state,
                                &mut result.scan,
                                visitor,
                            ) {
                                result.scan.stop_reason = reason;
                                return result;
                            }
                            let value = allocation[cluster as usize];
                            match allocation_kind(g.family(), cluster, value, g.cluster_count()) {
                                FatAllocationKind::Next(next) => cluster = next,
                                FatAllocationKind::End => break,
                                _ => {
                                    valid = false;
                                    if let Err(reason) = deliver_owner(
                                        FatOwnershipObservation::InvalidChain {
                                            source_id: self.source.id(),
                                            alias_offset: Some(slot.offset),
                                            cluster,
                                        },
                                        &mut state,
                                        &mut result.scan,
                                        visitor,
                                    ) {
                                        result.scan.stop_reason = reason;
                                        return result;
                                    }
                                    break;
                                }
                            }
                        }
                        let length = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);
                        let expected_clusters = u64::from(length).div_ceil(g.cluster_bytes());
                        if chain_clusters != expected_clusters {
                            valid = false;
                            if let Err(reason) = deliver_owner(
                                FatOwnershipObservation::LengthMismatch {
                                    source_id: self.source.id(),
                                    alias_offset: slot.offset,
                                    cluster: first,
                                    expected_clusters,
                                    observed_clusters: chain_clusters,
                                },
                                &mut state,
                                &mut result.scan,
                                visitor,
                            ) {
                                result.scan.stop_reason = reason;
                                return result;
                            }
                        }
                    }
                }
            }
        }
        result.namespace_complete = valid;
        for cluster in 2..g.cluster_count() + 2 {
            let size = 0;
            if let Err(reason) = state.boundary(size) {
                result.scan.stop_reason = reason;
                return result;
            }
            let value = allocation[cluster as usize];
            if valid
                && owners[cluster as usize].is_none()
                && matches!(
                    allocation_kind(g.family(), cluster, value, g.cluster_count()),
                    FatAllocationKind::Next(_) | FatAllocationKind::End
                )
                && let Err(reason) = deliver_owner(
                    FatOwnershipObservation::Orphan {
                        source_id: self.source.id(),
                        cluster,
                        value,
                    },
                    &mut state,
                    &mut result.scan,
                    visitor,
                )
            {
                result.scan.stop_reason = reason;
                return result;
            }
            if let Err(error) = coverage(CoverageEvent {
                range: ByteRange {
                    offset: u64::from(cluster),
                    length: 1,
                },
                kind: CoverageKind::Inspected,
            }) {
                result.scan.stop_reason = StopReason::DeliveryFailed(error);
                return result;
            }
            result.scan.coverage_events += 1;
            result.scan.advance(u64::from(cluster) + 1);
        }
        result.allocation_complete = true;
        if control.cancelled() || resources.cancellation.check().is_err() {
            result.scan.stop_reason = StopReason::Cancelled;
        }
        result
    }
}
struct OwnershipWork<'a> {
    limits: ScanLimits,
    resources: &'a crate::fs_core::Resources,
    control: &'a dyn ScanControl,
    records: u64,
    read_bytes: u64,
    output_bytes: u64,
}
impl OwnershipWork<'_> {
    fn boundary(&mut self, bytes: u64) -> Result<(), StopReason> {
        if self.control.cancelled() || self.resources.cancellation.check().is_err() {
            return Err(StopReason::Cancelled);
        }
        if self.records >= self.limits.records {
            return Err(StopReason::ResourceLimit("records"));
        }
        if self.read_bytes.saturating_add(bytes) > self.limits.read_bytes {
            return Err(StopReason::ResourceLimit("read_bytes"));
        }
        self.records += 1;
        self.read_bytes += bytes;
        Ok(())
    }
}
fn deliver_owner(
    observation: FatOwnershipObservation,
    state: &mut OwnershipWork<'_>,
    outcome: &mut ScanOutcome,
    visitor: &mut dyn FnMut(FatOwnershipObservation) -> io::Result<bool>,
) -> Result<(), StopReason> {
    let size = core::mem::size_of::<FatOwnershipObservation>() as u64;
    if state.output_bytes.saturating_add(size) > state.limits.output_bytes {
        return Err(StopReason::ResourceLimit("output_bytes"));
    }
    let delivered_cluster = match &observation {
        FatOwnershipObservation::LiveAlias { .. } => None,
        FatOwnershipObservation::Owner { cluster, .. }
        | FatOwnershipObservation::CrossLink { cluster, .. }
        | FatOwnershipObservation::Orphan { cluster, .. }
        | FatOwnershipObservation::InvalidChain { cluster, .. }
        | FatOwnershipObservation::LengthMismatch { cluster, .. }
        | FatOwnershipObservation::MirrorDisagreement { cluster, .. } => Some(*cluster),
    };
    let proceed = visitor(observation).map_err(StopReason::DeliveryFailed)?;
    if let Some(cluster) = delivered_cluster {
        outcome.last_delivered = Some(u64::from(cluster));
    }
    state.output_bytes += size;
    outcome.observations += 1;
    if !proceed {
        return Err(StopReason::CallerStop);
    }
    Ok(())
}

fn read_stop(source: &ForensicSource, error: io::Error) -> StopReason {
    match source.check_stability() {
        Ok(()) => StopReason::Io(error),
        Err(_) => StopReason::SourceStability(error),
    }
}

fn short_alias_valid(alias: &[u8]) -> bool {
    if alias[0] == b' ' {
        return false;
    }
    for range in [0..8, 8..11] {
        let mut padded = false;
        for index in range {
            let byte = alias[index];
            if byte == b' ' {
                padded = true;
                continue;
            }
            if padded
                || (byte < 0x20 && !(index == 0 && byte == 0x05))
                || b"\"*+,./:;<=>?[\\]|".contains(&byte)
            {
                return false;
            }
        }
    }
    true
}
