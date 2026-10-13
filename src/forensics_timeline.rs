//! Provenance-preserving timestamp events, independent of journals and replay.
//! Names/parents remain native record context; this module does not invent paths.
use crate::{
    forensics::{
        ByteRange, CoverageEvent, CoverageKind, ScanControl, ScanLimits, ScanOutcome,
        SourceIdentity, StopReason,
    },
    forensics_fat::{FatSlotKind, FatSlotObservation},
    forensics_ntfs::SlotObservation,
    forensics_time::{self, TimestampEvidence},
    io,
};

/// Native timestamp meaning, preserving the two independent NTFS timestamp sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// NTFS STANDARD_INFORMATION creation.
    NtfsStandardCreated,
    /// NTFS STANDARD_INFORMATION data modification.
    NtfsStandardModified,
    /// NTFS STANDARD_INFORMATION record change.
    NtfsStandardChanged,
    /// NTFS STANDARD_INFORMATION access.
    NtfsStandardAccessed,
    /// NTFS FILE_NAME creation.
    NtfsNameCreated,
    /// NTFS FILE_NAME data modification.
    NtfsNameModified,
    /// NTFS FILE_NAME record change.
    NtfsNameChanged,
    /// NTFS FILE_NAME access.
    NtfsNameAccessed,
    /// FAT creation, including its native subsecond field.
    FatCreated,
    /// FAT last access date, with day precision.
    FatAccessed,
    /// FAT last modification, with two-second precision.
    FatModified,
}
/// Exact native timestamp encoding and its explicit interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeValue {
    /// Eight-byte NTFS FILETIME.
    Filetime(TimestampEvidence<8>),
    /// FAT subsecond byte followed by packed time/date.
    FatCreation(TimestampEvidence<5>),
    /// FAT packed access date.
    FatAccess(TimestampEvidence<2>),
    /// FAT packed modification time/date.
    FatModification(TimestampEvidence<4>),
}
/// One timestamp observation. Neither valid calendar bits nor current allocation
/// authenticate an event or resolve a unique historical path.
pub struct TimestampObservation<'a> {
    /// Opaque bounded source-view identity; absent for detached decoding.
    pub source_id: Option<crate::forensics::SourceId>,
    /// Acquisition identity, explicitly separate from content digests.
    pub source: &'a SourceIdentity,
    /// Exact field range in the logical MFT stream or FAT volume, per scan profile.
    pub evidence: ByteRange,
    /// Physical volume fragments carrying the complete source record/slot.
    /// Empty means unavailable; logical MFT offsets never imply contiguity.
    pub record_volume_fragments: &'a [ByteRange],
    /// Attribute or slot bytes retaining native names, references and unknown fields.
    pub native_context: &'a [u8],
    /// Native field meaning.
    pub kind: TimestampKind,
    /// Lossless time and precision/timezone interpretation.
    pub value: TimeValue,
    /// FAT evidence lies after a terminator and is slack, rather than namespace.
    pub post_terminator: bool,
}
/// Timestamp findings and exact inspected/skipped coverage share an output boundary.
pub enum TimelineEvent<'a> {
    /// Timestamp field with its native context.
    Timestamp(TimestampObservation<'a>),
    /// Coverage in the outcome's requested coordinates.
    Coverage(CoverageEvent),
}
struct Delivery<'a, 'v> {
    outcome: ScanOutcome,
    limits: ScanLimits,
    emitted: u64,
    control: &'a dyn ScanControl,
    visitor: &'v mut dyn FnMut(TimelineEvent<'_>) -> io::Result<()>,
}
impl Delivery<'_, '_> {
    fn check(&self) -> Result<(), StopReason> {
        if self.control.cancelled() {
            Err(StopReason::Cancelled)
        } else if self.outcome.observations >= self.limits.records {
            Err(StopReason::ResourceLimit("records"))
        } else {
            Ok(())
        }
    }
    fn coverage(&mut self, end: u64, kind: CoverageKind) -> Result<(), StopReason> {
        let start = self.outcome.unvisited.offset;
        if end < start
            || end
                > self
                    .outcome
                    .domain
                    .offset
                    .saturating_add(self.outcome.domain.length)
        {
            return Err(StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timestamp evidence outside ordered domain",
            )));
        }
        if start == end {
            return Ok(());
        }
        (self.visitor)(TimelineEvent::Coverage(CoverageEvent {
            range: ByteRange {
                offset: start,
                length: end - start,
            },
            kind,
        }))
        .map_err(StopReason::DeliveryFailed)?;
        self.outcome.coverage_events += 1;
        self.outcome.advance(end);
        Ok(())
    }
    fn timestamp(&mut self, event: TimestampObservation<'_>) -> Result<(), StopReason> {
        self.check()?;
        let charge = event
            .evidence
            .length
            .saturating_add(event.native_context.len() as u64);
        if charge > self.limits.output_bytes.saturating_sub(self.emitted) {
            return Err(StopReason::ResourceLimit("output_bytes"));
        }
        let end = event
            .evidence
            .offset
            .checked_add(event.evidence.length)
            .ok_or_else(|| {
                StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "timestamp offset overflow",
                ))
            })?;
        self.coverage(event.evidence.offset, CoverageKind::Skipped)?;
        self.emitted += charge;
        (self.visitor)(TimelineEvent::Timestamp(event)).map_err(StopReason::DeliveryFailed)?;
        self.outcome.observations += 1;
        self.coverage(end, CoverageKind::Inspected)
    }
    fn finish(mut self, result: Result<(), StopReason>) -> ScanOutcome {
        if let Err(reason) = result {
            self.outcome.stop_reason = reason;
        } else if self.control.cancelled() {
            self.outcome.stop_reason = StopReason::Cancelled;
        } else {
            let end = self
                .outcome
                .domain
                .offset
                .saturating_add(self.outcome.domain.length);
            if let Err(reason) = self.coverage(end, CoverageKind::Skipped) {
                self.outcome.stop_reason = reason;
            }
        }
        self.outcome
    }
}

/// Stream both NTFS timestamp sets from an already delivered slot observation.
/// No source reads occur here. A bad record remains an inventory observation and
/// produces an incomplete timestamp outcome instead of validated timestamps.
pub fn ntfs_timestamps(
    slot: &SlotObservation<'_>,
    limits: ScanLimits,
    control: &dyn ScanControl,
    visitor: &mut dyn FnMut(TimelineEvent<'_>) -> io::Result<()>,
) -> ScanOutcome {
    let mut delivery = Delivery {
        outcome: ScanOutcome::new(
            ByteRange {
                offset: slot.stream_offset,
                length: slot.raw.len() as u64,
            },
            "ntfs-timestamps/logical-mft-bytes",
        )
        .with_coordinate_space(crate::forensics::CoordinateSpace::LogicalStreamBytes),
        limits,
        emitted: 0,
        control,
        visitor,
    };
    delivery.outcome.source_id = slot.source_id;
    let result = (|| {
        if control.cancelled() {
            return Err(StopReason::Cancelled);
        }
        ByteRange::checked(slot.stream_offset, slot.raw.len() as u64, u64::MAX)
            .map_err(StopReason::InvalidBootstrap)?;
        let record = match &slot.decoded {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(()),
            Err(_) => {
                return Err(StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NTFS timestamp record failed validation; retain raw slot inventory",
                )));
            }
        };
        for attribute in &record.attributes {
            if control.cancelled() {
                return Err(StopReason::Cancelled);
            }
            let Some(value) = attribute.resident else {
                continue;
            };
            let (start, kinds) = match attribute.kind {
                0x10 if matches!(value.len(), 48 | 72) => (
                    0,
                    [
                        TimestampKind::NtfsStandardCreated,
                        TimestampKind::NtfsStandardModified,
                        TimestampKind::NtfsStandardChanged,
                        TimestampKind::NtfsStandardAccessed,
                    ],
                ),
                0x30 if value.len() >= 66 && value.len() == 66 + usize::from(value[64]) * 2 => (
                    8,
                    [
                        TimestampKind::NtfsNameCreated,
                        TimestampKind::NtfsNameModified,
                        TimestampKind::NtfsNameChanged,
                        TimestampKind::NtfsNameAccessed,
                    ],
                ),
                0x10 | 0x30 => return Err(StopReason::UnsupportedProfile),
                _ => continue,
            };
            if attribute.raw.len() < 24 {
                return Err(StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "timestamp attribute header missing",
                )));
            }
            let value_offset =
                u64::from(u16::from_le_bytes([attribute.raw[20], attribute.raw[21]]));
            let value_start = (attribute.offset as u64)
                .checked_add(value_offset)
                .ok_or_else(|| {
                    StopReason::InvalidBootstrap(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "timestamp attribute offset overflow",
                    ))
                })?;
            ByteRange::checked(value_start, value.len() as u64, slot.raw.len() as u64)
                .map_err(StopReason::InvalidBootstrap)?;
            for (index, kind) in kinds.into_iter().enumerate() {
                let at = start + index * 8;
                let mut raw = [0; 8];
                raw.copy_from_slice(&value[at..at + 8]);
                delivery.timestamp(TimestampObservation {
                    source_id: slot.source_id,
                    source: slot.source,
                    evidence: ByteRange {
                        offset: slot.stream_offset + value_start + at as u64,
                        length: 8,
                    },
                    native_context: attribute.raw,
                    record_volume_fragments: slot.volume_ranges,
                    kind,
                    value: TimeValue::Filetime(forensics_time::filetime(raw)),
                    post_terminator: false,
                })?;
            }
        }
        Ok(())
    })();
    delivery.finish(result)
}

/// Stream raw FAT timestamp evidence, including deleted aliases and identified slack.
/// LFN fragments, labels and terminators contain no alias timestamp fields.
pub fn fat_timestamps(
    source: &SourceIdentity,
    slot: &FatSlotObservation,
    utc_offset_seconds: Option<i32>,
    limits: ScanLimits,
    control: &dyn ScanControl,
    visitor: &mut dyn FnMut(TimelineEvent<'_>) -> io::Result<()>,
) -> ScanOutcome {
    let mut delivery = Delivery {
        outcome: ScanOutcome::new(
            ByteRange {
                offset: slot.offset,
                length: 32,
            },
            "fat-timestamps/volume-bytes",
        ),
        limits,
        emitted: 0,
        control,
        visitor,
    };
    delivery.outcome.source_id = slot.source_id;
    let result = (|| {
        if control.cancelled() {
            return Err(StopReason::Cancelled);
        }
        ByteRange::checked(slot.offset, 32, u64::MAX).map_err(StopReason::InvalidBootstrap)?;
        if !matches!(
            slot.kind,
            FatSlotKind::File | FatSlotKind::Directory | FatSlotKind::DeletedAlias
        ) {
            return Ok(());
        }
        let mut creation = [0; 5];
        let volume_fragments = [ByteRange {
            offset: slot.offset,
            length: 32,
        }];
        creation.copy_from_slice(&slot.raw[13..18]);
        let mut access = [0; 2];
        access.copy_from_slice(&slot.raw[18..20]);
        let mut modified = [0; 4];
        modified.copy_from_slice(&slot.raw[22..26]);
        for (offset, length, kind, value) in [
            (
                13,
                5,
                TimestampKind::FatCreated,
                TimeValue::FatCreation(forensics_time::fat_created(creation, utc_offset_seconds)),
            ),
            (
                18,
                2,
                TimestampKind::FatAccessed,
                TimeValue::FatAccess(forensics_time::fat_accessed(access, utc_offset_seconds)),
            ),
            (
                22,
                4,
                TimestampKind::FatModified,
                TimeValue::FatModification(forensics_time::fat_modified(
                    modified,
                    utc_offset_seconds,
                )),
            ),
        ] {
            delivery.timestamp(TimestampObservation {
                source_id: slot.source_id,
                source,
                evidence: ByteRange {
                    offset: slot.offset + offset,
                    length,
                },
                native_context: &slot.raw,
                record_volume_fragments: &volume_fragments,
                kind,
                value,
                post_terminator: slot.post_terminator,
            })?;
        }
        Ok(())
    })();
    delivery.finish(result)
}

/// Serialize a native timestamp observation without rounding large UTC tick counts.
/// Integer tick counts are decimal JSON strings; native bytes/context are hexadecimal.
#[cfg(feature = "std")]
pub fn write_json(
    out: &mut dyn std::io::Write,
    event: &TimestampObservation<'_>,
) -> std::io::Result<()> {
    use crate::forensics_json::string;
    out.write_all(b"{\"version\":1,\"type\":\"timestamp\",\"acquisition_label\":")?;
    string(out, &event.source.acquisition)?;
    out.write_all(b",\"source_label\":")?;
    string(out, &event.source.source)?;
    out.write_all(b",\"source_id\":")?;
    match event.source_id {
        Some(id) => write!(out, "{}", id.get())?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b",\"kind\":")?;
    string(
        out,
        match event.kind {
            TimestampKind::NtfsStandardCreated => "ntfs_standard_created",
            TimestampKind::NtfsStandardModified => "ntfs_standard_modified",
            TimestampKind::NtfsStandardChanged => "ntfs_standard_changed",
            TimestampKind::NtfsStandardAccessed => "ntfs_standard_accessed",
            TimestampKind::NtfsNameCreated => "ntfs_name_created",
            TimestampKind::NtfsNameModified => "ntfs_name_modified",
            TimestampKind::NtfsNameChanged => "ntfs_name_changed",
            TimestampKind::NtfsNameAccessed => "ntfs_name_accessed",
            TimestampKind::FatCreated => "fat_created",
            TimestampKind::FatAccessed => "fat_accessed",
            TimestampKind::FatModified => "fat_modified",
        },
    )?;
    write!(
        out,
        ",\"evidence\":{{\"offset\":{},\"length\":{}}},\"record_volume_fragments\":[",
        event.evidence.offset, event.evidence.length
    )?;
    for (index, range) in event.record_volume_fragments.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        write!(
            out,
            "{{\"offset\":{},\"length\":{}}}",
            range.offset, range.length
        )?;
    }
    write!(
        out,
        "],\"post_terminator\":{},\"native_context_hex\":\"",
        event.post_terminator
    )?;
    for byte in event.native_context {
        write!(out, "{byte:02x}")?;
    }
    out.write_all(b"\",\"time\":")?;
    match &event.value {
        TimeValue::Filetime(time) => write_time(out, time)?,
        TimeValue::FatCreation(time) => write_time(out, time)?,
        TimeValue::FatAccess(time) => write_time(out, time)?,
        TimeValue::FatModification(time) => write_time(out, time)?,
    }
    out.write_all(b"}\n")
}
#[cfg(feature = "std")]
fn write_time<const N: usize>(
    out: &mut dyn std::io::Write,
    time: &TimestampEvidence<N>,
) -> std::io::Result<()> {
    out.write_all(b"{\"raw_hex\":\"")?;
    for byte in time.raw {
        write!(out, "{byte:02x}")?;
    }
    write!(
        out,
        "\",\"valid\":{},\"precision_100ns\":{},\"unix_ticks_100ns\":",
        time.valid, time.precision_100ns
    )?;
    match time.unix_ticks_100ns {
        Some(ticks) => write!(out, "\"{ticks}\"")?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b",\"utc_offset_seconds\":")?;
    match time.utc_offset_seconds {
        Some(offset) => write!(out, "{offset}")?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b"}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        forensics::NeverCancel,
        fs_core::{Budget, Cancellation, Resources},
    };
    fn identity() -> SourceIdentity {
        SourceIdentity {
            acquisition: "literal fixture".into(),
            source: "memory".into(),
            stability_provider: "owned bytes".into(),
        }
    }
    #[test]
    fn deleted_fat_slack_preserves_raw_time_timezone_and_exact_coverage() {
        let source = identity();
        let mut raw = [0; 32];
        raw[0] = 0xe5;
        raw[16..18].copy_from_slice(&0x21u16.to_le_bytes());
        raw[18..20].copy_from_slice(&0x21u16.to_le_bytes());
        raw[24..26].copy_from_slice(&0x21u16.to_le_bytes());
        let slot = FatSlotObservation::decode(512, 0, raw, true);
        let mut ranges = alloc::vec::Vec::new();
        let mut fields = 0;
        let result = fat_timestamps(
            &source,
            &slot,
            None,
            ScanLimits::default(),
            &NeverCancel,
            &mut |event| {
                match event {
                    TimelineEvent::Timestamp(event) => {
                        assert!(event.post_terminator);
                        assert_eq!(event.native_context, raw);
                        match event.value {
                            TimeValue::FatCreation(time) => assert_eq!(time.unix_ticks_100ns, None),
                            TimeValue::FatAccess(time) => {
                                assert_eq!(time.precision_100ns, 864_000_000_000)
                            }
                            _ => {}
                        }
                        fields += 1;
                    }
                    TimelineEvent::Coverage(event) => ranges.push(event),
                }
                Ok(())
            },
        );
        assert!(result.is_complete());
        assert_eq!(fields, 3);
        let mut next = 512;
        for range in ranges {
            assert_eq!(range.range.offset, next);
            next += range.range.length;
        }
        assert_eq!(next, 544);
    }
    #[test]
    fn ntfs_standard_timestamps_have_precise_logical_mft_provenance() {
        let source = identity();
        let mut raw = alloc::vec![0; 1024];
        raw[..4].copy_from_slice(b"FILE");
        for (at, value) in [(4, 48u16), (6, 3), (20, 56), (48, 7), (510, 7), (1022, 7)] {
            raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        raw[24..28].copy_from_slice(&136u32.to_le_bytes());
        raw[28..32].copy_from_slice(&1024u32.to_le_bytes());
        raw[56..60].copy_from_slice(&0x10u32.to_le_bytes());
        raw[60..64].copy_from_slice(&72u32.to_le_bytes());
        raw[72..76].copy_from_slice(&48u32.to_le_bytes());
        raw[76..78].copy_from_slice(&24u16.to_le_bytes());
        raw[128..132].copy_from_slice(&u32::MAX.to_le_bytes());
        for index in 0..4 {
            raw[80 + index * 8..88 + index * 8]
                .copy_from_slice(&(116_444_736_000_000_000u64 + index as u64).to_le_bytes());
        }
        let r = Resources {
            memory: Budget::new(65536),
            cancellation: Cancellation::default(),
        };
        let mut fixed = raw.clone();
        let decoded = crate::forensics_ntfs::decode_record(&mut fixed, 4, &r);
        let slot = SlotObservation {
            source_id: None,
            source: &source,
            stream_offset: 2048,
            volume_ranges: &[],
            mirror_agrees: Ok(None),
            slot: 2,
            raw: &raw,
            decoded,
            allocated: Ok(None),
        };
        let mut fields = 0;
        let result = ntfs_timestamps(&slot, ScanLimits::default(), &NeverCancel, &mut |event| {
            if let TimelineEvent::Timestamp(event) = event {
                assert_eq!(
                    event.evidence,
                    ByteRange {
                        offset: 2048 + 80 + fields * 8,
                        length: 8
                    }
                );
                if let TimeValue::Filetime(time) = event.value {
                    assert_eq!(time.unix_ticks_100ns, Some(i128::from(fields)));
                }
                fields += 1;
            }
            Ok(())
        });
        assert!(result.is_complete(), "{:?}", result.stop_reason);
        assert_eq!(fields, 4);
    }
    #[test]
    fn caller_offsets_and_output_failure_never_wrap_or_complete() {
        let source = identity();
        let mut raw = [0; 32];
        raw[0] = b'A';
        let slot = FatSlotObservation::decode(u64::MAX, 0, raw, false);
        let result = fat_timestamps(
            &source,
            &slot,
            Some(0),
            ScanLimits::default(),
            &NeverCancel,
            &mut |_| panic!("invalid domain delivered"),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        let slot = FatSlotObservation::decode(0, 0, raw, false);
        let result = fat_timestamps(
            &source,
            &slot,
            Some(0),
            ScanLimits::default(),
            &NeverCancel,
            &mut |_| Err(io::Error::other("sink")),
        );
        assert!(matches!(result.stop_reason, StopReason::DeliveryFailed(_)));
        assert!(!result.is_complete());
    }
}
