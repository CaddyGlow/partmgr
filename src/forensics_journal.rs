//! Validated native journal selection and bounded read-only observations.
//! Traversal completion does not establish historical journal completeness,
//! original paths, matched renames, recovery readiness or replay authority.
//! File and parent references retain their complete native identities, including
//! sequence numbers that may now be stale. Multiple names or parents remain
//! separate observations; no current namespace path is substituted for them.
//! Rename-old and rename-new reason flags are emitted independently, including
//! events without an observed partner. This profile does not assess pairing.
use crate::{
    forensics::*,
    forensics_ntfs::{MeteredSource, scan_resources, stop_for_metered_error},
    fs_core::*,
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsStreamLimits, NtfsVolume},
    fs_ntfs_usn::UsnRecord,
    fs_ntfs_usn_extract::{ExtractError, GapKind, JournalEvent, JournalLimits, NtfsUsnReader},
    io::{self, ReadAt},
    platform::sync::Arc,
};
/// Native `$UsnJrnl:$Max` fields; acquisition provenance is separate.
#[derive(Debug, Clone, Copy)]
pub struct JournalMax {
    /// Configured maximum size, not a claim of currently retained bytes.
    pub maximum_size: u64,
    /// Native allocation delta.
    pub allocation_delta: u64,
    /// Native journal instance identifier, not a cryptographic identity.
    pub journal_id: u64,
    /// Native first valid USN, signed byte position retained without history claims.
    pub lowest_valid_usn: i64,
}
/// Lossless `$Max` observation with independent field validation.
pub struct MaxObservation<'a> {
    /// Complete selected stream bytes (bounded by 4096 bytes in this profile).
    pub raw: &'a [u8],
    /// Native fields; trailing unknown bytes remain in `raw`.
    pub decoded: Result<JournalMax>,
}
/// Separate native USN and retention observations.
pub enum UsnObservation<'a> {
    /// Validated index namespace selection, not merely a caller-provided inode.
    Namespace {
        /// Exact bounded source view for this namespace and its journal observations.
        source_id: SourceId,
        /// Acquisition identity, never a digest.
        source: &'a SourceIdentity,
        /// `$Extend` identity selected through root index.
        extend: &'a ObjectId,
        /// `$UsnJrnl` identity selected through `$Extend` index.
        journal: &'a ObjectId,
    },
    /// Exact retention metadata and validation outcome.
    Max(MaxObservation<'a>),
    /// Native record, retaining ambiguous references and unmatched rename reasons.
    Record {
        /// Exact owning FILE reference.
        owner: &'a ObjectId,
        /// Native framing and timestamp representation. The zero evidence_id
        /// sentinel is a label; acquisition identity comes from Namespace.
        record: UsnRecord<'a>,
    },
    /// Missing historical/padding bytes are never joined into a record.
    Gap {
        /// Logical journal position.
        range: ByteRange,
        /// Sparse, unwritten or observed zero padding.
        kind: GapKind,
    },
    /// Native retention boundary compared to the first observed USN. This is a
    /// rollover/retention observation, not a proof that no records were lost.
    Retention {
        /// Lowest valid USN reported by `$Max`.
        lowest_valid_usn: i64,
        /// First actual delivered journal record.
        first_observed_usn: i64,
    },
    /// A validated record's USN differs from its logical stream offset.
    OffsetDisagreement {
        /// Logical offset.
        offset: u64,
        /// Native USN.
        usn: i64,
    },
    /// Logical `$J` traversal coverage, independently of evidence validity.
    Coverage(CoverageEvent),
}
fn invalid(s: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn qword(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}
/// Decode native retention fields, retaining raw extensions in the observation.
pub fn decode_max(raw: &[u8]) -> Result<JournalMax> {
    if raw.len() < 32 {
        return Err(invalid("NTFS $Max truncated"));
    }
    let lowest_valid_usn = qword(raw, 24) as i64;
    if lowest_valid_usn < 0 {
        return Err(invalid("NTFS $Max negative lowest-valid USN"));
    }
    Ok(JournalMax {
        maximum_size: qword(raw, 0),
        allocation_delta: qword(raw, 8),
        journal_id: qword(raw, 16),
        lowest_valid_usn,
    })
}
fn exact_name(name: &NativeName, wanted: &[u16]) -> bool {
    matches!(name,NativeName::Utf16(units) if units==wanted)
}
fn select_child(
    volume: &NtfsVolume,
    parent: &ObjectId,
    name: &[u16],
    directories: NtfsDirectoryLimits,
    streams: NtfsStreamLimits,
    r: &Resources,
) -> Result<ObjectId> {
    let directory = volume.directory_resolved(parent, directories, streams, r)?;
    let mut selected = directory
        .entries()
        .iter()
        .filter(|entry| exact_name(&entry.name, name));
    let entry = selected
        .next()
        .ok_or_else(|| invalid("NTFS journal namespace entry absent"))?;
    if selected.next().is_some() {
        return Err(invalid("NTFS journal namespace entry ambiguous"));
    }
    let mut native = alloc::vec::Vec::new();
    native
        .try_reserve_exact(entry.identity.native.len())
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "journal child identity"))?;
    native.extend_from_slice(&entry.identity.native);
    Ok(ObjectId {
        source: entry.identity.source,
        generation: entry.identity.generation,
        native,
    })
}
fn allocated(
    volume: &NtfsVolume,
    object: &ObjectId,
    streams: NtfsStreamLimits,
    r: &Resources,
) -> Result<()> {
    let zero = volume.stream_identity(0, r)?;
    let bitmap = volume.open_native_attribute_stream(&zero, 0xb0, &[], streams, r)?;
    let slot = u64::from_le_bytes(
        object
            .native
            .as_slice()
            .try_into()
            .map_err(|_| invalid("NTFS journal native identity"))?,
    );
    let mut bit = [0];
    if bitmap.read_at(slot / 8, &mut bit, r)? != 1 || bit[0] & (1 << (slot % 8)) == 0 {
        return Err(invalid("NTFS journal namespace allocation unknown/free"));
    }
    Ok(())
}
/// Discover `$Extend/$UsnJrnl`, inspect `$Max`, and traverse exactly `$J`.
/// Raw candidate scans and caller-selected unrelated streams are separate APIs.
#[allow(clippy::too_many_arguments)]
pub fn inspect_usn(
    source: &ForensicSource,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    directories: NtfsDirectoryLimits,
    journal: JournalLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    resources: &Resources,
    mut visitor: impl FnMut(UsnObservation<'_>) -> io::Result<bool>,
) -> ScanOutcome {
    let mut out = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: source.len(),
        },
        "ntfs-usn/discovery",
    )
    .with_source_id(source.id());
    let meter = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));
    let mut stopped = None;
    let mut output = 0u64;
    let result = (|| -> Result<()> {
        if control.cancelled() {
            stopped = Some(StopReason::Cancelled);
            return Err(invalid("USN cancelled"));
        }
        let (r, _lease) = scan_resources(resources, limits)?;
        let _identities = r.memory.reserve(64)?;
        let volume = NtfsVolume::open_for_forensics(meter.clone(), read, streams, &r)?;
        let root = volume.stream_identity(5, &r)?;
        allocated(&volume, &root, streams, &r)?;
        let extend = select_child(
            &volume,
            &root,
            &[36, 69, 120, 116, 101, 110, 100],
            directories,
            streams,
            &r,
        )?;
        allocated(&volume, &extend, streams, &r)?;
        let owner = select_child(
            &volume,
            &extend,
            &[36, 85, 115, 110, 74, 114, 110, 108],
            directories,
            streams,
            &r,
        )?;
        allocated(&volume, &owner, streams, &r)?;
        let max = volume.open_stream(&owner, &[36, 77, 97, 120], streams, &r)?;
        if max.len() > 4096 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "NTFS $Max larger than bounded profile",
            ));
        }
        let _max_lease = r.memory.reserve(max.len())?;
        let mut raw = alloc::vec::Vec::new();
        raw.try_reserve_exact(max.len() as usize)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS $Max bytes"))?;
        raw.resize(max.len() as usize, 0);
        if max.read_at(0, &mut raw, &r)? != raw.len() {
            return Err(invalid("NTFS $Max stream truncated"));
        }
        let reader = NtfsUsnReader::open(&volume, &owner, streams, journal, [0; 32], &r)?;
        out = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: reader.len(),
            },
            "ntfs-usn/$J-logical-stream",
        )
        .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
        .with_source_id(source.id());
        let mut emit =
            |event: UsnObservation<'_>, charge: u64, out: &mut ScanOutcome| -> Result<()> {
                if control.cancelled() {
                    stopped = Some(StopReason::Cancelled);
                    return Err(invalid("USN cancelled"));
                }
                let finding = !matches!(&event, UsnObservation::Coverage(_));
                if finding && out.observations >= limits.records {
                    stopped = Some(StopReason::ResourceLimit("records"));
                    return Err(invalid("USN record ceiling"));
                }
                if charge > limits.output_bytes.saturating_sub(output) {
                    stopped = Some(StopReason::ResourceLimit("output_bytes"));
                    return Err(invalid("USN output ceiling"));
                }
                match visitor(event) {
                    Ok(proceed) => {
                        output += charge;
                        if finding {
                            out.observations += 1;
                            out.last_delivered = Some(out.unvisited.offset);
                        }
                        if !proceed {
                            stopped = Some(StopReason::CallerStop);
                            return Err(invalid("USN visitor stopped"));
                        }
                        Ok(())
                    }
                    Err(e) => {
                        stopped = Some(StopReason::DeliveryFailed(e));
                        Err(invalid("USN delivery failed"))
                    }
                }
            };
        emit(
            UsnObservation::Namespace {
                source_id: source.id(),
                source: source.identity(),
                extend: &extend,
                journal: &owner,
            },
            64,
            &mut out,
        )?;
        let decoded = decode_max(&raw);
        let valid = decoded.as_ref().ok().copied();
        emit(
            UsnObservation::Max(MaxObservation { raw: &raw, decoded }),
            raw.len() as u64,
            &mut out,
        )?;
        let retention = valid.ok_or_else(|| invalid("NTFS $Max validation failed"))?;
        let mut first = true;
        let visit = reader.visit(&r, &mut |event| {
            let range = match event {
                JournalEvent::Record { owner, record } => {
                    if first {
                        emit(
                            UsnObservation::Retention {
                                lowest_valid_usn: retention.lowest_valid_usn,
                                first_observed_usn: record.usn,
                            },
                            32,
                            &mut out,
                        )?;
                        first = false;
                    }
                    if record.usn as u64 != record.provenance.offset {
                        emit(
                            UsnObservation::OffsetDisagreement {
                                offset: record.provenance.offset,
                                usn: record.usn,
                            },
                            24,
                            &mut out,
                        )?;
                    }
                    let range = ByteRange {
                        offset: record.provenance.offset,
                        length: record.raw().len() as u64,
                    };
                    emit(
                        UsnObservation::Record { owner, record },
                        range.length,
                        &mut out,
                    )?;
                    range
                }
                JournalEvent::Gap {
                    offset,
                    length,
                    kind,
                    ..
                } => {
                    let range = ByteRange { offset, length };
                    emit(UsnObservation::Gap { range, kind }, 32, &mut out)?;
                    range
                }
            };
            // Coverage is delivered through the same visitor and resource contract.
            emit(
                UsnObservation::Coverage(CoverageEvent {
                    range,
                    kind: CoverageKind::Inspected,
                }),
                32,
                &mut out,
            )?;
            out.coverage_events += 1;
            out.advance(range.offset + range.length);
            Ok(())
        });
        match visit {
            Ok(()) => Ok(()),
            Err(ExtractError::Core(e)) => Err(e),
            Err(ExtractError::Decode(e)) => Err(Error::io(
                "USN native decoder",
                io::Error::new(io::ErrorKind::InvalidData, e),
            )),
        }
    })();
    if let Err(e) = result {
        out.stop_reason = stopped.unwrap_or_else(|| {
            stop_for_metered_error(e, source, out.profile.ends_with("discovery"), &meter)
        });
    }
    if let Err(e) = source.check_stability() {
        out.stop_reason = StopReason::SourceStability(e);
    }
    out
}

/// Read-only restart-copy observations, deliberately separate from USN and replay.
pub enum LogObservation<'a> {
    /// Native report retains both raw copies, validation errors and disagreement.
    Restart(&'a crate::fs_ntfs_logfile::NtfsVolumeLogFileReport),
    /// Explicit covered logical restart-page domain.
    Coverage(CoverageEvent),
}
/// Inspect supported `$LogFile` restart copies without replay or mutation.
#[allow(clippy::too_many_arguments)]
pub fn inspect_logfile(
    source: &ForensicSource,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    log: crate::fs_ntfs_logfile::NtfsLogFileLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    resources: &Resources,
    mut visitor: impl FnMut(LogObservation<'_>) -> io::Result<bool>,
) -> ScanOutcome {
    let mut out = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: 8192,
        },
        "ntfs-logfile/restart-copies",
    )
    .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
    .with_source_id(source.id());
    let meter = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));
    let result = (|| -> Result<()> {
        if control.cancelled() {
            out.stop_reason = StopReason::Cancelled;
            return Ok(());
        }
        if limits.records == 0 {
            out.stop_reason = StopReason::ResourceLimit("records");
            return Ok(());
        }
        if limits.output_bytes < 8192 {
            out.stop_reason = StopReason::ResourceLimit("output_bytes");
            return Ok(());
        }
        let (r, _lease) = scan_resources(resources, limits)?;
        let report =
            crate::fs_ntfs_logfile::inspect_ntfs_logfile(meter.clone(), read, streams, log, &r)?;
        match visitor(LogObservation::Restart(&report)) {
            Ok(proceed) => {
                out.observations = 1;
                out.last_delivered = Some(0);
                if !proceed {
                    out.stop_reason = StopReason::CallerStop;
                    return Ok(());
                }
            }
            Err(e) => {
                out.stop_reason = StopReason::DeliveryFailed(e);
                return Ok(());
            }
        }
        for copy in report.report.copies() {
            let range = ByteRange {
                offset: copy.offset(),
                length: 4096,
            };
            let kind = if copy.read_complete() {
                CoverageKind::Inspected
            } else {
                CoverageKind::Unreadable
            };
            match visitor(LogObservation::Coverage(CoverageEvent { range, kind })) {
                Ok(proceed) => {
                    out.coverage_events += 1;
                    if copy.read_complete() && range.offset == out.unvisited.offset {
                        out.advance(range.offset + range.length);
                    }
                    if !proceed {
                        out.stop_reason = StopReason::CallerStop;
                        return Ok(());
                    }
                }
                Err(e) => {
                    out.stop_reason = StopReason::DeliveryFailed(e);
                    return Ok(());
                }
            }
        }
        match report.report.state() {
            crate::fs_ntfs_logfile::NtfsLogFileState::Unsupported => {
                out.stop_reason = StopReason::UnsupportedProfile
            }
            crate::fs_ntfs_logfile::NtfsLogFileState::Incomplete => {
                return Err(report
                    .report
                    .into_forensic_failure()
                    .unwrap_or_else(|| invalid("NTFS log restart copies disagree")));
            }
            _ => {}
        }
        Ok(())
    })();
    if let Err(e) = result {
        out.stop_reason = stop_for_metered_error(e, source, false, &meter);
    }
    if let Err(e) = source.check_stability() {
        out.stop_reason = StopReason::SourceStability(e);
    }
    out
}

#[cfg(feature = "std")]
mod json {
    use super::*;
    use crate::forensics_json as j;
    use std::io::{self, Write};
    fn hex(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
        out.write_all(b"\"")?;
        for byte in bytes {
            write!(out, "{byte:02x}")?;
        }
        out.write_all(b"\"")
    }
    fn object(out: &mut impl Write, value: &ObjectId) -> io::Result<()> {
        write!(
            out,
            "{{\"source_scope\":\"{}\",\"generation\":{},\"native_hex\":",
            value.source, value.generation
        )?;
        hex(out, &value.native)?;
        out.write_all(b"}")
    }
    fn errors(out: &mut impl Write, error: &dyn std::error::Error) -> io::Result<()> {
        out.write_all(b"[")?;
        let mut current = Some(error);
        let mut count = 0;
        while let Some(e) = current {
            if count != 0 {
                out.write_all(b",")?;
            }
            j::error_string(out, e)?;
            count += 1;
            current = e.source();
            if count == 16 {
                if current.is_some() {
                    out.write_all(b",\"causal_chain_truncated\"")?;
                }
                break;
            }
        }
        out.write_all(b"]")
    }
    fn reference(out: &mut impl Write, value: crate::fs_ntfs_usn::FileReference) -> io::Result<()> {
        match value {
            crate::fs_ntfs_usn::FileReference::V2(raw) => write!(
                out,
                "{{\"version\":2,\"raw\":\"{raw}\",\"record\":{},\"sequence\":{}}}",
                raw & 0x0000_ffff_ffff_ffff,
                raw >> 48
            ),
            crate::fs_ntfs_usn::FileReference::V3(raw) => {
                out.write_all(b"{\"version\":3,\"raw_hex\":")?;
                hex(out, &raw)?;
                out.write_all(b"}")
            }
        }
    }
    /// Write one version-one JSON Lines USN observation with lossless native bytes.
    pub fn write_usn_json(out: &mut impl Write, event: &UsnObservation<'_>) -> io::Result<()> {
        if let UsnObservation::Coverage(e) = event {
            return j::coverage(out, *e);
        }
        out.write_all(b"{\"version\":1,")?;
        match event {
            UsnObservation::Namespace {
                source_id,
                source,
                extend,
                journal,
            } => {
                write!(
                    out,
                    "\"type\":\"usn_namespace\",\"source_id\":{},\"acquisition_label\":",
                    source_id.get()
                )?;
                j::string(out, &source.acquisition)?;
                out.write_all(b",\"source_label\":")?;
                j::string(out, &source.source)?;
                out.write_all(b",\"extend\":")?;
                object(out, extend)?;
                out.write_all(b",\"journal\":")?;
                object(out, journal)?;
            }
            UsnObservation::Max(m) => {
                out.write_all(b"\"type\":\"usn_max\",\"raw_hex\":")?;
                hex(out, m.raw)?;
                match &m.decoded {
                    Ok(d) => write!(
                        out,
                        ",\"validated\":true,\"maximum_size\":{},\"allocation_delta\":{},\"journal_id\":\"{}\",\"lowest_valid_usn\":{}",
                        d.maximum_size, d.allocation_delta, d.journal_id, d.lowest_valid_usn
                    )?,
                    Err(e) => {
                        out.write_all(b",\"validated\":false,\"causes\":")?;
                        errors(out, e)?;
                    }
                }
            }
            UsnObservation::Record { owner, record: r } => {
                out.write_all(b"\"type\":\"usn_record\",\"owner\":")?;
                object(out, owner)?;
                write!(
                    out,
                    ",\"stream_offset\":{},\"major\":{},\"minor\":{},\"usn\":{},\"timestamp_ticks\":\"{}\",\"ticks_per_second\":10000000,\"epoch\":\"1601-01-01 UTC\",\"reason\":{},\"source_information\":{},\"security_id\":{},\"file_attributes\":{},\"file\":",
                    r.provenance.offset,
                    r.major,
                    r.minor,
                    r.usn,
                    r.timestamp_ticks,
                    r.reason.raw,
                    r.source.raw,
                    r.security_id,
                    r.file_attributes
                )?;
                reference(out, r.file)?;
                out.write_all(b",\"parent\":")?;
                reference(out, r.parent)?;
                out.write_all(b",\"name_utf16\":[")?;
                for (n, unit) in r.name.units().enumerate() {
                    if n != 0 {
                        out.write_all(b",")?;
                    }
                    write!(out, "{unit}")?;
                }
                out.write_all(b"],\"raw_hex\":")?;
                hex(out, r.raw())?;
                out.write_all(b",\"verified_original\":false")?;
            }
            UsnObservation::Gap { range, kind } => {
                out.write_all(b"\"type\":\"usn_gap\",\"range\":")?;
                j::range(out, *range)?;
                out.write_all(b",\"kind\":")?;
                j::string(
                    out,
                    match kind {
                        GapKind::Sparse => "sparse",
                        GapKind::Unwritten => "unwritten",
                        GapKind::ZeroPadding => "zero_padding",
                    },
                )?;
            }
            UsnObservation::Retention {
                lowest_valid_usn,
                first_observed_usn,
            } => write!(
                out,
                "\"type\":\"usn_retention\",\"lowest_valid_usn\":{lowest_valid_usn},\"first_observed_usn\":{first_observed_usn},\"historical_completeness_established\":false"
            )?,
            UsnObservation::OffsetDisagreement { offset, usn } => write!(
                out,
                "\"type\":\"usn_offset_disagreement\",\"stream_offset\":{offset},\"usn\":{usn}"
            )?,
            UsnObservation::Coverage(_) => unreachable!(),
        }
        out.write_all(b"}\n")
    }
    /// Write one version-one JSON Lines LogFile observation, including both raw
    /// restart copies and their independent validation and causal failures.
    pub fn write_log_json(out: &mut impl Write, event: &LogObservation<'_>) -> io::Result<()> {
        if let LogObservation::Coverage(e) = event {
            return j::coverage(out, *e);
        }
        let LogObservation::Restart(native) = event else {
            return Ok(());
        };
        out.write_all(b"{\"version\":1,\"type\":\"logfile_restart\",\"owner\":")?;
        object(out, &native.owner)?;
        write!(
            out,
            ",\"volume_flags\":{},\"copies_disagree\":{},\"transaction_analysis_complete\":false,\"state\":",
            native.volume_flags,
            native.report.copies_disagree()
        )?;
        j::string(
            out,
            match native.report.state() {
                crate::fs_ntfs_logfile::NtfsLogFileState::CleanFlagObserved => {
                    "clean_flag_observed"
                }
                crate::fs_ntfs_logfile::NtfsLogFileState::RecoveryRequired => "recovery_required",
                crate::fs_ntfs_logfile::NtfsLogFileState::Unsupported => "unsupported",
                crate::fs_ntfs_logfile::NtfsLogFileState::Incomplete => "incomplete",
            },
        )?;
        out.write_all(b",\"source_causes\":")?;
        if let Some(e) = native.report.source_error() {
            errors(out, e)?;
        } else {
            out.write_all(b"null")?;
        }
        out.write_all(b",\"copies\":[")?;
        for (n, copy) in native.report.copies().iter().enumerate() {
            if n != 0 {
                out.write_all(b",")?;
            }
            write!(
                out,
                "{{\"stream_offset\":{},\"read_complete\":{},\"raw_hex\":",
                copy.offset(),
                copy.read_complete()
            )?;
            if copy.read_complete() {
                hex(out, copy.raw())?;
            } else {
                out.write_all(b"null")?;
            }
            match copy.area() {
                Ok(a) => write!(
                    out,
                    ",\"validated\":true,\"major\":{},\"minor\":{},\"current_lsn\":\"{}\",\"flags\":{},\"file_bytes\":{},\"sequence_bits\":{},\"client_count\":{},\"free_head\":{},\"in_use_head\":{},\"record_header_bytes\":{},\"page_data_offset\":{},\"open_count\":{}",
                    a.version.0,
                    a.version.1,
                    a.current_lsn,
                    a.flags,
                    a.file_bytes,
                    a.sequence_bits,
                    a.client_count,
                    a.free_head,
                    a.in_use_head,
                    a.record_header_bytes,
                    a.page_data_offset,
                    a.open_count
                )?,
                Err(e) => {
                    out.write_all(b",\"validated\":false,\"causes\":")?;
                    errors(out, e)?;
                }
            }
            out.write_all(b"}")?;
        }
        out.write_all(b"]}\n")
    }
}
#[cfg(feature = "std")]
pub use json::{write_log_json, write_usn_json};
