//! Version-one streaming JSON Lines for shared forensic evidence contracts.
//! A stream without a successfully written terminal outcome is incomplete.
use crate::forensics::{ByteRange, CoverageEvent, ScanOutcome, StopReason};
use std::io::{self, Write};

/// Write a JSON string without replacing native characters or admitting control bytes.
pub fn string(out: &mut dyn Write, value: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    string_content(out, value)?;
    out.write_all(b"\"")
}
fn string_content(out: &mut dyn Write, value: &str) -> io::Result<()> {
    for c in value.chars() {
        match c {
            '"' => out.write_all(b"\\\"")?,
            '\\' => out.write_all(b"\\\\")?,
            c if c <= '\u{1f}' => write!(out, "\\u{:04x}", c as u32)?,
            c => {
                let mut bytes = [0; 4];
                out.write_all(c.encode_utf8(&mut bytes).as_bytes())?;
            }
        }
    }
    Ok(())
}
/// Write a stable logical byte range object.
pub fn range(out: &mut dyn Write, value: ByteRange) -> io::Result<()> {
    write!(
        out,
        "{{\"offset\":{},\"length\":{}}}",
        value.offset, value.length
    )
}

/// Write acquisition identity explicitly as labels, never verified digests.
pub fn source(out: &mut dyn Write, source: &crate::forensics::ForensicSource) -> io::Result<()> {
    let identity = source.identity();
    write!(
        out,
        "{{\"version\":1,\"type\":\"source\",\"source_id\":{},\"logical_disk_region\":",
        source.id().get()
    )?;
    range(out, source.logical_disk_region())?;
    out.write_all(b",\"acquisition_label\":")?;
    string(out, &identity.acquisition)?;
    out.write_all(b",\"source_label\":")?;
    string(out, &identity.source)?;
    out.write_all(b",\"stability_provider\":")?;
    string(out, &identity.stability_provider)?;
    out.write_all(b"}\n")
}

/// Serialize a shared library coverage event directly.
pub fn coverage(out: &mut dyn Write, event: CoverageEvent) -> io::Result<()> {
    out.write_all(b"{\"version\":1,\"type\":\"coverage\",\"range\":")?;
    range(out, event.range)?;
    out.write_all(b",\"kind\":")?;
    string(
        out,
        match event.kind {
            crate::forensics::CoverageKind::Inspected => "inspected",
            crate::forensics::CoverageKind::Skipped => "skipped",
            crate::forensics::CoverageKind::Unreadable => "unreadable",
            crate::forensics::CoverageKind::Unsupported => "unsupported",
        },
    )?;
    out.write_all(b"}\n")
}

/// Serialize the complete terminal library outcome, including every causal error.
/// The caller must propagate write/flush failures and return a failure exit status
/// for incomplete outcomes. A hash or observation count cannot replace this record.
pub fn terminal(out: &mut dyn Write, outcome: &ScanOutcome) -> io::Result<()> {
    out.write_all(b"{\"version\":1,\"type\":\"terminal\",\"profile\":")?;
    string(out, outcome.profile)?;
    out.write_all(b",\"source_id\":")?;
    match outcome.source_id {
        Some(id) => write!(out, "{}", id.get())?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b",\"coordinate_space\":")?;
    string(
        out,
        match outcome.coordinate_space {
            crate::forensics::CoordinateSpace::VolumeBytes => "volume_bytes",
            crate::forensics::CoordinateSpace::LogicalDiskBytes => "logical_disk_bytes",
            crate::forensics::CoordinateSpace::LogicalStreamBytes => "logical_stream_bytes",
            crate::forensics::CoordinateSpace::EntryOrdinals => "entry_ordinals",
            crate::forensics::CoordinateSpace::ClusterOrdinals => "cluster_ordinals",
            crate::forensics::CoordinateSpace::RecordOrdinals => "record_ordinals",
        },
    )?;
    out.write_all(b",\"domain\":")?;
    range(out, outcome.domain)?;
    out.write_all(b",\"unvisited\":")?;
    range(out, outcome.unvisited)?;
    write!(
        out,
        ",\"observations\":{},\"coverage_events\":{},\"complete\":{},\"last_delivered\":",
        outcome.observations,
        outcome.coverage_events,
        outcome.is_complete()
    )?;
    match outcome.last_delivered {
        Some(n) => write!(out, "{n}")?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b",\"stop_reason\":")?;
    let (reason, cause, ceiling) = match &outcome.stop_reason {
        StopReason::Completed => ("completed", None, None),
        StopReason::Cancelled => ("cancelled", None, None),
        StopReason::CallerStop => ("caller_stop", None, None),
        StopReason::ResourceLimit(ceiling) => ("resource_limit", None, Some(*ceiling)),
        StopReason::ResourceCause { ceiling, cause } => {
            ("resource_limit", Some(cause), Some(*ceiling))
        }
        StopReason::Io(cause) => ("io_failure", Some(cause), None),
        StopReason::InvalidBootstrap(cause) => ("invalid_bootstrap", Some(cause), None),
        StopReason::UnsupportedProfile => ("unsupported_profile", None, None),
        StopReason::UnsupportedCause(cause) => ("unsupported_profile", Some(cause), None),
        StopReason::SourceStability(cause) => ("source_stability_failure", Some(cause), None),
        StopReason::DeliveryFailed(cause) => ("delivery_failure", Some(cause), None),
    };
    string(out, reason)?;
    out.write_all(b",\"resource_ceiling\":")?;
    match ceiling {
        Some(value) => string(out, value)?,
        None => out.write_all(b"null")?,
    }
    out.write_all(b",\"causes\":[")?;
    if let Some(cause) = cause {
        let mut current: Option<&dyn std::error::Error> = Some(cause);
        let mut depth = 0;
        while let Some(error) = current {
            if depth != 0 {
                out.write_all(b",")?;
            }
            error_string(out, error)?;
            depth += 1;
            // Causal chains supplied by arbitrary host errors may contain cycles.
            if depth == 32 {
                out.write_all(b",\"causal chain depth limit\"")?;
                break;
            }
            current = error.source();
        }
    }
    out.write_all(b"]}\n")
}

/// Serialize stream and volume ranges separately from original logical disk ranges.
/// These offsets never claim a physical container-file mapping.
pub fn extraction_range(
    out: &mut dyn Write,
    source: &crate::forensics::ForensicSource,
    value: crate::forensics_extract::ExtractionRange,
) -> io::Result<()> {
    use crate::forensics_extract::{ExtractionKind, ReuseEvidence};
    write!(
        out,
        "{{\"version\":1,\"type\":\"extraction_range\",\"source_id\":{},\"stream_range\":",
        source.id().get()
    )?;
    range(out, value.logical)?;
    let kind = match value.kind {
        ExtractionKind::Data(_) => "data",
        ExtractionKind::Sparse => "sparse",
        ExtractionKind::Unwritten => "unwritten",
        ExtractionKind::Unavailable => "unavailable",
    };
    out.write_all(b",\"kind\":")?;
    string(out, kind)?;
    out.write_all(b",\"volume_range\":")?;
    if let ExtractionKind::Data(offset) = value.kind {
        range(
            out,
            ByteRange {
                offset,
                length: value.logical.length,
            },
        )?;
        out.write_all(b",\"logical_disk_range\":")?;
        range(
            out,
            source
                .translate_range(ByteRange {
                    offset,
                    length: value.logical.length,
                })
                .map_err(io::Error::other)?,
        )?;
    } else {
        out.write_all(b"null,\"logical_disk_range\":null")?;
    }
    out.write_all(b",\"current_reuse_evidence\":")?;
    string(
        out,
        match value.reuse {
            ReuseEvidence::Unknown => "unknown",
            ReuseEvidence::CurrentlyFree => "currently_free",
            ReuseEvidence::AllocatedOwnerUnknown => "allocated_owner_unknown",
            ReuseEvidence::ConflictingOwner => "conflicting_owner",
            ReuseEvidence::SelectedLiveOwner => "selected_live_owner",
        },
    )?;
    out.write_all(b",\"verified_original\":false}\n")
}

// Streaming formatting avoids allocating an arbitrary caller error's Display.
// The explicit truncation marker preserves that causal text is incomplete.
pub(crate) fn error_string(out: &mut dyn Write, error: &dyn std::error::Error) -> io::Result<()> {
    struct BoundedDisplay<'a> {
        out: &'a mut dyn Write,
        remaining: usize,
        failure: Option<io::Error>,
        truncated: bool,
    }
    impl core::fmt::Write for BoundedDisplay<'_> {
        fn write_str(&mut self, value: &str) -> core::fmt::Result {
            let mut length = value.len().min(self.remaining);
            while !value.is_char_boundary(length) {
                length -= 1;
            }
            if let Err(error) = string_content(self.out, &value[..length]) {
                self.failure = Some(error);
                return Err(core::fmt::Error);
            }
            self.remaining -= length;
            if length != value.len() {
                self.truncated = true;
                return Err(core::fmt::Error);
            }
            Ok(())
        }
    }
    out.write_all(b"\"")?;
    let mut bounded = BoundedDisplay {
        out,
        remaining: 2048,
        failure: None,
        truncated: false,
    };
    let formatted = core::fmt::write(&mut bounded, format_args!("{error}"));
    if let Some(error) = bounded.failure {
        return Err(error);
    }
    if bounded.truncated || formatted.is_err() {
        bounded.out.write_all(b"[causal text truncated]")?;
    }
    bounded.out.write_all(b"\"")
}

/// Write explicit acquisition times, uncertainty, parent inputs and digest domains.
/// A null manifest leaves acquisition metadata unknown rather than assuming a
/// point-in-time capture or a verified caller label.
pub fn acquisition_manifest(
    out: &mut dyn Write,
    source: &crate::forensics::ForensicSource,
) -> io::Result<()> {
    use crate::forensics::{AcquisitionTime, EvidenceDigest, EvidenceInputRole, HashDomain};
    fn time(out: &mut dyn Write, time: Option<AcquisitionTime>) -> io::Result<()> {
        match time {
            Some(time) => write!(
                out,
                "{{\"unix_seconds\":{},\"nanoseconds\":{}}}",
                time.unix_seconds, time.nanoseconds
            ),
            None => out.write_all(b"null"),
        }
    }
    fn digest(out: &mut dyn Write, digest: &EvidenceDigest) -> io::Result<()> {
        out.write_all(b"{\"algorithm\":\"sha256\",\"domain\":")?;
        string(
            out,
            match digest.domain {
                HashDomain::OriginalContainerBytes => "original_container_bytes",
                HashDomain::LogicalDiskBytes => "logical_disk_bytes",
                HashDomain::SelectedEvidenceRange(_) => "selected_evidence_range",
                HashDomain::ExtractedOutputPrefix => "extracted_output_prefix",
            },
        )?;
        out.write_all(b",\"range\":")?;
        match digest.domain {
            HashDomain::SelectedEvidenceRange(value) => range(out, value)?,
            _ => out.write_all(b"null")?,
        }
        out.write_all(b",\"sha256\":\"")?;
        for byte in digest.sha256 {
            write!(out, "{byte:02x}")?;
        }
        out.write_all(b"\",\"verified_original\":false}")
    }
    out.write_all(
        b"{\"version\":1,\"type\":\"acquisition_manifest\",\"selected_logical_disk_range\":",
    )?;
    range(out, source.logical_disk_region())?;
    out.write_all(b",\"unavailable_logical_disk_ranges\":[")?;
    for (index, value) in source.unavailable_ranges().iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        range(out, *value)?;
    }
    out.write_all(b"],\"manifest\":")?;
    let Some(manifest) = source.acquisition_manifest() else {
        return out.write_all(b"null}\n");
    };
    out.write_all(b"{\"started\":")?;
    time(out, manifest.started)?;
    out.write_all(b",\"completed\":")?;
    time(out, manifest.completed)?;
    out.write_all(b",\"consistency_uncertainty\":")?;
    string(out, &manifest.consistency_uncertainty)?;
    out.write_all(b",\"stability_lifetime\":\"session_including_deferred_reads\",\"inputs\":[")?;
    for (index, input) in manifest.inputs.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        out.write_all(b"{\"role\":")?;
        string(
            out,
            match input.role {
                EvidenceInputRole::Container => "container",
                EvidenceInputRole::Parent => "parent",
                EvidenceInputRole::ImmutableRecoveryOverlay => "immutable_recovery_overlay",
            },
        )?;
        out.write_all(b",\"identity_label\":")?;
        string(out, &input.identity_label)?;
        out.write_all(b",\"digest\":")?;
        match &input.digest {
            Some(value) => digest(out, value)?,
            None => out.write_all(b"null")?,
        }
        out.write_all(b"}")?;
    }
    out.write_all(b"],\"digests\":[")?;
    for (index, value) in manifest.digests.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        digest(out, value)?;
    }
    out.write_all(b"]}}\n")
}

/// Persist FAT recovery qualifications independently of the extraction byte hash.
pub fn fat_candidate_context(
    out: &mut dyn Write,
    map: &crate::forensics_fat_extract::FatCandidateMap,
) -> io::Result<()> {
    use crate::forensics_fat::FatAllocationKind;
    write!(
        out,
        "{{\"version\":1,\"type\":\"fat_candidate_context\",\"source_id\":{},\"slot_volume_offset\":{},\"deleted_alias\":{},\"selected_live_alias_observed\":{},\"raw_slot_hex\":\"",
        map.source().id().get(),
        map.slot.offset,
        map.deleted,
        map.selected_alias_observed
    )?;
    for byte in map.slot.raw {
        write!(out, "{byte:02x}")?;
    }
    out.write_all(b"\",\"historical_authenticity\":\"unproven\",\"ranges\":[")?;
    for (index, value) in map.ranges().iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        out.write_all(b"{\"stream_range\":")?;
        range(out, value.extraction.logical)?;
        write!(
            out,
            ",\"contiguous_hypothesis\":{},\"ownership_complete\":{},\"selected_owner_observed\":{},\"allocation\":",
            value.contiguous_hypothesis, value.ownership_complete, value.selected_owner_observed
        )?;
        match value.allocation {
            None => out.write_all(b"null")?,
            Some(kind) => {
                out.write_all(b"{\"kind\":")?;
                string(
                    out,
                    match kind {
                        FatAllocationKind::Free => "free",
                        FatAllocationKind::Next(_) => "next",
                        FatAllocationKind::End => "end",
                        FatAllocationKind::Bad => "bad",
                        FatAllocationKind::Reserved => "reserved",
                        FatAllocationKind::OutOfRange => "out_of_range",
                    },
                )?;
                out.write_all(b",\"next_cluster\":")?;
                match kind {
                    FatAllocationKind::Next(next) => write!(out, "{next}")?,
                    _ => out.write_all(b"null")?,
                };
                out.write_all(b"}")?;
            }
        }
        out.write_all(b",\"conflicting_owner\":")?;
        match value.conflicting_owner {
            None => out.write_all(b"null")?,
            Some(None) => out.write_all(b"{\"kind\":\"fat32_root\"}")?,
            Some(Some(offset)) => write!(
                out,
                "{{\"kind\":\"alias\",\"slot_volume_offset\":{offset}}}"
            )?,
        }
        out.write_all(b"}")?;
    }
    out.write_all(b"]}\n")?;
    terminal(out, &map.mapping)?;
    if let Some(ownership) = &map.ownership {
        terminal(out, ownership)?;
    }
    Ok(())
}

/// Persist free NTFS record evidence and every independent reuse check.
pub fn ntfs_candidate_context(
    out: &mut dyn Write,
    candidate: &crate::forensics_ntfs::DeletedStreamCandidate,
    assessments: &[Option<crate::forensics_ntfs::RangeReuseAssessment>],
) -> io::Result<()> {
    use crate::forensics_ntfs::RangeAllocation;
    write!(
        out,
        "{{\"version\":1,\"type\":\"ntfs_candidate_context\",\"source_id\":{},\"record\":{},\"sequence\":{},\"resident\":{},\"historical_authenticity\":\"unproven\",\"raw_record_hex\":\"",
        candidate.source().id().get(),
        candidate.record,
        candidate.sequence,
        candidate.resident
    )?;
    for byte in candidate.raw_record() {
        write!(out, "{byte:02x}")?;
    }
    out.write_all(b"\"}\n")?;
    for (index, (range_value, assessment)) in candidate.ranges.iter().zip(assessments).enumerate() {
        write!(
            out,
            "{{\"version\":1,\"type\":\"ntfs_reuse_assessment\",\"source_id\":{},\"range_index\":{index},\"stream_range\":",
            candidate.source().id().get()
        )?;
        range(out, range_value.logical)?;
        out.write_all(b",\"allocation\":")?;
        string(
            out,
            match assessment.as_ref().map(|assessment| assessment.allocation) {
                None | Some(RangeAllocation::Unknown) => "unknown",
                Some(RangeAllocation::Free) => "free",
                Some(RangeAllocation::Allocated) => "allocated",
                Some(RangeAllocation::Mixed) => "mixed",
            },
        )?;
        out.write_all(b",\"conflicting_current_owner\":")?;
        if let Some(owner) = assessment
            .as_ref()
            .and_then(|assessment| assessment.conflicting_owner)
        {
            write!(
                out,
                "{{\"source_id\":{},\"owner_record\":{},\"carrier_record\":{},\"attribute_type\":{},\"attribute_offset\":{},\"volume_range\":",
                owner.source_id.get(),
                owner.owner,
                owner.carrier,
                owner.kind,
                owner.attribute_offset
            )?;
            range(out, owner.range)?;
            out.write_all(b"}")?;
        } else {
            out.write_all(b"null")?;
        }
        writeln!(out, ",\"checks_available\":{}}}", assessment.is_some())?;
        if let Some(assessment) = assessment {
            writeln!(
                out,
                "{{\"version\":1,\"type\":\"assessment_scan\",\"range_index\":{index},\"which\":\"bitmap\"}}"
            )?;
            terminal(out, &assessment.bitmap_outcome)?;
            writeln!(
                out,
                "{{\"version\":1,\"type\":\"assessment_scan\",\"range_index\":{index},\"which\":\"ownership\"}}"
            )?;
            terminal(out, &assessment.ownership_outcome)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_labels_are_json_strings_not_records() {
        let mut output = Vec::new();
        string(&mut output, "a\n\u{0}\"\\é").unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "\"a\\u000a\\u0000\\\"\\\\é\""
        );
    }
    #[test]
    fn no_observation_failure_has_explicit_terminal_and_cause() {
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 3,
                length: 9,
            },
            "test",
        );
        outcome.stop_reason = StopReason::DeliveryFailed(io::Error::other("broken sink").into());
        let mut output = Vec::new();
        terminal(&mut output, &outcome).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("\"complete\":false"));
        assert!(text.contains("\"last_delivered\":null"));
        assert!(text.contains("\"causes\":[\"broken sink\""));
        assert!(text.ends_with("}\n"));
    }
    #[test]
    fn terminal_write_failure_is_not_success() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(
            terminal(
                &mut Broken,
                &ScanOutcome::new(
                    ByteRange {
                        offset: 0,
                        length: 0
                    },
                    "empty"
                )
            )
            .is_err()
        );
    }
    #[test]
    fn caller_error_display_is_bounded_and_explicitly_truncated() {
        #[derive(Debug)]
        struct Verbose;
        impl core::fmt::Display for Verbose {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                for _ in 0..10_000 {
                    formatter.write_str("é")?;
                }
                Ok(())
            }
        }
        impl std::error::Error for Verbose {}
        let mut output = Vec::new();
        error_string(&mut output, &Verbose).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.len() < 2100);
        assert!(text.ends_with("[causal text truncated]\""));
    }
}
