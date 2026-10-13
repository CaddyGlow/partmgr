//! Exclusive host exports with generated filenames and terminal JSONL manifests.
//! The caller must hold the output directory stable against concurrent replacement.
//! Evidence names are manifest data and never participate in host path resolution.
use crate::{
    forensics::{ByteRange, ForensicSource, ScanControl, ScanLimits, ScanOutcome, StopReason},
    forensics_extract::{ExtractionEvent, ExtractionOutcome, ExtractionRange, extract_ranges},
    forensics_json,
    fs_core::{NativeName, Resources},
    io::ReadAt,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Failed host export retaining traversal, hash and partial artifact information.
/// Even failures before output creation have an explicit incomplete outcome.
#[derive(Debug)]
pub struct ExportFailure {
    /// Original host/validation failure, shared with the final outcome's cause.
    pub cause: std::sync::Arc<io::Error>,
    /// Final incomplete delivery outcome with previously delivered prefix/hash.
    pub outcome: ExtractionOutcome,
    /// Traversal or earlier delivery outcome before this host failure.
    pub prior_outcome: ExtractionOutcome,
    /// Earlier logical traversal when data-file sync also failed.
    pub prior_scan: Option<ScanOutcome>,
    /// Partial output path, if it was created.
    pub output: Option<PathBuf>,
    /// Partial manifest path, if it was created.
    pub manifest: Option<PathBuf>,
    /// Terminal record was fully written, flushed and synchronized successfully.
    /// This remains false after any reporting failure, regardless of buffered bytes.
    /// It may be true after a data-file durability failure: the terminal then
    /// reports that failure rather than successful delivery.
    pub terminal_delivered: bool,
}
impl core::fmt::Display for ExportFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "forensic export delivery failed: {}", self.cause)
    }
}
impl std::error::Error for ExportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
#[derive(Debug)]
struct SharedExportIo(std::sync::Arc<io::Error>);
impl core::fmt::Display for SharedExportIo {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for SharedExportIo {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
struct ExportState {
    outcome: Option<ExtractionOutcome>,
    prior_scan: Option<ScanOutcome>,
    output: Option<PathBuf>,
    manifest: Option<PathBuf>,
    source_id: crate::forensics::SourceId,
    domain: ByteRange,
    terminal_delivered: bool,
}
fn empty_export_outcome(
    source_id: crate::forensics::SourceId,
    domain: ByteRange,
) -> ExtractionOutcome {
    let mut scan = ScanOutcome::new(domain, "export-output/bootstrap")
        .with_source_id(source_id)
        .with_coordinate_space(crate::forensics::CoordinateSpace::LogicalStreamBytes);
    scan.stop_reason = StopReason::CallerStop;
    ExtractionOutcome {
        scan,
        output_bytes: 0,
        prefix_sha256: Sha256::digest([]).into(),
    }
}
fn failed_scan(prior: &ScanOutcome, cause: std::sync::Arc<io::Error>) -> ScanOutcome {
    ScanOutcome {
        source_id: prior.source_id,
        coordinate_space: prior.coordinate_space,
        domain: prior.domain,
        profile: prior.profile,
        observations: prior.observations,
        coverage_events: prior.coverage_events,
        last_delivered: prior.last_delivered,
        unvisited: prior.unvisited,
        stop_reason: StopReason::DeliveryFailed(crate::io::Error::other(SharedExportIo(cause))),
    }
}
impl ExportState {
    fn new(source: &ForensicSource, length: u64) -> Self {
        let domain = ByteRange { offset: 0, length };
        let source_id = source.id();
        Self {
            outcome: Some(empty_export_outcome(source_id, domain)),
            prior_scan: None,
            output: None,
            manifest: None,
            source_id,
            domain,
            terminal_delivered: false,
        }
    }
    fn fail(self, error: io::Error) -> Box<ExportFailure> {
        let cause = std::sync::Arc::new(error);
        let prior_outcome = self
            .outcome
            .unwrap_or_else(|| empty_export_outcome(self.source_id, self.domain));
        let outcome = ExtractionOutcome {
            scan: failed_scan(&prior_outcome.scan, cause.clone()),
            output_bytes: prior_outcome.output_bytes,
            prefix_sha256: prior_outcome.prefix_sha256,
        };
        Box::new(ExportFailure {
            cause,
            outcome,
            prior_outcome,
            prior_scan: self.prior_scan,
            output: self.output,
            manifest: self.manifest,
            terminal_delivered: self.terminal_delivered,
        })
    }
}
/// Caller-selected candidate stream and its exact native name.
pub struct ExportRequest<'a> {
    /// Native name, including invalid Unicode units, retained in the manifest.
    pub name: &'a NativeName,
    /// Expected logical length.
    pub length: u64,
    /// Complete explicit map with current reuse observations.
    pub ranges: &'a [ExtractionRange],
    /// Independent operation limits.
    pub limits: ScanLimits,
}
/// Validated live NTFS DATA/ADS selection and supported decoder limits.
pub struct NtfsStreamExportRequest<'a> {
    /// Native record slot, resolved to its current live sequence by the reader.
    pub record: u64,
    /// Exact UTF16 stream name; an empty UTF16 name selects unnamed DATA.
    pub name: &'a NativeName,
    /// Per-record bootstrap and framing bounds.
    pub read: crate::fs_ntfs::NtfsReadLimits,
    /// Aggregate attribute-list and stream resolution bounds.
    pub streams: crate::fs_ntfs::NtfsStreamLimits,
    /// Explicit supported compression profile; None rejects compressed streams.
    pub compression: Option<crate::fs_ntfs::NtfsCompressionLimits>,
    /// Independent extraction and host manifest/output bounds.
    pub limits: ScanLimits,
}
/// Export resident, fragmented, sparse/unwritten or supported compressed live NTFS
/// streams exclusively, retaining logical provenance without invented physical mappings.
pub fn export_ntfs_live_stream(
    directory: &Path,
    source: &ForensicSource,
    request: NtfsStreamExportRequest<'_>,
    resources: &Resources,
    control: &dyn ScanControl,
) -> Result<ExportResult, Box<ExportFailure>> {
    if !matches!(request.name, NativeName::Utf16(_)) {
        return Err(ExportState::new(source, source.len()).fail(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NTFS streams require native UTF16 names",
        )));
    }
    export_with_context(
        directory,
        source,
        ExportRequest {
            name: request.name,
            length: 0,
            ranges: &[],
            limits: request.limits,
        },
        resources,
        control,
        None,
        Some(&request),
    )
}
/// Export artifact paths and terminal outcome; incomplete outputs retain `.partial`.
pub struct ExportResult {
    /// Exclusive output file, with no evidence-controlled path components.
    pub output: PathBuf,
    /// JSONL manifest. Missing terminal record means incomplete regardless of name.
    pub manifest: PathBuf,
    /// Traversal outcome before a later data-file durability failure, if any.
    /// Preserve this independently of the final delivery failure and output hash.
    pub prior_scan: Option<ScanOutcome>,
    /// Output-byte hash and shared terminal status.
    pub outcome: ExtractionOutcome,
}
fn exclusive(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}
fn create_pair(root: &Path, state: &mut ExportState) -> io::Result<(PathBuf, File, PathBuf, File)> {
    for index in 0..10_000u32 {
        let output = root.join(format!("candidate-{index:06}.partial"));
        let manifest = root.join(format!("candidate-{index:06}.jsonl.partial"));
        // Reserve the manifest first. Old partial artifacts are never overwritten.
        let log = match exclusive(&manifest) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        state.manifest = Some(manifest.clone());
        match exclusive(&output) {
            Ok(file) => {
                state.output = Some(output.clone());
                return Ok((output, file, manifest, log));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                drop(log);
                fs::remove_file(&manifest)?;
                state.manifest = None;
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "candidate filename collision limit",
    ))
}

/// Export exclusively to a caller-controlled directory without resolving evidence paths.
///
/// Partial output and manifests are retained on every error. Errors writing the
/// terminal record are returned directly; those manifests are necessarily incomplete.
/// Successful candidates keep `.partial` filenames as a reminder that recovered
/// bytes are not authenticated historical content; consult the terminal outcome.
pub fn export(
    directory: &Path,
    source: &ForensicSource,
    request: ExportRequest<'_>,
    resources: &Resources,
    control: &dyn ScanControl,
) -> Result<ExportResult, Box<ExportFailure>> {
    export_with_context(directory, source, request, resources, control, None, None)
}
#[derive(Clone, Copy)]
enum CandidateContext<'a> {
    Fat(&'a crate::forensics_fat_extract::FatCandidateMap),
    Ntfs {
        candidate: &'a crate::forensics_ntfs::DeletedStreamCandidate,
        assessments: &'a [Option<crate::forensics_ntfs::RangeReuseAssessment>],
    },
}
fn export_with_context(
    directory: &Path,
    source: &ForensicSource,
    request: ExportRequest<'_>,
    resources: &Resources,
    control: &dyn ScanControl,
    context: Option<CandidateContext<'_>>,
    live: Option<&NtfsStreamExportRequest<'_>>,
) -> Result<ExportResult, Box<ExportFailure>> {
    let mut state = ExportState::new(
        source,
        if live.is_some() {
            source.len()
        } else {
            request.length
        },
    );
    if live.is_some()
        && let Some(outcome) = &mut state.outcome
    {
        outcome.scan.coordinate_space = crate::forensics::CoordinateSpace::VolumeBytes;
    }
    match export_io(
        directory, source, request, resources, control, context, live, &mut state,
    ) {
        Ok(result) => Ok(result),
        Err(error) => Err(state.fail(error)),
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "shared artifact state and explicit source/profile boundaries"
)]
fn export_io(
    directory: &Path,
    source: &ForensicSource,
    request: ExportRequest<'_>,
    resources: &Resources,
    control: &dyn ScanControl,
    context: Option<CandidateContext<'_>>,
    live: Option<&NtfsStreamExportRequest<'_>>,
    state: &mut ExportState,
) -> io::Result<ExportResult> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output must be a stable ordinary directory",
        ));
    }
    let root = directory.canonicalize()?;
    let (output, mut file, manifest, mut log) = create_pair(&root, state)?;
    // Manifest metadata and extracted bytes share one output ceiling. Terminal
    // reporting is reserved outside it, so exhaustion still produces status.
    let mut capped = ManifestWriter {
        output: &mut log,
        remaining: request.limits.output_bytes,
        exhausted: false,
        at_line_start: true,
        control,
        cancellation: &resources.cancellation,
    };
    let name_units = match request.name {
        NativeName::Bytes(bytes) => bytes.len(),
        NativeName::Utf16(units) => units.len(),
    };
    let name_bytes = match request.name {
        NativeName::Bytes(bytes) => bytes.len() as u64,
        NativeName::Utf16(units) => (units.len() as u64).saturating_mul(2),
    };
    let context_bytes = context.map_or(0, |context| match context {
        CandidateContext::Fat(map) => {
            (map.ranges().len() as u64).saturating_mul(core::mem::size_of::<
                crate::forensics_fat_extract::FatCandidateRange,
            >() as u64)
        }
        CandidateContext::Ntfs {
            candidate,
            assessments,
        } => (candidate.raw_record().len() as u64).saturating_add(
            (assessments.len() as u64).saturating_mul(core::mem::size_of::<
                crate::forensics_ntfs::RangeReuseAssessment,
            >() as u64),
        ),
    });
    let manifest_bytes = source
        .acquisition_manifest()
        .map_or(0, |manifest| manifest.metadata_bytes())
        .saturating_add(
            (source.unavailable_ranges().len() as u64)
                .saturating_mul(core::mem::size_of::<ByteRange>() as u64),
        );
    let labels = source
        .identity()
        .acquisition
        .len()
        .saturating_add(source.identity().source.len())
        .saturating_add(source.identity().stability_provider.len()) as u64;
    let early_stop = if control.cancelled() || resources.cancellation.check().is_err() {
        Some(StopReason::Cancelled)
    } else if name_bytes
        .saturating_add(labels)
        .saturating_add(manifest_bytes)
        .saturating_add(context_bytes)
        > request.limits.memory_bytes
    {
        Some(StopReason::ResourceLimit("manifest_metadata_bytes"))
    } else {
        let metadata = (|| -> io::Result<()> {
            forensics_json::source(&mut capped, source)?;
            forensics_json::acquisition_manifest(&mut capped, source)?;
            if let Some(live) = live {
                writeln!(
                    capped,
                    "{{\"version\":1,\"type\":\"ntfs_stream_selection\",\"record\":{},\"physical_mapping\":\"not_claimed_decoded_logical_stream\"}}",
                    live.record
                )?;
            }
            match context {
                Some(CandidateContext::Fat(map)) => {
                    forensics_json::fat_candidate_context(&mut capped, map)?
                }
                Some(CandidateContext::Ntfs {
                    candidate,
                    assessments,
                }) => forensics_json::ntfs_candidate_context(&mut capped, candidate, assessments)?,
                None => {}
            }
            capped.write_all(b"{\"version\":1,\"type\":\"native_name\",\"encoding\":")?;
            forensics_json::string(
                &mut capped,
                match request.name {
                    NativeName::Bytes(_) => "bytes",
                    NativeName::Utf16(_) => "utf16",
                },
            )?;
            capped.write_all(b",\"units\":[")?;
            for index in 0..name_units {
                if index % 256 == 0
                    && (control.cancelled() || resources.cancellation.check().is_err())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "export cancelled",
                    ));
                }
                let unit = match request.name {
                    NativeName::Bytes(bytes) => u16::from(bytes[index]),
                    NativeName::Utf16(units) => units[index],
                };
                if index != 0 {
                    capped.write_all(b",")?;
                }
                write!(capped, "{unit}")?;
            }
            capped.write_all(b"]}\n")
        })();
        metadata.err().map(|error| {
            if capped.exhausted {
                StopReason::ResourceLimit("export_output_bytes")
            } else if control.cancelled()
                || resources.cancellation.check().is_err()
                || error.kind() == io::ErrorKind::Interrupted
            {
                StopReason::Cancelled
            } else {
                StopReason::DeliveryFailed(error.into())
            }
        })
    };
    let outcome = if let Some(reason) = early_stop {
        let mut scan = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: if live.is_some() {
                    source.len()
                } else {
                    request.length
                },
            },
            if live.is_some() {
                "ntfs-live-stream/bootstrap"
            } else {
                "candidate-extraction-v1"
            },
        )
        .with_source_id(source.id());
        if live.is_none() {
            scan.coordinate_space = crate::forensics::CoordinateSpace::LogicalStreamBytes;
        }
        scan.stop_reason = reason;
        ExtractionOutcome {
            scan,
            output_bytes: 0,
            prefix_sha256: Sha256::digest([]).into(),
        }
    } else if let Some(live) = live {
        let NativeName::Utf16(name) = live.name else {
            unreachable!("validated by live wrapper")
        };
        crate::forensics_ntfs_extract::extract_live_stream(
            source,
            live.record,
            name,
            live.read,
            live.streams,
            live.compression,
            live.limits,
            resources,
            control,
            |event| {
                use crate::forensics_ntfs_extract::StreamExtractionEvent;
                match event {
                    StreamExtractionEvent::Extent(extent) => {
                        capped.write_all(
                            b"{\"version\":1,\"type\":\"ntfs_logical_extent\",\"stream_range\":",
                        )?;
                        forensics_json::range(
                            &mut capped,
                            ByteRange {
                                offset: extent.offset,
                                length: extent.length,
                            },
                        )?;
                        capped.write_all(b",\"kind\":")?;
                        forensics_json::string(
                            &mut capped,
                            match extent.kind {
                                crate::fs_core::ExtentKind::Data => "data",
                                crate::fs_core::ExtentKind::Hole => "sparse",
                                crate::fs_core::ExtentKind::Unwritten => "unwritten",
                            },
                        )?;
                        capped.write_all(b",\"physical_mapping\":null}\n")?;
                    }
                    StreamExtractionEvent::Bytes { bytes, .. } => {
                        capped.charge(bytes.len() as u64)?;
                        file.write_all(bytes)?;
                    }
                    StreamExtractionEvent::Coverage(event) => {
                        forensics_json::coverage(&mut capped, event)?
                    }
                }
                Ok(())
            },
        )
    } else {
        extract_ranges(
            source,
            request.length,
            request.ranges,
            request.limits,
            resources,
            control,
            &mut |event| match event {
                ExtractionEvent::Range(range) => {
                    forensics_json::extraction_range(&mut capped, source, range)?;
                    Ok(())
                }
                ExtractionEvent::Bytes { bytes, .. } => {
                    capped.charge(bytes.len() as u64)?;
                    file.write_all(bytes)?;
                    Ok(())
                }
                ExtractionEvent::Coverage(event) => {
                    forensics_json::coverage(&mut capped, event)?;
                    Ok(())
                }
            },
        )
    };
    // Cancellation observed after a causal scan failure must not erase it.
    state.outcome = Some(outcome);
    let Some(outcome) = state.outcome.as_mut() else {
        return Err(io::Error::other("export outcome unavailable"));
    };
    if matches!(outcome.scan.stop_reason, StopReason::Completed)
        && (control.cancelled() || resources.cancellation.check().is_err())
    {
        outcome.scan.stop_reason = StopReason::Cancelled;
    }
    if capped.exhausted {
        outcome.scan.stop_reason = StopReason::ResourceLimit("export_output_bytes");
    }
    let at_line_start = capped.at_line_start;
    finalize_output(&mut file, &mut log, state, at_line_start)?;
    let outcome = state
        .outcome
        .take()
        .ok_or_else(|| io::Error::other("export outcome unavailable"))?;
    let prior_scan = state.prior_scan.take();
    Ok(ExportResult {
        output,
        manifest,
        prior_scan,
        outcome,
    })
}

trait DurableWrite: Write {
    fn sync_all(&mut self) -> io::Result<()>;
}
impl DurableWrite for File {
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}
fn finalize_output(
    file: &mut impl DurableWrite,
    log: &mut impl DurableWrite,
    state: &mut ExportState,
    at_line_start: bool,
) -> io::Result<()> {
    let Some(outcome) = state.outcome.as_mut() else {
        return Err(io::Error::other("export outcome unavailable"));
    };
    // A failed metadata write can leave a partial JSON record. Start terminal
    // reporting on a fresh line; consumers must reject the malformed prefix.
    if !at_line_start {
        log.write_all(b"\n")?;
    }
    let data_failure = file
        .flush()
        .and_then(|()| file.sync_all())
        .err()
        .map(std::sync::Arc::new);
    if let Some(error) = &data_failure {
        let failed = ScanOutcome {
            source_id: outcome.scan.source_id,
            coordinate_space: outcome.scan.coordinate_space,
            domain: outcome.scan.domain,
            profile: outcome.scan.profile,
            observations: outcome.scan.observations,
            coverage_events: outcome.scan.coverage_events,
            last_delivered: outcome.scan.last_delivered,
            unvisited: outcome.scan.unvisited,
            stop_reason: StopReason::DeliveryFailed(crate::io::Error::other(SharedExportIo(
                error.clone(),
            ))),
        };
        let prior = core::mem::replace(&mut outcome.scan, failed);
        // The final terminal describes host delivery. Keep the preceding logical
        // traversal status (including its causal error) as a separate phase.
        state.prior_scan = Some(prior);
        log.write_all(
            b"{\"version\":1,\"type\":\"export_phase\",\"phase\":\"before_output_sync_failure\"}\n",
        )?;
        if let Some(prior) = &state.prior_scan {
            forensics_json::terminal(log, prior)?;
        }
    }
    write!(
        log,
        "{{\"version\":1,\"type\":\"output_hash\",\"domain\":\"extracted_output_prefix\",\"bytes\":{},\"sha256\":\"",
        outcome.output_bytes
    )?;
    for byte in outcome.prefix_sha256 {
        write!(log, "{byte:02x}")?;
    }
    log.write_all(b"\",\"verified_original\":false}\n")?;
    forensics_json::terminal(log, &outcome.scan)?;
    log.flush()?;
    log.sync_all()?;
    state.terminal_delivered = true;
    if let Some(error) = data_failure {
        return Err(io::Error::new(error.kind(), SharedExportIo(error)));
    }
    Ok(())
}

/// Export a FAT map with raw slot evidence, range hypotheses and independent
/// mapping/ownership outcomes in the standalone extraction manifest.
/// An incomplete mapping is rejected; incomplete ownership stays explicitly unknown.
pub fn export_fat_candidate(
    directory: &Path,
    map: &crate::forensics_fat_extract::FatCandidateMap,
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
) -> Result<ExportResult, Box<ExportFailure>> {
    let admission = (|| -> io::Result<_> {
        if !map.mapping.is_complete() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate mapping is incomplete",
            ));
        }
        let charge = (map.ranges().len() as u64)
            .saturating_mul(core::mem::size_of::<ExtractionRange>() as u64)
            .saturating_add(11);
        if charge > limits.memory_bytes {
            return Err(io::Error::other("candidate export memory ceiling"));
        }
        let _reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(map.ranges().len())
            .map_err(io::Error::other)?;
        ranges.extend(map.ranges().iter().map(|range| range.extraction));
        let name = NativeName::Bytes(
            map.slot
                .alias()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "candidate has no native alias")
                })?
                .to_vec(),
        );
        Ok((_reservation, ranges, name))
    })();
    let (_reservation, ranges, name) =
        admission.map_err(|error| ExportState::new(map.source(), map.length).fail(error))?;
    export_with_context(
        directory,
        map.source(),
        ExportRequest {
            name: &name,
            length: map.length,
            ranges: &ranges,
            limits,
        },
        resources,
        control,
        Some(CandidateContext::Fat(map)),
        None,
    )
}

/// Export a free-record NTFS candidate with exact native record evidence and
/// independent bitmap/current-owner outcomes. Missing assessments stay unknown.
/// Completed extraction never authenticates retained historical bytes.
pub fn export_ntfs_candidate(
    directory: &Path,
    candidate: &crate::forensics_ntfs::DeletedStreamCandidate,
    assessments: &[Option<crate::forensics_ntfs::RangeReuseAssessment>],
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
) -> Result<ExportResult, Box<ExportFailure>> {
    let admission = (|| -> io::Result<_> {
        if assessments.len() != candidate.ranges.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "one assessment position per candidate range required",
            ));
        }
        if assessments.iter().flatten().any(|assessment| {
            assessment.bitmap_outcome.source_id != Some(candidate.source().id())
                || assessment.ownership_outcome.source_id != Some(candidate.source().id())
                || assessment
                    .conflicting_owner
                    .is_some_and(|owner| owner.source_id != candidate.source().id())
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate reuse assessment/source view mismatch",
            ));
        }
        let charge = (candidate.ranges.len() as u64)
            .saturating_mul(core::mem::size_of::<ExtractionRange>() as u64)
            .saturating_add((candidate.name.len() as u64).saturating_mul(2));
        if charge > limits.memory_bytes {
            return Err(io::Error::other("candidate export memory ceiling"));
        }
        let _reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(candidate.ranges.len())
            .map_err(io::Error::other)?;
        for (range, assessment) in candidate.ranges.iter().zip(assessments) {
            let mut range = *range;
            range.reuse = assessment.as_ref().map_or(
                crate::forensics_extract::ReuseEvidence::Unknown,
                |assessment| assessment.reuse_evidence(),
            );
            ranges.push(range);
        }
        let name = NativeName::Utf16(candidate.name.clone());
        Ok((_reservation, ranges, name))
    })();
    let (_reservation, ranges, name) = admission
        .map_err(|error| ExportState::new(candidate.source(), candidate.length).fail(error))?;
    export_with_context(
        directory,
        candidate.source(),
        ExportRequest {
            name: &name,
            length: candidate.length,
            ranges: &ranges,
            limits,
        },
        resources,
        control,
        Some(CandidateContext::Ntfs {
            candidate,
            assessments,
        }),
        None,
    )
}

struct ManifestWriter<'a> {
    output: &'a mut File,
    remaining: u64,
    exhausted: bool,
    at_line_start: bool,
    control: &'a dyn ScanControl,
    cancellation: &'a crate::fs_core::Cancellation,
}
impl ManifestWriter<'_> {
    fn charge(&mut self, bytes: u64) -> io::Result<()> {
        if bytes > self.remaining {
            self.exhausted = true;
            return Err(io::Error::other("export output limit"));
        }
        self.remaining -= bytes;
        Ok(())
    }
}
impl Write for ManifestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.control.cancelled() || self.cancellation.check().is_err() {
            // write_all retries Interrupted indefinitely; cancellation is terminal.
            return Err(io::Error::other("export cancelled"));
        }
        if bytes.len() as u64 > self.remaining {
            self.exhausted = true;
            return Err(io::Error::other("manifest output limit"));
        }
        let count = self.output.write(bytes)?;
        self.remaining -= count as u64;
        if count != 0 {
            self.at_line_start = bytes[count - 1] == b'\n';
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        forensics::{AcquisitionLease, ByteRange, NeverCancel, SourceIdentity},
        forensics_extract::{ExtractionKind, ReuseEvidence},
        fs_core::{Budget, Cancellation},
        io::ReadAt,
    };
    use std::sync::{Arc, atomic::AtomicBool};
    #[derive(Default)]
    struct FaultWriter {
        bytes: Vec<u8>,
        fail_write: bool,
        fail_flush: bool,
        fail_sync: bool,
    }
    impl Write for FaultWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::other("terminal write fault"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("flush fault"))
            } else {
                Ok(())
            }
        }
    }
    impl DurableWrite for FaultWriter {
        fn sync_all(&mut self) -> io::Result<()> {
            if self.fail_sync {
                Err(io::Error::other("sync fault"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn terminal_delivery_faults_preserve_traversal_and_prefix() {
        for stage in 0..3 {
            let source = source();
            let mut state = ExportState::new(&source, 4);
            let prior = state.outcome.as_mut().unwrap();
            prior.scan.stop_reason = StopReason::Io(crate::io::Error::other("source fault"));
            prior.scan.observations = 7;
            prior.output_bytes = 3;
            prior.prefix_sha256 = Sha256::digest(b"abc").into();
            let mut log = FaultWriter {
                fail_write: stage == 0,
                fail_flush: stage == 1,
                fail_sync: stage == 2,
                ..FaultWriter::default()
            };
            let error = finalize_output(&mut FaultWriter::default(), &mut log, &mut state, true)
                .unwrap_err();
            let failure = state.fail(error);
            assert!(!failure.terminal_delivered);
            assert!(matches!(
                failure.outcome.scan.stop_reason,
                StopReason::DeliveryFailed(_)
            ));
            assert!(matches!(
                failure.prior_outcome.scan.stop_reason,
                StopReason::Io(_)
            ));
            assert_eq!(failure.outcome.scan.source_id, Some(source.id()));
            assert_eq!(failure.outcome.scan.observations, 7);
            assert_eq!(failure.outcome.output_bytes, 3);
            assert_eq!(
                failure.outcome.prefix_sha256,
                <[u8; 32]>::from(Sha256::digest(b"abc"))
            );
        }
    }
    #[test]
    fn data_sync_fault_retains_prior_scan_even_when_terminal_also_fails() {
        for terminal_fails in [false, true] {
            let mut state = ExportState::new(&source(), 4);
            state.outcome.as_mut().unwrap().scan.stop_reason = StopReason::Completed;
            state.outcome.as_mut().unwrap().scan.unvisited = ByteRange {
                offset: 4,
                length: 0,
            };
            let mut data = FaultWriter {
                fail_sync: true,
                ..FaultWriter::default()
            };
            let mut log = FaultWriter {
                fail_write: terminal_fails,
                ..FaultWriter::default()
            };
            let error = finalize_output(&mut data, &mut log, &mut state, true).unwrap_err();
            let failure = state.fail(error);
            assert_eq!(failure.terminal_delivered, !terminal_fails);
            assert!(failure.prior_scan.unwrap().is_complete());
            assert!(matches!(
                failure.prior_outcome.scan.stop_reason,
                StopReason::DeliveryFailed(_)
            ));
            assert!(matches!(
                failure.outcome.scan.stop_reason,
                StopReason::DeliveryFailed(_)
            ));
        }
    }
    struct Bytes;
    impl ReadAt for Bytes {
        fn len(&self) -> u64 {
            1024
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> crate::io::Result<()> {
            ByteRange::checked(offset, bytes.len() as u64, self.len())?;
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (offset + index as u64) as u8;
            }
            Ok(())
        }
    }
    fn source() -> ForensicSource {
        ForensicSource::new(
            Arc::new(Bytes),
            SourceIdentity {
                acquisition: "test".into(),
                source: "bytes".into(),
                stability_provider: "lease".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange {
                offset: 512,
                length: 512,
            },
            vec![],
        )
        .unwrap()
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn range(kind: ExtractionKind) -> ExtractionRange {
        ExtractionRange {
            logical: ByteRange {
                offset: 0,
                length: 4,
            },
            kind,
            reuse: ReuseEvidence::Unknown,
        }
    }
    #[test]
    fn hostile_native_names_never_resolve_paths_and_collisions_are_exclusive() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("candidate-000000.partial"), b"untouched").unwrap();
        let name = NativeName::Bytes(b"../../escape\0\n".to_vec());
        let ranges = [range(ExtractionKind::Data(3))];
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 4,
                ranges: &ranges,
                limits: ScanLimits::default(),
            },
            &resources(),
            &NeverCancel,
        )
        .unwrap();
        assert!(result.outcome.scan.is_complete());
        assert_eq!(
            fs::read(root.path().join("candidate-000000.partial")).unwrap(),
            b"untouched"
        );
        assert_eq!(
            result.output.file_name().unwrap(),
            "candidate-000001.partial"
        );
        assert_eq!(fs::read(&result.output).unwrap(), [3, 4, 5, 6]);
        let manifest = fs::read_to_string(result.manifest).unwrap();
        assert!(manifest.contains("\"stream_range\":{\"offset\":0,\"length\":4}"));
        assert!(manifest.contains("\"volume_range\":{\"offset\":3,\"length\":4}"));
        assert!(manifest.contains("\"logical_disk_range\":{\"offset\":515,\"length\":4}"));
        assert!(manifest.contains("\"units\":[46,46,47,46,46,47,101,115,99,97,112,101,0,10]"));
        assert!(manifest.contains("\"complete\":true"));
        assert!(
            manifest
                .lines()
                .all(|line| line.starts_with('{') && line.ends_with('}'))
        );
    }
    #[test]
    fn unavailable_and_cancelled_exports_keep_partial_files_and_terminal_status() {
        let root = tempfile::tempdir().unwrap();
        let name = NativeName::Utf16(vec![0xd800, 47, 0]);
        let ranges = [range(ExtractionKind::Unavailable)];
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 4,
                ranges: &ranges,
                limits: ScanLimits::default(),
            },
            &resources(),
            &NeverCancel,
        )
        .unwrap();
        assert!(!result.outcome.scan.is_complete());
        assert!(result.output.ends_with("candidate-000000.partial"));
        assert!(fs::read(result.output).unwrap().is_empty());
        let manifest = fs::read_to_string(result.manifest).unwrap();
        assert!(manifest.contains("\"units\":[55296,47,0]"));
        assert!(manifest.contains("\"stop_reason\":\"io_failure\""));
        let cancelled = AtomicBool::new(true);
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 4,
                ranges: &ranges,
                limits: ScanLimits::default(),
            },
            &resources(),
            &cancelled,
        )
        .unwrap();
        assert!(matches!(
            result.outcome.scan.stop_reason,
            StopReason::Cancelled
        ));
        assert!(
            fs::read_to_string(result.manifest)
                .unwrap()
                .contains("\"stop_reason\":\"cancelled\"")
        );
    }
    #[cfg(unix)]
    #[test]
    fn existing_symlink_collisions_never_follow_external_targets() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("candidate-000000.partial"))
            .unwrap();
        let name = NativeName::Bytes(b"../../outside".to_vec());
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 0,
                ranges: &[],
                limits: ScanLimits::default(),
            },
            &resources(),
            &NeverCancel,
        )
        .unwrap();
        assert_eq!(fs::read(outside.path()).unwrap(), b"outside");
        assert!(result.output.ends_with("candidate-000001.partial"));
    }
    #[test]
    fn acquisition_manifest_keeps_parent_overlay_and_hash_domains_explicit() {
        use crate::forensics::{
            AcquisitionManifest, AcquisitionTime, EvidenceDigest, EvidenceInput, EvidenceInputRole,
            HashDomain,
        };
        let source = source()
            .with_acquisition_manifest(AcquisitionManifest {
                started: Some(AcquisitionTime {
                    unix_seconds: 1,
                    nanoseconds: 2,
                }),
                completed: None,
                consistency_uncertainty: "changing original media".into(),
                inputs: vec![
                    EvidenceInput {
                        role: EvidenceInputRole::Parent,
                        identity_label: "parent label".into(),
                        digest: None,
                    },
                    EvidenceInput {
                        role: EvidenceInputRole::ImmutableRecoveryOverlay,
                        identity_label: "overlay label".into(),
                        digest: Some(EvidenceDigest {
                            domain: HashDomain::OriginalContainerBytes,
                            sha256: [1; 32],
                        }),
                    },
                ],
                digests: vec![
                    EvidenceDigest {
                        domain: HashDomain::LogicalDiskBytes,
                        sha256: [2; 32],
                    },
                    EvidenceDigest {
                        domain: HashDomain::SelectedEvidenceRange(ByteRange {
                            offset: 512,
                            length: 4,
                        }),
                        sha256: [3; 32],
                    },
                ],
            })
            .unwrap();
        let mut bytes = Vec::new();
        forensics_json::acquisition_manifest(&mut bytes, &source).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"started\":{\"unix_seconds\":1,\"nanoseconds\":2}"));
        assert!(text.contains("\"completed\":null"));
        assert!(text.contains("\"role\":\"parent\""));
        assert!(text.contains("\"role\":\"immutable_recovery_overlay\""));
        assert!(text.contains("\"domain\":\"original_container_bytes\""));
        assert!(text.contains("\"domain\":\"logical_disk_bytes\""));
        assert!(text.contains(
            "\"domain\":\"selected_evidence_range\",\"range\":{\"offset\":512,\"length\":4}"
        ));
        assert!(text.contains("\"verified_original\":false"));
    }
    #[test]
    fn cancelled_manifest_writer_returns_a_terminal_nonretryable_error() {
        let cancelled = AtomicBool::new(true);
        let resources = resources();
        let mut file = tempfile::tempfile().unwrap();
        let mut writer = ManifestWriter {
            output: &mut file,
            remaining: 1024,
            exhausted: false,
            at_line_start: true,
            control: &cancelled,
            cancellation: &resources.cancellation,
        };
        let error = writer.write(b"record").unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::Interrupted);
        assert!(writer.write_all(b"record").is_err());
    }
    #[test]
    fn late_cancellation_preserves_read_failure_and_delivered_metadata() {
        struct Fault(Arc<AtomicBool>);
        struct LateCancellation {
            read_failed: Arc<AtomicBool>,
            cancelled: Arc<AtomicBool>,
        }
        impl crate::forensics::StabilityProvider for LateCancellation {
            fn check(&self) -> crate::io::Result<()> {
                if self.read_failed.load(std::sync::atomic::Ordering::Acquire) {
                    self.cancelled
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                Ok(())
            }
        }
        impl ReadAt for Fault {
            fn len(&self) -> u64 {
                512
            }
            fn read_exact_at(&self, _: u64, _: &mut [u8]) -> crate::io::Result<()> {
                self.0.store(true, std::sync::atomic::Ordering::Release);
                Err(crate::io::Error::other("causal data failure"))
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let read_failed = Arc::new(AtomicBool::new(false));
        let source = ForensicSource::new(
            Arc::new(Fault(read_failed.clone())),
            SourceIdentity {
                acquisition: "fault-fixture".into(),
                source: "immutable fault map".into(),
                stability_provider: "lease".into(),
            },
            Arc::new(LateCancellation {
                read_failed,
                cancelled: cancelled.clone(),
            }),
            ByteRange {
                offset: 0,
                length: 512,
            },
            vec![],
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let name = NativeName::Bytes(b"candidate".to_vec());
        let ranges = [range(ExtractionKind::Data(0))];
        let result = export(
            root.path(),
            &source,
            ExportRequest {
                name: &name,
                length: 4,
                ranges: &ranges,
                limits: ScanLimits::default(),
            },
            &resources(),
            cancelled.as_ref(),
        )
        .unwrap();
        assert!(matches!(result.outcome.scan.stop_reason, StopReason::Io(_)));
        assert_eq!(result.outcome.scan.observations, 1);
        assert_eq!(
            result.outcome.scan.unvisited,
            ByteRange {
                offset: 0,
                length: 4
            }
        );
        let manifest = fs::read_to_string(result.manifest).unwrap();
        assert!(manifest.contains("causal data failure"));
        assert!(manifest.contains("\"stop_reason\":\"io_failure\""));
    }
    #[test]
    fn metadata_limits_still_deliver_terminal_outcomes() {
        let root = tempfile::tempdir().unwrap();
        let name = NativeName::Bytes(vec![1; 1024]);
        let limits = ScanLimits {
            memory_bytes: 64,
            ..ScanLimits::default()
        };
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 0,
                ranges: &[],
                limits,
            },
            &resources(),
            &NeverCancel,
        )
        .unwrap();
        assert!(matches!(
            result.outcome.scan.stop_reason,
            StopReason::ResourceLimit("manifest_metadata_bytes")
        ));
        assert!(
            fs::read_to_string(result.manifest)
                .unwrap()
                .contains("\"type\":\"terminal\"")
        );
        let limits = ScanLimits {
            output_bytes: 0,
            ..ScanLimits::default()
        };
        let result = export(
            root.path(),
            &source(),
            ExportRequest {
                name: &name,
                length: 0,
                ranges: &[],
                limits,
            },
            &resources(),
            &NeverCancel,
        )
        .unwrap();
        assert!(matches!(
            result.outcome.scan.stop_reason,
            StopReason::ResourceLimit("export_output_bytes")
        ));
        assert!(
            fs::read_to_string(result.manifest)
                .unwrap()
                .contains("\"type\":\"terminal\"")
        );
    }
}
