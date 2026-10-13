//! Read-only forensic JSONL inventory and qualified FAT candidate extraction.
//! Run with --help for supported profiles and acquisition prerequisites.
use partmgr::{
    forensics::{
        AcquisitionLease, ByteRange, ForensicSource, NeverCancel, ScanLimits, ScanOutcome,
        SourceIdentity, StopReason,
    },
    forensics_export,
    forensics_fat::{FatAllocationKind, FatForensics, FatSlotKind, FatSlotObservation},
    forensics_fat_extract::{FatRecoveryPolicy, map_fat_candidate},
    forensics_json as json,
    forensics_ntfs::{self, InventoryEvent},
    forensics_timeline::{self, TimelineEvent},
    forensics_timeline_spool::TemporalSpool,
    fs_core::{Budget, Cancellation, NativeName, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
    sync::Arc,
};
use virtdisk::{ImageFormat, ReadAt, ReaderOpenOptions};

const HELP: &str = "filesystem-forensics COMMAND IMAGE --format raw|vdi|vhdx|qcow2|vmdk --sector-size N\n  --assert-stable --acquisition-id ID --stability-provider PROVIDER\n  [--offset N --length N | --partition N] [--parent PATH ...]\n  [--records N --read-bytes N --output-bytes N --memory-bytes N]\n  Timeline sorting: --sort --temporary-dir DIRECTORY (FAT requires timezone)\nCommands:\n  inventory-ntfs     raw MFT slots, independent bitmap bits and validation\n  extract-ntfs       --record N --output-dir DIRECTORY [--stream-name-utf16 HEX,...]\n                    [--allow-lznt1] validated live DATA/ADS streams\n  recover-ntfs       --record N --output-dir DIRECTORY [--stream-name-utf16 HEX,...]\n                    qualified free-record candidates, never verified originals\n  inspect-usn        validated journal namespace, retention, records and gaps\n                    [--directory-entries N]\n  inspect-logfile    restart copies only, without replay\n  timeline-usn       validated journal records; [--sort --temporary-dir DIRECTORY]\n  timeline-ntfs      both native timestamp sets; source order unless --sort\n  timeline-fat       alias timestamps; --directory-offset N --directory-length N\n                    [--utc-offset-seconds N]; absent timezone remains unknown\n  allocation-fat    entries from every FAT copy\n  compare-fat-copies  independent raw/decoded disagreements; no historical authority\n  compare-fat-chains  --start-cluster N --chain-transitions N; every copy independently\n  slots-fat         --directory-offset N --directory-length N\n  extract-fat       --directory-offset N --directory-length N --slot-offset N\n                    --output-dir DIRECTORY [--contiguous-hypothesis]\nSource offsets are logical disk bytes; directory offsets are selected-volume bytes.\nThe stable assertion requires an externally held immutable artifact/snapshot/offline\nacquisition for this entire process. Read-only opening alone supplies no stability.\nDirect physical devices are intentionally unavailable in this CLI. Recovery outputs\nremain qualified candidates, never verified historical content. Partial scans fail.\nNo journal replay, editing or repair. Container parents require explicit --parent.\n";

type Error = Box<dyn std::error::Error>;
struct Options {
    command: String,
    image: String,
    values: BTreeMap<String, String>,
    parents: Vec<String>,
}
impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Self>, Error> {
        let Some(command) = args.next() else {
            return Err(HELP.into());
        };
        if command == "--help" || command == "-h" {
            return Ok(None);
        }
        if !matches!(
            command.as_str(),
            "inventory-ntfs"
                | "extract-ntfs"
                | "recover-ntfs"
                | "inspect-usn"
                | "timeline-usn"
                | "inspect-logfile"
                | "timeline-ntfs"
                | "timeline-fat"
                | "allocation-fat"
                | "compare-fat-copies"
                | "compare-fat-chains"
                | "slots-fat"
                | "extract-fat"
        ) {
            return Err("unsupported command (use --help)".into());
        }
        let image = args.next().ok_or("missing image path")?;
        let mut options = Self {
            command,
            image,
            values: BTreeMap::new(),
            parents: Vec::new(),
        };
        while let Some(key) = args.next() {
            if key == "--parent" {
                options
                    .parents
                    .push(args.next().ok_or("missing parent path")?);
                continue;
            }
            let value = if key == "--assert-stable"
                || key == "--contiguous-hypothesis"
                || key == "--allow-lznt1"
                || key == "--sort"
            {
                "true".into()
            } else {
                args.next().ok_or("missing option value")?
            };
            if !matches!(
                key.as_str(),
                "--format"
                    | "--sector-size"
                    | "--assert-stable"
                    | "--acquisition-id"
                    | "--stability-provider"
                    | "--offset"
                    | "--length"
                    | "--partition"
                    | "--records"
                    | "--read-bytes"
                    | "--output-bytes"
                    | "--memory-bytes"
                    | "--directory-offset"
                    | "--directory-length"
                    | "--slot-offset"
                    | "--output-dir"
                    | "--contiguous-hypothesis"
                    | "--utc-offset-seconds"
                    | "--record"
                    | "--stream-name-utf16"
                    | "--allow-lznt1"
                    | "--sort"
                    | "--temporary-dir"
                    | "--directory-entries"
                    | "--start-cluster"
                    | "--chain-transitions"
            ) {
                return Err(format!("unknown option {key}").into());
            }
            if options.values.insert(key, value).is_some() {
                return Err("duplicate option".into());
            }
        }
        for key in options.values.keys() {
            let allowed = match key.as_str() {
                "--directory-offset" | "--directory-length" => matches!(
                    options.command.as_str(),
                    "slots-fat" | "timeline-fat" | "extract-fat"
                ),
                "--slot-offset" | "--contiguous-hypothesis" => options.command == "extract-fat",
                "--output-dir" => {
                    matches!(
                        options.command.as_str(),
                        "extract-fat" | "extract-ntfs" | "recover-ntfs"
                    )
                }
                "--record" | "--stream-name-utf16" => {
                    matches!(options.command.as_str(), "extract-ntfs" | "recover-ntfs")
                }
                "--allow-lznt1" => options.command == "extract-ntfs",
                "--start-cluster" | "--chain-transitions" => {
                    options.command == "compare-fat-chains"
                }
                "--utc-offset-seconds" => options.command == "timeline-fat",
                "--directory-entries" => {
                    matches!(options.command.as_str(), "inspect-usn" | "timeline-usn")
                }
                "--sort" | "--temporary-dir" => {
                    matches!(
                        options.command.as_str(),
                        "timeline-fat" | "timeline-ntfs" | "timeline-usn"
                    )
                }
                _ => true,
            };
            if !allowed {
                return Err(format!("{key} is unsupported for {}", options.command).into());
            }
        }
        if options.values.contains_key("--sort") != options.values.contains_key("--temporary-dir") {
            return Err("--sort and --temporary-dir must be supplied together".into());
        }
        Ok(Some(options))
    }
    fn required(&self, key: &str) -> Result<&str, Error> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {key}").into())
    }
    fn number(&self, key: &str, default: u64) -> Result<u64, Error> {
        self.values
            .get(key)
            .map_or(Ok(default), |value| Ok(value.parse()?))
    }
    fn range(&self, offset: &str, length: &str) -> Result<ByteRange, Error> {
        Ok(ByteRange {
            offset: self.required(offset)?.parse()?,
            length: self.required(length)?.parse()?,
        })
    }
}
struct Output<W> {
    inner: W,
    remaining: u64,
    exhausted: bool,
    line_start: bool,
}
impl<W: Write> Write for Output<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exhausted = true;
            return Err(io::Error::other("JSONL output ceiling"));
        }
        let count = self.inner.write(bytes)?;
        self.remaining -= count as u64;
        if count != 0 {
            self.line_start = bytes[count - 1] == b'\n';
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn hex(out: &mut dyn Write, bytes: &[u8]) -> io::Result<()> {
    out.write_all(b"\"")?;
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    out.write_all(b"\"")
}
fn nullable_bool(
    out: &mut dyn Write,
    result: &partmgr::fs_core::Result<Option<bool>>,
) -> io::Result<()> {
    match result {
        Ok(Some(value)) => write!(out, "{value}"),
        Ok(None) | Err(_) => out.write_all(b"null"),
    }
}
fn validation_error(
    out: &mut dyn Write,
    error: Option<&partmgr::fs_core::Error>,
) -> io::Result<()> {
    match error {
        Some(error) => json::string(out, &error.to_string()),
        None => out.write_all(b"null"),
    }
}
fn ntfs_slot(
    out: &mut dyn Write,
    source: &ForensicSource,
    slot: &forensics_ntfs::SlotObservation<'_>,
) -> io::Result<()> {
    if slot.source_id != Some(source.id()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NTFS slot/source view mismatch",
        ));
    }
    write!(
        out,
        "{{\"version\":1,\"type\":\"ntfs_slot\",\"source_id\":{},\"slot\":{},\"mft_stream_offset\":{},\"volume_ranges\":[",
        source.id().get(),
        slot.slot,
        slot.stream_offset
    )?;
    for (index, range) in slot.volume_ranges.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        json::range(out, *range)?;
    }
    out.write_all(b"],\"logical_disk_ranges\":[")?;
    for (index, range) in slot.volume_ranges.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        json::range(
            out,
            source.translate_range(*range).map_err(io::Error::other)?,
        )?;
    }
    out.write_all(b"],\"raw_hex\":")?;
    hex(out, slot.raw)?;
    out.write_all(b",\"allocated_bitmap_bit\":")?;
    nullable_bool(out, &slot.allocated)?;
    out.write_all(b",\"bitmap_error\":")?;
    validation_error(out, slot.allocated.as_ref().err())?;
    out.write_all(b",\"mirror_agrees\":")?;
    nullable_bool(out, &slot.mirror_agrees)?;
    out.write_all(b",\"mirror_error\":")?;
    validation_error(out, slot.mirror_agrees.as_ref().err())?;
    match &slot.decoded {
        Ok(Some(record)) => {
            write!(
                out,
                ",\"validation\":\"validated_framing\",\"sequence\":{},\"file_in_use\":{},\"base_reference\":{},\"fixed_hex\":",
                record.sequence, record.in_use, record.base_reference
            )?;
            hex(out, record.fixed)?;
            out.write_all(b",\"attributes\":[")?;
            for (index, attribute) in record.attributes.iter().enumerate() {
                if index != 0 {
                    out.write_all(b",")?;
                }
                write!(
                    out,
                    "{{\"offset\":{},\"type\":{},\"raw_hex\":",
                    attribute.offset, attribute.kind
                )?;
                hex(out, attribute.raw)?;
                out.write_all(b"}")?;
            }
            out.write_all(b"]")?;
        }
        Ok(None) => out.write_all(b",\"validation\":\"empty_slot\"")?,
        Err(error) => {
            out.write_all(b",\"validation\":\"rejected\",\"validation_error\":")?;
            validation_error(out, Some(error))?;
        }
    }
    out.write_all(b",\"verified_original\":false}\n")
}
fn fat_slot(
    out: &mut dyn Write,
    source: &ForensicSource,
    slot: &FatSlotObservation,
) -> io::Result<()> {
    if slot.source_id != Some(source.id()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FAT slot/source view mismatch",
        ));
    }
    write!(
        out,
        "{{\"version\":1,\"type\":\"fat_slot\",\"source_id\":{},\"volume_range\":",
        source.id().get()
    )?;
    let range = ByteRange {
        offset: slot.offset,
        length: 32,
    };
    json::range(out, range)?;
    out.write_all(b",\"logical_disk_range\":")?;
    json::range(
        out,
        source.translate_range(range).map_err(io::Error::other)?,
    )?;
    write!(
        out,
        ",\"directory_offset\":{},\"post_terminator\":{},\"kind\":",
        slot.directory_offset, slot.post_terminator
    )?;
    json::string(
        out,
        match slot.kind {
            FatSlotKind::Terminator => "terminator",
            FatSlotKind::DeletedLongName => "deleted_lfn_fragment",
            FatSlotKind::DeletedAlias => "deleted_alias",
            FatSlotKind::LongName => "lfn_fragment",
            FatSlotKind::Label => "label",
            FatSlotKind::Directory => "directory",
            FatSlotKind::File => "file",
        },
    )?;
    out.write_all(b",\"raw_hex\":")?;
    hex(out, &slot.raw)?;
    out.write_all(b",\"verified_original\":false}\n")
}
fn fat_copy_entry(
    out: &mut dyn Write,
    source: &ForensicSource,
    entry: &partmgr::forensics_fat::FatAllocationObservation,
) -> io::Result<()> {
    if entry.source_id != source.id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FAT entry/source view mismatch",
        ));
    }
    write!(
        out,
        "{{\"source_id\":{},\"copy\":{},\"cluster\":{},\"value\":{},\"volume_range\":",
        entry.source_id.get(),
        entry.copy,
        entry.cluster,
        entry.value
    )?;
    let range = ByteRange {
        offset: entry.offset,
        length: u64::from(entry.raw_length),
    };
    json::range(out, range)?;
    out.write_all(b",\"logical_disk_range\":")?;
    json::range(
        out,
        source.translate_range(range).map_err(io::Error::other)?,
    )?;
    out.write_all(b",\"raw_hex\":")?;
    hex(out, &entry.raw[..usize::from(entry.raw_length)])?;
    out.write_all(b",\"kind\":")?;
    json::string(
        out,
        match entry.kind {
            FatAllocationKind::Free => "free",
            FatAllocationKind::Next(_) => "next",
            FatAllocationKind::End => "end",
            FatAllocationKind::Bad => "bad",
            FatAllocationKind::Reserved => "reserved",
            FatAllocationKind::OutOfRange => "out_of_range",
        },
    )?;
    out.write_all(b"}")
}
fn fs_stop(error: partmgr::fs_core::Error) -> StopReason {
    match error.kind {
        partmgr::fs_core::ErrorKind::Cancelled => StopReason::Cancelled,
        partmgr::fs_core::ErrorKind::BudgetExhausted => {
            StopReason::ResourceLimit("candidate_limits")
        }
        partmgr::fs_core::ErrorKind::Unsupported => {
            StopReason::UnsupportedCause(partmgr::io::Error::other(error))
        }
        partmgr::fs_core::ErrorKind::Io => StopReason::Io(partmgr::io::Error::other(error)),
        _ => StopReason::InvalidBootstrap(partmgr::io::Error::other(error)),
    }
}
fn finish<W: Write>(out: &RefCell<Output<W>>, mut outcome: ScanOutcome) -> Result<bool, Error> {
    let mut out = out.borrow_mut();
    if out.exhausted {
        outcome.stop_reason = StopReason::ResourceLimit("jsonl_output_bytes");
    }
    if !out.line_start {
        out.inner.write_all(b"\n")?;
    }
    json::terminal(&mut out.inner, &outcome)?;
    out.line_start = true;
    out.inner.flush()?;
    let complete = outcome.is_complete();
    eprintln!(
        "profile={} complete={} observations={} coverage_events={}",
        outcome.profile, complete, outcome.observations, outcome.coverage_events
    );
    Ok(complete)
}
fn timestamp<W: Write>(
    out: &RefCell<Output<W>>,
    spool: &Option<RefCell<TemporalSpool>>,
    event: &forensics_timeline::TimestampObservation<'_>,
) -> io::Result<()> {
    if let Some(spool) = spool {
        spool.borrow_mut().push(event).map_err(io::Error::other)
    } else {
        forensics_timeline::write_json(&mut *out.borrow_mut(), event)
    }
}
fn finish_timeline<W: Write>(
    out: &RefCell<Output<W>>,
    outcome: ScanOutcome,
    timestamps_complete: bool,
    spool: &Option<RefCell<TemporalSpool>>,
    limits: ScanLimits,
    resources: &Resources,
) -> Result<bool, Error> {
    let complete = finish(out, outcome)? && timestamps_complete;
    let Some(spool) = spool else {
        return Ok(complete);
    };
    let mut spool = spool.borrow_mut();
    if !complete {
        spool.abort_producer();
    }
    let options = partmgr::forensics_sort::TimelineSortOptions {
        chunk_bytes: (limits.memory_bytes / 2).min(4 << 20),
        max_event_bytes: spool.max_event_bytes(),
        merge_fan_in: 8,
    };
    let outcome = spool.finish(
        options,
        limits,
        resources,
        &NeverCancel,
        &mut |record| {
            out.borrow_mut().write_all(&record.event)?;
            Ok(true)
        },
        &mut |event| {
            json::coverage(&mut *out.borrow_mut(), event)?;
            Ok(())
        },
    );
    finish(out, outcome)
}
fn finish_export<W: Write>(
    out: &RefCell<Output<W>>,
    result: Result<forensics_export::ExportResult, Box<forensics_export::ExportFailure>>,
) -> Result<bool, Error> {
    match result {
        Ok(result) => {
            {
                let mut output = out.borrow_mut();
                output.write_all(b"{\"version\":1,\"type\":\"export_manifest\",\"path\":")?;
                json::string(&mut *output, &result.manifest.to_string_lossy())?;
                output.write_all(b"}\n")?;
            }
            finish(out, result.outcome.scan)
        }
        Err(failure) => {
            {
                let mut output = out.borrow_mut();
                output.write_all(
                    b"{\"version\":1,\"type\":\"export_failure\",\"manifest_terminal_delivered\":",
                )?;
                write!(output, "{},\"output\":", failure.terminal_delivered)?;
                match &failure.output {
                    Some(path) => json::string(&mut *output, &path.to_string_lossy())?,
                    None => output.write_all(b"null")?,
                }
                output.write_all(b",\"manifest\":")?;
                match &failure.manifest {
                    Some(path) => json::string(&mut *output, &path.to_string_lossy())?,
                    None => output.write_all(b"null")?,
                }
                output.write_all(b"}\n")?;
                if let Some(prior) = &failure.prior_scan {
                    json::terminal(&mut *output, prior)?;
                }
                json::terminal(&mut *output, &failure.prior_outcome.scan)?;
            }
            finish(out, failure.outcome.scan)
        }
    }
}
fn run(options: Options) -> Result<bool, Error> {
    if !options.values.contains_key("--assert-stable") {
        return Err(
            "--assert-stable requires an externally held stable acquisition (see --help)".into(),
        );
    }
    let acquisition = options.required("--acquisition-id")?;
    let provider = options.required("--stability-provider")?;
    if acquisition.is_empty() || provider.is_empty() {
        return Err("acquisition and stability-provider labels must be nonempty".into());
    }
    let sector = options.required("--sector-size")?.parse()?;
    let format = match options.required("--format")? {
        "raw" => ImageFormat::Raw,
        "vdi" => ImageFormat::Vdi,
        "vhdx" => ImageFormat::Vhdx,
        "qcow2" => ImageFormat::Qcow2,
        "vmdk" => ImageFormat::Vmdk,
        _ => return Err("unsupported explicit source format".into()),
    };
    let mut reader_options = ReaderOpenOptions::default().format(format);
    if !options.parents.is_empty() {
        reader_options =
            reader_options.authorized_paths(options.parents.iter().map(std::path::PathBuf::from));
    }
    let host = if format == ImageFormat::Raw {
        if !options.parents.is_empty() {
            return Err("raw sources do not have container parents".into());
        }
        partmgr::forensics_host::HostSource::Raw(Path::new(&options.image))
    } else {
        partmgr::forensics_host::HostSource::Container {
            path: Path::new(&options.image),
            format,
            options: &reader_options,
        }
    };
    let region =
        if options.values.contains_key("--offset") || options.values.contains_key("--length") {
            Some(options.range("--offset", "--length")?)
        } else {
            None
        };
    if region.is_some() && options.values.contains_key("--partition") {
        return Err("choose either an explicit region or a partition".into());
    }
    let mut opened = partmgr::forensics_host::open(
        host,
        SourceIdentity {
            acquisition: acquisition.into(),
            source: options.image.clone(),
            stability_provider: provider.into(),
        },
        Arc::new(AcquisitionLease::default()),
        Some(sector),
        region,
        vec![],
    )?;
    if let Some(partition) = options.values.get("--partition") {
        opened = opened.select_partition(partition.parse()?)?;
    }
    let source = &opened.source;
    let defaults = ScanLimits::default();
    let limits = ScanLimits {
        records: options.number("--records", defaults.records)?,
        read_bytes: options.number("--read-bytes", defaults.read_bytes)?,
        output_bytes: options.number("--output-bytes", defaults.output_bytes)?,
        memory_bytes: options.number("--memory-bytes", defaults.memory_bytes)?,
    };
    let resources = Resources {
        memory: Budget::new(limits.memory_bytes),
        cancellation: Cancellation::default(),
    };
    let stdout = io::stdout();
    let out = RefCell::new(Output {
        inner: io::BufWriter::new(stdout.lock()),
        remaining: limits.output_bytes,
        exhausted: false,
        line_start: true,
    });
    let header = (|| -> io::Result<()> {
        let mut out = out.borrow_mut();
        json::source(&mut *out, source)?;
        json::acquisition_manifest(&mut *out, source)
    })();
    if let Err(error) = header {
        let mut outcome = ScanOutcome::new(source.logical_disk_region(), "cli-source-metadata")
            .with_source_id(source.id())
            .with_coordinate_space(partmgr::forensics::CoordinateSpace::LogicalDiskBytes);
        outcome.stop_reason = StopReason::DeliveryFailed(error.into());
        return finish(&out, outcome);
    }
    if options.command == "timeline-fat"
        && options.values.contains_key("--sort")
        && !options.values.contains_key("--utc-offset-seconds")
    {
        let mut outcome =
            ScanOutcome::new(source.logical_disk_region(), "fat-timeline-sorted/timezone")
                .with_source_id(source.id())
                .with_coordinate_space(partmgr::forensics::CoordinateSpace::LogicalDiskBytes);
        outcome.stop_reason = StopReason::UnsupportedProfile;
        return finish(&out, outcome);
    }
    let sort_limits = limits;
    let spool = if options.values.contains_key("--sort") {
        Some(RefCell::new(TemporalSpool::new(
            Path::new(options.required("--temporary-dir")?),
            &resources,
            limits,
        )?))
    } else {
        None
    };
    let limits = ScanLimits {
        memory_bytes: limits.memory_bytes.saturating_sub(
            spool
                .as_ref()
                .map_or(0, |spool| spool.borrow().reserved_bytes()),
        ),
        ..limits
    };
    let read = NtfsReadLimits {
        attributes: 256,
        runs: 4096,
        names: 128,
    };
    let streams = NtfsStreamLimits {
        extension_records: 64,
        list_entries: 4096,
        list_bytes: 1 << 20,
        attributes: 256,
        runs: 2048,
        work: 2_000_000,
    };

    if options.command == "extract-ntfs" || options.command == "recover-ntfs" {
        let units = options
            .values
            .get("--stream-name-utf16")
            .map_or(Ok(Vec::new()), |value| {
                if value.is_empty() {
                    Ok(Vec::new())
                } else {
                    value
                        .split(',')
                        .map(|unit| u16::from_str_radix(unit, 16))
                        .collect::<Result<Vec<_>, _>>()
                }
            })?;
        let name = NativeName::Utf16(units);
        if options.command == "recover-ntfs" {
            let NativeName::Utf16(units) = &name else {
                return Err("native NTFS name required".into());
            };
            let slot = options.required("--record")?.parse()?;
            let candidate = match forensics_ntfs::bounded_deleted_stream_candidate(
                source, slot, units, read, streams, limits, &resources,
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    let mut outcome = ScanOutcome::new(
                        ByteRange {
                            offset: slot,
                            length: 1,
                        },
                        "ntfs-deleted-candidate/selected-record",
                    )
                    .with_coordinate_space(partmgr::forensics::CoordinateSpace::RecordOrdinals)
                    .with_source_id(source.id());
                    outcome.stop_reason = fs_stop(error);
                    return finish(&out, outcome);
                }
            };
            let count = candidate.ranges.len();
            if count as u64 > limits.records {
                let mut outcome = ScanOutcome::new(
                    ByteRange {
                        offset: 0,
                        length: count as u64,
                    },
                    "ntfs-candidate-ranges",
                )
                .with_coordinate_space(partmgr::forensics::CoordinateSpace::EntryOrdinals)
                .with_source_id(source.id());
                outcome.stop_reason = StopReason::ResourceLimit("records");
                return finish(&out, outcome);
            }
            let _reservation = resources.memory.reserve((count as u64).saturating_mul(
                std::mem::size_of::<Option<forensics_ntfs::RangeReuseAssessment>>() as u64,
            ))?;
            let mut assessments = Vec::new();
            assessments.try_reserve_exact(count)?;
            let mut checks_complete = true;
            for (index, range) in candidate.ranges.iter().enumerate() {
                if !matches!(
                    range.kind,
                    partmgr::forensics_extract::ExtractionKind::Data(_)
                ) {
                    assessments.push(None);
                    continue;
                }
                match forensics_ntfs::assess_candidate_range(
                    &candidate,
                    index,
                    read,
                    streams,
                    limits,
                    &NeverCancel,
                    &resources,
                ) {
                    Ok(assessment) => {
                        checks_complete &= assessment.bitmap_outcome.is_complete()
                            && assessment.ownership_outcome.is_complete();
                        assessments.push(Some(assessment));
                    }
                    Err(error) => {
                        let mut outcome = ScanOutcome::new(
                            ByteRange {
                                offset: index as u64,
                                length: 1,
                            },
                            "ntfs-reuse-assessment/range",
                        )
                        .with_coordinate_space(partmgr::forensics::CoordinateSpace::EntryOrdinals)
                        .with_source_id(source.id());
                        outcome.stop_reason = fs_stop(error);
                        json::terminal(&mut *out.borrow_mut(), &outcome)?;
                        checks_complete = false;
                        assessments.push(None);
                    }
                }
            }
            json::ntfs_candidate_context(&mut *out.borrow_mut(), &candidate, &assessments)?;
            return Ok(finish_export(
                &out,
                forensics_export::export_ntfs_candidate(
                    Path::new(options.required("--output-dir")?),
                    &candidate,
                    &assessments,
                    limits,
                    &resources,
                    &NeverCancel,
                ),
            )? && checks_complete);
        }
        let compression = options.values.contains_key("--allow-lznt1").then_some(
            partmgr::fs_ntfs::NtfsCompressionLimits {
                max_unit_bytes: 65536,
                max_units_per_read: 1024,
                max_work: 1_000_000,
            },
        );
        return finish_export(
            &out,
            forensics_export::export_ntfs_live_stream(
                Path::new(options.required("--output-dir")?),
                source,
                forensics_export::NtfsStreamExportRequest {
                    record: options.required("--record")?.parse()?,
                    name: &name,
                    read,
                    streams,
                    compression,
                    limits,
                },
                &resources,
                &NeverCancel,
            ),
        );
    }
    if options.command == "inspect-usn" || options.command == "timeline-usn" {
        let journal = partmgr::fs_ntfs_usn_extract::JournalLimits {
            record: partmgr::fs_ntfs_usn::RecordLimits {
                record_bytes: usize::try_from(limits.memory_bytes)
                    .unwrap_or(usize::MAX)
                    .min(1 << 20),
                name_units: 32768,
            },
            records: usize::try_from(limits.records).unwrap_or(usize::MAX),
            extents: 100_000,
            read_bytes: limits.read_bytes,
            work: limits.records.saturating_mul(1024),
        };
        let directories = partmgr::fs_ntfs::NtfsDirectoryLimits {
            blocks: 1024,
            entries: usize::try_from(options.number(
                "--directory-entries",
                (limits.memory_bytes / 16384).min(4096),
            )?)
            .map_err(|_| "directory entry ceiling exceeds host address space")?,
            depth: 64,
        };
        let outcome = partmgr::forensics_journal::inspect_usn(
            source,
            read,
            streams,
            directories,
            journal,
            limits,
            &NeverCancel,
            &resources,
            |event| {
                if let (
                    Some(spool),
                    partmgr::forensics_journal::UsnObservation::Record { record, .. },
                ) = (&spool, &event)
                {
                    let key = i128::from(record.timestamp_ticks) - 116_444_736_000_000_000;
                    spool.borrow_mut().push_json(Some(key), |mut writer| {
                        partmgr::forensics_journal::write_usn_json(&mut writer, &event)
                    })?;
                } else {
                    partmgr::forensics_journal::write_usn_json(&mut *out.borrow_mut(), &event)?;
                }
                Ok(true)
            },
        );
        return finish_timeline(&out, outcome, true, &spool, sort_limits, &resources);
    }
    if options.command == "inspect-logfile" {
        let log = partmgr::fs_ntfs_logfile::NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 1,
            work: 1_000_000,
        };
        let outcome = partmgr::forensics_journal::inspect_logfile(
            source,
            read,
            streams,
            log,
            limits,
            &NeverCancel,
            &resources,
            |event| {
                partmgr::forensics_journal::write_log_json(&mut *out.borrow_mut(), &event)?;
                Ok(true)
            },
        );
        return finish(&out, outcome);
    }
    if options.command == "inventory-ntfs" || options.command == "timeline-ntfs" {
        let mut timestamps_complete = true;
        let outcome = forensics_ntfs::inventory(
            source,
            read,
            streams,
            limits,
            &NeverCancel,
            &resources,
            |event| {
                match event {
                    InventoryEvent::Slot(slot) => {
                        ntfs_slot(&mut *out.borrow_mut(), source, &slot)?;
                        if options.command == "timeline-ntfs" {
                            let child = forensics_timeline::ntfs_timestamps(
                                &slot,
                                limits,
                                &NeverCancel,
                                &mut |event| {
                                    match event {
                                        TimelineEvent::Timestamp(event) => {
                                            timestamp(&out, &spool, &event)?
                                        }
                                        TimelineEvent::Coverage(event) => {
                                            json::coverage(&mut *out.borrow_mut(), event)?
                                        }
                                    }
                                    Ok(())
                                },
                            );
                            timestamps_complete &= child.is_complete();
                            json::terminal(&mut *out.borrow_mut(), &child)?;
                        }
                    }
                    InventoryEvent::Coverage(event) => {
                        json::coverage(&mut *out.borrow_mut(), event)?
                    }
                }
                Ok(true)
            },
        );
        return finish_timeline(
            &out,
            outcome,
            timestamps_complete,
            &spool,
            sort_limits,
            &resources,
        );
    }
    if limits.read_bytes < 1024 {
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: 512,
            },
            "fat-bootstrap",
        )
        .with_source_id(source.id());
        outcome.stop_reason = StopReason::ResourceLimit("read_bytes");
        return finish(&out, outcome);
    }
    let limits = ScanLimits {
        read_bytes: limits.read_bytes - 1024,
        ..limits
    };
    let volume = match FatForensics::open(source.clone()) {
        Ok(volume) => volume,
        Err(error) => {
            let mut outcome = ScanOutcome::new(
                ByteRange {
                    offset: 0,
                    length: source.len(),
                },
                "fat-bootstrap",
            )
            .with_source_id(source.id());
            outcome.stop_reason = StopReason::InvalidBootstrap(error);
            return finish(&out, outcome);
        }
    };
    let boot_delivery = (|| -> io::Result<()> {
        let mut output = out.borrow_mut();
        write!(
            output,
            "{{\"version\":1,\"type\":\"fat_boot\",\"source_id\":{},\"volume_range\":",
            source.id().get()
        )?;
        json::range(
            &mut *output,
            ByteRange {
                offset: 0,
                length: 512,
            },
        )?;
        output.write_all(b",\"raw_hex\":")?;
        hex(&mut *output, volume.boot_sector())?;
        output.write_all(b"}\n")
    })();
    if let Err(error) = boot_delivery {
        let mut outcome = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: 512,
            },
            "fat-bootstrap-delivery",
        )
        .with_source_id(source.id());
        outcome.stop_reason = StopReason::DeliveryFailed(error.into());
        return finish(&out, outcome);
    }
    if options.command == "allocation-fat" {
        let outcome = volume.scan_allocation(limits, &NeverCancel, &mut |entry| {
            let mut output = out.borrow_mut();
            write!(output, "{{\"version\":1,\"type\":\"fat_allocation\",\"source_id\":{},\"copy\":{},\"cluster\":{},\"value\":{},\"volume_range\":", source.id().get(), entry.copy, entry.cluster, entry.value)?;
            let range = ByteRange { offset: entry.offset, length: u64::from(entry.raw_length) }; json::range(&mut *output, range)?;
            output.write_all(b",\"logical_disk_range\":")?; json::range(&mut *output, source.translate_range(range).map_err(io::Error::other)?)?;
            output.write_all(b",\"raw_hex\":")?; hex(&mut *output, &entry.raw[..entry.raw_length as usize])?;
            output.write_all(b",\"kind\":")?; json::string(&mut *output, match entry.kind { FatAllocationKind::Free => "free", FatAllocationKind::Next(_) => "next", FatAllocationKind::End => "end", FatAllocationKind::Bad => "bad", FatAllocationKind::Reserved => "reserved", FatAllocationKind::OutOfRange => "out_of_range" })?; output.write_all(b"}\n")?; Ok(true)
        }, &mut |event| { json::coverage(&mut *out.borrow_mut(), event)?; Ok(()) });
        return finish(&out, outcome);
    }
    if options.command == "compare-fat-copies" {
        let outcome = volume.scan_fat_copy_differences(limits, &resources, &NeverCancel, &mut |difference| {
            let mut output = out.borrow_mut();
            output.write_all(b"{\"version\":1,\"type\":\"fat_copy_difference\",\"baseline_is_historical_authority\":false,\"baseline\":")?;
            fat_copy_entry(&mut *output, source, &difference.baseline)?;
            output.write_all(b",\"other\":")?;
            fat_copy_entry(&mut *output, source, &difference.other)?;
            writeln!(output, ",\"meaningful_difference\":{},\"raw_difference\":{}}}", difference.meaningful_difference, difference.raw_difference)?;
            Ok(true)
        }, &mut |event| { json::coverage(&mut *out.borrow_mut(), event)?; Ok(()) });
        return finish(&out, outcome);
    }
    if options.command == "compare-fat-chains" {
        let first = options.required("--start-cluster")?.parse::<u32>()?;
        let transitions = options.required("--chain-transitions")?.parse::<u32>()?;
        let outcome = volume.scan_fat_copy_chains(first, transitions, limits, &resources, &NeverCancel, &mut |transition| {
            let mut output = out.borrow_mut();
            write!(output, "{{\"version\":1,\"type\":\"fat_copy_chain\",\"baseline_is_historical_authority\":false,\"step\":{},\"cycle_to\":", transition.step)?;
            match transition.cycle_to { Some(step) => write!(output, "{step}")?, None => output.write_all(b"null")? }
            output.write_all(b",\"entry\":")?;
            fat_copy_entry(&mut *output, source, &transition.entry)?;
            output.write_all(b",\"baseline\":")?;
            fat_copy_entry(&mut *output, source, &transition.baseline)?;
            writeln!(output, "}}")?;
            Ok(true)
        }, &mut |event| { json::coverage(&mut *out.borrow_mut(), event)?; Ok(()) });
        return finish(&out, outcome);
    }
    let directory = options.range("--directory-offset", "--directory-length")?;
    let selected = options
        .values
        .get("--slot-offset")
        .map(|value| value.parse::<u64>())
        .transpose()?;
    if options.command == "extract-fat" && selected.is_none() {
        return Err("extract-fat requires --slot-offset".into());
    }
    let utc_offset_seconds = options
        .values
        .get("--utc-offset-seconds")
        .map(|value| value.parse::<i32>())
        .transpose()?;
    if utc_offset_seconds.is_some_and(|offset| !(-86_400..=86_400).contains(&offset)) {
        return Err("timezone offset outside +/-86400 seconds".into());
    }
    let mut timestamps_complete = true;
    let mut slot = None;
    let outcome = volume.scan_directory_region(
        directory,
        limits,
        &NeverCancel,
        &mut |observation| {
            fat_slot(&mut *out.borrow_mut(), source, &observation)?;
            if options.command == "timeline-fat" {
                let child = forensics_timeline::fat_timestamps(
                    source.identity(),
                    &observation,
                    utc_offset_seconds,
                    limits,
                    &NeverCancel,
                    &mut |event| {
                        match event {
                            TimelineEvent::Timestamp(event) => timestamp(&out, &spool, &event)?,
                            TimelineEvent::Coverage(event) => {
                                json::coverage(&mut *out.borrow_mut(), event)?
                            }
                        }
                        Ok(())
                    },
                );
                timestamps_complete &= child.is_complete();
                json::terminal(&mut *out.borrow_mut(), &child)?;
            }
            if selected == Some(observation.offset) {
                slot = Some(observation);
            }
            Ok(true)
        },
        &mut |event| {
            json::coverage(&mut *out.borrow_mut(), event)?;
            Ok(())
        },
    );
    if options.command != "extract-fat" || !outcome.is_complete() {
        return finish_timeline(
            &out,
            outcome,
            timestamps_complete,
            &spool,
            sort_limits,
            &resources,
        );
    }
    // Persist every independent phase outcome instead of presenting map/extraction
    // success as if it covered a failed directory/ownership phase.
    if !finish(&out, outcome)? {
        return Ok(false);
    }
    let slot = slot.ok_or("requested slot was not visited in the directory region")?;
    let policy = if options.values.contains_key("--contiguous-hypothesis") {
        FatRecoveryPolicy::ContiguousHypothesis
    } else {
        FatRecoveryPolicy::RetainedChain
    };
    let map = map_fat_candidate(
        &volume,
        slot,
        policy,
        limits,
        &resources,
        &NeverCancel,
        &mut |event| {
            json::coverage(&mut *out.borrow_mut(), event)?;
            Ok(())
        },
    );
    let mapping_complete = map.mapping.is_complete();
    {
        let mut output = out.borrow_mut();
        json::terminal(&mut output.inner, &map.mapping)?;
        if let Some(ownership) = &map.ownership {
            json::terminal(&mut output.inner, ownership)?;
        }
    }
    if !mapping_complete {
        out.borrow_mut().flush()?;
        return Ok(false);
    }
    let ownership_complete = map.ownership.as_ref().is_some_and(ScanOutcome::is_complete);
    Ok(finish_export(
        &out,
        forensics_export::export_fat_candidate(
            Path::new(options.required("--output-dir")?),
            &map,
            limits,
            &resources,
            &NeverCancel,
        ),
    )? && ownership_complete)
}
fn main() {
    let result = Options::parse(std::env::args().skip(1)).and_then(|options| match options {
        None => {
            print!("{HELP}");
            Ok(true)
        }
        Some(options) => run(options),
    });
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("filesystem-forensics: {error}");
            std::process::exit(1);
        }
    }
}
