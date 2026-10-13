//! Bounded host spooling of complete timestamp observations for external sorting.
//! Native context and exact provenance are serialized before their borrowed input
//! expires. The caller must hold the temporary directory stable until drop.
use crate::{
    forensics::{
        ByteRange, CoordinateSpace, CoverageEvent, ScanControl, ScanLimits, ScanOutcome, StopReason,
    },
    forensics_sort::{TimelineSortOptions, TimelineSortRecord, sort_timeline},
    forensics_timeline::{TimeValue, TimestampObservation, write_json},
    fs_core::{Reservation, Resources},
    io,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
static NEXT_SPOOL: AtomicU64 = AtomicU64::new(1);
const HEADER: u64 = 33;

#[derive(Debug)]
struct SharedIo(Arc<io::Error>);
impl core::fmt::Display for SharedIo {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, out)
    }
}
impl core::error::Error for SharedIo {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
struct CappedWriter<'a> {
    buffer: &'a mut Vec<u8>,
    maximum: usize,
    cancellation: &'a crate::fs_core::Cancellation,
    failed: bool,
}
impl Write for CappedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.cancellation.check().is_err() {
            self.failed = true;
            return Err(std::io::Error::other("timestamp serialization cancelled"));
        }
        if bytes.len() > self.maximum.saturating_sub(self.buffer.len()) {
            self.failed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "timestamp JSON exceeds bounded event scratch",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Exclusively created timestamp spool retaining bounded serialization scratch.
/// `push` never retains borrowed names, attributes, source labels or record bytes.
/// No sorted output is delivered until all pushed timestamps have valid UTC keys.
pub struct TemporalSpool {
    file: Option<File>,
    path: Option<PathBuf>,
    parent: PathBuf,
    buffer: Vec<u8>,
    scratch: Option<Reservation>,
    _metadata: Reservation,
    metadata_bytes: u64,
    scratch_bytes: u64,
    resources: Resources,
    limits: ScanLimits,
    count: u64,
    written: u64,
    stopped: Option<StopReason>,
    finished: bool,
}
impl TemporalSpool {
    /// Reserve capped event scratch before a producer starts, then create a
    /// private input file exclusively in the stable caller-owned directory.
    /// Constructor failure creates no usable spool and retains its I/O cause.
    pub fn new(directory: &Path, resources: &Resources, limits: ScanLimits) -> io::Result<Self> {
        resources
            .cancellation
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))?;
        if !fs::metadata(directory)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeline spool parent is not a directory",
            ));
        }
        let metadata_bytes = (core::mem::size_of::<Self>() as u64)
            .checked_add((directory.as_os_str().len() as u64).saturating_mul(2))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "timeline spool path budget overflow",
                )
            })?;
        let scratch_bytes = (limits.memory_bytes / 4).min(1 << 20);
        if scratch_bytes == 0 || metadata_bytes.saturating_add(scratch_bytes) > limits.memory_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "timeline spool memory ceiling",
            ));
        }
        let metadata = resources
            .memory
            .reserve(metadata_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        let scratch = resources
            .memory
            .reserve(scratch_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(scratch_bytes as usize)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        for _ in 0..128 {
            let nonce = NEXT_SPOOL.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".partmgr-timestamps-{}-{nonce}.spool",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        path: Some(path),
                        parent: directory.to_path_buf(),
                        buffer,
                        scratch: Some(scratch),
                        _metadata: metadata,
                        metadata_bytes,
                        scratch_bytes,
                        resources: resources.clone(),
                        limits,
                        count: 0,
                        written: 0,
                        stopped: None,
                        finished: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exclusive timestamp spool collision limit",
        ))
    }
    /// Held reservation, to subtract from an independent producer memory ceiling.
    pub fn reserved_bytes(&self) -> u64 {
        self.metadata_bytes
            + if self.scratch.is_some() {
                self.scratch_bytes
            } else {
                0
            }
    }
    /// Maximum serialized event admitted by the fixed serialization buffer.
    pub fn max_event_bytes(&self) -> u64 {
        self.scratch_bytes
    }
    /// Number of fully stored observations; failed appends never increment this.
    pub fn len(&self) -> u64 {
        self.count
    }
    /// Whether no complete observation has been stored.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    fn resource_failure(&mut self, ceiling: &'static str) -> io::Error {
        self.stopped = Some(StopReason::ResourceLimit(ceiling));
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("timeline spool {ceiling} ceiling"),
        )
    }
    fn io_failure(&mut self, error: io::Error) -> io::Error {
        let cause = Arc::new(error);
        self.stopped = Some(StopReason::Io(io::Error::other(SharedIo(cause.clone()))));
        io::Error::other(SharedIo(cause))
    }
    /// Serialize one complete observation with a delivery-ordinal tie breaker.
    /// Uninterpretable timezone/calendar values retain a missing key; `finish`
    /// returns `UnsupportedProfile` before delivering any chronological output.
    /// Call `finish` even after an append error to obtain its typed terminal cause.
    pub fn push(&mut self, event: &TimestampObservation<'_>) -> io::Result<()> {
        let key = match event.value {
            TimeValue::Filetime(time) => time.valid.then_some(time.unix_ticks_100ns).flatten(),
            TimeValue::FatCreation(time) => time.valid.then_some(time.unix_ticks_100ns).flatten(),
            TimeValue::FatAccess(time) => time.valid.then_some(time.unix_ticks_100ns).flatten(),
            TimeValue::FatModification(time) => {
                time.valid.then_some(time.unix_ticks_100ns).flatten()
            }
        };
        self.push_json(key, |out| write_json(out, event))
    }
    /// Append one opaque serialized event with an explicit UTC 100 ns key.
    /// This shares the fixed scratch, cancellation, record and aggregate write
    /// ceilings used by native timestamps. Missing keys remain unsupported for
    /// chronological export; the complete original payload is never rounded.
    pub fn push_json(
        &mut self,
        key: Option<i128>,
        mut producer: impl FnMut(&mut dyn Write) -> std::io::Result<()>,
    ) -> io::Result<()> {
        if self.finished || self.stopped.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "timestamp spool already stopped or finished",
            ));
        }
        if self.resources.cancellation.check().is_err() {
            self.stopped = Some(StopReason::Cancelled);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "timestamp spool cancelled",
            ));
        }
        if self.count >= self.limits.records {
            return Err(self.resource_failure("records"));
        }
        self.buffer.clear();
        let remaining_output = self.limits.output_bytes.saturating_sub(self.written);
        if remaining_output < HEADER {
            return Err(self.resource_failure("output_bytes"));
        }
        let maximum = self.scratch_bytes.min(remaining_output - HEADER) as usize;
        let mut writer = CappedWriter {
            buffer: &mut self.buffer,
            maximum,
            cancellation: &self.resources.cancellation,
            failed: false,
        };
        let serialized = producer(&mut writer);
        let serialized = if serialized.is_ok() && writer.failed {
            Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "timestamp producer ignored a bounded writer failure",
            ))
        } else {
            serialized
        };
        if let Err(error) = serialized {
            if self.resources.cancellation.check().is_err() {
                self.stopped = Some(StopReason::Cancelled);
                return Err(error.into());
            }
            if error.kind() == std::io::ErrorKind::OutOfMemory {
                return Err(
                    self.resource_failure(if maximum as u64 == self.scratch_bytes {
                        "event_bytes"
                    } else {
                        "output_bytes"
                    }),
                );
            }
            return Err(self.io_failure(error.into()));
        }
        if self.resources.cancellation.check().is_err() {
            self.stopped = Some(StopReason::Cancelled);
            return Err(io::Error::other("timestamp serialization cancelled"));
        }
        let bytes = HEADER + self.buffer.len() as u64;
        if bytes > self.limits.output_bytes.saturating_sub(self.written) {
            return Err(self.resource_failure("output_bytes"));
        }
        let result = (|| -> std::io::Result<()> {
            let file = self.file.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "timestamp spool closed")
            })?;
            file.write_all(&[u8::from(key.is_some())])?;
            file.write_all(&key.unwrap_or(0).to_le_bytes())?;
            file.write_all(&self.count.to_le_bytes())?;
            file.write_all(&(self.buffer.len() as u64).to_le_bytes())?;
            file.write_all(&self.buffer)
        })();
        if let Err(error) = result {
            return Err(self.io_failure(error.into()));
        }
        self.count += 1;
        self.written += bytes;
        Ok(())
    }
    /// Mark an incomplete upstream producer without promoting its sorted prefix
    /// to complete output. An earlier append resource/cancellation/I/O failure
    /// retains its original typed cause when `finish` is called.
    pub fn abort_producer(&mut self) {
        if !self.finished && self.stopped.is_none() {
            self.stopped = Some(StopReason::CallerStop);
        }
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.file.take();
        if let Some(path) = self.path.as_ref() {
            fs::remove_file(path)?;
            self.path = None;
        }
        Ok(())
    }
    /// Close input production and externally sort the exact serialized events.
    /// Scratch is released before sorting. Limits include admitted input versions
    /// and spool writes, followed by sorter record versions, reads and writes.
    /// Caller must serialize coverage and this terminal outcome alongside payloads.
    pub fn finish(
        &mut self,
        options: TimelineSortOptions,
        limits: ScanLimits,
        resources: &Resources,
        control: &dyn ScanControl,
        output: &mut dyn FnMut(&TimelineSortRecord) -> io::Result<bool>,
        coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
    ) -> ScanOutcome {
        let domain = ByteRange {
            offset: 0,
            length: self.count.saturating_add(u64::from(self.stopped.is_some())),
        };
        let mut outcome = ScanOutcome::new(domain, "timestamp-spool-output-record-ordinals")
            .with_coordinate_space(CoordinateSpace::RecordOrdinals);
        if self.finished {
            outcome.stop_reason = StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timestamp spool already finished",
            ));
            return outcome;
        }
        self.finished = true;
        self.buffer = Vec::new();
        self.scratch.take();
        if let Some(reason) = self.stopped.take() {
            outcome.stop_reason = reason;
            let _ = self.cleanup();
            return outcome;
        }
        if control.cancelled() || self.resources.cancellation.check().is_err() {
            outcome.stop_reason = StopReason::Cancelled;
            let _ = self.cleanup();
            return outcome;
        }
        let prepared = (|| -> std::io::Result<()> {
            let file = self.file.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "timestamp spool closed")
            })?;
            file.flush()?;
            file.seek(SeekFrom::Start(0))?;
            Ok(())
        })();
        if let Err(error) = prepared {
            outcome.stop_reason = StopReason::Io(error.into());
            let _ = self.cleanup();
            return outcome;
        }
        let sorter_limits = ScanLimits {
            records: limits
                .records
                .min(self.limits.records)
                .saturating_sub(self.count),
            read_bytes: limits.read_bytes.min(self.limits.read_bytes),
            output_bytes: limits
                .output_bytes
                .min(self.limits.output_bytes)
                .saturating_sub(self.written),
            memory_bytes: limits
                .memory_bytes
                .min(self.limits.memory_bytes)
                .saturating_sub(self.metadata_bytes),
        };
        let bound_control = BoundControl {
            control,
            cancellation: &self.resources.cancellation,
        };
        let mut input = InputMeter {
            ordinal: 0,
            read: 0,
            budget: sorter_limits.read_bytes,
            stored_bytes: self.written,
        };
        let mut input_stop = None;
        if let Some(file) = self.file.as_mut() {
            outcome = sort_timeline(
                &self.parent,
                self.count,
                options,
                sorter_limits,
                resources,
                &bound_control,
                &mut || match read_input(
                    file,
                    options.max_event_bytes.min(self.scratch_bytes),
                    &mut input,
                ) {
                    Ok(record) => Ok(record),
                    Err(reason) => {
                        input_stop = Some(reason);
                        Err(io::Error::other(
                            "timestamp spool input stopped; terminal retains causal reason",
                        ))
                    }
                },
                output,
                coverage,
            );
        } else {
            outcome.stop_reason = StopReason::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "timestamp spool closed",
            ));
        }
        if let Some(reason) = input_stop {
            outcome.stop_reason = reason;
        }
        if let Err(error) = self.cleanup()
            && outcome.is_complete()
        {
            outcome.stop_reason = StopReason::Io(error);
        }
        outcome
    }
}
impl Drop for TemporalSpool {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
struct BoundControl<'a> {
    control: &'a dyn ScanControl,
    cancellation: &'a crate::fs_core::Cancellation,
}
impl ScanControl for BoundControl<'_> {
    fn cancelled(&self) -> bool {
        self.control.cancelled() || self.cancellation.check().is_err()
    }
}
struct InputMeter {
    ordinal: u64,
    read: u64,
    budget: u64,
    stored_bytes: u64,
}
fn read_input(
    file: &mut File,
    maximum: u64,
    meter: &mut InputMeter,
) -> Result<Option<TimelineSortRecord>, StopReason> {
    if meter.read == meter.stored_bytes {
        return Ok(None);
    }
    if HEADER > meter.budget.saturating_sub(meter.read) {
        return Err(StopReason::ResourceLimit("read_bytes"));
    }
    let mut header = [0; HEADER as usize];
    file.read_exact(&mut header)
        .map_err(|error| StopReason::Io(error.into()))?;
    meter.read += HEADER;
    let malformed = || {
        StopReason::InvalidBootstrap(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed timestamp spool header",
        ))
    };
    let key = match header[0] {
        0 => None,
        1 => Some(i128::from_le_bytes(
            header[1..17].try_into().map_err(|_| malformed())?,
        )),
        _ => return Err(malformed()),
    };
    let source_order = u64::from_le_bytes(header[17..25].try_into().map_err(|_| malformed())?);
    let length = u64::from_le_bytes(header[25..33].try_into().map_err(|_| malformed())?);
    if source_order != meter.ordinal {
        return Err(malformed());
    }
    if length > maximum {
        return Err(StopReason::ResourceLimit("event_bytes"));
    }
    if length > meter.budget.saturating_sub(meter.read) {
        return Err(StopReason::ResourceLimit("read_bytes"));
    }
    if length > meter.stored_bytes.saturating_sub(meter.read) {
        return Err(StopReason::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "timestamp spool payload exceeds stored bytes",
        )));
    }
    let length = usize::try_from(length).map_err(|_| StopReason::ResourceLimit("event_bytes"))?;
    let mut event = Vec::new();
    event
        .try_reserve_exact(length)
        .map_err(|_| StopReason::ResourceLimit("memory allocation"))?;
    event.resize(length, 0);
    file.read_exact(&mut event)
        .map_err(|error| StopReason::Io(error.into()))?;
    meter.read += length as u64;
    meter.ordinal += 1;
    Ok(Some(TimelineSortRecord {
        timestamp: key,
        source_order,
        event,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        forensics::{NeverCancel, SourceIdentity},
        forensics_time,
        forensics_timeline::TimestampKind,
        fs_core::{Budget, Cancellation},
    };
    fn resources(bytes: u64) -> Resources {
        Resources {
            memory: Budget::new(bytes),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> ScanLimits {
        ScanLimits {
            memory_bytes: 1 << 20,
            ..ScanLimits::default()
        }
    }
    fn options() -> TimelineSortOptions {
        TimelineSortOptions {
            chunk_bytes: 512,
            max_event_bytes: 1 << 16,
            merge_fan_in: 2,
        }
    }
    fn identity() -> SourceIdentity {
        SourceIdentity {
            acquisition: "source\"label".into(),
            source: "native evidence".into(),
            stability_provider: "offline lease".into(),
        }
    }
    fn observation(source: &SourceIdentity, ticks: u64) -> TimestampObservation<'_> {
        TimestampObservation {
            source,
            source_id: None,
            evidence: ByteRange {
                offset: ticks * 8,
                length: 8,
            },
            record_volume_fragments: &[ByteRange {
                offset: 4096,
                length: 1024,
            }],
            native_context: &[0xe5, 0xff, 0, 0xd8],
            kind: TimestampKind::NtfsStandardCreated,
            value: TimeValue::Filetime(forensics_time::filetime(
                (116_444_736_000_000_000 + ticks).to_le_bytes(),
            )),
            post_terminator: false,
        }
    }
    #[test]
    fn streamed_observations_sort_without_losing_original_json_or_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        assert!(spool.reserved_bytes() > spool.max_event_bytes());
        let mut expected = Vec::new();
        for ticks in [3, 1, 2] {
            let event = observation(&source, ticks);
            let mut bytes = Vec::new();
            write_json(&mut bytes, &event).unwrap();
            expected.push((ticks, bytes));
            spool.push(&event).unwrap();
        }
        let mut output = Vec::new();
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |record| {
                output.push(record.event.clone());
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        expected.sort_by_key(|(ticks, _)| *ticks);
        assert!(outcome.is_complete());
        assert_eq!(outcome.observations, 3);
        assert_eq!(
            output,
            expected
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        drop(spool);
        assert_eq!(resources.memory.used(), 0);
    }
    #[test]
    fn timezone_unknown_fat_is_explicitly_unsupported_before_sorted_output() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool.push(&observation(&source, 1)).unwrap();
        let mut event = observation(&source, 2);
        event.kind = TimestampKind::FatAccessed;
        event.value =
            TimeValue::FatAccess(forensics_time::fat_accessed(0x21u16.to_le_bytes(), None));
        spool.push(&event).unwrap();
        let mut count = 0;
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| {
                count += 1;
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(
            outcome.stop_reason,
            StopReason::UnsupportedProfile
        ));
        assert_eq!(count, 0);
        assert_eq!(outcome.unvisited.length, 2);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    #[test]
    fn serialization_record_and_output_ceilings_retain_typed_terminal_causes() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        for (name, limits) in [
            (
                "records",
                ScanLimits {
                    records: 0,
                    ..limits()
                },
            ),
            (
                "output_bytes",
                ScanLimits {
                    output_bytes: 0,
                    ..limits()
                },
            ),
            (
                "event_bytes",
                ScanLimits {
                    memory_bytes: 4096,
                    ..limits()
                },
            ),
        ] {
            let mut spool = TemporalSpool::new(directory.path(), &resources, limits).unwrap();
            let mut event = observation(&source, 1);
            let large = vec![0; 2048];
            if name == "event_bytes" {
                event.native_context = &large;
            }
            assert!(spool.push(&event).is_err());
            let result = spool.finish(
                options(),
                limits,
                &resources,
                &NeverCancel,
                &mut |_| Ok(true),
                &mut |_| Ok(()),
            );
            assert!(
                matches!(result.stop_reason, StopReason::ResourceLimit(actual) if actual == name)
            );
            assert_eq!(result.observations, 0);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn zero_read_limit_stops_before_spool_input_io() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool.push(&observation(&source, 1)).unwrap();
        let result = spool.finish(
            options(),
            ScanLimits {
                read_bytes: 0,
                ..limits()
            },
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::ResourceLimit("read_bytes")
        ));
        assert_eq!(result.observations, 0);
    }
    #[test]
    fn failed_delivery_cancellation_and_drop_remove_only_owned_spools() {
        let directory = tempfile::tempdir().unwrap();
        let sentinel = directory.path().join("caller-file");
        fs::write(&sentinel, b"owned by caller").unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool.push(&observation(&source, 1)).unwrap();
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| Err(io::Error::other("output failed")),
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::DeliveryFailed(_)));
        assert_eq!(fs::read(&sentinel).unwrap(), b"owned by caller");
        drop(spool);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        resources.cancellation.cancel();
        assert!(spool.push(&observation(&source, 1)).is_err());
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        drop(spool);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(resources.memory.used(), 0);
    }
    #[test]
    fn producer_cancellation_remains_bound_during_finish_with_other_resources() {
        let directory = tempfile::tempdir().unwrap();
        let producer = resources(1 << 20);
        let sorter = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &producer, limits()).unwrap();
        spool.push(&observation(&source, 2)).unwrap();
        spool.push(&observation(&source, 1)).unwrap();
        let mut output = 0;
        let outcome = spool.finish(
            options(),
            limits(),
            &sorter,
            &NeverCancel,
            &mut |_| {
                output += 1;
                producer.cancellation.cancel();
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        assert_eq!(output, 1);
        assert_eq!(outcome.observations, 1);
        assert_eq!(
            outcome.unvisited,
            ByteRange {
                offset: 1,
                length: 1
            }
        );
    }
    #[test]
    fn cancellation_inside_write_all_is_not_retryable() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        let result = spool.push_json(Some(0), |out| {
            resources.cancellation.cancel();
            out.write_all(b"must stop immediately")
        });
        assert!(result.is_err());
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Cancelled));
        assert_eq!(outcome.observations, 0);
    }
    #[test]
    fn producer_cancellation_after_final_write_prevents_spool_admission() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        assert!(
            spool
                .push_json(Some(0), |out| {
                    out.write_all(b"{}\n")?;
                    resources.cancellation.cancel();
                    Ok(())
                })
                .is_err()
        );
        assert!(spool.is_empty());
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("cancelled event must not be delivered"),
            &mut |_| Ok(()),
        );
        assert!(matches!(result.stop_reason, StopReason::Cancelled));
    }
    #[test]
    fn a_producer_cannot_hide_a_serialization_ceiling_and_admit_a_partial_event() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        let too_large = vec![b'x'; spool.max_event_bytes() as usize + 1];
        assert!(
            spool
                .push_json(Some(0), |out| {
                    out.write_all(b"prefix")?;
                    let _ = out.write_all(&too_large);
                    Ok(())
                })
                .is_err()
        );
        assert!(spool.is_empty());
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("failed serialization must not deliver a partial event"),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::ResourceLimit("event_bytes")
        ));
    }
    #[test]
    fn generic_payloads_preserve_exact_bytes_and_share_prewrite_limits() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool
            .push_json(Some(2), |out| {
                out.write_all(b"{\"type\":\"usn\",\"raw_name\":\"d800\"}\n")
            })
            .unwrap();
        spool
            .push_json(Some(1), |out| {
                out.write_all(b"{\"type\":\"usn\",\"raw_name\":\"0041\"}\n")
            })
            .unwrap();
        let mut output = Vec::new();
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |record| {
                output.push(record.event.clone());
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(result.is_complete());
        assert_eq!(
            output,
            vec![
                b"{\"type\":\"usn\",\"raw_name\":\"0041\"}\n".to_vec(),
                b"{\"type\":\"usn\",\"raw_name\":\"d800\"}\n".to_vec()
            ]
        );
        let mut spool = TemporalSpool::new(
            directory.path(),
            &resources,
            ScanLimits {
                output_bytes: 0,
                ..limits()
            },
        )
        .unwrap();
        assert!(
            spool
                .push_json(Some(0), |_| panic!(
                    "exhausted output ceiling must precede serializer"
                ))
                .is_err()
        );
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::ResourceLimit("output_bytes")
        ));
    }
    #[test]
    fn aborting_producer_preserves_push_failure_and_never_sorts_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(
            directory.path(),
            &resources,
            ScanLimits {
                records: 1,
                ..limits()
            },
        )
        .unwrap();
        spool
            .push_json(Some(0), |out| out.write_all(b"{}\n"))
            .unwrap();
        assert!(
            spool
                .push_json(Some(1), |out| out.write_all(b"{}\n"))
                .is_err()
        );
        spool.abort_producer();
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("incomplete producer cannot export sorted prefix"),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::ResourceLimit("records")
        ));
        assert_eq!(result.observations, 0);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool
            .push_json(Some(0), |out| out.write_all(b"{}\n"))
            .unwrap();
        spool.abort_producer();
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("aborted producer cannot export sorted prefix"),
            &mut |_| Ok(()),
        );
        assert!(matches!(result.stop_reason, StopReason::CallerStop));
        assert_eq!(result.observations, 0);
    }
    #[test]
    fn exact_spool_and_sort_ceilings_do_not_charge_an_eof_probe() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let bounded = ScanLimits {
            records: 3,        // One spool append, one sort input and one run read.
            read_bytes: 86,    // Two sorter record versions, each 40 + 3 bytes.
            output_bytes: 122, // Spool 33 + 3, run 40 + 3, delivery 40 + 3.
            ..limits()
        };
        let mut spool = TemporalSpool::new(directory.path(), &resources, bounded).unwrap();
        spool
            .push_json(Some(0), |out| out.write_all(b"{}\n"))
            .unwrap();
        let mut output = Vec::new();
        let result = spool.finish(
            options(),
            bounded,
            &resources,
            &NeverCancel,
            &mut |record| {
                output.extend_from_slice(&record.event);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(result.is_complete(), "{:?}", result.stop_reason);
        assert_eq!(output, b"{}\n");
        assert_eq!(result.observations, 1);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    #[test]
    fn host_append_failure_does_not_admit_a_record_or_sort_a_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let sentinel = directory.path().join("caller-owned");
        fs::write(&sentinel, b"retain").unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        let path = spool.path.clone().unwrap();
        // Use a real host descriptor that rejects writes without relying on
        // permissions (the test may execute with elevated privileges).
        spool.file = Some(File::open(&path).unwrap());
        let error = spool
            .push_json(Some(1), |out| out.write_all(b"{}\n"))
            .unwrap_err();
        assert_eq!(spool.len(), 0);
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("failed append must not deliver a record"),
            &mut |_| panic!("failed append must not claim coverage"),
        );
        let StopReason::Io(cause) = result.stop_reason else {
            panic!("host write failure must retain its I/O cause");
        };
        assert_eq!(cause.kind(), error.kind());
        assert_eq!(cause.to_string(), error.to_string());
        let native = std::error::Error::source(&cause)
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_ne!(native.kind(), io::ErrorKind::Other);
        assert!(native.raw_os_error().is_some());
        assert_eq!(result.observations, 0);
        assert!(!path.exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"retain");
        drop(spool);
        assert_eq!(resources.memory.used(), 0);
    }

    #[test]
    fn closed_host_spool_preparation_retains_cause_and_unvisited_record() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool
            .push_json(Some(1), |out| out.write_all(b"{}\n"))
            .unwrap();
        let path = spool.path.clone().unwrap();
        spool.file.take();
        let result = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| panic!("closed input must not deliver records"),
            &mut |_| panic!("closed input must not claim coverage"),
        );
        assert!(matches!(&result.stop_reason, StopReason::Io(cause)
            if cause.kind() == io::ErrorKind::BrokenPipe && cause.to_string() == "timestamp spool closed"));
        assert_eq!(
            result.unvisited,
            ByteRange {
                offset: 0,
                length: 1
            }
        );
        assert_eq!(result.observations, 0);
        assert!(!path.exists());
        drop(spool);
        assert_eq!(resources.memory.used(), 0);
    }

    #[test]
    fn malformed_temporary_input_preserves_causal_io_failure() {
        let directory = tempfile::tempdir().unwrap();
        let resources = resources(1 << 20);
        let source = identity();
        let mut spool = TemporalSpool::new(directory.path(), &resources, limits()).unwrap();
        spool.push(&observation(&source, 1)).unwrap();
        spool.file.as_mut().unwrap().set_len(2).unwrap();
        let outcome = spool.finish(
            options(),
            limits(),
            &resources,
            &NeverCancel,
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(outcome.stop_reason, StopReason::Io(_)));
        assert_eq!(outcome.observations, 0);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
