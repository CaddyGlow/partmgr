//! Bounded host external sorting of already interpreted timeline events.
//! Caller-owned temporary directories must remain stable for the operation.
//! Unknown or timezone-ambiguous keys are rejected rather than chronologically guessed.
use crate::{
    forensics::{
        ByteRange, CoverageEvent, CoverageKind, ScanControl, ScanLimits, ScanOutcome, StopReason,
    },
    fs_core::Resources,
    io,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_SORT: AtomicU64 = AtomicU64::new(1);
const HEADER: u64 = 40;

/// An opaque event with an explicitly interpreted chronological key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineSortRecord {
    /// Signed 100-nanosecond ticks since Unix epoch; `None` is unsupported.
    pub timestamp: Option<i128>,
    /// Caller-defined source order, used after timestamp for deterministic ties.
    pub source_order: u64,
    /// Original serialized event bytes, preserved exactly without parsing.
    pub event: Vec<u8>,
}
/// Independent external-sort work and fan-in bounds.
#[derive(Clone, Copy, Debug)]
pub struct TimelineSortOptions {
    /// Approximate payload plus record storage admitted into each sorted chunk.
    pub chunk_bytes: u64,
    /// Maximum opaque event storage accepted from input or a temporary run.
    /// Input vectors must also keep their allocated capacity within this ceiling.
    pub max_event_bytes: u64,
    /// Maximum open input runs per merge; must be at least two.
    pub merge_fan_in: usize,
}
impl Default for TimelineSortOptions {
    fn default() -> Self {
        Self {
            chunk_bytes: 4 << 20,
            max_event_bytes: 1 << 20,
            merge_fan_in: 8,
        }
    }
}
struct Record {
    timestamp: i128,
    source_order: u64,
    ordinal: u64,
    event: Vec<u8>,
}
impl Record {
    fn key(&self) -> (i128, u64, u64) {
        (self.timestamp, self.source_order, self.ordinal)
    }
}
struct ScratchDirectory(PathBuf);
impl ScratchDirectory {
    fn create(parent: &Path) -> io::Result<Self> {
        if !fs::metadata(parent)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sort temporary parent is not a directory",
            ));
        }
        for _ in 0..128 {
            let nonce = NEXT_SORT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".partmgr-sort-{}-{nonce}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exclusive sort directory collision limit",
        ))
    }
    fn run(&self, pass: u64, index: u64) -> PathBuf {
        self.0.join(format!("run-{pass}-{index}"))
    }
    fn create_run(&self, pass: u64, index: u64) -> io::Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.run(pass, index))?)
    }
}
impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
        let _ = fs::remove_dir(&self.0);
    }
}
struct Work<'a> {
    limits: ScanLimits,
    options: TimelineSortOptions,
    resources: &'a Resources,
    control: &'a dyn ScanControl,
    records: u64,
    read: u64,
    written: u64,
}
impl Work<'_> {
    fn check(&self) -> Result<(), StopReason> {
        if self.control.cancelled() || self.resources.cancellation.check().is_err() {
            Err(StopReason::Cancelled)
        } else {
            Ok(())
        }
    }
    fn record(&mut self) -> Result<(), StopReason> {
        self.check()?;
        if self.records >= self.limits.records {
            return Err(StopReason::ResourceLimit("records"));
        }
        self.records += 1;
        Ok(())
    }
    fn read_charge(&mut self, length: u64) -> Result<(), StopReason> {
        self.check()?;
        self.read = self
            .read
            .checked_add(length)
            .filter(|count| *count <= self.limits.read_bytes)
            .ok_or(StopReason::ResourceLimit("read_bytes"))?;
        Ok(())
    }
    fn write_charge(&mut self, length: u64) -> Result<(), StopReason> {
        self.check()?;
        self.written = self
            .written
            .checked_add(length)
            .filter(|count| *count <= self.limits.output_bytes)
            .ok_or(StopReason::ResourceLimit("output_bytes"))?;
        Ok(())
    }
}
fn write_record(file: &mut File, record: &Record, work: &mut Work<'_>) -> Result<(), StopReason> {
    work.write_charge(HEADER + record.event.len() as u64)?;
    file.write_all(&record.timestamp.to_le_bytes())
        .map_err(|error| StopReason::Io(error.into()))?;
    file.write_all(&record.source_order.to_le_bytes())
        .map_err(|error| StopReason::Io(error.into()))?;
    file.write_all(&record.ordinal.to_le_bytes())
        .map_err(|error| StopReason::Io(error.into()))?;
    file.write_all(&(record.event.len() as u64).to_le_bytes())
        .map_err(|error| StopReason::Io(error.into()))?;
    file.write_all(&record.event)
        .map_err(|error| StopReason::Io(error.into()))
}
fn read_record(file: &mut File, work: &mut Work<'_>) -> Result<Option<Record>, StopReason> {
    work.check()?;
    // Owned regular runs have a stable length. Metadata establishes EOF without
    // consuming a phantom byte or crossing an exhausted record ceiling.
    let position = file
        .stream_position()
        .map_err(|error| StopReason::Io(error.into()))?;
    let length = file
        .metadata()
        .map_err(|error| StopReason::Io(error.into()))?
        .len();
    if position == length {
        return Ok(None);
    }
    if position > length {
        return Err(StopReason::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary run cursor exceeds stable length",
        )));
    }
    work.record()?;
    work.read_charge(HEADER)?;
    let mut header = [0; 40];
    file.read_exact(&mut header)
        .map_err(|error| StopReason::Io(error.into()))?;
    let length = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| StopReason::UnsupportedProfile)?,
    );
    if length > work.options.max_event_bytes {
        return Err(StopReason::ResourceLimit("event_bytes"));
    }
    work.read_charge(length)?;
    let length = usize::try_from(length).map_err(|_| StopReason::ResourceLimit("event_bytes"))?;
    let mut event = Vec::new();
    event
        .try_reserve_exact(length)
        .map_err(|_| StopReason::ResourceLimit("memory allocation"))?;
    event.resize(length, 0);
    file.read_exact(&mut event)
        .map_err(|error| StopReason::Io(error.into()))?;
    Ok(Some(Record {
        timestamp: i128::from_le_bytes(
            header[..16]
                .try_into()
                .map_err(|_| StopReason::UnsupportedProfile)?,
        ),
        source_order: u64::from_le_bytes(
            header[16..24]
                .try_into()
                .map_err(|_| StopReason::UnsupportedProfile)?,
        ),
        ordinal: u64::from_le_bytes(
            header[24..32]
                .try_into()
                .map_err(|_| StopReason::UnsupportedProfile)?,
        ),
        event,
    }))
}
fn flush_chunk(
    chunk: &mut Vec<Record>,
    scratch: &ScratchDirectory,
    index: u64,
    work: &mut Work<'_>,
) -> Result<(), StopReason> {
    chunk.sort_unstable_by_key(Record::key);
    let mut output = scratch.create_run(0, index).map_err(StopReason::Io)?;
    for record in chunk.iter() {
        write_record(&mut output, record, work)?;
    }
    output
        .flush()
        .map_err(|error| StopReason::Io(error.into()))?;
    chunk.clear();
    Ok(())
}
fn merge_runs(
    scratch: &ScratchDirectory,
    pass: u64,
    first: u64,
    count: u64,
    next_index: u64,
    work: &mut Work<'_>,
) -> Result<(), StopReason> {
    let mut cursors = Vec::new();
    cursors
        .try_reserve_exact(count as usize)
        .map_err(|_| StopReason::ResourceLimit("memory allocation"))?;
    for index in first..first + count {
        let mut file =
            File::open(scratch.run(pass, index)).map_err(|error| StopReason::Io(error.into()))?;
        let record = read_record(&mut file, work)?;
        cursors.push((file, record));
    }
    let mut output = scratch
        .create_run(pass + 1, next_index)
        .map_err(StopReason::Io)?;
    loop {
        work.check()?;
        let selected = cursors
            .iter()
            .enumerate()
            .filter_map(|(index, (_, record))| record.as_ref().map(|record| (index, record.key())))
            .min_by_key(|(_, key)| *key)
            .map(|(index, _)| index);
        let Some(index) = selected else {
            break;
        };
        if let Some(record) = cursors[index].1.take() {
            write_record(&mut output, &record, work)?;
        }
        cursors[index].1 = read_record(&mut cursors[index].0, work)?;
    }
    output
        .flush()
        .map_err(|error| StopReason::Io(error.into()))?;
    drop(cursors);
    for index in first..first + count {
        fs::remove_file(scratch.run(pass, index)).map_err(|error| StopReason::Io(error.into()))?;
    }
    Ok(())
}

/// Sort exactly `expected_records` events using exclusive temporary runs.
/// Unknown keys return `UnsupportedProfile` before any sorted output. Input must
/// produce exactly the declared count and then EOF. Timestamp ties use source
/// order followed by original input ordinal, preserving duplicate keys exactly.
/// `records` counts input and each temporary record read; byte ceilings include
/// temporary I/O and final output. The input callback owns its allocation bounds.
/// Coverage and the terminal outcome use sorted-output ordinal coordinates.
/// Temporary files are removed on success, cancellation, or delivery failure.
#[expect(
    clippy::too_many_arguments,
    reason = "independent input, output, coverage and resource controls"
)]
pub fn sort_timeline(
    temporary_parent: &Path,
    expected_records: u64,
    options: TimelineSortOptions,
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
    input: &mut dyn FnMut() -> io::Result<Option<TimelineSortRecord>>,
    output: &mut dyn FnMut(&TimelineSortRecord) -> io::Result<bool>,
    coverage: &mut dyn FnMut(CoverageEvent) -> io::Result<()>,
) -> ScanOutcome {
    let mut outcome = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: expected_records,
        },
        "external-timeline-sorted-output-ordinals",
    )
    .with_coordinate_space(crate::forensics::CoordinateSpace::RecordOrdinals);
    let mut work = Work {
        limits,
        options,
        resources,
        control,
        records: 0,
        read: 0,
        written: 0,
    };
    let mut run = || -> Result<(), StopReason> {
        work.check()?;
        if options.merge_fan_in < 2
            || options.chunk_bytes < core::mem::size_of::<Record>() as u64
            || options.max_event_bytes > usize::MAX as u64
        {
            return Err(StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid external sort bounds",
            )));
        }
        // Empty input still checks declared EOF, but creates no host artifact.
        if expected_records == 0 {
            if input().map_err(StopReason::Io)?.is_some() {
                return Err(StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input exceeds declared record count",
                )));
            }
            work.check()?;
            return Ok(());
        }
        let chunk_memory = options
            .chunk_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(options.max_event_bytes))
            .ok_or(StopReason::ResourceLimit("memory_bytes"))?;
        let merge_memory = options
            .max_event_bytes
            .checked_add(256)
            .and_then(|bytes| bytes.checked_mul(options.merge_fan_in as u64))
            .ok_or(StopReason::ResourceLimit("memory_bytes"))?;
        let path_memory = (temporary_parent.as_os_str().len() as u64)
            .checked_add(128)
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or(StopReason::ResourceLimit("memory_bytes"))?;
        let memory = chunk_memory
            .max(merge_memory)
            .checked_add(path_memory)
            .ok_or(StopReason::ResourceLimit("memory_bytes"))?;
        if memory > limits.memory_bytes {
            return Err(StopReason::ResourceLimit("memory_bytes"));
        }
        let _reservation = resources
            .memory
            .reserve(memory)
            .map_err(|_| StopReason::ResourceLimit("shared memory"))?;
        let scratch = ScratchDirectory::create(temporary_parent).map_err(StopReason::Io)?;
        let capacity = usize::try_from(options.chunk_bytes / core::mem::size_of::<Record>() as u64)
            .map_err(|_| StopReason::ResourceLimit("memory_bytes"))?;
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(capacity)
            .map_err(|_| StopReason::ResourceLimit("memory allocation"))?;
        let mut chunk_bytes = 0u64;
        let mut runs = 0u64;
        for ordinal in 0..expected_records {
            work.record()?;
            let record = input().map_err(StopReason::Io)?.ok_or_else(|| {
                StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input shorter than declared record count",
                ))
            })?;
            let timestamp = record.timestamp.ok_or(StopReason::UnsupportedProfile)?;
            if record.event.capacity() as u64 > options.max_event_bytes {
                return Err(StopReason::ResourceLimit("event_bytes"));
            }
            work.read_charge(HEADER + record.event.len() as u64)?;
            let size = record.event.capacity() as u64 + core::mem::size_of::<Record>() as u64;
            if !chunk.is_empty() && chunk_bytes.saturating_add(size) > options.chunk_bytes {
                flush_chunk(&mut chunk, &scratch, runs, &mut work)?;
                runs += 1;
                chunk_bytes = 0;
            }
            chunk_bytes += size;
            chunk.push(Record {
                timestamp,
                source_order: record.source_order,
                ordinal,
                event: record.event,
            });
            if chunk_bytes >= options.chunk_bytes {
                flush_chunk(&mut chunk, &scratch, runs, &mut work)?;
                runs += 1;
                chunk_bytes = 0;
            }
        }
        if input().map_err(StopReason::Io)?.is_some() {
            return Err(StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidData,
                "input exceeds declared record count",
            )));
        }
        if !chunk.is_empty() {
            flush_chunk(&mut chunk, &scratch, runs, &mut work)?;
            runs += 1;
        }
        drop(chunk);
        let mut pass = 0;
        while runs > 1 {
            let mut next = 0;
            let mut first = 0;
            while first < runs {
                let count = (runs - first).min(options.merge_fan_in as u64);
                merge_runs(&scratch, pass, first, count, next, &mut work)?;
                first += count;
                next += 1;
            }
            runs = next;
            pass += 1;
        }
        let mut sorted =
            File::open(scratch.run(pass, 0)).map_err(|error| StopReason::Io(error.into()))?;
        for ordinal in 0..expected_records {
            let record = read_record(&mut sorted, &mut work)?.ok_or_else(|| {
                StopReason::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sorted run missing record",
                ))
            })?;
            work.write_charge(HEADER + record.event.len() as u64)?;
            let record = TimelineSortRecord {
                timestamp: Some(record.timestamp),
                source_order: record.source_order,
                event: record.event,
            };
            let proceed = output(&record).map_err(StopReason::DeliveryFailed)?;
            outcome.observations += 1;
            outcome.last_delivered = Some(ordinal + 1);
            coverage(CoverageEvent {
                range: ByteRange {
                    offset: ordinal,
                    length: 1,
                },
                kind: CoverageKind::Inspected,
            })
            .map_err(StopReason::DeliveryFailed)?;
            outcome.coverage_events += 1;
            outcome.advance(ordinal + 1);
            if !proceed {
                return Err(StopReason::CallerStop);
            }
        }
        if read_record(&mut sorted, &mut work)?.is_some() {
            return Err(StopReason::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "sorted run has extra records",
            )));
        }
        drop(sorted);
        fs::remove_file(scratch.run(pass, 0)).map_err(|error| StopReason::Io(error.into()))?;
        fs::remove_dir(&scratch.0).map_err(|error| StopReason::Io(error.into()))?;
        work.check()?;
        Ok(())
    };
    if let Err(reason) = run() {
        outcome.stop_reason = reason;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        forensics::NeverCancel,
        fs_core::{Budget, Cancellation},
    };
    struct Parent(PathBuf);
    impl Parent {
        fn new() -> Self {
            let directory = ScratchDirectory::create(&std::env::temp_dir()).unwrap();
            let path = directory.0.clone();
            core::mem::forget(directory);
            Self(path)
        }
        fn empty(&self) -> bool {
            fs::read_dir(&self.0).unwrap().next().is_none()
        }
    }
    impl Drop for Parent {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn options() -> TimelineSortOptions {
        TimelineSortOptions {
            chunk_bytes: 80,
            max_event_bytes: 16,
            merge_fan_in: 2,
        }
    }
    fn event(timestamp: Option<i128>, source_order: u64, value: u8) -> TimelineSortRecord {
        TimelineSortRecord {
            timestamp,
            source_order,
            event: vec![value, 0, b'\n', 0xff],
        }
    }
    #[test]
    fn multipass_sort_preserves_opaque_bytes_and_deterministic_ties() {
        let parent = Parent::new();
        let resources = resources();
        let records = vec![
            event(Some(7), 2, 0),
            event(Some(-1), 0, 1),
            event(Some(7), 1, 2),
            event(Some(7), 1, 3),
            event(Some(i128::MAX), 0, 4),
            event(Some(i128::MIN), 0, 5),
            event(Some(0), 1, 6),
            event(Some(0), 0, 7),
            event(Some(7), 2, 8),
        ];
        let mut input = records.into_iter();
        let mut output = Vec::new();
        let mut coverage = Vec::new();
        let result = sort_timeline(
            &parent.0,
            9,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |record| {
                output.push(record.clone());
                Ok(true)
            },
            &mut |event| {
                coverage.push(event);
                Ok(())
            },
        );
        assert!(result.is_complete());
        assert_eq!(
            output
                .iter()
                .map(|record| record.event[0])
                .collect::<Vec<_>>(),
            vec![5, 1, 7, 6, 2, 3, 0, 8, 4]
        );
        assert!(
            output
                .iter()
                .all(|record| record.event[1..] == [0, b'\n', 0xff])
        );
        assert_eq!(coverage.len(), 9);
        assert!(parent.empty());
        assert_eq!(resources.memory.used(), 0);
    }
    #[test]
    fn unsupported_timestamp_emits_no_sorted_prefix() {
        let parent = Parent::new();
        let resources = resources();
        let mut input = vec![event(Some(2), 0, 0), event(None, 0, 1)].into_iter();
        let mut delivered = 0;
        let result = sort_timeline(
            &parent.0,
            2,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |_| {
                delivered += 1;
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(result.stop_reason, StopReason::UnsupportedProfile));
        assert_eq!(delivered, 0);
        assert_eq!(result.unvisited.length, 2);
        assert!(parent.empty());
    }
    #[test]
    fn empty_sort_succeeds_without_resources_or_host_artifacts() {
        let parent = Parent::new();
        let resources = resources();
        let result = sort_timeline(
            &parent.0,
            0,
            options(),
            ScanLimits {
                records: 0,
                read_bytes: 0,
                output_bytes: 0,
                memory_bytes: 0,
            },
            &resources,
            &NeverCancel,
            &mut || Ok(None),
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(result.is_complete());
        assert_eq!(result.observations, 0);
        assert!(parent.empty());
    }
    #[test]
    fn resource_ceilings_stop_with_terminal_state_and_cleanup() {
        let parent = Parent::new();
        let resources = resources();
        for (name, limits) in [
            (
                "records",
                ScanLimits {
                    records: 0,
                    ..ScanLimits::default()
                },
            ),
            (
                "read_bytes",
                ScanLimits {
                    read_bytes: 0,
                    ..ScanLimits::default()
                },
            ),
            (
                "output_bytes",
                ScanLimits {
                    output_bytes: 0,
                    ..ScanLimits::default()
                },
            ),
            (
                "memory_bytes",
                ScanLimits {
                    memory_bytes: 0,
                    ..ScanLimits::default()
                },
            ),
        ] {
            let mut input = vec![event(Some(0), 0, 0)].into_iter();
            let result = sort_timeline(
                &parent.0,
                1,
                options(),
                limits,
                &resources,
                &NeverCancel,
                &mut || Ok(input.next()),
                &mut |_| Ok(true),
                &mut |_| Ok(()),
            );
            assert!(
                matches!(result.stop_reason, StopReason::ResourceLimit(actual) if actual == name)
            );
            assert!(!result.is_complete());
            assert_eq!(result.observations, 0);
            assert!(parent.empty());
        }
    }
    #[test]
    fn output_failure_retains_delivered_prefix_and_causal_error() {
        let parent = Parent::new();
        let resources = resources();
        let mut input = vec![
            event(Some(3), 0, 3),
            event(Some(1), 0, 1),
            event(Some(2), 0, 2),
        ]
        .into_iter();
        let mut seen = Vec::new();
        let result = sort_timeline(
            &parent.0,
            3,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |record| {
                if seen.len() == 2 {
                    return Err(io::Error::other("sink failed"));
                }
                seen.push(record.event[0]);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(
            matches!(result.stop_reason, StopReason::DeliveryFailed(ref error) if error.to_string().contains("sink failed"))
        );
        assert_eq!(seen, vec![1, 2]);
        assert_eq!(result.observations, 2);
        assert_eq!(
            result.unvisited,
            ByteRange {
                offset: 2,
                length: 1
            }
        );
        assert!(parent.empty());
    }
    #[test]
    fn cancellation_and_input_truncation_do_not_produce_sorted_output() {
        let parent = Parent::new();
        let resources = resources();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let mut calls = 0;
        let result = sort_timeline(
            &parent.0,
            3,
            options(),
            ScanLimits::default(),
            &resources,
            &cancelled,
            &mut || {
                calls += 1;
                if calls == 2 {
                    cancelled.store(true, Ordering::Release);
                }
                Ok(Some(event(Some(0), 0, 0)))
            },
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(result.stop_reason, StopReason::Cancelled));
        assert_eq!(result.observations, 0);
        assert!(parent.empty());
        let mut input = vec![event(Some(1), 0, 0)].into_iter();
        let result = sort_timeline(
            &parent.0,
            2,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        assert_eq!(result.observations, 0);
        assert!(parent.empty());
    }
    #[test]
    fn coverage_failure_and_shared_budget_are_explicit() {
        let parent = Parent::new();
        let resources = resources();
        let mut input = vec![event(Some(0), 0, 0)].into_iter();
        let result = sort_timeline(
            &parent.0,
            1,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |_| Ok(true),
            &mut |_| Err(io::Error::other("coverage sink")),
        );
        assert!(matches!(result.stop_reason, StopReason::DeliveryFailed(_)));
        assert_eq!(result.observations, 1);
        assert_eq!(result.coverage_events, 0);
        assert_eq!(result.last_delivered, Some(1));
        assert_eq!(result.unvisited.length, 1);
        assert!(parent.empty());
        let resources = Resources {
            memory: Budget::new(1),
            cancellation: Cancellation::default(),
        };
        let result = sort_timeline(
            &parent.0,
            1,
            options(),
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut || panic!("budget must be reserved before input"),
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(matches!(
            result.stop_reason,
            StopReason::ResourceLimit("shared memory")
        ));
        assert!(parent.empty());
    }
    #[test]
    fn truncated_run_header_is_not_interpreted_as_clean_eof() {
        let parent = Parent::new();
        let scratch = ScratchDirectory::create(&parent.0).unwrap();
        let mut file = scratch.create_run(0, 0).unwrap();
        file.write_all(b"short").unwrap();
        drop(file);
        let resources = resources();
        let control = NeverCancel;
        let mut work = Work {
            limits: ScanLimits::default(),
            options: options(),
            resources: &resources,
            control: &control,
            records: 0,
            read: 0,
            written: 0,
        };
        let mut file = File::open(scratch.run(0, 0)).unwrap();
        assert!(matches!(
            read_record(&mut file, &mut work),
            Err(StopReason::Io(_))
        ));
    }
    #[test]
    fn exact_record_and_byte_ceilings_allow_complete_sort() {
        let parent = Parent::new();
        let resources = resources();
        let mut input = vec![event(Some(0), 0, 0)].into_iter();
        let result = sort_timeline(
            &parent.0,
            1,
            options(),
            ScanLimits {
                records: 2,
                read_bytes: 88,
                output_bytes: 88,
                ..ScanLimits::default()
            },
            &resources,
            &NeverCancel,
            &mut || Ok(input.next()),
            &mut |_| Ok(true),
            &mut |_| Ok(()),
        );
        assert!(result.is_complete());
        assert_eq!(result.observations, 1);
        assert!(parent.empty());
    }
    #[test]
    fn exhausted_record_ceiling_precedes_run_data_reads() {
        let parent = Parent::new();
        let scratch = ScratchDirectory::create(&parent.0).unwrap();
        let mut writer = scratch.create_run(0, 0).unwrap();
        writer.write_all(b"short").unwrap();
        drop(writer);
        let resources = resources();
        let control = NeverCancel;
        let mut work = Work {
            limits: ScanLimits {
                records: 0,
                ..ScanLimits::default()
            },
            options: options(),
            resources: &resources,
            control: &control,
            records: 0,
            read: 0,
            written: 0,
        };
        let mut file = File::open(scratch.run(0, 0)).unwrap();
        assert!(matches!(
            read_record(&mut file, &mut work),
            Err(StopReason::ResourceLimit("records"))
        ));
        assert_eq!(file.stream_position().unwrap(), 0);
        assert_eq!(work.read, 0);
    }
    #[test]
    fn temporary_runs_are_created_exclusively() {
        let parent = Parent::new();
        let scratch = ScratchDirectory::create(&parent.0).unwrap();
        let mut run = scratch.create_run(0, 0).unwrap();
        run.write_all(b"sentinel").unwrap();
        drop(run);
        assert!(scratch.create_run(0, 0).is_err());
        assert_eq!(fs::read(scratch.run(0, 0)).unwrap(), b"sentinel");
        drop(scratch);
        assert!(parent.empty());
    }
}
