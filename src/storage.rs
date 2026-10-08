//! Reviewable positional writes with explicit durability barriers.
//!
//! A plan is not atomic. Callers must hold exclusive access for its entire
//! preflight, write, flush and verification sequence. Preconditions detect stale
//! snapshots, but cannot enforce that contract against concurrent writers.
use std::{fmt, io};

/// Exclusive positional storage capability.
///
/// Implementors must prevent concurrent writers, or callers must independently
/// enforce exclusive access. `flush` must make prior writes durable on the medium.
pub trait Storage {
    /// Current byte length, rechecked before a commit.
    fn len(&self) -> io::Result<u64>;
    /// Whether storage has zero length.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Fill an in-bounds range exactly.
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()>;
    /// Write some bytes at a position; short writes are supported.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize>;
    /// Durably flush all preceding writes.
    fn flush(&mut self) -> io::Result<()>;
}
/// Optional exclusive image resizing capability, separate from metadata writes.
pub trait ResizableStorage: Storage {
    /// Change logical byte length and durably flush the new geometry. Shrink is
    /// destructive and must occur only after metadata and payload prerequisites.
    fn resize(&mut self, bytes: u64) -> io::Result<()>;
}
/// One exact metadata replacement and its stale-state precondition.
#[derive(Clone, Debug)]
pub struct WriteRange {
    offset: u64,
    expected: Vec<u8>,
    replacement: Vec<u8>,
}
impl WriteRange {
    /// Construct a nonempty equal-length replacement with checked offsets.
    pub fn new(offset: u64, expected: Vec<u8>, replacement: Vec<u8>) -> io::Result<Self> {
        if expected.is_empty()
            || expected.len() != replacement.len()
            || offset.checked_add(expected.len() as u64).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid write range",
            ));
        }
        Ok(Self {
            offset,
            expected,
            replacement,
        })
    }
    /// Byte offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Exact expected bytes.
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }
    /// Replacement bytes.
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }
    /// Retained payload allocation, including spare vector capacity.
    /// Use when charging ownership to a shared filesystem budget.
    pub fn retained_payload_bytes(&self) -> u128 {
        self.expected.capacity() as u128 + self.replacement.capacity() as u128
    }
}
/// Ordered writes followed by a durable flush.
#[derive(Clone, Debug)]
pub struct Barrier {
    name: String,
    writes: Vec<WriteRange>,
}
impl Barrier {
    /// Construct a named nonempty stage.
    pub fn new(name: impl Into<String>, writes: Vec<WriteRange>) -> io::Result<Self> {
        let name = name.into();
        if name.is_empty() || writes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty commit stage",
            ));
        }
        Ok(Self { name, writes })
    }
    /// Reviewable stage name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Exact ordered replacements.
    pub fn writes(&self) -> &[WriteRange] {
        &self.writes
    }
}
/// Validated immutable write plan. All preconditions are checked before writes.
#[derive(Clone, Debug)]
pub struct WritePlan {
    length: u64,
    stages: Vec<Barrier>,
    preconditions: Vec<ReadCondition>,
}
/// Read-only metadata precondition, including sources that will not be written.
#[derive(Clone, Debug)]
pub struct ReadCondition {
    offset: u64,
    expected: Vec<u8>,
}
impl ReadCondition {
    /// Capture an exact bounded metadata snapshot.
    pub fn new(offset: u64, expected: Vec<u8>) -> io::Result<Self> {
        if expected.is_empty() || offset.checked_add(expected.len() as u64).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid read precondition",
            ));
        }
        Ok(Self { offset, expected })
    }
    /// Snapshot byte offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Expected source bytes.
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }
}
/// Completed and durably flushed stages.
#[derive(Debug)]
pub struct CommitReport {
    completed: Vec<String>,
}
impl CommitReport {
    /// Names in durability order.
    pub fn completed_stages(&self) -> &[String] {
        &self.completed
    }
}
/// Staleness or interrupted commit, retaining underlying I/O failures.
#[derive(Debug)]
pub enum CommitError {
    /// A precondition differed; no writes occurred.
    Stale {
        /// Description of the mismatch.
        reason: &'static str,
    },
    /// Preflight I/O failed before any writes.
    Preflight(io::Error),
    /// Some writes may have reached storage; inspect before retrying.
    Interrupted {
        /// Stages already flushed successfully.
        completed_stages: Vec<String>,
        /// Current or verification stage.
        stage: String,
        /// True when writes may exist without a confirmed flush.
        durability_uncertain: bool,
        /// Underlying failure.
        source: io::Error,
    },
}
impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale { reason } => write!(f, "stale write plan: {reason}"),
            Self::Preflight(e) => write!(f, "commit preflight: {e}"),
            Self::Interrupted { stage, source, .. } => {
                write!(f, "commit interrupted at {stage}: {source}")
            }
        }
    }
}
impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(e) | Self::Interrupted { source: e, .. } => Some(e),
            Self::Stale { .. } => None,
        }
    }
}
impl WritePlan {
    /// Validate ranges against geometry and reject overlapping replacements.
    pub fn new(length: u64, stages: Vec<Barrier>) -> io::Result<Self> {
        let mut ranges = Vec::new();
        for stage in &stages {
            for write in &stage.writes {
                let end = write.offset + write.expected.len() as u64;
                if end > length {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "write exceeds geometry",
                    ));
                }
                ranges.push((write.offset, end));
            }
        }
        ranges.sort_unstable();
        if stages.is_empty() || ranges.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty or overlapping plan",
            ));
        }
        Ok(Self {
            length,
            stages,
            preconditions: Vec::new(),
        })
    }
    /// Add source metadata snapshots checked before any writes.
    pub fn with_preconditions(mut self, preconditions: Vec<ReadCondition>) -> io::Result<Self> {
        if preconditions
            .iter()
            .any(|p| p.offset + p.expected.len() as u64 > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "precondition exceeds geometry",
            ));
        }
        self.preconditions.extend(preconditions);
        Ok(self)
    }
    /// Read-only source snapshots included in plan review.
    pub fn preconditions(&self) -> &[ReadCondition] {
        &self.preconditions
    }
    /// Expected byte geometry.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// Reviewable writes and barriers.
    pub fn stages(&self) -> &[Barrier] {
        &self.stages
    }
    /// Check all preconditions, write in order, flush, and reread every replacement.
    ///
    /// This verifies emitted bytes. A format-specific caller must additionally
    /// perform strict layout reinspection before reporting table validity.
    pub fn commit(
        &self,
        storage: &mut (impl Storage + ?Sized),
    ) -> Result<CommitReport, CommitError> {
        if storage.len().map_err(CommitError::Preflight)? != self.length {
            return Err(CommitError::Stale {
                reason: "disk geometry changed",
            });
        }
        for condition in &self.preconditions {
            let mut bytes = vec![0; condition.expected.len()];
            storage
                .read_exact_at(condition.offset, &mut bytes)
                .map_err(CommitError::Preflight)?;
            if bytes != condition.expected {
                return Err(CommitError::Stale {
                    reason: "source metadata changed",
                });
            }
        }
        for stage in &self.stages {
            for write in &stage.writes {
                let mut bytes = vec![0; write.expected.len()];
                storage
                    .read_exact_at(write.offset, &mut bytes)
                    .map_err(CommitError::Preflight)?;
                if bytes != write.expected {
                    return Err(CommitError::Stale {
                        reason: "metadata changed",
                    });
                }
            }
        }
        let mut completed = Vec::new();
        for stage in &self.stages {
            let result = (|| {
                for write in &stage.writes {
                    let mut done = 0;
                    while done < write.replacement.len() {
                        let n = storage
                            .write_at(write.offset + done as u64, &write.replacement[done..])?;
                        if n == 0 || n > write.replacement.len() - done {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "invalid positional write count",
                            ));
                        }
                        done += n;
                    }
                }
                storage.flush()
            })();
            if let Err(source) = result {
                return Err(CommitError::Interrupted {
                    completed_stages: completed,
                    stage: stage.name.clone(),
                    durability_uncertain: true,
                    source,
                });
            }
            completed.push(stage.name.clone());
        }
        for stage in &self.stages {
            for write in &stage.writes {
                let mut bytes = vec![0; write.replacement.len()];
                let result = storage
                    .read_exact_at(write.offset, &mut bytes)
                    .and_then(|()| {
                        if bytes == write.replacement {
                            Ok(())
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "commit readback mismatch",
                            ))
                        }
                    });
                if let Err(source) = result {
                    return Err(CommitError::Interrupted {
                        completed_stages: completed,
                        stage: "verification".into(),
                        durability_uncertain: false,
                        source,
                    });
                }
            }
        }
        Ok(CommitReport { completed })
    }
}

/// Regular raw-image adapter holding an operating-system exclusive file lock.
///
/// File locks may be advisory on Unix; all writers must honor the lock. This
/// adapter rejects device nodes and does not advertise raw block-device support.
pub struct FileStorage {
    file: std::sync::Mutex<std::fs::File>,
}
impl FileStorage {
    /// Open a preexisting image read/write and acquire its exclusive lock.
    pub fn open(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw storage requires a regular file",
            ));
        }
        file.try_lock().map_err(io::Error::other)?;
        Ok(Self {
            file: std::sync::Mutex::new(file),
        })
    }
    fn locked(&self) -> io::Result<std::sync::MutexGuard<'_, std::fs::File>> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("file lock poisoned"))
    }
}
impl Storage for FileStorage {
    fn len(&self) -> io::Result<u64> {
        Ok(self.locked()?.metadata()?.len())
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = self.locked()?;
        let length = file.metadata()?.len();
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = self.locked()?;
        let length = file.metadata()?.len();
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write exceeds image",
            ));
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.locked()?.sync_all()
    }
}
impl ResizableStorage for FileStorage {
    fn resize(&mut self, bytes: u64) -> io::Result<()> {
        let file = self.locked()?;
        file.set_len(bytes)?;
        file.sync_all()
    }
}

/// Borrowed read capability for an exclusively held storage adapter.
///
/// Construct and drop this view before borrowing the adapter mutably to commit.
/// The captured geometry is fixed; keep storage unchanged while inspecting it.
pub struct StorageReader<'a, S> {
    storage: &'a S,
    length: u64,
}
impl<'a, S: Storage> StorageReader<'a, S> {
    /// Capture the current geometry without opening another file handle.
    pub fn new(storage: &'a S) -> io::Result<Self> {
        Ok(Self {
            storage,
            length: storage.len()?,
        })
    }
}
impl<S: Storage + Send + Sync> virtdisk::ReadAt for StorageReader<'_, S> {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.storage.read_exact_at(offset, out)
    }
}
