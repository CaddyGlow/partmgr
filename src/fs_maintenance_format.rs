//! std-only creation of new classic ext2 working images; never live formatting.
//!
//! Caller must exclusively control the working path, its directory and this
//! file for the whole session. create_new prevents replacing an existing path;
//! it does not prevent another process opening the new file. Publication and
//! directory durability are separate caller operations after verified extraction.
use crate::platform::io;
use crate::{
    fs_core::{Error, ErrorKind, Reservation, Resources, Result},
    fs_ext_audit::{ExtAuditLimits, ExtAuditReport, audit_ext_storage},
    fs_ext_builder::{
        ExtBuildLimits, ExtBuildMetadata, ExtBuildOptions, ExtBuildPlan, ExtBuildReport,
    },
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Finite ceilings in addition to the builder and full-audit limits.
#[derive(Clone, Copy, Debug)]
pub struct ExtFormatLimits {
    /// Maximum bytes read to prove the newly created working image remains zero.
    pub zero_scan_bytes: u64,
    /// Complete namespace and allocation planning ceilings.
    pub build: ExtBuildLimits,
    /// Complete post-emission ownership and namespace audit ceilings.
    pub audit: ExtAuditLimits,
}
/// Working image authorization state; Failed is terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtFormatState {
    /// New zero-filled image available for planning.
    Empty,
    /// An exclusive plan owns the session borrow.
    Planned,
    /// Emission or final verification is in progress.
    Emitting,
    /// Emission and complete native audit succeeded.
    Verified,
    /// A failed operation requires discarding this session.
    Failed,
}
struct WorkingFile(Mutex<File>);
impl WorkingFile {
    fn file(&self) -> io::Result<std::sync::MutexGuard<'_, File>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("working file lock poisoned"))
    }
}
impl Storage for WorkingFile {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file()?.metadata()?.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let mut f = self.file()?;
        f.seek(SeekFrom::Start(at))?;
        f.read_exact(out).map_err(Into::into)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut f = self.file()?;
        f.seek(SeekFrom::Start(at))?;
        f.write(bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file()?.sync_all().map_err(Into::into)
    }
}
// Tracks possible payload mutation at the exact backend boundary, including
// writes which return an error after changing bytes.
struct Tracking<S> {
    backend: S,
    attempted_write: bool,
}
impl<S: Storage> Storage for Tracking<S> {
    fn len(&self) -> io::Result<u64> {
        self.backend.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.attempted_write = true;
        self.backend.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.backend.flush()
    }
}
struct Core<S> {
    file: Tracking<S>,
    length: u64,
    state: ExtFormatState,
}
/// Owns an exclusive unpublished working output. There is no backend accessor.
pub struct ExtFormatImage {
    core: Core<WorkingFile>,
    working_path: PathBuf,
    path_lease: Reservation,
}
impl ExtFormatImage {
    /// Atomically create a previously absent absolute working path. Never
    /// truncates, adopts an existing file, accepts a region, or publishes a name.
    pub fn create_new(working_path: impl AsRef<Path>, length: u64, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        let path = working_path.as_ref();
        if !path.is_absolute() || length < 2048 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "invalid fresh ext2 working output",
            ));
        }
        let path_bytes = path.as_os_str().len();
        let path_lease = r.memory.reserve(path_bytes as u64)?;
        let mut owned = std::ffi::OsString::new();
        owned
            .try_reserve_exact(path_bytes)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "working path allocation"))?;
        if owned.capacity() > path_bytes {
            return Err(Error::new(
                ErrorKind::BudgetExhausted,
                "working path capacity",
            ));
        }
        owned.push(path.as_os_str());
        let owned_path = PathBuf::from(owned);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| Error::io("create new ext2 working output", e.into()))?;
        if !file
            .metadata()
            .map_err(|e| Error::io("working output metadata", e.into()))?
            .is_file()
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "working output must be a regular file",
            ));
        }
        // Failure leaves a new unpublished artifact; no cleanup or publication
        // is implied. The existing path is never removed by this API.
        file.set_len(length)
            .map_err(|e| Error::io("size fresh ext2 working output", e.into()))?;
        r.cancellation.check()?;
        Ok(Self {
            core: Core {
                file: Tracking {
                    backend: WorkingFile(Mutex::new(file)),
                    attempted_write: false,
                },
                length,
                state: ExtFormatState::Empty,
            },
            working_path: owned_path,
            path_lease,
        })
    }
    /// Current authorization state; no failure grants artifact extraction.
    pub fn state(&self) -> ExtFormatState {
        self.core.state
    }
    /// Plan an empty root directory under the explicit classic ext2 profile.
    /// The plan borrows this exact owner until it is emitted or dropped.
    ///
    /// ```compile_fail
    /// use partmgr::{fs_core::Resources, fs_ext_builder::{ExtBuildOptions,
    ///     ExtBuildMetadata}, fs_maintenance_format::{ExtFormatImage, ExtFormatLimits}};
    /// fn cannot_extract(mut image: ExtFormatImage, options: ExtBuildOptions,
    ///     metadata: ExtBuildMetadata, limits: ExtFormatLimits, r: &Resources) {
    ///     let plan = image.plan_empty(options, metadata, limits, r).unwrap();
    ///     let artifact = image.into_verified();
    ///     let operation = plan.operation();
    /// }
    /// ```
    pub fn plan_empty<'a>(
        &'a mut self,
        options: ExtBuildOptions,
        defaults: ExtBuildMetadata,
        limits: ExtFormatLimits,
        r: &Resources,
    ) -> Result<ExtFormatPlan<'a>> {
        Ok(ExtFormatPlan {
            inner: self.core.plan_empty(options, defaults, limits, r)?,
        })
    }
    /// Release only a verified working artifact. This does not rename, publish,
    /// delete or fsync its directory. Failed sessions expose no ready artifact.
    pub fn into_verified(self) -> Result<ExtFormatArtifact> {
        if self.core.state != ExtFormatState::Verified {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "working output is not verified",
            ));
        }
        let file = self
            .core
            .file
            .backend
            .0
            .into_inner()
            .map_err(|_| Error::new(ErrorKind::Io, "working file lock poisoned"))?;
        Ok(ExtFormatArtifact {
            file,
            working_path: self.working_path,
            _path_lease: self.path_lease,
        })
    }
}
/// Verified descriptor and its working name; publication remains explicit.
pub struct ExtFormatArtifact {
    /// Owned verified working descriptor; publication is a separate operation.
    pub file: File,
    /// Unpublished working name supplied to create_new.
    pub working_path: PathBuf,
    _path_lease: Reservation,
}
/// Plan lifetime prevents owner access until emission or abandonment.
pub struct ExtFormatPlan<'a> {
    inner: CorePlan<'a, WorkingFile>,
}
impl ExtFormatPlan<'_> {
    /// Common maintenance operation represented by this concrete plan.
    pub fn operation(&self) -> crate::fs_maintenance::MaintenanceOperation {
        crate::fs_maintenance::MaintenanceOperation::Format
    }
    /// Consume the plan, emit, read back, and completely audit the working image.
    /// Any error leaves the session terminal; no artifact is returned.
    pub fn emit(self, r: &Resources) -> Result<ExtFormatReport> {
        self.inner.emit(r)
    }
}
struct CorePlan<'a, S: Storage> {
    owner: &'a mut Core<S>,
    builder: ExtBuildPlan,
    options: ExtBuildOptions,
    limits: ExtFormatLimits,
}
impl<S: Storage> Core<S> {
    /// An exclusive borrow binds this plan to this exact owned descriptor;
    /// callers cannot switch backends or supply an observed identity assertion.
    pub fn plan_empty<'a>(
        &'a mut self,
        options: ExtBuildOptions,
        defaults: ExtBuildMetadata,
        limits: ExtFormatLimits,
        r: &Resources,
    ) -> Result<CorePlan<'a, S>> {
        if self.state != ExtFormatState::Empty {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "working output is not empty",
            ));
        }
        r.cancellation.check()?;
        if self.length > limits.zero_scan_bytes {
            return Err(Error::new(
                ErrorKind::BudgetExhausted,
                "ext2 zero scan ceiling",
            ));
        }
        let builder = ExtBuildPlan::new(
            self.length,
            options,
            Vec::new(),
            Vec::new(),
            defaults,
            limits.build,
            r,
        )?;
        self.state = ExtFormatState::Planned;
        Ok(CorePlan {
            owner: self,
            builder,
            options,
            limits,
        })
    }
}
/// Actual output evidence, without inventing a persistent backend identity.
pub struct ExtFormatReport {
    /// Byte emission and whole-image verification evidence.
    pub build: ExtBuildReport,
    /// Complete clean ownership and namespace audit.
    pub audit: ExtAuditReport,
    /// UUID read from the actual emitted primary superblock.
    pub uuid: [u8; 16],
    /// Native allocation unit read from the emitted superblock.
    pub block_size: u32,
    /// Native total block count read from the emitted superblock.
    pub blocks: u32,
    /// Actual compatible, incompatible and read-only feature words.
    pub feature_words: [u32; 3],
    /// SHA-256 of the actual 1024-byte primary superblock.
    pub primary_sha256: [u8; 32],
}
impl<S: Storage> Drop for CorePlan<'_, S> {
    fn drop(&mut self) {
        if self.owner.state == ExtFormatState::Planned {
            self.owner.state = ExtFormatState::Empty;
        }
    }
}
impl<S: Storage> CorePlan<'_, S> {
    fn emit(self, r: &Resources) -> Result<ExtFormatReport> {
        let result = (|| {
            r.cancellation.check()?;
            if self
                .owner
                .file
                .len()
                .map_err(|e| Error::io("working output length", e))?
                != self.owner.length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "working output length changed",
                ));
            }
            // Bounded constant scratch; zero scan is independent of filesystem
            // geometry and checks the actual descriptor rather than a claim.
            let _lease = r.memory.reserve(65536)?;
            let mut scratch = Vec::new();
            scratch.try_reserve_exact(65536).map_err(|_| {
                Error::new(ErrorKind::BudgetExhausted, "ext2 zero scratch allocation")
            })?;
            if scratch.capacity() > 65536 {
                return Err(Error::new(
                    ErrorKind::BudgetExhausted,
                    "ext2 zero scratch capacity",
                ));
            }
            scratch.resize(65536, 0);
            let mut at = 0;
            while at < self.owner.length {
                r.cancellation.check()?;
                let n = (self.owner.length - at).min(scratch.len() as u64) as usize;
                self.owner
                    .file
                    .read_exact_at(at, &mut scratch[..n])
                    .map_err(|e| Error::io("fresh output zero scan", e))?;
                if scratch[..n].iter().any(|b| *b != 0) {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "fresh output contains nonzero bytes",
                    ));
                }
                at += n as u64;
            }
            if self
                .owner
                .file
                .len()
                .map_err(|e| Error::io("working output final zero length", e))?
                != self.owner.length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "working output zero scan length changed",
                ));
            }
            drop(scratch);
            drop(_lease);
            self.owner.state = ExtFormatState::Emitting;
            let build = self.builder.emit(&mut self.owner.file, r)?;
            let audit = audit_ext_storage(&self.owner.file, self.limits.audit, r)?;
            if !audit.is_clean() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "formatted ext2 full audit failed",
                ));
            }
            r.cancellation.check()?;
            let mut primary = [0u8; 1024];
            self.owner
                .file
                .read_exact_at(1024, &mut primary)
                .map_err(|e| Error::io("formatted primary", e))?;
            let u32at = |at| {
                u32::from_le_bytes([
                    primary[at],
                    primary[at + 1],
                    primary[at + 2],
                    primary[at + 3],
                ])
            };
            let blocks = u32at(4);
            let block_size = 1024u32
                .checked_shl(u32at(24))
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "formatted block size"))?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&primary[104..120]);
            let features = [u32at(92), u32at(96), u32at(100)];
            if primary[56..58] != [0x53, 0xef]
                || u32at(76) != 1
                || block_size != self.options.block_size
                || uuid != self.options.uuid
                || u64::from(blocks) * u64::from(block_size) != self.owner.length
                || features != [0, 2, 1]
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "formatted native profile differs from plan",
                ));
            }
            if self
                .owner
                .file
                .len()
                .map_err(|e| Error::io("formatted final length", e))?
                != self.owner.length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "formatted final length changed",
                ));
            }
            r.cancellation.check()?;
            Ok(ExtFormatReport {
                build,
                audit,
                uuid,
                block_size,
                blocks,
                feature_words: features,
                primary_sha256: Sha256::digest(primary).into(),
            })
        })();
        match result {
            Ok(report) => {
                self.owner.state = ExtFormatState::Verified;
                Ok(report)
            }
            Err(error) => {
                self.owner.state = ExtFormatState::Failed;
                if self.owner.file.attempted_write && error.kind != ErrorKind::UncertainDurability {
                    let mut outer = Error::io(
                        "ext2 working image emission interrupted",
                        io::Error::other(error),
                    );
                    outer.kind = ErrorKind::InterruptedWrite;
                    Err(outer)
                } else {
                    Err(error)
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "fs_maintenance_format_tests.rs"]
mod tests;
