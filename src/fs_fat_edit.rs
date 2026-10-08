//! Exclusive FAT sessions and recoverable existing-file replacement, extension and truncation.
//! Creation, renaming and deletion remain subsequent namespace operations.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};
use crate::{
    fs_core::{Error, ErrorKind, NativeName, ObjectId, Reservation, Resources, Result},
    fs_fat::{FatDecodedFileMap, FatGeometry, FatStorageDecoder},
    fs_fat_audit::{FatAuditLimits, FatAuditReport, audit_fat_storage},
    fs_file::ExtentKind,
    fs_undo::{self, UndoBinding, UndoFailure, UndoLimits, UndoPlan, UndoState, UndoStatus},
    storage::{Storage, WriteRange},
};
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
#[path = "fs_fat_edit_namespace.rs"]
mod namespace;
#[path = "fs_fat_edit_resize.rs"]
mod resize;
pub use namespace::{
    FatCreateMetadata, FatEditDirectory, FatEditName, FatNamePolicy, FatNamespaceOperation,
    FatNamespaceReport,
};
pub use resize::FatResizeReport;
/// Selected filesystem region within exclusively owned storage.
#[derive(Clone, Copy, Debug)]
pub struct FatEditRegion {
    /// Storage-relative first byte, which may be nonzero.
    pub offset: u64,
    /// Region length, including any caller-selected trailing volume padding.
    pub length: u64,
}
/// Explicit opening, file-map and transaction ceilings.
#[derive(Clone, Copy, Debug)]
pub struct FatEditLimits {
    /// Complete allocation/reference audit ceilings.
    pub audit: FatAuditLimits,
    /// Maximum clusters indexed for an opened existing file.
    pub file_clusters: usize,
    /// Maximum aggregate physically affected bytes in one batch, including initialized allocation.
    pub affected_bytes: u64,
    /// Maximum replacement requests in one batch.
    pub replacements: usize,
    /// Maximum extent/metadata/allocation visits across one batch.
    pub work: usize,
    /// Encoded undo patch and body limits; a fragmented replacement can need many patches.
    pub undo: UndoLimits,
}
/// Caller-verified volume/region identity and exclusive-session generation.
#[derive(Clone, Copy, Debug)]
pub struct FatEditBinding {
    /// Identifies both the actual selected volume and its bounded region; length is insufficient.
    pub volume: [u8; 32],
    /// Caller-assigned generation of the exclusive session, retained across recovery reopen.
    pub generation: u64,
}
/// State gates all file access after a failed transaction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatEditState {
    /// Complete clean audit established under the currently owned exclusive session.
    Ready,
    /// Commit uncertainty requires external undo recovery and fresh same-session inspection.
    NeedsRecovery,
}
struct Region<S> {
    storage: S,
    bounds: crate::fs_storage::RegionBounds,
}
impl<S: Storage> Region<S> {
    fn position(&self, at: u64, length: usize) -> io::Result<u64> {
        self.len()?;
        self.bounds.position(
            at,
            length as u64,
            || io::ErrorKind::UnexpectedEof.into(),
            || io::ErrorKind::InvalidInput.into(),
        )
    }
}
impl<S: Storage> Storage for Region<S> {
    fn len(&self) -> io::Result<u64> {
        self.bounds.check_parent(&self.storage, || {
            io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "FAT edit container length changed",
            ))
        })?;
        Ok(self.bounds.length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.storage
            .read_exact_at(self.position(at, out.len())?, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.storage
            .write_at(self.position(at, bytes.len())?, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.storage.flush()
    }
}
fn native(error: io::Error) -> Error {
    let kind = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .map_or_else(
            || match error.kind() {
                io::ErrorKind::InvalidData => ErrorKind::InvalidData,
                io::ErrorKind::Unsupported => ErrorKind::Unsupported,
                io::ErrorKind::InvalidInput => ErrorKind::InvalidOperation,
                _ => ErrorKind::Io,
            },
            |cause| cause.kind,
        );
    let mut mapped = Error::io("exclusive FAT decoder/storage access", error);
    mapped.kind = kind;
    mapped
}

fn exhausted(message: impl crate::platform::fmt::Display) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message.to_string())
}
fn copied(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len()).map_err(exhausted)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "FAT batch preflight",
        recovery_required: false,
        target_may_have_changed: false,
        source,
    }
}
/// Reusable source/generation-scoped mapping of one validated existing file.
/// It holds no backend read or write capability; all operations go through its editor.
pub struct FatEditFile {
    identity: ObjectId,
    name: NativeName,
    raw: [u8; 32],
    map: FatDecodedFileMap,
    _metadata: Reservation,
}
impl FatEditFile {
    /// Source and current editor generation, with physical directory-slot identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Exact native directory name.
    pub fn name(&self) -> &NativeName {
        &self.name
    }
    /// Unchanged original FAT metadata slot.
    pub fn raw_metadata(&self) -> &[u8; 32] {
        &self.raw
    }
    /// Logical length captured when this generation-scoped file handle was opened.
    pub fn len(&self) -> u64 {
        self.map.length
    }
    /// Whether the file has zero logical bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// One positional, equal-length replacement within a current file handle.
pub struct FatReplacement<'a> {
    /// File mapped by this exclusive session.
    pub file: &'a FatEditFile,
    /// Logical file offset.
    pub offset: u64,
    /// Replacement bytes; an empty request is rejected.
    pub bytes: &'a [u8],
}
/// Reviewable bounded file-derived patch batch, tied to one editor generation.
/// It cannot be constructed from arbitrary physical offsets.
pub struct FatEditBatch {
    source: u128,
    generation: u64,
    patches: Vec<WriteRange>,
    bytes: u64,
    stages: Option<Vec<usize>>,
    resize: Option<FatResizeReport>,
    namespace: Option<FatNamespaceReport>,
    _planning: Reservation,
}
impl FatEditBatch {
    /// Exact namespace operation and native metadata policy, if present.
    pub fn namespace_report(&self) -> Option<&FatNamespaceReport> {
        self.namespace.as_ref()
    }
    /// Allocation/length changes and explicit metadata policy, if this is a resize.
    pub fn resize_report(&self) -> Option<&FatResizeReport> {
        self.resize.as_ref()
    }
    /// Physically affected bytes, including initialized allocation for resize plans.
    pub fn affected_bytes(&self) -> u64 {
        self.bytes
    }
    /// Exact volume-relative patches derived from audited file mappings.
    pub fn patches(&self) -> &[WriteRange] {
        &self.patches
    }
}
#[derive(Clone, Copy)]
enum SessionState {
    Ready,
    NeedsRecovery {
        binding: UndoBinding,
        target_may_have_changed: bool,
    },
}
impl SessionState {
    fn public(self) -> FatEditState {
        match self {
            Self::Ready => FatEditState::Ready,
            Self::NeedsRecovery { .. } => FatEditState::NeedsRecovery,
        }
    }
}
/// Owns exclusive target and disjoint independently persistent external journal.
///
/// Storage implementors/callers must enforce exclusivity and journal disjointness.
/// Mutable storage is decoded through a borrowed Storage boundary, never ReadAt.
pub struct FatEditor<S: Storage, J: Storage> {
    target: Region<S>,
    journal: J,
    limits: FatEditLimits,
    binding: FatEditBinding,
    scope: u128,
    generation: u64,
    state: SessionState,
    geometry: FatGeometry,
    audit: Option<FatAuditReport>,
}
impl<S: Storage, J: Storage> FatEditor<S, J> {
    fn region(storage: S, region: FatEditRegion) -> Result<Region<S>> {
        let container_length = storage.len().map_err(native)?;
        if region.length < 512
            || region
                .offset
                .checked_add(region.length)
                .is_none_or(|end| end > container_length)
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "FAT edit region outside exclusive storage",
            ));
        }
        Ok(Region {
            storage,
            bounds: crate::fs_storage::RegionBounds::new(
                region.offset,
                region.length,
                container_length,
            ),
        })
    }
    /// Open only after a complete clean ownership/state audit of the currently owned target.
    /// A prepared journal must first be handled through `recover_open`.
    pub fn open(
        storage: S,
        journal: J,
        region: FatEditRegion,
        binding: FatEditBinding,
        limits: FatEditLimits,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        let target = Self::region(storage, region)?;
        let status = fs_undo::inspect(&journal, resources)?;
        if status
            .binding
            .is_some_and(|b| b.volume != binding.volume || b.generation != binding.generation)
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "FAT edit journal belongs to another volume/region/session binding",
            ));
        }
        if status.state == UndoState::Prepared {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT edit opening requires pending external undo recovery",
            ));
        }
        Self::inspected(target, journal, binding, limits, resources)
    }
    fn inspected(
        target: Region<S>,
        journal: J,
        binding: FatEditBinding,
        limits: FatEditLimits,
        resources: &Resources,
    ) -> Result<Self> {
        let number = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| exhausted("FAT editor source scope exhausted"))?;
        let scope = (5u128 << 64) | u128::from(number);
        let geometry = FatStorageDecoder::open_storage(&target, scope)
            .map_err(native)?
            .geometry()
            .clone();
        let audit = Self::clean_audit(&target, limits, resources)?;
        Ok(Self {
            target,
            journal,
            limits,
            binding,
            scope,
            generation: 0,
            state: SessionState::Ready,
            geometry,
            audit: Some(audit),
        })
    }
    fn clean_audit(
        target: &dyn Storage,
        limits: FatEditLimits,
        resources: &Resources,
    ) -> Result<FatAuditReport> {
        let audit = audit_fat_storage(target, limits.audit, resources).map_err(native)?;
        if !audit.namespace_complete() || !audit.findings().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "exclusive FAT editing requires a complete clean ownership/state audit",
            ));
        }
        Ok(audit)
    }
    /// Restore/verify a caller-bound persisted journal, then audit before creating a new session.
    /// The caller must independently verify the journal volume/region/session binding.
    pub fn recover_open(
        storage: S,
        mut journal: J,
        region: FatEditRegion,
        binding: UndoBinding,
        limits: FatEditLimits,
        resources: &Resources,
    ) -> crate::platform::result::Result<Self, UndoFailure> {
        resources.cancellation.check().map_err(failure)?;
        let mut target = Self::region(storage, region).map_err(failure)?;
        fs_undo::recover(&mut target, &mut journal, binding, limits.undo, resources)?;
        Self::inspected(
            target,
            journal,
            FatEditBinding {
                volume: binding.volume,
                generation: binding.generation,
            },
            limits,
            resources,
        )
        .map_err(failure)
    }
    /// Current operation gate.
    pub fn state(&self) -> FatEditState {
        self.state.public()
    }
    /// Logical generation used by file handles and batches.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Validated geometry, retained under exclusive ownership.
    pub fn geometry(&self) -> &FatGeometry {
        &self.geometry
    }
    fn ready(&self, resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        if self.state.public() != FatEditState::Ready {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT edit session requires recovery and reinspection",
            ));
        }
        self.target.len().map_err(native)?;
        Ok(())
    }
    fn check_file(&self, file: &FatEditFile, resources: &Resources) -> Result<()> {
        self.ready(resources)?;
        if file.identity.source != self.scope || file.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated FAT edit file handle",
            ));
        }
        Ok(())
    }
    /// Resolve an exact native path and index its existing file under the audited exclusive session.
    pub fn open_file(&self, path: &[NativeName], resources: &Resources) -> Result<FatEditFile> {
        self.ready(resources)?;
        if path.is_empty() || path.len() > self.limits.audit.entries {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT edit native path depth",
            ));
        }
        let decoder = FatStorageDecoder::open_storage(&self.target, self.scope).map_err(native)?;
        let mut directory = decoder
            .root_directory(
                self.limits.audit.clusters,
                self.limits.audit.directory_slots,
                resources,
            )
            .map_err(native)?;
        let metadata = resources.memory.reserve(1024)?;
        for (index, name) in path.iter().enumerate() {
            resources.cancellation.check()?;
            let entry = directory.lookup(name).map_err(native)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    "FAT edit native path not found",
                )
            })?;
            if index + 1 == path.len() {
                if entry.is_directory() || entry.raw_metadata()[11] & 1 != 0 {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "FAT edit range replacement requires a writable regular file",
                    ));
                }
                let map = decoder
                    .file_map(entry, self.limits.file_clusters, resources)
                    .map_err(native)?;
                let identity = ObjectId {
                    source: self.scope,
                    generation: self.generation,
                    native: copied(&entry.identity().native)?,
                };
                let name = match entry.name() {
                    NativeName::Bytes(alias) => NativeName::Bytes(copied(alias)?),
                    NativeName::Utf16(units) => {
                        let mut value = Vec::new();
                        value.try_reserve_exact(units.len()).map_err(exhausted)?;
                        value.extend_from_slice(units);
                        NativeName::Utf16(value)
                    }
                };
                return Ok(FatEditFile {
                    identity,
                    name,
                    raw: *entry.raw_metadata(),
                    map,
                    _metadata: metadata,
                });
            }
            directory = decoder
                .read_directory(
                    entry,
                    self.limits.audit.clusters,
                    self.limits.audit.directory_slots,
                    resources,
                )
                .map_err(native)?;
        }
        unreachable!("nonempty native path returns its final file")
    }
    /// Positional read of the current mapping, without creating an immutable backend alias.
    pub fn read_at(
        &self,
        file: &FatEditFile,
        offset: u64,
        out: &mut [u8],
        resources: &Resources,
    ) -> Result<usize> {
        self.check_file(file, resources)?;
        if offset >= file.len() || out.is_empty() {
            return Ok(0);
        }
        let count = (file.len() - offset).min(out.len() as u64) as usize;
        let mut done = 0;
        let first = file
            .map
            .extents
            .partition_point(|e| e.offset + e.length <= offset);
        for extent in &file.map.extents[first..] {
            resources.cancellation.check()?;
            let at = offset + done as u64;
            if at < extent.offset || at >= extent.offset + extent.length {
                continue;
            }
            let n = ((extent.offset + extent.length - at) as usize).min(count - done);
            let ExtentKind::Data(physical) = extent.kind else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "FAT edit file contains a nondata extent",
                ));
            };
            self.target
                .read_exact_at(physical + at - extent.offset, &mut out[done..done + n])
                .map_err(native)?;
            done += n;
            if done == count {
                return Ok(count);
            }
        }
        Err(Error::new(
            ErrorKind::InvalidData,
            "FAT edit mapping does not cover file range",
        ))
    }
    /// Prepare an explicit batch from existing file ranges; no writes occur here.
    /// Overlapping physical replacements are rejected before retaining authorization.
    pub fn plan_batch(
        &self,
        replacements: &[FatReplacement<'_>],
        resources: &Resources,
    ) -> Result<FatEditBatch> {
        self.ready(resources)?;
        if replacements.is_empty() || replacements.len() > self.limits.replacements {
            return Err(exhausted("FAT edit replacement count cap"));
        }
        let mut bytes = 0u64;
        for replacement in replacements {
            self.check_file(replacement.file, resources)?;
            if replacement.bytes.is_empty()
                || replacement
                    .offset
                    .checked_add(replacement.bytes.len() as u64)
                    .is_none_or(|end| end > replacement.file.len())
            {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "FAT edit replacement extends outside existing file",
                ));
            }
            bytes = bytes
                .checked_add(replacement.bytes.len() as u64)
                .filter(|n| *n <= self.limits.affected_bytes)
                .ok_or_else(|| exhausted("FAT edit affected-byte cap"))?;
        }
        let charge = bytes
            .checked_mul(2)
            .and_then(|n| {
                n.checked_add(
                    u64::from(self.limits.undo.patches)
                        * crate::platform::mem::size_of::<WriteRange>() as u64,
                )
            })
            .ok_or_else(|| exhausted("FAT edit batch accounting overflow"))?;
        let planning = resources.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(self.limits.undo.patches as usize)
            .map_err(exhausted)?;
        let mut work = 0usize;
        for replacement in replacements {
            let mut done = 0usize;
            for extent in &replacement.file.map.extents {
                resources.cancellation.check()?;
                work = work
                    .checked_add(1)
                    .filter(|n| *n <= self.limits.work)
                    .ok_or_else(|| exhausted("FAT edit transaction work cap"))?;
                let at = replacement.offset + done as u64;
                if at < extent.offset || at >= extent.offset + extent.length {
                    continue;
                }
                if patches.len() == self.limits.undo.patches as usize {
                    return Err(exhausted("FAT edit undo patch cap"));
                }
                let n = ((extent.offset + extent.length - at) as usize)
                    .min(replacement.bytes.len() - done);
                let ExtentKind::Data(physical) = extent.kind else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "FAT edit replacement maps nondata",
                    ));
                };
                let physical = physical + at - extent.offset;
                let mut old = copied(&replacement.bytes[done..done + n])?;
                self.target
                    .read_exact_at(physical, &mut old)
                    .map_err(native)?;
                let new = copied(&replacement.bytes[done..done + n])?;
                patches.push(WriteRange::new(physical, old, new).map_err(native)?);
                done += n;
                if done == replacement.bytes.len() {
                    break;
                }
            }
            if done != replacement.bytes.len() {
                return Err(Error::new(ErrorKind::InvalidData, "FAT edit batch map gap"));
            }
        }
        patches.sort_unstable_by_key(WriteRange::offset);
        for pair in patches.windows(2) {
            if pair[0].offset() + pair[0].expected().len() as u64 > pair[1].offset() {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "FAT edit batch has overlapping file ranges",
                ));
            }
        }
        Ok(FatEditBatch {
            source: self.scope,
            generation: self.generation,
            patches,
            bytes,
            stages: None,
            resize: None,
            namespace: None,
            _planning: planning,
        })
    }
    /// Commit only this generation's file-derived batch using the owned external undo medium.
    /// Caller transaction identifiers must be unique for the caller's durable session binding.
    /// All handles/batches invalidate after success or a failed transaction attempt.
    pub fn commit(
        &mut self,
        batch: FatEditBatch,
        transaction: [u8; 16],
        resources: &Resources,
    ) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
        self.ready(resources).map_err(failure)?;
        if batch.source != self.scope || batch.generation != self.generation {
            return Err(failure(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated FAT edit batch",
            )));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| failure(exhausted("FAT edit generation exhausted")))?;
        let binding = UndoBinding {
            volume: self.binding.volume,
            generation: self.binding.generation,
            transaction,
        };
        let resize = batch.resize.is_some() || batch.namespace.is_some();
        let plan = match batch.stages {
            Some(stages) => UndoPlan::new_staged(
                binding,
                self.target.bounds.length,
                batch.patches,
                &stages,
                self.limits.undo,
                resources,
            ),
            None => UndoPlan::new(
                binding,
                self.target.bounds.length,
                batch.patches,
                self.limits.undo,
                resources,
            ),
        }
        .map_err(failure)?;
        drop(batch._planning);
        self.state = SessionState::NeedsRecovery {
            binding,
            target_may_have_changed: true,
        };
        self.generation = next_generation;
        let result = plan.commit(&mut self.target, &mut self.journal, resources);
        if let Err(error) = &result {
            self.state = SessionState::NeedsRecovery {
                binding,
                target_may_have_changed: error.target_may_have_changed,
            };
        }
        if result.is_ok() {
            if resize {
                self.audit = None;
                self.audit = Some(
                    Self::clean_audit(&self.target, self.limits, resources).map_err(|source| {
                        UndoFailure {
                            stage: "FAT resize committed reinspection",
                            recovery_required: true,
                            target_may_have_changed: true,
                            source,
                        }
                    })?,
                );
            }
            self.state = SessionState::Ready;
        }
        result
    }
    /// Recover the attempted transaction and repeat the complete ownership/state audit.
    /// When the retained failure proves no target write was attempted, this continuing
    /// owner may reset its failed journal publication before reauditing. That proof
    /// is not inferred from a filesystem audit and is not retained after releasing stores.
    /// Otherwise invalid/torn headers or mismatching journals remain blocked.
    pub fn recover(
        &mut self,
        resources: &Resources,
    ) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
        let SessionState::NeedsRecovery {
            binding,
            target_may_have_changed,
        } = self.state
        else {
            return Err(failure(Error::new(
                ErrorKind::InvalidOperation,
                "FAT edit session has no pending recovery",
            )));
        };
        let status = if target_may_have_changed {
            fs_undo::recover(
                &mut self.target,
                &mut self.journal,
                binding,
                self.limits.undo,
                resources,
            )?
        } else {
            // This owned session opened without Prepared and attempted no target writes.
            // Its failed journal publication can be discarded, then the target is reaudited.
            let mut at = 0usize;
            let zeros = [0u8; 1024];
            let _scratch = resources.memory.reserve(2048).map_err(failure)?;
            while at < zeros.len() {
                resources.cancellation.check().map_err(failure)?;
                let n = self
                    .journal
                    .write_at(at as u64, &zeros[at..])
                    .map_err(native)
                    .map_err(failure)?;
                if n == 0 || n > zeros.len() - at {
                    return Err(failure(Error::new(
                        ErrorKind::Io,
                        "FAT unpublished journal reset short write",
                    )));
                }
                at += n;
            }
            self.journal.flush().map_err(native).map_err(failure)?;
            let mut verified = [0u8; 1024];
            self.journal
                .read_exact_at(0, &mut verified)
                .map_err(native)
                .map_err(failure)?;
            if verified != zeros {
                return Err(failure(Error::new(
                    ErrorKind::InvalidData,
                    "FAT unpublished journal reset verification",
                )));
            }
            fs_undo::inspect(&self.journal, resources).map_err(failure)?
        };
        self.audit = None;
        let audit = Self::clean_audit(&self.target, self.limits, resources).map_err(failure)?;
        self.audit = Some(audit);
        self.state = SessionState::Ready;
        Ok(status)
    }
    /// Release both exclusively owned stores and the explicit uncertainty state.
    /// Releasing a blocked session does not discharge its persisted recovery obligation.
    pub fn into_stores(self) -> (S, J, FatEditState) {
        (self.target.storage, self.journal, self.state.public())
    }
}
