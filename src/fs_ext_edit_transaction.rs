//! Scoped ranges and native dirty-fenced external undo transactions.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_file::ExtentKind,
    fs_undo::{UndoBinding, UndoFailure, UndoPlan, UndoStatus},
    storage::WriteRange,
};
const STATE: u64 = 1024 + 58;
const CLEAN: [u8; 2] = [1, 0];
const DIRTY: [u8; 2] = [0, 0];
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}
fn failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "ext2 edit preflight",
        recovery_required: false,
        target_may_have_changed: false,
        source,
    }
}
fn recovery_failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "ext2 recovery inspection",
        recovery_required: true,
        target_may_have_changed: true,
        source,
    }
}
fn copied(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| budget("ext2 payload allocation"))?;
    v.extend_from_slice(bytes);
    Ok(v)
}
/// One existing-file positional range, interpreted only through its owning session.
pub struct ExtReplacement<'a> {
    /// Scoped current file handle.
    pub file: &'a ExtEditFile,
    /// Logical byte offset.
    pub offset: u64,
    /// Exact caller bytes.
    pub bytes: &'a [u8],
}
// Planner-authored semantic evidence, never inferred from execution stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OrderedOperation {
    Extend {
        inode: u32,
        inode_generation: u32,
        old_length: u64,
        new_length: u64,
    },
    #[cfg_attr(
        not(feature = "std"),
        expect(
            dead_code,
            reason = "Ordered truncation requires the std owned journal controller"
        )
    )]
    Truncate {
        inode: u32,
        inode_generation: u32,
        old_length: u64,
        new_length: u64,
    },
    #[cfg_attr(
        not(feature = "std"),
        expect(dead_code, reason = "Ordered sparse extension requires std controller")
    )]
    SparseExtend {
        inode: u32,
        inode_generation: u32,
        old_length: u64,
        new_length: u64,
    },
    #[cfg_attr(
        not(feature = "std"),
        expect(dead_code, reason = "Ordered overwrite requires std owned controller")
    )]
    Overwrite {
        inode: u32,
        inode_generation: u32,
        length: u64,
        offset: u64,
        bytes: u64,
    },
    Create {
        inode: u32,
        inode_generation: u32,
        length: u64,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OrderedOrigin {
    AuditedFree,
    ExistingAppendTail { visible_prefix_bytes: usize },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OrderedDataPatch {
    pub(super) offset: u64,
    pub(super) bytes: usize,
    pub(super) logical_block: u64,
    pub(super) origin: OrderedOrigin,
}
pub(super) struct OverwriteEvidence {
    pub(super) guards: Vec<(u64, Vec<u8>, Reservation)>,
    pub(super) input: Vec<u8>,
    pub(super) _lease: Reservation,
}
pub(super) struct OrderedDataEvidence {
    pub(super) source: u128,
    pub(super) generation: u64,
    pub(super) operation: OrderedOperation,
    pub(super) data: Vec<OrderedDataPatch>,
    pub(super) source_guard: Option<(u64, Vec<u8>, Reservation)>,
    pub(super) overwrite: Option<OverwriteEvidence>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SymlinkAction {
    Create,
    #[cfg_attr(
        not(feature = "std"),
        expect(
            dead_code,
            reason = "Target replacement requires the std owned controller"
        )
    )]
    Replace,
    Rename,
    Unlink,
}
pub(super) struct SymlinkEvidence {
    pub(super) action: SymlinkAction,
    pub(super) source: u128,
    pub(super) generation: u64,
    pub(super) inode: u32,
    pub(super) inode_offset: u64,
    pub(super) original_inode: [u8; 128],
    pub(super) final_inode: [u8; 128],
    pub(super) target: Vec<u8>,
    pub(super) original_slow: Option<(u64, Vec<u8>)>,
    pub(super) fresh_slow: Option<u32>,
    pub(super) final_allocated: bool,
    pub(super) _lease: Reservation,
}
#[cfg(feature = "std")]
impl SymlinkEvidence {
    pub(super) fn guards(&self) -> impl Iterator<Item = (u64, &[u8])> {
        core::iter::once((self.inode_offset, self.original_inode.as_slice())).chain(
            self.original_slow
                .iter()
                .map(|(at, body)| (*at, body.as_slice())),
        )
    }
    pub(super) fn report_matches(&self, report: &ExtNamespaceReport) -> bool {
        let operation = match self.action {
            SymlinkAction::Create => ExtNamespaceOperation::CreateSymlink,
            SymlinkAction::Replace => ExtNamespaceOperation::ReplaceSymlinkTarget,
            SymlinkAction::Rename => ExtNamespaceOperation::RenameSymlink,
            SymlinkAction::Unlink => ExtNamespaceOperation::DeleteSymlink,
        };
        report.operation == operation
            && report.inode == self.inode
            && report.assigned_inode_generation
                == if self.action == SymlinkAction::Create {
                    Some(u32::from_le_bytes(
                        self.final_inode[100..104].try_into().unwrap(),
                    ))
                } else {
                    None
                }
            && report.released_inode != self.final_allocated
            && report.deletion_time
                == if self.final_allocated {
                    None
                } else {
                    Some(u32::from_le_bytes(
                        self.final_inode[20..24].try_into().unwrap(),
                    ))
                }
            && report.native_times_preserved
            && report.new_name.is_some() == (self.action != SymlinkAction::Unlink)
    }
}

/// Reviewable generation-bound patches with native dirty-state publication last.
pub struct ExtEditBatch {
    pub(super) source: u128,
    pub(super) generation: u64,
    pub(super) ordered: Option<OrderedDataEvidence>,
    #[cfg_attr(
        not(feature = "std"),
        expect(
            dead_code,
            reason = "Retains portable namespace proof leases; std controller additionally checks source guards"
        )
    )]
    pub(super) symlink: Vec<SymlinkEvidence>,
    pub(super) patches: Vec<WriteRange>,
    pub(super) stages: Vec<usize>,
    pub(super) bytes: u64,
    pub(super) _lease: Reservation,
    pub(super) resize: Option<ExtResizeReport>,
    pub(super) namespace: Option<ExtNamespaceReport>,
    pub(super) range_allocation: Option<ExtRangeAllocationReport>,
}
// Construction remains inside the semantic planner's module. The native
// controller can borrow the partition but cannot supply its own data roles.
#[cfg(feature = "std")]
pub(crate) struct NativeOrderedPatches {
    source: u128,
    generation: u64,
    metadata: Vec<WriteRange>,
    data: Vec<WriteRange>,
    source_guard: Option<(u64, Vec<u8>, Reservation)>,
    truncating: bool,
    overwriting: bool,
    sparse_extending: bool,
    overwrite: Option<OverwriteEvidence>,
    _lease: Reservation,
}
#[cfg(feature = "std")]
impl NativeOrderedPatches {
    pub(crate) fn binding(&self) -> (u128, u64) {
        (self.source, self.generation)
    }
    pub(crate) fn metadata(&self) -> &[WriteRange] {
        &self.metadata
    }
    pub(crate) fn is_truncate(&self) -> bool {
        self.truncating
    }
    pub(crate) fn is_sparse_extend(&self) -> bool {
        self.sparse_extending
    }
    pub(crate) fn is_overwrite(&self) -> bool {
        self.overwriting
    }
    pub(crate) fn source_guards(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.source_guard
            .iter()
            .map(|(at, bytes, _)| (*at, bytes.as_slice()))
            .chain(self.overwrite.iter().flat_map(|e| {
                e.guards
                    .iter()
                    .map(|(at, bytes, _)| (*at, bytes.as_slice()))
            }))
    }
    pub(crate) fn data(&self) -> &[WriteRange] {
        &self.data
    }
}
// This owner can only be minted by consuming a checked semantic namespace batch.
// Missing ordered-data evidence alone never authorizes metadata publication.
#[cfg(feature = "std")]
pub(crate) struct NativeNamespacePatches {
    symlink: Vec<SymlinkEvidence>,
    source: u128,
    generation: u64,
    patches: Vec<WriteRange>,
    _lease: Reservation,
}
#[cfg(feature = "std")]
impl NativeNamespacePatches {
    pub(crate) fn source_guards(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.symlink.iter().flat_map(|e| e.guards())
    }
    pub(crate) fn binding(&self) -> (u128, u64) {
        (self.source, self.generation)
    }
    pub(crate) fn patches(&self) -> &[WriteRange] {
        &self.patches
    }
}
impl ExtEditBatch {
    #[cfg(feature = "std")]
    pub(crate) fn into_namespace_patches(
        self,
        source: u128,
        generation: u64,
        work_limit: usize,
        resources: &Resources,
    ) -> Result<NativeNamespacePatches> {
        if (self.source, self.generation) != (source, generation) {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "native namespace batch binding changed",
            ));
        }
        resources.cancellation.check()?;
        if self.ordered.is_some() || self.resize.is_some() || self.range_allocation.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "native namespace batch contains a data operation",
            ));
        }
        let report = self.namespace.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "operation lacks semantic namespace evidence",
            )
        })?;
        if report.operation == ExtNamespaceOperation::CreateFile {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "regular creation requires ordered-data authority",
            ));
        }
        let is_symlink = matches!(
            report.operation,
            ExtNamespaceOperation::CreateSymlink
                | ExtNamespaceOperation::ReplaceSymlinkTarget
                | ExtNamespaceOperation::RenameSymlink
                | ExtNamespaceOperation::DeleteSymlink
        );
        if self.symlink.len() != usize::from(is_symlink)
            || self.symlink.first().is_some_and(|e| {
                e.source != source || e.generation != generation || !e.report_matches(report)
            })
        {
            return Err(bad("namespace lacks exact typed symlink proof"));
        }
        let mut work = 0usize;
        let mut tick = || -> Result<()> {
            resources.cancellation.check()?;
            work = work
                .checked_add(1)
                .filter(|n| *n <= work_limit)
                .ok_or_else(|| budget("native namespace extraction work ceiling"))?;
            Ok(())
        };
        tick()?;
        if report.inode == 0 || !report.native_times_preserved {
            return Err(bad("native namespace semantic report is inconsistent"));
        }
        match report.operation {
            ExtNamespaceOperation::CreateDirectory | ExtNamespaceOperation::CreateSymlink
                if report.assigned_inode_generation.is_some_and(|n| n != 0)
                    && !report.released_inode
                    && report.deletion_time.is_none() => {}
            ExtNamespaceOperation::CreateHardlink
            | ExtNamespaceOperation::Rename
            | ExtNamespaceOperation::ReplaceSymlinkTarget
            | ExtNamespaceOperation::RenameSymlink
                if report.assigned_inode_generation.is_none()
                    && !report.released_inode
                    && report.deletion_time.is_none() => {}
            ExtNamespaceOperation::DeleteFile
            | ExtNamespaceOperation::DeleteDirectory
            | ExtNamespaceOperation::DeleteSymlink
                if report.assigned_inode_generation.is_none()
                    && report.new_name.is_none()
                    && report.deletion_time.is_some_and(|n| n != 0) == report.released_inode
                    && (report.released_inode || report.deletion_time.is_none())
                    && (report.operation != ExtNamespaceOperation::DeleteDirectory
                        || report.released_inode) => {}
            _ => return Err(bad("native namespace operation report is inconsistent")),
        }
        if matches!(
            report.operation,
            ExtNamespaceOperation::CreateDirectory
                | ExtNamespaceOperation::CreateHardlink
                | ExtNamespaceOperation::Rename
                | ExtNamespaceOperation::CreateSymlink
                | ExtNamespaceOperation::ReplaceSymlinkTarget
                | ExtNamespaceOperation::RenameSymlink
        ) {
            let name = report
                .new_name
                .as_ref()
                .ok_or_else(|| bad("native namespace operation lacks its name"))?;
            if name.is_empty() || name.len() > 255 || name == b"." || name == b".." {
                return Err(bad("native namespace operation name is invalid"));
            }
            for byte in name {
                tick()?;
                if matches!(*byte, 0 | b'/') {
                    return Err(bad("native namespace operation name is invalid"));
                }
            }
        }
        if self.patches.is_empty() {
            return Err(bad("native namespace batch has no patches"));
        }
        let mut bytes = 0u64;
        for patch in &self.patches {
            tick()?;
            if patch.expected().is_empty()
                || patch.expected().len() != patch.replacement().len()
                || patch
                    .offset()
                    .checked_add(patch.expected().len() as u64)
                    .is_none()
            {
                return Err(bad("native namespace patch framing is invalid"));
            }
            bytes = bytes
                .checked_add(patch.expected().len() as u64)
                .ok_or_else(|| budget("native namespace byte accounting overflow"))?;
        }
        if bytes != self.bytes {
            return Err(bad("native namespace byte accounting differs"));
        }
        // Moving the original vector and byte buffers keeps their planner lease.
        Ok(NativeNamespacePatches {
            symlink: self.symlink,
            source,
            generation,
            patches: self.patches,
            _lease: self._lease,
        })
    }
    #[cfg(feature = "std")]
    pub(crate) fn into_ordered_patches(
        self,
        source: u128,
        generation: u64,
        work_limit: usize,
        resources: &Resources,
    ) -> Result<NativeOrderedPatches> {
        let evidence = self.ordered.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "operation lacks ordered-data evidence",
            )
        })?;
        if self.source != source
            || self.generation != generation
            || evidence.source != source
            || evidence.generation != generation
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "native ordered batch binding changed",
            ));
        }
        let mut work = 0usize;
        let mut tick = || -> Result<()> {
            resources.cancellation.check()?;
            work = work
                .checked_add(1)
                .filter(|n| *n <= work_limit)
                .ok_or_else(|| budget("native ordered partition work ceiling"))?;
            Ok(())
        };
        // Recheck exact role cardinality before moving any patch. The planner
        // already proved original ownership and prospective regular-file mapping.
        for role in &evidence.data {
            tick()?;
            let mut matches = 0usize;
            for patch in &self.patches {
                tick()?;
                matches += usize::from(
                    patch.offset() == role.offset && patch.expected().len() == role.bytes,
                );
            }
            if matches != 1 {
                return Err(bad("native ordered role lacks a unique exact patch"));
            }
        }
        let mut data_count = 0usize;
        for patch in &self.patches {
            tick()?;
            let mut matches = 0usize;
            for role in &evidence.data {
                tick()?;
                matches += usize::from(
                    patch.offset() == role.offset && patch.expected().len() == role.bytes,
                );
            }
            if matches > 1 {
                return Err(bad("native ordered duplicate data role"));
            }
            data_count += matches;
        }
        if data_count != evidence.data.len() {
            return Err(bad("native ordered partition coverage differs"));
        }
        let mut metadata = Vec::new();
        let mut data = Vec::new();
        let metadata_count = self.patches.len() - data_count;
        metadata
            .try_reserve_exact(metadata_count)
            .map_err(|_| budget("native ordered metadata allocation"))?;
        data.try_reserve_exact(data_count)
            .map_err(|_| budget("native ordered data allocation"))?;
        if metadata.capacity() > metadata_count || data.capacity() > data_count {
            return Err(budget("native ordered partition capacity"));
        }
        for patch in self.patches {
            tick()?;
            let mut is_data = false;
            for role in &evidence.data {
                tick()?;
                is_data |= patch.offset() == role.offset && patch.expected().len() == role.bytes;
            }
            if is_data {
                data.push(patch);
            } else {
                metadata.push(patch);
            }
        }
        // Both partition vectors fit the planner's retained patch-vector lease;
        // moving WriteRange transfers its byte buffers without copying them.
        let truncating = matches!(evidence.operation, OrderedOperation::Truncate { .. });
        let overwriting = matches!(evidence.operation, OrderedOperation::Overwrite { .. });
        let sparse_extending = matches!(evidence.operation, OrderedOperation::SparseExtend { .. });
        let evidence = self
            .ordered
            .ok_or_else(|| bad("ordered evidence vanished"))?;
        let source_guard = evidence.source_guard;
        let overwrite = evidence.overwrite;
        Ok(NativeOrderedPatches {
            source,
            generation,
            metadata,
            data,
            source_guard,
            truncating,
            overwriting,
            sparse_extending,
            overwrite,
            _lease: self._lease,
        })
    }
    #[cfg(feature = "std")]
    pub(crate) fn into_native_patches(self) -> (Vec<WriteRange>, Reservation) {
        // The full-journal controller consumes patches, not external-undo stages
        // or ordered-data evidence. Keep their reservation through extraction.
        let Self {
            patches, _lease, ..
        } = self;
        (patches, _lease)
    }
    /// Exact native before/after ranges; native clean state is published last.
    pub fn patches(&self) -> &[WriteRange] {
        &self.patches
    }
    /// Total target bytes including the explicit clean-state patch.
    pub fn affected_bytes(&self) -> u64 {
        self.bytes
    }
    /// Native resize allocation and metadata policy, when applicable.
    pub fn resize_report(&self) -> Option<&ExtResizeReport> {
        self.resize.as_ref()
    }
    /// Allocation effects when existing sparse holes receive replacement bytes.
    pub fn range_allocation_report(&self) -> Option<&ExtRangeAllocationReport> {
        self.range_allocation.as_ref()
    }
    /// Exact native namespace and metadata decisions, when applicable.
    pub fn namespace_report(&self) -> Option<&ExtNamespaceReport> {
        self.namespace.as_ref()
    }
    /// Nonempty stage sizes in execution order.
    pub fn stage_lengths(&self) -> &[usize] {
        &self.stages
    }
}
impl<S: Storage, J: Storage> ExtEditor<S, J> {
    pub(super) fn check_file(&self, file: &ExtEditFile, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if file.identity.source != self.scope || file.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated ext2 file handle",
            ));
        }
        Ok(())
    }
    /// Plan disjoint in-place data ranges; unrelated native inode fields remain byte-exact.
    pub fn plan_replace(
        &self,
        ranges: &[ExtReplacement<'_>],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.ready(r)?;
        if ranges.is_empty() || ranges.len() > self.limits.work {
            return Err(bad("ext2 replacement batch must be bounded and nonempty"));
        }
        let mut bytes = 2u64;
        for item in ranges {
            self.check_file(item.file, r)?;
            if item.bytes.is_empty()
                || item
                    .offset
                    .checked_add(item.bytes.len() as u64)
                    .is_none_or(|end| end > item.file.len())
            {
                return Err(bad("ext2 replacement outside existing logical file"));
            }
            bytes = bytes
                .checked_add(item.bytes.len() as u64)
                .filter(|n| *n <= self.limits.affected_bytes)
                .ok_or_else(|| budget("ext2 affected byte ceiling"))?;
        }
        if ranges.iter().any(|item| {
            item.file.map.extents.iter().any(|e| {
                matches!(e.kind, ExtentKind::Hole)
                    && e.offset < item.offset + item.bytes.len() as u64
                    && e.offset + e.length > item.offset
            })
        }) {
            return self.plan_replace_allocating(ranges, r);
        }
        let charge = bytes
            .checked_mul(2)
            .and_then(|n| {
                n.checked_add(
                    u64::from(self.limits.undo.patches)
                        * (crate::platform::mem::size_of::<WriteRange>() as u64 + 64),
                )
            })
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| budget("ext2 planning reservation overflow"))?;
        let lease = r.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(self.limits.undo.patches as usize)
            .map_err(|_| budget("ext2 patch vector allocation"))?;
        let mut work = 0usize;
        for item in ranges {
            let mut done = 0usize;
            let first = item
                .file
                .map
                .extents
                .partition_point(|e| e.offset + e.length <= item.offset);
            for extent in &item.file.map.extents[first..] {
                r.cancellation.check()?;
                work = work
                    .checked_add(1)
                    .filter(|n| *n <= self.limits.work)
                    .ok_or_else(|| budget("ext2 replacement work ceiling"))?;
                if patches.len() + 1 >= self.limits.undo.patches as usize {
                    return Err(budget("ext2 transaction patch ceiling"));
                }
                let at = item.offset + done as u64;
                if at < extent.offset || at >= extent.offset + extent.length {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "ext2 replacement map gap",
                    ));
                }
                let n = (extent.offset + extent.length - at).min((item.bytes.len() - done) as u64)
                    as usize;
                let ExtentKind::Data(physical) = extent.kind else {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "ext2 sparse replacement requires allocation planning",
                    ));
                };
                let physical = physical + at - extent.offset;
                let mut old = copied(&item.bytes[done..done + n])?;
                self.target
                    .read_exact_at(physical, &mut old)
                    .map_err(native)?;
                patches.push(
                    WriteRange::new(physical, old, copied(&item.bytes[done..done + n])?)
                        .map_err(native)?,
                );
                done += n;
                if done == item.bytes.len() {
                    break;
                }
            }
            if done != item.bytes.len() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ext2 incomplete replacement mapping",
                ));
            }
        }
        patches.sort_unstable_by_key(WriteRange::offset);
        for pair in patches.windows(2) {
            if pair[0].offset() + pair[0].expected().len() as u64 > pair[1].offset() {
                return Err(bad("ext2 replacements overlap through inode hardlinks"));
            }
        }
        let data = patches.len();
        patches.push(WriteRange::new(STATE, CLEAN.to_vec(), CLEAN.to_vec()).map_err(native)?);
        Ok(ExtEditBatch {
            source: self.scope,
            generation: self.generation,
            patches,
            stages: vec![data, 1],
            bytes,
            _lease: lease,
            resize: None,
            namespace: None,
            range_allocation: None,
            ordered: None,
            symlink: Vec::new(),
        })
    }
    /// Commit after durable undo publication; dirty fence precedes all target changes.
    pub fn commit(
        &mut self,
        batch: ExtEditBatch,
        transaction: [u8; 16],
        r: &Resources,
    ) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
        self.ready(r).map_err(failure)?;
        if batch
            .ordered
            .as_ref()
            .is_some_and(|e| e.source != batch.source || e.generation != batch.generation)
        {
            return Err(failure(Error::new(
                ErrorKind::StalePlan,
                "ext2 ordered evidence binding differs from batch",
            )));
        }
        if batch.source != self.scope || batch.generation != self.generation {
            return Err(failure(Error::new(
                ErrorKind::StalePlan,
                "foreign or stale ext2 batch",
            )));
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| failure(budget("ext2 handle generation exhausted")))?;
        let binding = UndoBinding {
            volume: self.binding.volume,
            generation: self.binding.generation,
            transaction,
        };
        let plan = UndoPlan::new_staged(
            binding,
            self.target.bounds.length,
            batch.patches,
            &batch.stages,
            self.limits.undo,
            r,
        )
        .map_err(failure)?;
        drop(batch.ordered);
        drop(batch._lease);
        self.state = ExtEditState::NeedsRecovery;
        self.pending = Some(binding);
        self.pending_write = true;
        self.generation = generation;
        self.audit = None;
        let (result, audit) = {
            let mut target = DirtyTarget {
                target: &mut self.target,
                started: false,
                limits: self.limits,
                r,
                audit: None,
            };
            let result = plan.commit(&mut target, &mut self.journal, r);
            (result, target.audit.take())
        };
        if let Err(error) = &result {
            self.pending_write = error.target_may_have_changed;
        }
        if result.is_ok() {
            // Growth changes native geometry inside the fixed owned region.
            // Keep recovery obligations sticky if post-commit observation fails.
            r.cancellation.check().map_err(recovery_failure)?;
            self.target
                .len()
                .map_err(native)
                .map_err(recovery_failure)?;
            let geometry = ExtStorageDecoder::open_storage(&self.target, self.scope, r)
                .map_err(native)
                .map_err(recovery_failure)?
                .geometry()
                .clone();
            self.target
                .len()
                .map_err(native)
                .map_err(recovery_failure)?;
            r.cancellation.check().map_err(recovery_failure)?;
            let verified_audit = audit.ok_or_else(|| {
                recovery_failure(Error::new(
                    ErrorKind::InvalidData,
                    "ext2 commit omitted clean structural audit",
                ))
            })?;
            self.geometry = geometry;
            self.audit = Some(verified_audit);
            self.state = ExtEditState::Ready;
            self.pending = None;
            self.pending_write = false;
        }
        result
    }
}
fn write_full(target: &mut dyn Storage, at: u64, bytes: &[u8], r: &Resources) -> io::Result<()> {
    let mut done = 0;
    while done < bytes.len() {
        r.cancellation.check().map_err(io::Error::other)?;
        let n = target.write_at(at + done as u64, &bytes[done..])?;
        if n == 0 || n > bytes.len() - done {
            return Err(io::ErrorKind::WriteZero.into());
        }
        done += n;
    }
    Ok(())
}
fn fence(target: &mut dyn Storage, r: &Resources) -> io::Result<()> {
    let mut state = [0; 2];
    target.read_exact_at(STATE, &mut state)?;
    if state != CLEAN && state != DIRTY {
        return Err(io::Error::other("ext2 unsupported native state fence"));
    }
    write_full(target, STATE, &DIRTY, r)?;
    target.flush()?;
    target.read_exact_at(STATE, &mut state)?;
    if state != DIRTY {
        return Err(io::Error::other("ext2 dirty state readback"));
    }
    Ok(())
}
struct Masked<'a> {
    target: &'a dyn Storage,
}
impl Storage for Masked<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)?;
        for (i, &b) in CLEAN.iter().enumerate() {
            let p = STATE + i as u64;
            if p >= at && p - at < out.len() as u64 {
                out[(p - at) as usize] = b;
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
struct DirtyTarget<'a> {
    target: &'a mut dyn Storage,
    started: bool,
    limits: ExtEditLimits,
    r: &'a Resources,
    audit: Option<ExtAuditReport>,
}
impl Storage for DirtyTarget<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            fence(self.target, self.r)?;
        }
        if at == STATE {
            if bytes != CLEAN {
                return Err(io::Error::other("ext2 unexpected clean publication"));
            }
            let audit = audit_ext_storage(
                &Masked {
                    target: self.target,
                },
                self.limits.audit,
                self.r,
            )
            .map_err(io::Error::other)?;
            if !audit.is_clean() {
                return Err(io::Error::other(
                    "ext2 final structural audit rejected clean publication",
                ));
            }
            self.audit = Some(audit);
        } else if at < STATE + 2 && at + bytes.len() as u64 > STATE {
            return Err(io::Error::other("ext2 state patch overlap"));
        }
        self.target.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()
    }
}

struct FenceValidator {
    seen: bool,
    work: usize,
    limit: usize,
}
impl fs_undo::UndoRecoveryValidator for FenceValidator {
    fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
        self.work = self
            .work
            .checked_add(1)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| budget("ext2 recovery framing work ceiling"))?;
        let end = at
            .checked_add(old.len() as u64)
            .ok_or_else(|| bad("ext2 recovery range overflow"))?;
        if at < STATE + 2 && end > STATE {
            if self.seen || at != STATE || old != CLEAN || new != CLEAN {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ext2 journal lacks exact clean-state framing",
                ));
            }
            self.seen = true;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        if !self.seen {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ext2 journal does not contain clean-state restoration",
            ));
        }
        Ok(())
    }
}
struct RestoreTarget<'a> {
    target: &'a mut dyn Storage,
    r: &'a Resources,
    limits: ExtEditLimits,
    started: bool,
    state_seen: bool,
    saved: Vec<(u64, Vec<u8>)>,
    recorded: u64,
}
impl Storage for RestoreTarget<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        if !self.started {
            self.started = true;
            fence(self.target, self.r)?;
        }
        if at == STATE {
            if bytes != CLEAN {
                return Err(io::Error::other("ext2 restoration native state framing"));
            }
            self.state_seen = true;
            return Ok(2);
        }
        if at < STATE + 2 && at + bytes.len() as u64 > STATE {
            return Err(io::Error::other("ext2 restoration state overlap"));
        }
        if self
            .recorded
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > self.limits.undo.body_bytes)
        {
            return Err(io::Error::other(budget("ext2 restore recording bytes")));
        }
        let adjacent = self
            .saved
            .last()
            .is_some_and(|(previous, data)| previous.checked_add(data.len() as u64) == Some(at));
        if !adjacent && self.saved.len() >= self.limits.undo.patches as usize {
            return Err(io::Error::other(budget("ext2 restore recording ranges")));
        }
        let n = self.target.write_at(at, bytes)?;
        if n == 0 || n > bytes.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.recorded += n as u64;
        if adjacent {
            let data = &mut self.saved.last_mut().unwrap().1;
            data.try_reserve(n).map_err(io::Error::other)?;
            data.extend_from_slice(&bytes[..n]);
        } else {
            let mut data = Vec::new();
            data.try_reserve_exact(n).map_err(io::Error::other)?;
            data.extend_from_slice(&bytes[..n]);
            self.saved.push((at, data));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()?;
        if !self.state_seen {
            return Err(io::Error::other("ext2 restored state patch missing"));
        }
        let mut scratch = [0; 4096];
        for (at, bytes) in &self.saved {
            for (i, part) in bytes.chunks(scratch.len()).enumerate() {
                self.r.cancellation.check().map_err(io::Error::other)?;
                self.target
                    .read_exact_at(*at + (i * 4096) as u64, &mut scratch[..part.len()])?;
                if &scratch[..part.len()] != part {
                    return Err(io::Error::other("ext2 restoration readback differs"));
                }
            }
        }
        let audit = audit_ext_storage(
            &Masked {
                target: self.target,
            },
            self.limits.audit,
            self.r,
        )
        .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(io::Error::other(
                "ext2 restored structural audit rejected clean state",
            ));
        }
        drop(audit);
        write_full(self.target, STATE, &CLEAN, self.r)?;
        self.target.flush()?;
        let mut state = [0; 2];
        self.target.read_exact_at(STATE, &mut state)?;
        if state != CLEAN {
            return Err(io::Error::other("ext2 restored clean state readback"));
        }
        Ok(())
    }
}
fn recover_guarded(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: ExtEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    let charge = limits
        .undo
        .body_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(u64::from(limits.undo.patches) * 64))
        .and_then(|n| n.checked_add(4096))
        .ok_or_else(|| recovery_failure(budget("ext2 recovery reservation overflow")))?;
    let _lease = r.memory.reserve(charge).map_err(recovery_failure)?;
    let mut saved = Vec::new();
    saved
        .try_reserve_exact(limits.undo.patches as usize)
        .map_err(|_| recovery_failure(budget("ext2 restoration vector")))?;
    let mut guarded = RestoreTarget {
        target,
        r,
        limits,
        started: false,
        state_seen: false,
        saved,
        recorded: 0,
    };
    let mut validator = FenceValidator {
        seen: false,
        work: 0,
        limit: limits.work,
    };
    fs_undo::recover_validated(
        &mut guarded,
        journal,
        binding,
        limits.undo,
        r,
        &mut validator,
    )
}
impl<S: Storage, J: Storage> ExtEditor<S, J> {
    /// Restart persisted recovery under independently verified volume/region/transaction identity.
    pub fn recover_open(
        storage: S,
        mut journal: J,
        region: ExtEditRegion,
        binding: UndoBinding,
        limits: ExtEditLimits,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, UndoFailure> {
        let container_length = storage.len().map_err(native).map_err(recovery_failure)?;
        if region.length < 2048
            || region
                .offset
                .checked_add(region.length)
                .is_none_or(|end| end > container_length)
        {
            return Err(recovery_failure(bad("ext2 recovery region outside target")));
        }
        let mut target = Region {
            storage,
            bounds: crate::fs_storage::RegionBounds::new(
                region.offset,
                region.length,
                container_length,
            ),
        };
        recover_guarded(&mut target, &mut journal, binding, limits, r)?;
        Self::open(
            target.storage,
            journal,
            region,
            ExtEditBinding {
                volume: binding.volume,
                generation: binding.generation,
            },
            limits,
            r,
        )
        .map_err(recovery_failure)
    }
    /// Resolve the pending transaction before allowing access to current handles or allocation.
    pub fn recover(
        &mut self,
        r: &Resources,
    ) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
        if self.state != ExtEditState::NeedsRecovery {
            return Err(failure(bad("ext2 session has no pending recovery")));
        }
        let binding = self
            .pending
            .ok_or_else(|| recovery_failure(bad("ext2 pending recovery binding absent")))?;
        let status = if self.pending_write {
            recover_guarded(&mut self.target, &mut self.journal, binding, self.limits, r)?
        } else {
            write_full(&mut self.journal, 0, &[0; 1024], r)
                .map_err(native)
                .map_err(recovery_failure)?;
            self.journal
                .flush()
                .map_err(native)
                .map_err(recovery_failure)?;
            let mut check = [1; 1024];
            self.journal
                .read_exact_at(0, &mut check)
                .map_err(native)
                .map_err(recovery_failure)?;
            if check != [0; 1024] {
                return Err(recovery_failure(bad(
                    "ext2 unpublished journal reset readback",
                )));
            }
            fs_undo::inspect(&self.journal, r).map_err(recovery_failure)?
        };
        self.audit = None;
        let audit =
            audit_ext_storage(&self.target, self.limits.audit, r).map_err(recovery_failure)?;
        if !audit.is_clean() {
            return Err(recovery_failure(Error::new(
                ErrorKind::InvalidData,
                "ext2 recovered ownership audit rejected",
            )));
        }
        let geometry = ExtStorageDecoder::open_storage(&self.target, self.scope, r)
            .map_err(native)
            .map_err(recovery_failure)?
            .geometry()
            .clone();
        self.target
            .len()
            .map_err(native)
            .map_err(recovery_failure)?;
        r.cancellation.check().map_err(recovery_failure)?;
        self.geometry = geometry;
        self.audit = Some(audit);
        self.state = ExtEditState::Ready;
        self.pending = None;
        self.pending_write = false;
        Ok(status)
    }
}
