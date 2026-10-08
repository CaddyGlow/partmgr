//! Exclusive bounded exFAT sessions with disjoint external undo and native dirty fences.
use crate::{
    fs_core::{Error, ErrorKind, NativeName, ObjectId, Reservation, Resources, Result},
    fs_exfat::ExfatBoot,
    fs_exfat_audit::{ExfatAuditLimits, ExfatAuditReport, audit_exfat_storage},
    fs_exfat_volume::{ExfatDecoder, ExfatReadLimits, Mapping},
    fs_undo::{self, UndoBinding, UndoFailure, UndoLimits, UndoPlan, UndoState, UndoStatus},
    storage::{Storage, WriteRange},
};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
#[path = "fs_exfat_edit_namespace.rs"]
mod namespace;
pub use namespace::{
    ExfatCreateMetadata, ExfatEditDirectory, ExfatNamespaceOperation, ExfatNamespaceReport,
};
/// Bounded selected filesystem region; journal must be physically disjoint.
#[derive(Clone, Copy, Debug)]
pub struct ExfatEditRegion {
    /// Storage-relative region start.
    pub offset: u64,
    /// Bounded filesystem region length.
    pub length: u64,
}
/// Caller-verified identity includes volume, selected region and session provenance.
#[derive(Clone, Copy, Debug)]
pub struct ExfatEditBinding {
    /// Caller-verified volume and selected region identity.
    pub volume: [u8; 32],
    /// Caller-assigned exclusive session generation.
    pub generation: u64,
}
/// Explicit decoder/audit/planning/undo ceilings.
#[derive(Clone, Copy, Debug)]
pub struct ExfatEditLimits {
    /// Native decoder limits.
    pub read: ExfatReadLimits,
    /// Complete ownership audit limits.
    pub audit: ExfatAuditLimits,
    /// Maximum physically affected final patch bytes in one transaction.
    pub affected_bytes: u64,
    /// Maximum planning visits.
    pub work: usize,
    /// External journal patch and encoded body limits.
    pub undo: UndoLimits,
}
/// Failure gates all further file reads/plans until recovery succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExfatEditState {
    /// Complete clean same-owner audit permits access.
    Ready,
    /// All access is blocked until bound external undo recovery.
    NeedsRecovery,
}
fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn native(e: io::Error) -> Error {
    Error::io("exFAT owned storage", e)
}
fn failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "exFAT session preflight",
        recovery_required: false,
        target_may_have_changed: false,
        source,
    }
}
fn recovery_failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "exFAT recovery preflight",
        recovery_required: true,
        target_may_have_changed: false,
        source,
    }
}
fn zeros(n: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    b.try_reserve_exact(n)
        .map_err(|_| budget("exFAT edit allocation"))?;
    b.resize(n, 0);
    Ok(b)
}
struct Region<S> {
    store: S,
    region: ExfatEditRegion,
    observed: u64,
}
impl<S: Storage> Region<S> {
    fn at(&self, at: u64, n: usize) -> io::Result<u64> {
        if self.store.len()? != self.observed {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "exFAT target length changed",
            )));
        }
        if at
            .checked_add(n as u64)
            .is_none_or(|end| end > self.region.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.region
            .offset
            .checked_add(at)
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}
impl<S: Storage> Storage for Region<S> {
    fn len(&self) -> io::Result<u64> {
        self.at(0, 0)?;
        Ok(self.region.length)
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.store.read_exact_at(self.at(at, b.len())?, b)?;
        self.at(0, 0)?;
        Ok(())
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.store.write_at(self.at(at, b.len())?, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.at(0, 0)?;
        self.store.flush()?;
        self.at(0, 0)?;
        Ok(())
    }
}
/// Source/generation-scoped existing file; mapping and native metadata retain leases.
pub struct ExfatEditFile {
    identity: ObjectId,
    name: Vec<u16>,
    raw: Vec<[u8; 32]>,
    locations: Vec<u64>,
    map: Mapping,
    valid: u64,
    contiguous: bool,
    _lease: Reservation,
}
impl ExfatEditFile {
    /// Same-session object identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Exact native UTF16 name.
    pub fn name(&self) -> &[u16] {
        &self.name
    }
    /// Logical file length.
    pub fn len(&self) -> u64 {
        self.map.file.len()
    }
    /// Whether the logical file is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Initialized prefix length.
    pub fn valid_data_length(&self) -> u64 {
        self.valid
    }
    /// Whether the native allocation is contiguous.
    pub fn no_fat_chain(&self) -> bool {
        self.contiguous
    }
    /// Complete native file entry set.
    pub fn raw_metadata(&self) -> &[[u8; 32]] {
        &self.raw
    }
}
/// Reviewable disjoint final patches and ordered durable publication stages.
pub struct ExfatEditBatch {
    source: u128,
    generation: u64,
    patches: Vec<WriteRange>,
    stages: Vec<usize>,
    names: Vec<&'static str>,
    bytes: u64,
    dirty: u16,
    final_flags: u16,
    namespace: Option<ExfatNamespaceReport>,
    _namespace_lease: Option<Reservation>,
    _lease: Reservation,
}
impl ExfatEditBatch {
    /// Namespace and allocation changes, when this is a namespace operation.
    pub fn namespace_report(&self) -> Option<&ExfatNamespaceReport> {
        self.namespace.as_ref()
    }
    /// Disjoint final byte replacements.
    pub fn patches(&self) -> &[WriteRange] {
        &self.patches
    }
    /// Patch counts in durable execution order.
    pub fn stage_lengths(&self) -> &[usize] {
        &self.stages
    }
    /// Maximum physically affected final patch bytes in one transaction.
    pub fn affected_bytes(&self) -> u64 {
        self.bytes
    }
    /// Names for ordered flush-and-verification barriers.
    pub fn stage_names(&self) -> &[&'static str] {
        &self.names
    }
    /// Intermediate main volume flags, persisted before target changes.
    pub fn dirty_flags(&self) -> u16 {
        self.dirty
    }
    /// Final main volume flags, persisted last.
    pub fn final_flags(&self) -> u16 {
        self.final_flags
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
    fn public(self) -> ExfatEditState {
        match self {
            Self::Ready => ExfatEditState::Ready,
            Self::NeedsRecovery { .. } => ExfatEditState::NeedsRecovery,
        }
    }
}
/// Owns both exclusive stores. Storage ownership alone cannot establish physical disjointness.
pub struct ExfatEditor<S: Storage, J: Storage> {
    target: Region<S>,
    journal: J,
    limits: ExfatEditLimits,
    binding: ExfatEditBinding,
    scope: u128,
    generation: u64,
    state: SessionState,
    boot: ExfatBoot,
    audit: Option<ExfatAuditReport>,
}
impl<S: Storage, J: Storage> ExfatEditor<S, J> {
    fn region(store: S, region: ExfatEditRegion) -> Result<Region<S>> {
        let observed = store.len().map_err(native)?;
        if region.length == 0
            || region
                .offset
                .checked_add(region.length)
                .is_none_or(|end| end > observed)
        {
            return Err(bad("exFAT edit region outside target"));
        }
        Ok(Region {
            store,
            region,
            observed,
        })
    }
    /// Open exclusively owned target and disjoint external journal after complete clean audit.
    pub fn open(
        store: S,
        journal: J,
        region: ExfatEditRegion,
        binding: ExfatEditBinding,
        limits: ExfatEditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let target = Self::region(store, region)?;
        let status = fs_undo::inspect(&journal, r)?;
        if status.state == UndoState::Prepared {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT edit needs external undo recovery",
            ));
        }
        if status
            .binding
            .is_some_and(|b| b.volume != binding.volume || b.generation != binding.generation)
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign exFAT external journal",
            ));
        }
        Self::inspected(target, journal, binding, limits, r)
    }
    fn inspected(
        target: Region<S>,
        journal: J,
        binding: ExfatEditBinding,
        limits: ExfatEditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let n = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| budget("exFAT edit scope exhausted"))?;
        let scope = (8u128 << 64) | u128::from(n);
        let decoder = ExfatDecoder::open_storage(&target, scope, limits.read, r)?;
        let boot = decoder.boot().clone();
        if boot.flags & 8 != 0 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "exFAT ClearToZero write profile unsupported",
            ));
        }
        drop(decoder);
        let audit = Self::clean(&target, limits, r)?;
        Ok(Self {
            target,
            journal,
            limits,
            binding,
            scope,
            generation: 0,
            state: SessionState::Ready,
            boot,
            audit: Some(audit),
        })
    }
    fn clean(
        target: &dyn Storage,
        limits: ExfatEditLimits,
        r: &Resources,
    ) -> Result<ExfatAuditReport> {
        let audit = audit_exfat_storage(target, limits.read, limits.audit, r)?;
        if !audit.is_clean() {
            return Err(bad(
                "exFAT edit requires complete clean same-owner allocation audit",
            ));
        }
        Ok(audit)
    }
    fn ready(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.target.len().map_err(native)?;
        if self.state.public() != ExfatEditState::Ready {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT session needs recovery",
            ));
        }
        Ok(())
    }
    fn check_file(&self, f: &ExfatEditFile, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if f.identity.source != self.scope || f.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or stale exFAT edit file",
            ));
        }
        for (at, expected) in f.locations.iter().zip(&f.raw) {
            let mut b = [0; 32];
            self.target.read_exact_at(*at, &mut b).map_err(native)?;
            if &b != expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "exFAT native file set changed",
                ));
            }
        }
        Ok(())
    }
    /// Current readiness or recovery obligation.
    pub fn state(&self) -> ExfatEditState {
        self.state.public()
    }
    /// Caller-assigned exclusive session generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Validated geometry under this exclusive session.
    pub fn boot(&self) -> &ExfatBoot {
        &self.boot
    }
    /// Resolve exact native components and retain a generation-bound file map.
    pub fn open_file(&self, path: &[NativeName], r: &Resources) -> Result<ExfatEditFile> {
        self.ready(r)?;
        if path.is_empty() {
            return Err(bad("empty exFAT edit file path"));
        }
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        let mut directory = decoder.root_directory(r)?;
        for (index, name) in path.iter().enumerate() {
            let NativeName::Utf16(name) = name else {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "exFAT edit needs exact UTF16 native names",
                ));
            };
            let entry = directory
                .lookup(name)?
                .ok_or_else(|| bad("exFAT edit path component missing"))?;
            if index + 1 == path.len() {
                if entry.attributes() & 1 != 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidOperation,
                        "exFAT read-only file cannot be edited",
                    ));
                }
                let map = decoder.file_map(entry, r)?;
                let lease = r.memory.reserve(
                    entry.raw_metadata().len() as u64 * 80 + name.len() as u64 * 2 + 128,
                )?;
                let mut copied_name = Vec::new();
                copied_name
                    .try_reserve_exact(entry.name().len())
                    .map_err(|_| budget("exFAT edit name"))?;
                copied_name.extend_from_slice(entry.name());
                let mut raw = Vec::new();
                raw.try_reserve_exact(entry.raw_metadata().len())
                    .map_err(|_| budget("exFAT edit set"))?;
                raw.extend_from_slice(entry.raw_metadata());
                let mut locations = Vec::new();
                locations
                    .try_reserve_exact(raw.len())
                    .map_err(|_| budget("exFAT edit locations"))?;
                locations.extend_from_slice(entry.edit_locations());
                let mut native = zeros(8)?;
                native.copy_from_slice(&locations[0].to_le_bytes());
                return Ok(ExfatEditFile {
                    identity: ObjectId {
                        source: self.scope,
                        generation: self.generation,
                        native,
                    },
                    name: copied_name,
                    raw,
                    locations,
                    map,
                    valid: entry.valid_data_length(),
                    contiguous: entry.no_fat_chain(),
                    _lease: lease,
                });
            }
            directory = decoder.read_directory(entry, r)?;
        }
        unreachable!()
    }
    /// Read mapped data with native initialized-prefix zero semantics.
    pub fn read_at(
        &self,
        f: &ExfatEditFile,
        at: u64,
        out: &mut [u8],
        r: &Resources,
    ) -> Result<usize> {
        self.check_file(f, r)?;
        if at >= f.len() {
            return Ok(0);
        }
        let n = f
            .map
            .file
            .read_at_with(at, out, |p, b| {
                r.cancellation.check().map_err(io::Error::other)?;
                self.target.read_exact_at(p, b)
            })
            .map_err(native)?;
        self.ready(r)?;
        Ok(n)
    }
    fn planner<'a>(&'a self, r: &'a Resources) -> Result<Planner<'a, S>> {
        self.ready(r)?;
        let charge = self
            .limits
            .affected_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(u64::from(self.limits.undo.patches) * 128))
            .and_then(|n| {
                n.checked_add((self.limits.read.max_chain_clusters as u64).checked_mul(8)?)
            })
            .ok_or_else(|| budget("exFAT planning charge"))?;
        let lease = r.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(self.limits.undo.patches as usize)
            .map_err(|_| budget("exFAT patch allocation"))?;
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(8)
            .map_err(|_| budget("exFAT stage index"))?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(8)
            .map_err(|_| budget("exFAT stage names"))?;
        Ok(Planner {
            target: &self.target,
            limits: self.limits,
            r,
            patches,
            stages,
            names,
            bytes: 0,
            work: 0,
            lease,
        })
    }
    /// Replace one existing-length range; zero an uninitialized gap before publishing its new valid length.
    pub fn plan_replace(
        &self,
        f: &ExfatEditFile,
        offset: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.check_file(f, r)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= f.len())
            .ok_or_else(|| bad("exFAT replacement outside existing logical length"))?;
        if bytes.is_empty() {
            return Err(bad("empty exFAT replacement"));
        }
        let mut p = self.planner(r)?;
        let start = offset.min(f.valid);
        p.file_bytes(
            &self.boot,
            &f.map.clusters,
            start,
            end,
            Some((offset, bytes)),
        )?;
        p.stage("initialize replacement and valid-length gap");
        if end > f.valid {
            p.metadata(
                f,
                f.len(),
                end,
                f.map.clusters.first().copied().unwrap_or(0),
                f.contiguous,
            )?;
            p.stage("publish initialized prefix");
        }
        p.final_flags(self.boot.flags)?;
        p.finish(self.scope, self.generation, self.boot.flags)
    }
    /// Extend with initialized zero bytes or truncate, allocating only from the retained clean audit.
    pub fn plan_resize(
        &self,
        f: &ExfatEditFile,
        new_length: u64,
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.check_file(f, r)?;
        if new_length == f.len() {
            return Err(bad("unchanged exFAT length"));
        }
        let mut p = self.planner(r)?;
        let needed = new_length.div_ceil(u64::from(self.boot.cluster_bytes));
        if needed > self.limits.read.max_chain_clusters as u64
            || needed > u64::from(self.boot.clusters)
        {
            return Err(budget("exFAT resize allocation ceiling"));
        }
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        let old_count = f.map.clusters.len();
        p.tick(old_count)?;
        let mut clusters = Vec::new();
        clusters
            .try_reserve_exact(needed.max(f.map.clusters.len() as u64) as usize)
            .map_err(|_| budget("exFAT resize clusters"))?;
        clusters.extend_from_slice(&f.map.clusters);
        if needed as usize > old_count {
            for range in self.audit.as_ref().expect("ready audit").free_ranges() {
                let mut at = range.offset;
                while at < range.offset + range.length && clusters.len() < needed as usize {
                    p.tick(1)?;
                    clusters.push(
                        ((at - self.boot.heap_offset) / u64::from(self.boot.cluster_bytes)) as u32
                            + 2,
                    );
                    at += u64::from(self.boot.cluster_bytes);
                }
                if clusters.len() == needed as usize {
                    break;
                }
            }
            if clusters.len() != needed as usize {
                return Err(budget("exFAT insufficient audited free clusters"));
            }
        }
        let growing = new_length > f.len();
        p.tick(needed as usize)?;
        let contiguous = needed != 0
            && clusters[..needed as usize]
                .windows(2)
                .all(|c| c[1] == c[0] + 1);
        let first = clusters
            .first()
            .copied()
            .filter(|_| needed != 0)
            .unwrap_or(0);
        if growing {
            let initialize_end = if needed as usize > old_count {
                needed * u64::from(self.boot.cluster_bytes)
            } else {
                new_length
            };
            p.file_bytes(&self.boot, &clusters, f.valid, initialize_end, None)?;
            p.stage("initialize extension before allocation publication");
        }
        if !growing {
            p.metadata(f, new_length, f.valid.min(new_length), first, contiguous)?;
            p.stage("publish truncated native file set");
        }
        if !contiguous && needed != 0 {
            for (i, &c) in clusters[..needed as usize].iter().enumerate() {
                let next = clusters
                    .get(i + 1)
                    .copied()
                    .filter(|_| i + 1 < needed as usize)
                    .unwrap_or(u32::MAX);
                p.patch(
                    self.boot.fat_offset + u64::from(c) * 4,
                    next.to_le_bytes().to_vec(),
                )?;
            }
        }
        if !growing && !f.contiguous {
            for &c in &clusters[needed as usize..] {
                p.patch(self.boot.fat_offset + u64::from(c) * 4, vec![0; 4])?;
            }
        }
        p.stage("publish FAT mapping");
        let changed = if growing {
            &clusters[old_count..]
        } else {
            &clusters[needed as usize..]
        };
        let mut edits = std::collections::BTreeMap::<u64, (u8, u8)>::new();
        for &c in changed {
            p.tick(1)?;
            let (at, mask) = decoder.bitmap_position(c)?;
            p.tick((edits.len() + 1).ilog2() as usize + 1)?;
            if !edits.contains_key(&at) && edits.len() >= self.limits.undo.patches as usize {
                return Err(budget("exFAT bitmap patch limit"));
            }
            let e = match edits.entry(at) {
                std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::btree_map::Entry::Vacant(e) => {
                    let mut old = [0];
                    self.target.read_exact_at(at, &mut old).map_err(native)?;
                    e.insert((old[0], old[0]))
                }
            };
            if growing {
                e.1 |= mask;
            } else {
                e.1 &= !mask;
            }
        }
        for (at, (_, new)) in edits {
            p.patch(at, vec![new])?;
        }
        p.stage("publish allocation bitmap");
        if growing {
            p.metadata(f, new_length, new_length, first, contiguous)?;
            p.stage("publish extended native file set");
        }
        let allocated = self.audit.as_ref().unwrap().allocated_clusters() as i128 + needed as i128
            - old_count as i128;
        let percent = (allocated * 100 / i128::from(self.boot.clusters)) as u8;
        p.patch(112, vec![percent])?;
        p.stage("publish allocation usage");
        p.final_flags(self.boot.flags)?;
        p.finish(self.scope, self.generation, self.boot.flags)
    }
    /// Durably journal, fence dirty, execute and verify stages, clear dirty last, then re-audit.
    pub fn commit(
        &mut self,
        batch: ExfatEditBatch,
        transaction: [u8; 16],
        r: &Resources,
    ) -> std::result::Result<UndoStatus, UndoFailure> {
        self.ready(r).map_err(failure)?;
        if batch.source != self.scope || batch.generation != self.generation {
            return Err(failure(Error::new(
                ErrorKind::StalePlan,
                "stale exFAT edit batch",
            )));
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| failure(budget("exFAT edit generation")))?;
        let binding = UndoBinding {
            volume: self.binding.volume,
            generation: self.binding.generation,
            transaction,
        };
        let plan = UndoPlan::new_staged(
            binding,
            self.target.region.length,
            batch.patches,
            &batch.stages,
            self.limits.undo,
            r,
        )
        .map_err(failure)?;
        drop(batch._lease);
        self.state = SessionState::NeedsRecovery {
            binding,
            target_may_have_changed: true,
        };
        self.generation = next;
        let (result, new_audit) = {
            let mut guarded = DirtyTarget {
                target: &mut self.target,
                dirty: batch.dirty,
                started: false,
                r,
                limits: self.limits,
                audit: None,
            };
            let result = plan.commit(&mut guarded, &mut self.journal, r);
            (result, guarded.audit.take())
        };
        if let Err(e) = &result {
            self.state = SessionState::NeedsRecovery {
                binding,
                target_may_have_changed: e.target_may_have_changed,
            };
        }
        if result.is_ok() {
            self.audit = new_audit;
            if self.audit.is_none() {
                return Err(UndoFailure {
                    stage: "exFAT missing pre-clean audit",
                    recovery_required: true,
                    target_may_have_changed: true,
                    source: bad("exFAT final flags were not structurally verified"),
                });
            }
            let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)
                .map_err(|source| UndoFailure {
                    stage: "exFAT committed decoder refresh",
                    recovery_required: true,
                    target_may_have_changed: true,
                    source,
                })?;
            self.boot = decoder.boot().clone();
            self.state = SessionState::Ready;
        }
        result
    }
    /// Recover a caller-bound persisted transaction and establish a fresh clean session.
    pub fn recover_open(
        store: S,
        mut journal: J,
        region: ExfatEditRegion,
        binding: UndoBinding,
        limits: ExfatEditLimits,
        r: &Resources,
    ) -> std::result::Result<Self, UndoFailure> {
        let mut target = Self::region(store, region).map_err(recovery_failure)?;
        recover_guarded(&mut target, &mut journal, binding, limits, r)?;
        Self::inspected(
            target,
            journal,
            ExfatEditBinding {
                volume: binding.volume,
                generation: binding.generation,
            },
            limits,
            r,
        )
        .map_err(recovery_failure)
    }
    /// Restore or verify the pending transaction before permitting further operations.
    pub fn recover(&mut self, r: &Resources) -> std::result::Result<UndoStatus, UndoFailure> {
        let SessionState::NeedsRecovery {
            binding,
            target_may_have_changed,
        } = self.state
        else {
            return Err(failure(bad("exFAT session has no recovery obligation")));
        };
        let status = if target_may_have_changed {
            recover_guarded(&mut self.target, &mut self.journal, binding, self.limits, r)?
        } else {
            write_full(&mut self.journal, 0, &[0; 1024], r)
                .map_err(native)
                .map_err(failure)?;
            self.journal.flush().map_err(native).map_err(failure)?;
            let mut check = [1; 1024];
            self.journal
                .read_exact_at(0, &mut check)
                .map_err(native)
                .map_err(failure)?;
            if check != [0; 1024] {
                return Err(failure(bad("exFAT unpublished journal reset")));
            }
            fs_undo::inspect(&self.journal, r).map_err(failure)?
        };
        self.audit = None;
        self.audit = Some(Self::clean(&self.target, self.limits, r).map_err(failure)?);
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)
            .map_err(|source| UndoFailure {
                stage: "exFAT recovered decoder refresh",
                recovery_required: true,
                target_may_have_changed,
                source,
            })?;
        self.boot = decoder.boot().clone();
        self.state = SessionState::Ready;
        Ok(status)
    }
    /// Release both owned stores and the remaining explicit recovery obligation.
    pub fn into_stores(self) -> (S, J, ExfatEditState) {
        (self.target.store, self.journal, self.state.public())
    }
}
struct Planner<'a, S: Storage> {
    target: &'a Region<S>,
    limits: ExfatEditLimits,
    r: &'a Resources,
    patches: Vec<WriteRange>,
    stages: Vec<usize>,
    names: Vec<&'static str>,
    bytes: u64,
    work: usize,
    lease: Reservation,
}
impl<S: Storage> Planner<'_, S> {
    fn tick(&mut self, n: usize) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("exFAT planning work"))?;
        Ok(())
    }
    fn patch(&mut self, at: u64, after: Vec<u8>) -> Result<()> {
        self.tick(1)?;
        self.bytes = self
            .bytes
            .checked_add(after.len() as u64)
            .filter(|n| *n <= self.limits.affected_bytes)
            .ok_or_else(|| budget("exFAT affected bytes"))?;
        if self.patches.len() >= self.limits.undo.patches as usize {
            return Err(budget("exFAT patch ceiling"));
        }
        let mut before = zeros(after.len())?;
        self.target.read_exact_at(at, &mut before).map_err(native)?;
        self.patches
            .push(WriteRange::new(at, before, after).map_err(native)?);
        Ok(())
    }
    fn stage(&mut self, name: &'static str) {
        let previous = self.stages.iter().sum::<usize>();
        let n = self.patches.len() - previous;
        if n != 0 {
            self.stages.push(n);
            self.names.push(name);
        }
    }
    fn file_bytes(
        &mut self,
        boot: &ExfatBoot,
        clusters: &[u32],
        start: u64,
        end: u64,
        payload: Option<(u64, &[u8])>,
    ) -> Result<()> {
        if end
            .checked_sub(start)
            .and_then(|n| self.bytes.checked_add(n))
            .is_none_or(|n| n > self.limits.affected_bytes)
        {
            return Err(budget("exFAT initialization byte ceiling"));
        }
        let mut pos = start;
        while pos < end {
            self.tick(1)?;
            let index = (pos / u64::from(boot.cluster_bytes)) as usize;
            let within = pos % u64::from(boot.cluster_bytes);
            let n = (end - pos)
                .min(u64::from(boot.cluster_bytes) - within)
                .min(65536) as usize;
            let mut out = zeros(n)?;
            if let Some((at, data)) = payload {
                let first = pos.max(at);
                let last = (pos + n as u64).min(at + data.len() as u64);
                if first < last {
                    out[(first - pos) as usize..(last - pos) as usize]
                        .copy_from_slice(&data[(first - at) as usize..(last - at) as usize]);
                }
            }
            self.patch(
                boot.cluster_offset(
                    *clusters
                        .get(index)
                        .ok_or_else(|| bad("exFAT initialization map"))?,
                )? + within,
                out,
            )?;
            pos += n as u64;
        }
        Ok(())
    }
    fn metadata(
        &mut self,
        f: &ExfatEditFile,
        length: u64,
        valid: u64,
        first: u32,
        contiguous: bool,
    ) -> Result<()> {
        self.tick(f.raw.len())?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(f.raw.len())
            .map_err(|_| budget("exFAT file set planning"))?;
        raw.extend_from_slice(&f.raw);
        raw[1][1] = if length == 0 {
            1
        } else if contiguous {
            3
        } else {
            1
        };
        raw[1][8..16].copy_from_slice(&valid.to_le_bytes());
        raw[1][20..24].copy_from_slice(&first.to_le_bytes());
        raw[1][24..32].copy_from_slice(&length.to_le_bytes());
        let sum = raw
            .iter()
            .flatten()
            .enumerate()
            .filter(|(i, _)| *i != 2 && *i != 3)
            .fold(0u16, |sum, (_, b)| {
                sum.rotate_right(1).wrapping_add(u16::from(*b))
            });
        raw[0][2..4].copy_from_slice(&sum.to_le_bytes());
        for (at, b) in f.locations.iter().zip(raw) {
            self.patch(*at, b.to_vec())?;
        }
        Ok(())
    }
    fn final_flags(&mut self, flags: u16) -> Result<()> {
        self.patch(106, (flags & !8).to_le_bytes().to_vec())?;
        self.stage("clear dirty after all metadata verification");
        Ok(())
    }
    fn finish(self, source: u128, generation: u64, flags: u16) -> Result<ExfatEditBatch> {
        Ok(ExfatEditBatch {
            source,
            generation,
            patches: self.patches,
            stages: self.stages,
            names: self.names,
            bytes: self.bytes,
            dirty: (flags | 2) & !8,
            final_flags: flags & !8,
            namespace: None,
            _namespace_lease: None,
            _lease: self.lease,
        })
    }
}
fn write_full(target: &mut dyn Storage, at: u64, b: &[u8], r: &Resources) -> io::Result<()> {
    let mut done = 0;
    while done < b.len() {
        r.cancellation.check().map_err(io::Error::other)?;
        let n = target.write_at(at + done as u64, &b[done..])?;
        if n == 0 || n > b.len() - done {
            return Err(io::Error::other("exFAT invalid short write"));
        }
        done += n;
    }
    Ok(())
}
struct DirtyTarget<'a> {
    target: &'a mut dyn Storage,
    dirty: u16,
    started: bool,
    limits: ExfatEditLimits,
    audit: Option<ExfatAuditReport>,
    r: &'a Resources,
}
impl Storage for DirtyTarget<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, b)
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            write_full(self.target, 106, &self.dirty.to_le_bytes(), self.r)?;
            self.target.flush()?;
            let mut flags = [0; 2];
            self.target.read_exact_at(106, &mut flags)?;
            if flags != self.dirty.to_le_bytes() {
                return Err(io::Error::other("exFAT dirty fence verification"));
            }
        }
        if at == 106 {
            if b != [0, 0] {
                return Err(io::Error::other("exFAT unexpected final flags patch"));
            }
            let masked = Masked {
                target: self.target,
                flags: [0, 0],
            };
            let audit = audit_exfat_storage(&masked, self.limits.read, self.limits.audit, self.r)
                .map_err(io::Error::other)?;
            if !audit.is_clean() {
                return Err(io::Error::other("exFAT pre-clean structural audit"));
            }
            self.audit = Some(audit);
        }
        self.target.write_at(at, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()
    }
}
struct Masked<'a> {
    target: &'a dyn Storage,
    flags: [u8; 2],
}
impl Storage for Masked<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, b)?;
        for (i, &value) in self.flags.iter().enumerate() {
            let p = 106 + i as u64;
            if p >= at && p - at < b.len() as u64 {
                b[(p - at) as usize] = value;
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
struct RestoreTarget<'a> {
    target: &'a mut dyn Storage,
    flags: Option<[u8; 2]>,
    writes: Vec<(u64, Vec<u8>)>,
    started: bool,
    limits: ExfatEditLimits,
    r: &'a Resources,
    recorded: u64,
}
impl Storage for RestoreTarget<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, b)
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        if !self.started {
            // The journal is physically sorted. Every editor transaction saves the
            // exact main flags patch first; reject foreign framing before mutation.
            if at != 106 || b.len() != 2 || b != [0, 0] {
                return Err(io::Error::other(
                    "exFAT journal lacks supported clean flags as first patch",
                ));
            }
            let mut current = [0; 2];
            self.target.read_exact_at(106, &mut current)?;
            if !matches!(u16::from_le_bytes(current), 0 | 2) {
                return Err(io::Error::other("exFAT unsupported current rollback flags"));
            }
            self.flags = Some([0, 0]);
            self.started = true;
            write_full(self.target, 106, &2u16.to_le_bytes(), self.r)?;
            self.target.flush()?;
            self.target.read_exact_at(106, &mut current)?;
            if current != 2u16.to_le_bytes() {
                return Err(io::Error::other("exFAT rollback dirty fence"));
            }
            return Ok(2);
        }
        if at < 108 && at + b.len() as u64 > 106 {
            return Err(io::Error::other("exFAT rollback flags framing"));
        }
        if self
            .recorded
            .checked_add(b.len() as u64)
            .is_none_or(|n| n > self.limits.undo.body_bytes)
        {
            return Err(io::Error::other("exFAT rollback recording cap"));
        }
        let adjacent = self
            .writes
            .last()
            .is_some_and(|(previous, bytes)| previous.checked_add(bytes.len() as u64) == Some(at));
        if !adjacent && self.writes.len() >= self.limits.undo.patches as usize {
            return Err(io::Error::other("exFAT rollback range cap"));
        }
        let n = self.target.write_at(at, b)?;
        if n == 0 || n > b.len() {
            return Err(io::Error::other("exFAT invalid restoration short write"));
        }
        self.recorded += n as u64;
        if adjacent {
            let bytes = &mut self.writes.last_mut().unwrap().1;
            bytes.try_reserve(n).map_err(io::Error::other)?;
            bytes.extend_from_slice(&b[..n]);
        } else {
            let mut copy = Vec::new();
            copy.try_reserve_exact(n).map_err(io::Error::other)?;
            copy.extend_from_slice(&b[..n]);
            self.writes.push((at, copy));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()?;
        let mut scratch = [0; 4096];
        for (at, b) in &self.writes {
            for (i, part) in b.chunks(4096).enumerate() {
                self.r.cancellation.check().map_err(io::Error::other)?;
                self.target
                    .read_exact_at(*at + i as u64 * 4096, &mut scratch[..part.len()])?;
                if &scratch[..part.len()] != part {
                    return Err(io::Error::other("exFAT restored data verification"));
                }
            }
        }
        let flags = self
            .flags
            .ok_or_else(|| io::Error::other("exFAT journal lacks flag restoration"))?;
        let masked = Masked {
            target: self.target,
            flags,
        };
        let audit = audit_exfat_storage(&masked, self.limits.read, self.limits.audit, self.r)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(io::Error::other("exFAT restored structural audit"));
        }
        drop(audit);
        write_full(self.target, 106, &flags, self.r)?;
        self.target.flush()?;
        let mut actual = [0; 2];
        self.target.read_exact_at(106, &mut actual)?;
        if actual != flags {
            return Err(io::Error::other("exFAT restored flags verification"));
        }
        Ok(())
    }
}
fn recover_guarded(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: ExfatEditLimits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    let _lease = r
        .memory
        .reserve(
            limits
                .undo
                .body_bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(u64::from(limits.undo.patches) * 128))
                .and_then(|n| n.checked_add(4096))
                .ok_or_else(|| recovery_failure(budget("exFAT rollback charge")))?,
        )
        .map_err(recovery_failure)?;
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(limits.undo.patches as usize)
        .map_err(|_| recovery_failure(budget("exFAT rollback range allocation")))?;
    let mut guarded = RestoreTarget {
        target,
        flags: None,
        writes,
        started: false,
        limits,
        r,
        recorded: 0,
    };
    fs_undo::recover(&mut guarded, journal, binding, limits.undo, r)
}
