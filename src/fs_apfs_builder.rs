//! Deterministic native APFS construction for unpublished single-store images.
use crate::fs_core::*;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
#[path = "fs_apfs_builder_disk.rs"]
mod disk;
use disk::*;
#[path = "fs_apfs_builder_layout.rs"]
mod layout;
use crate::{
    fs_apfs::{ApfsContainer, ApfsReadLimits, ApfsVolume},
    fs_apfs_audit::{ApfsAuditLimits, ApfsAuditReport, audit_apfs},
    storage::Storage,
};
use layout::Layout;
use sha2::{Digest, Sha256};
use virtdisk::ReadAt;

/// Explicit interpretation of source names.
#[derive(Clone, Copy, Debug)]
pub enum ApfsBuildNames {
    /// Preserve native valid UTF-8 byte names exactly.
    ExactBytes,
    /// Preserve byte names; explicitly encode valid UTF-16 as UTF-8.
    Utf16ToUtf8,
}
/// Explicit replacement metadata under the new-volume profile.
#[derive(Clone, Copy, Debug)]
pub struct ApfsBuildDefaults {
    /// Native Unix owner ID.
    pub uid: u32,
    /// Native Unix group ID.
    pub gid: u32,
    /// Regular Unix permission bits, at most 0777.
    pub file_permissions: u16,
    /// Directory Unix permission bits, at most 0777.
    pub directory_permissions: u16,
    /// Unix nanoseconds for creation/modification/access/change.
    pub timestamp: u64,
}
/// Native metadata treatment is independent of payload and topology preservation.
#[derive(Clone, Copy, Debug)]
pub enum ApfsBuildMetadata {
    /// Authorize replacement of all inspected source metadata with these defaults.
    ContentOnlyDefaults(ApfsBuildDefaults),
    /// Reject until a typed cross-format metadata preservation profile exists.
    RequirePreservation,
}
/// Explicit mapping of common named streams to ordinary native user xattrs.
/// This does not reinterpret security/system streams or preserve opaque descriptors.
#[derive(Clone, Copy, Debug)]
pub struct ApfsNamedXattrLimits {
    /// Maximum named streams across unique objects.
    pub streams: usize,
    /// Maximum total exact UTF8 name bytes.
    pub name_bytes: usize,
}
/// Reviewable preservation of exact named-stream names and logical values.
#[derive(Clone, Debug)]
pub struct ApfsNamedStreamOutcome {
    /// Bound source object, counting hardlink aliases once.
    pub object: ObjectId,
    /// Exact native source name.
    pub name: NativeName,
    /// Exact logical source length.
    pub length: u64,
    /// Logical names/bytes are preserved; other native metadata uses selected policy.
    pub decision: Preservation,
}
struct NamedInput {
    name: Vec<u8>,
    file: Arc<dyn FileRead>,
    length: u64,
}
/// Inspection status is retained without converting unavailable information to absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApfsMetadataInspection {
    /// No native source field exists.
    Absent,
    /// Source exposes an interpreted native field.
    Known,
    /// Source exposes uninterpreted native bytes.
    Opaque,
    /// Source cannot inspect this class.
    Uninspectable,
}
/// Reviewable per-object metadata transformation before any destination writes.
#[derive(Clone, Debug)]
pub struct ApfsMetadataOutcome {
    /// Bound source-scoped identity.
    pub object: ObjectId,
    /// Native metadata class.
    pub class: &'static str,
    /// Actual source inspection status.
    pub inspection: ApfsMetadataInspection,
    /// Explicit omission/replacement; opaque relocation is never presumed.
    pub decision: Preservation,
}
/// Independent authoring ceilings, checked before destination mutation.
#[derive(Clone, Copy, Debug)]
pub struct ApfsBuildLimits {
    /// Unique objects, including the source root.
    pub objects: usize,
    /// Namespace occurrences, counting hardlink aliases.
    pub occurrences: usize,
    /// Retained name bytes across occurrences.
    pub name_bytes: usize,
    /// Directory depth, root at zero.
    pub depth: usize,
    /// Native image blocks and total indexed logical payload blocks, including holes.
    pub blocks: u64,
    /// Inventory, extent, allocation and serialization work.
    pub work: u64,
    /// Maximum entries in one source page.
    pub page_entries: usize,
}
/// Exact deterministic construction choices.
pub struct ApfsBuildOptions {
    /// Exact target byte length, divisible by 4096.
    pub image_bytes: u64,
    /// Caller-selected native container UUID.
    pub container_uuid: [u8; 16],
    /// Caller-selected native volume UUID.
    pub volume_uuid: [u8; 16],
    /// Valid UTF-8 native volume label, at most 255 bytes.
    pub volume_label: Vec<u8>,
    /// Explicit native name policy.
    pub names: ApfsBuildNames,
    /// Explicit source metadata treatment.
    pub metadata: ApfsBuildMetadata,
    /// Caller-selected bounds.
    pub limits: ApfsBuildLimits,
}
struct Input {
    identity: ObjectId,
    directory: bool,
    parent: usize,
    primary: Vec<u8>,
    children: Vec<(Vec<u8>, usize)>,
    data: Option<Arc<dyn FileRead>>,
    fork: Option<Arc<dyn FileRead>>,
    data_length: u64,
    fork_length: u64,
    extents: Vec<LogicalExtent>,
    named: Vec<NamedInput>,
}
struct Inventory {
    source: Arc<dyn TreeSource>,
    inputs: Vec<Input>,
    defaults: ApfsBuildDefaults,
    transformed_names: usize,
    outcomes: Vec<ApfsMetadataOutcome>,
    named_outcomes: Vec<ApfsNamedStreamOutcome>,
    _lease: Reservation,
}
/// Additive authoring capacity for retained native COW checkpoints; existing plan defaults stay byte-compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApfsCheckpointCapacity {
    /// Native descriptor-ring blocks, even and in8..=128.
    pub descriptor_blocks: u32,
    /// Native checkpoint-data-ring blocks, a multiple of4 in8..=256.
    pub data_blocks: u32,
}
impl Default for ApfsCheckpointCapacity {
    fn default() -> Self {
        Self {
            descriptor_blocks: 8,
            data_blocks: 8,
        }
    }
}
impl ApfsCheckpointCapacity {
    fn validate(self) -> Result<()> {
        if !(8..=128).contains(&self.descriptor_blocks)
            || !self.descriptor_blocks.is_multiple_of(2)
            || !(8..=256).contains(&self.data_blocks)
            || !self.data_blocks.is_multiple_of(4)
        {
            return Err(invalid("APFS bounded checkpoint/internal-pool capacity"));
        }
        Ok(())
    }
}
/// Retained source inventory and native allocation/index construction.
/// Payload handles remain deferred and all owned maps retain shared leases.
pub struct ApfsBuildPlan {
    inventory: Inventory,
    layout: Layout,
    bytes: u64,
    _lease: Reservation,
    resources: Resources,
}
/// Readback evidence for an unpublished generated image.
#[derive(Clone, Debug)]
pub struct ApfsBuildReport {
    /// Fully initialized target bytes.
    pub image_bytes: u64,
    /// Full target SHA-256 after all durability barriers and readback.
    pub sha256: [u8; 32],
    /// Explicit generated native volume object ID.
    pub volume_oid: u64,
    /// Globally allocated blocks, including reserved native areas.
    pub allocated_blocks: u64,
    /// Native volume allocation count, including unique payload blocks.
    pub volume_allocated_blocks: u64,
    /// Unique regular source objects, excluding aliases.
    pub files: usize,
    /// All source metadata was explicitly replaced with the selected defaults.
    pub metadata_transformed: bool,
    /// Source objects whose complete metadata inventory was explicitly replaced.
    pub metadata_objects: usize,
    /// Exact selected replacement metadata, without a preservation claim.
    pub metadata_defaults: ApfsBuildDefaults,
    /// Namespace occurrences explicitly encoded from valid UTF-16 to native UTF-8.
    pub transformed_names: usize,
    /// Whole-block source holes remain sparse; partial-block holes retain logical zeros.
    pub sparse_block_rounding: bool,
    /// Actual source isolation assurance; callers must keep source bytes stable during capture.
    pub source_stability: SourceStability,
}
impl ApfsBuildReport {
    /// Reopen exact generated bytes and require complete clean allocation/reference proof.
    /// This separate step must succeed before the caller publishes the staged image.
    pub fn audit(
        &self,
        source: Arc<dyn ReadAt>,
        mut read: ApfsReadLimits,
        limits: ApfsAuditLimits,
        r: &Resources,
    ) -> Result<ApfsAuditReport> {
        r.cancellation.check()?;
        if source.len() != self.image_bytes {
            return Err(invalid("APFS generated image length changed"));
        }
        if self.image_bytes / BLOCK as u64 > read.blocks.min(limits.blocks) {
            return Err(budget("APFS generated audit block ceiling"));
        }
        read.work = read
            .work
            .checked_sub(self.image_bytes)
            .ok_or_else(|| budget("APFS generated audit hashing work ceiling"))?;
        let lease = r.memory.reserve(BLOCK as u64)?;
        let mut b = zero(BLOCK)?;
        let mut hash = Sha256::new();
        for at in (0..self.image_bytes).step_by(BLOCK) {
            r.cancellation.check()?;
            source
                .read_exact_at(at, &mut b)
                .map_err(|e| Error::io("APFS generated audit readback", e))?;
            hash.update(&b);
        }
        drop(lease);
        if source.len() != self.image_bytes || <[u8; 32]>::from(hash.finalize()) != self.sha256 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS generated bytes changed before reopened audit",
            ));
        }
        let container = ApfsContainer::open(source, read, r)?;
        let volume = ApfsVolume::open(container, self.volume_oid, r)?;
        let report = audit_apfs(&volume, limits, r)?;
        if !report.is_clean() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "APFS generated image failed complete clean audit",
            ));
        }
        Ok(report)
    }
}
impl ApfsBuildPlan {
    /// Inventory and construct all native metadata before destination mutation.
    pub fn plan(
        source: Arc<dyn TreeSource>,
        options: ApfsBuildOptions,
        r: &Resources,
    ) -> Result<Self> {
        Self::plan_with_checkpoint_capacity(source, options, ApfsCheckpointCapacity::default(), r)
    }
    /// Author larger native checkpoint rings for repeated retained-history COW without changing ordinary options.
    pub fn plan_with_checkpoint_capacity(
        source: Arc<dyn TreeSource>,
        options: ApfsBuildOptions,
        capacity: ApfsCheckpointCapacity,
        r: &Resources,
    ) -> Result<Self> {
        Self::plan_with_named_xattrs_inner(source, options, capacity, None, r)
    }
    /// Map representable common named streams to dense native user xattrs.
    /// Exact byte names and deferred values are preserved, including directories.
    /// System/security semantics and sparse/unwritten xattr allocation are rejected.
    pub fn plan_with_named_xattrs(
        source: Arc<dyn TreeSource>,
        options: ApfsBuildOptions,
        capacity: ApfsCheckpointCapacity,
        named: ApfsNamedXattrLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::plan_with_named_xattrs_inner(source, options, capacity, Some(named), r)
    }
    fn plan_with_named_xattrs_inner(
        source: Arc<dyn TreeSource>,
        options: ApfsBuildOptions,
        capacity: ApfsCheckpointCapacity,
        named: Option<ApfsNamedXattrLimits>,
        r: &Resources,
    ) -> Result<Self> {
        capacity.validate()?;
        r.cancellation.check()?;
        let blocks = options.image_bytes / BLOCK as u64;
        if !options.image_bytes.is_multiple_of(BLOCK as u64)
            || !(256..=127 * 32768).contains(&blocks)
            || 1 + u64::from(capacity.descriptor_blocks)
                + u64::from(capacity.data_blocks)
                + 24
                + 3 * (blocks.div_ceil(32768) + blocks.div_ceil(32768).div_ceil(126))
                >= blocks
            || blocks > options.limits.blocks
            || options.limits.occurrences > u32::MAX as usize
        {
            return Err(invalid(
                "APFS authoring geometry/counts outside native construction profile",
            ));
        }
        if options.volume_label.is_empty()
            || options.volume_label.len() > 255
            || options.volume_label.contains(&0)
            || std::str::from_utf8(&options.volume_label).is_err()
            || options.container_uuid == [0; 16]
            || options.volume_uuid == [0; 16]
        {
            return Err(invalid("APFS authoring label or UUID"));
        }
        let charge = options
            .limits
            .blocks
            .checked_mul(1024)
            .and_then(|n| n.checked_add((options.limits.objects as u64).checked_mul(16384)?))
            .and_then(|n| n.checked_add((options.limits.occurrences as u64).checked_mul(1024)?))
            .ok_or_else(|| budget("APFS build reservation overflow"))?;
        let lease = r.memory.reserve(charge)?;
        let mut work = Work {
            remaining: options.limits.work,
        };
        let inventory = inventory(source, &options, named, r, &mut work)?;
        let layout = layout::construct(&inventory, &options, capacity, r, &mut work)?;
        Ok(Self {
            inventory,
            layout,
            bytes: options.image_bytes,
            _lease: lease,
            resources: r.clone(),
        })
    }
    /// Exact requested unpublished destination length.
    pub fn image_bytes(&self) -> u64 {
        self.bytes
    }
    /// Review the explicit metadata policy before staging writes.
    pub fn metadata_policy(&self) -> ApfsBuildMetadata {
        ApfsBuildMetadata::ContentOnlyDefaults(self.inventory.defaults)
    }
    /// Actual source isolation; emission requires stable bytes throughout deferred reading.
    pub fn source_stability(&self) -> SourceStability {
        self.inventory.source.stability()
    }
    /// Per-object metadata decisions, including opaque and unavailable source classes.
    pub fn outcomes(&self) -> &[ApfsMetadataOutcome] {
        &self.inventory.outcomes
    }
    /// Exact per-object named-stream preservation decisions, before emission.
    pub fn named_stream_outcomes(&self) -> &[ApfsNamedStreamOutcome] {
        &self.inventory.named_outcomes
    }
    fn payload_file(&self, p: &layout::Payload) -> &Arc<dyn FileRead> {
        let input = &self.inventory.inputs[p.input];
        match p.named {
            Some(index) => &input.named[index].file,
            None => input.data.as_ref().unwrap(),
        }
    }
    fn check(&self, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        for input in &self.inventory.inputs {
            self.inventory.source.revalidate(&input.identity, r)?;
            for named in &input.named {
                if named.file.identity() != &input.identity || named.file.len() != named.length {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "APFS named xattr deferred binding changed",
                    ));
                }
            }
            for (file, length) in [
                (input.data.as_ref(), input.data_length),
                (input.fork.as_ref(), input.fork_length),
            ] {
                if let Some(file) = file
                    && (file.identity() != &input.identity || file.len() != length)
                {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "APFS deferred stream identity changed",
                    ));
                }
            }
        }
        Ok(())
    }
    fn metadata(&self, at: u64, r: &Resources) -> Result<Vec<u8>> {
        let mut b = self.layout.metadata[&at].clone();
        for patch in self.layout.forks.iter().filter(|p| p.block == at) {
            let input = &self.inventory.inputs[patch.input];
            let file = input
                .fork
                .as_ref()
                .ok_or_else(|| invalid("APFS missing planned fork"))?;
            if file.len() != patch.length as u64 {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS resource fork length changed",
                ));
            }
            read_file(
                file.as_ref(),
                0,
                &mut b[patch.offset..patch.offset + patch.length],
                r,
            )?;
        }
        if !self.layout.raw_bitmaps.contains(&at) {
            seal(&mut b);
        }
        Ok(b)
    }
    /// Initialize, stream, durably flush and read back the unpublished target.
    /// An error leaves staging only; call report.audit before publication.
    pub fn emit(&self, target: &mut dyn Storage, r: &Resources) -> Result<ApfsBuildReport> {
        self.check(r)?;
        if target
            .len()
            .map_err(|e| Error::io("APFS staging length", e))?
            != self.bytes
        {
            return Err(invalid("APFS staging length mismatch"));
        }
        let _scratch = r.memory.reserve((BLOCK * 3) as u64)?;
        let mut b = zero(BLOCK)?;
        let mut actual = zero(BLOCK)?;
        for at in (0..self.bytes).step_by(BLOCK) {
            self.resources.cancellation.check()?;
            r.cancellation.check()?;
            write(target, at, &b, "APFS initialize image")?;
        }
        target
            .flush()
            .map_err(|e| Error::io("APFS initialization barrier", e))?;
        for p in &self.layout.payload {
            self.check_one(p.input, r)?;
            b.fill(0);
            let file = self.payload_file(p);
            let n = (file.len() - p.logical).min(BLOCK as u64) as usize;
            read_file(file.as_ref(), p.logical, &mut b[..n], r)?;
            self.check_one(p.input, r)?;
            write(
                target,
                p.physical * BLOCK as u64,
                &b,
                "APFS deferred payload write",
            )?;
        }
        target
            .flush()
            .map_err(|e| Error::io("APFS payload durability barrier", e))?;
        for p in &self.layout.payload {
            self.check_one(p.input, r)?;
            b.fill(0);
            let file = self.payload_file(p);
            let n = (file.len() - p.logical).min(BLOCK as u64) as usize;
            read_file(file.as_ref(), p.logical, &mut b[..n], r)?;
            target
                .read_exact_at(p.physical * BLOCK as u64, &mut actual)
                .map_err(|e| Error::io("APFS payload prerequisite readback", e))?;
            if actual != b {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "APFS payload prerequisite readback differs",
                ));
            }
        }
        for &at in self
            .layout
            .metadata
            .keys()
            .filter(|&&at| !matches!(at, 0..=2))
        {
            self.resources.cancellation.check()?;
            r.cancellation.check()?;
            let block = self.metadata(at, r)?;
            write(
                target,
                at * BLOCK as u64,
                &block,
                "APFS metadata construction",
            )?;
        }
        target
            .flush()
            .map_err(|e| Error::io("APFS metadata durability barrier", e))?;
        self.check(r)?;
        for at in [1, 2] {
            write(
                target,
                at * BLOCK as u64,
                &self.metadata(at, r)?,
                "APFS initial checkpoint publication",
            )?;
        }
        target
            .flush()
            .map_err(|e| Error::io("APFS checkpoint durability barrier", e))?;
        write(
            target,
            0,
            &self.metadata(0, r)?,
            "APFS initial block-zero publication",
        )?;
        target
            .flush()
            .map_err(|e| Error::io("APFS block-zero durability barrier", e))?;
        let mut hash = Sha256::new();
        let mut payload = 0;
        for at in 0..self.bytes / BLOCK as u64 {
            self.resources.cancellation.check()?;
            r.cancellation.check()?;
            b.fill(0);
            if self.layout.metadata.contains_key(&at) {
                b = self.metadata(at, r)?;
            } else if self
                .layout
                .payload
                .get(payload)
                .is_some_and(|p| p.physical == at)
            {
                let p = &self.layout.payload[payload];
                self.check_one(p.input, r)?;
                let file = self.payload_file(p);
                let n = (file.len() - p.logical).min(BLOCK as u64) as usize;
                read_file(file.as_ref(), p.logical, &mut b[..n], r)?;
                payload += 1;
            }
            target
                .read_exact_at(at * BLOCK as u64, &mut actual)
                .map_err(|e| Error::io("APFS generated block readback", e))?;
            if actual != b {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "APFS generated block differs at readback",
                ));
            }
            hash.update(&actual);
        }
        self.check(r)?;
        if target
            .len()
            .map_err(|e| Error::io("APFS final staging length", e))?
            != self.bytes
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS staging length changed",
            ));
        }
        Ok(ApfsBuildReport {
            image_bytes: self.bytes,
            sha256: hash.finalize().into(),
            volume_oid: 1026,
            allocated_blocks: self.layout.allocated,
            volume_allocated_blocks: self.layout.volume_allocated,
            files: self
                .inventory
                .inputs
                .iter()
                .filter(|n| !n.directory)
                .count(),
            metadata_transformed: true,
            metadata_objects: self.inventory.inputs.len(),
            metadata_defaults: self.inventory.defaults,
            transformed_names: self.inventory.transformed_names,
            sparse_block_rounding: true,
            source_stability: self.inventory.source.stability(),
        })
    }
    fn check_one(&self, index: usize, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        let input = &self.inventory.inputs[index];
        self.inventory.source.revalidate(&input.identity, r)?;
        if let Some(file) = &input.data {
            let length = input.extents.last().map_or(0, |e| e.offset + e.length);
            if file.len() != length || file.identity() != &input.identity {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS deferred data stream binding changed",
                ));
            }
        }
        for named in &input.named {
            if named.file.identity() != &input.identity || named.file.len() != named.length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS named xattr deferred binding changed",
                ));
            }
        }
        Ok(())
    }
}
fn read_file(file: &dyn FileRead, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
    let mut done = 0;
    while done < out.len() {
        r.cancellation.check()?;
        let n = file.read_at(at + done as u64, &mut out[done..], r)?;
        if n == 0 || n > out.len() - done {
            return Err(Error::io(
                "APFS deferred short read",
                std::io::ErrorKind::UnexpectedEof.into(),
            ));
        }
        done += n;
    }
    Ok(())
}
fn write(target: &mut dyn Storage, at: u64, b: &[u8], stage: &str) -> Result<()> {
    let mut done = 0;
    while done < b.len() {
        let n = target
            .write_at(at + done as u64, &b[done..])
            .map_err(|e| Error::io(stage, e))?;
        if n == 0 || n > b.len() - done {
            return Err(Error::io(stage, std::io::ErrorKind::WriteZero.into()));
        }
        done += n;
    }
    Ok(())
}
fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
struct Work {
    remaining: u64,
}
impl Work {
    fn tick(&mut self, n: u64, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.remaining = self
            .remaining
            .checked_sub(n)
            .ok_or_else(|| budget("APFS authoring work ceiling"))?;
        Ok(())
    }
}
fn native_name(n: &NativeName, p: ApfsBuildNames) -> Result<Vec<u8>> {
    let b = match n {
        NativeName::Bytes(b) => {
            if b.len() > 255 {
                return Err(unsupported("APFS native name byte ceiling"));
            }
            let mut copy = zero(b.len())?;
            copy.copy_from_slice(b);
            copy
        }
        NativeName::Utf16(u) if matches!(p, ApfsBuildNames::Utf16ToUtf8) => {
            if u.len() > 255 {
                return Err(unsupported("APFS native name unit ceiling"));
            }
            String::from_utf16(u)
                .map_err(|_| unsupported("APFS unpaired UTF-16 name"))?
                .into_bytes()
        }
        _ => {
            return Err(unsupported(
                "APFS source name conversion requires explicit policy",
            ));
        }
    };
    if b.is_empty()
        || b.len() > 255
        || b == b"."
        || b == b".."
        || b.iter().any(|c| *c == 0 || *c == b'/')
        || std::str::from_utf8(&b).is_err()
    {
        return Err(unsupported("APFS name is outside exact UTF-8 profile"));
    }
    Ok(b)
}
fn inspection<T>(f: &MetadataField<T>) -> ApfsMetadataInspection {
    match f {
        MetadataField::Absent => ApfsMetadataInspection::Absent,
        MetadataField::Known(_) => ApfsMetadataInspection::Known,
        MetadataField::Opaque { .. } => ApfsMetadataInspection::Opaque,
        MetadataField::Uninspectable { .. } => ApfsMetadataInspection::Uninspectable,
    }
}
fn metadata_outcomes(
    id: &ObjectId,
    m: &Metadata,
    out: &mut Vec<ApfsMetadataOutcome>,
) -> Result<()> {
    let attributes = m.attributes.iter().map(|(_, f)| inspection(f)).fold(
        ApfsMetadataInspection::Absent,
        |a, b| {
            use ApfsMetadataInspection::*;
            match (a, b) {
                (Uninspectable, _) | (_, Uninspectable) => Uninspectable,
                (Opaque, _) | (_, Opaque) => Opaque,
                (Known, _) | (_, Known) => Known,
                _ => Absent,
            }
        },
    );
    out.try_reserve_exact(10)
        .map_err(|_| budget("APFS metadata outcome allocation"))?;
    for (class, status) in [
        ("created", inspection(&m.created)),
        ("modified", inspection(&m.modified)),
        ("accessed", inspection(&m.accessed)),
        ("owner", inspection(&m.owner)),
        ("mode", inspection(&m.mode)),
        ("security", inspection(&m.security)),
        ("attributes", attributes),
        ("native_flags", inspection(&m.native_flags)),
        ("symlink_target", inspection(&m.symlink_target)),
        ("reparse_data", inspection(&m.reparse_data)),
    ] {
        out.push(ApfsMetadataOutcome {
            object: id.clone(),
            class,
            inspection: status,
            decision: Preservation::Transform {
                policy: "explicit APFS content-only native defaults".into(),
                report: if status == ApfsMetadataInspection::Uninspectable {
                    "source class unavailable; preservation unverified and not claimed"
                } else if status == ApfsMetadataInspection::Opaque {
                    "opaque source class intentionally omitted; no relocation claim"
                } else {
                    "source class intentionally replaced or omitted under selected defaults"
                }
                .into(),
            },
        });
    }
    Ok(())
}
fn canonical_inventory(inputs: Vec<Input>, work: &mut Work, r: &Resources) -> Result<Vec<Input>> {
    let n = inputs.len();
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical inventory allocation"))?;
    for input in inputs {
        slots.push(Some(input));
    }
    let mut map = Vec::new();
    map.try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical identity map"))?;
    map.resize(n, usize::MAX);
    map[0] = 0;
    let mut order = Vec::new();
    order
        .try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical order map"))?;
    order.push(0);
    let mut parent = Vec::new();
    parent
        .try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical parent map"))?;
    parent.resize(n, 0);
    let mut names = Vec::new();
    names
        .try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical name map"))?;
    names.resize_with(n, Vec::new);
    names[0] = b"root".to_vec();
    let mut cursor = 0;
    while cursor < order.len() {
        let old = order[cursor];
        let input = slots[old].as_mut().unwrap();
        let count = input.children.len() as u64;
        work.tick(
            count
                .checked_mul(u64::from(count.max(1).ilog2()) + 1)
                .ok_or_else(|| budget("APFS canonical sorting work"))?,
            r,
        )?;
        input.children.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, child) in &input.children {
            work.tick(1, r)?;
            if map[*child] == usize::MAX {
                map[*child] = order.len();
                parent[*child] = cursor;
                names[*child] = name.clone();
                order.push(*child);
            }
        }
        cursor += 1;
    }
    if order.len() != n {
        return Err(invalid("APFS disconnected common-tree object"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(n)
        .map_err(|_| budget("APFS canonical inventory allocation"))?;
    for old in order {
        let mut input = slots[old].take().unwrap();
        input.parent = parent[old];
        input.primary = std::mem::take(&mut names[old]);
        for (_, child) in &mut input.children {
            *child = map[*child];
        }
        out.push(input);
    }
    Ok(out)
}
fn inventory(
    source: Arc<dyn TreeSource>,
    o: &ApfsBuildOptions,
    named_limits: Option<ApfsNamedXattrLimits>,
    r: &Resources,
    w: &mut Work,
) -> Result<Inventory> {
    let defaults = match o.metadata {
        ApfsBuildMetadata::ContentOnlyDefaults(d) => d,
        ApfsBuildMetadata::RequirePreservation => {
            return Err(unsupported(
                "APFS required source metadata preservation unavailable",
            ));
        }
    };
    if defaults.file_permissions & !0o777 != 0
        || defaults.directory_permissions & !0o777 != 0
        || o.limits.objects == 0
        || o.limits.page_entries == 0
    {
        return Err(invalid("APFS authoring metadata or inventory limits"));
    }
    let charge = (o.limits.objects as u64)
        .checked_mul(4096)
        .and_then(|x| x.checked_add((o.limits.occurrences as u64).checked_mul(8192)?))
        .and_then(|x| x.checked_add((o.limits.name_bytes as u64).checked_mul(4)?))
        .ok_or_else(|| budget("APFS inventory reservation overflow"))?;
    let named_charge = match named_limits {
        Some(l) if l.streams <= u32::MAX as usize => (l.streams as u64)
            .checked_mul(4096)
            .and_then(|v| v.checked_add((l.name_bytes as u64).checked_mul(2)?))
            .ok_or_else(|| budget("APFS named xattr reservation overflow"))?,
        Some(_) => return Err(budget("APFS named xattr count ceiling")),
        None => 0,
    };
    let lease = r.memory.reserve(
        charge
            .checked_add(named_charge)
            .ok_or_else(|| budget("APFS inventory reservation overflow"))?,
    )?;
    let root = source.root();
    if root.native.len() > 1024 {
        return Err(budget("APFS source identity byte ceiling"));
    }
    source.revalidate(&root, r)?;
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(o.limits.objects)
        .map_err(|_| budget("APFS inventory allocation"))?;
    inputs.push(Input {
        identity: root.clone(),
        directory: true,
        parent: 0,
        primary: b"root".to_vec(),
        children: Vec::new(),
        data: None,
        fork: None,
        data_length: 0,
        fork_length: 0,
        extents: Vec::new(),
        named: Vec::new(),
    });
    let mut ids = HashMap::new();
    ids.try_reserve(o.limits.objects)
        .map_err(|_| budget("APFS identity map allocation"))?;
    ids.insert(root, 0usize);
    let mut queue = VecDeque::new();
    queue
        .try_reserve(o.limits.objects)
        .map_err(|_| budget("APFS directory queue allocation"))?;
    queue.push_back((0, 0usize));
    let (mut occurrences, mut names) = (0usize, 0usize);
    let mut transformed_names = 0;
    let mut outcomes = Vec::new();
    let mut named_outcomes = Vec::new();
    let mut named_bytes = 0usize;
    let mut pages = 0usize;
    while let Some((index, depth)) = queue.pop_front() {
        w.tick(1, r)?;
        let id = inputs[index].identity.clone();
        // Inspect even transformed metadata so unavailable classes remain an explicit policy outcome.
        drop(source.metadata(&id, r)?);
        let mut continuation = None;
        let mut tokens = HashSet::new();
        let mut names_seen = HashSet::new();
        loop {
            w.tick(1, r)?;
            pages = pages
                .checked_add(1)
                .ok_or_else(|| budget("APFS page count overflow"))?;
            if pages
                > o.limits
                    .occurrences
                    .saturating_add(o.limits.objects)
                    .saturating_add(1)
            {
                return Err(budget("APFS inventory page ceiling"));
            }
            let page =
                source.directory_page(&id, continuation.as_deref(), o.limits.page_entries, r)?;
            if page.entries.len() > o.limits.page_entries {
                return Err(invalid("APFS source oversized inventory page"));
            }
            for entry in &page.entries {
                w.tick(1, r)?;
                if entry.object.native.len() > 1024 {
                    return Err(budget("APFS source identity byte ceiling"));
                }
                occurrences = occurrences
                    .checked_add(1)
                    .ok_or_else(|| budget("APFS occurrence overflow"))?;
                if occurrences > o.limits.occurrences {
                    return Err(budget("APFS occurrence ceiling"));
                }
                let name = native_name(&entry.name, o.names)?;
                transformed_names += usize::from(matches!(entry.name, NativeName::Utf16(_)));
                names = names
                    .checked_add(name.len())
                    .ok_or_else(|| budget("APFS name overflow"))?;
                if names > o.limits.name_bytes {
                    return Err(budget("APFS name ceiling"));
                }
                names_seen
                    .try_reserve(1)
                    .map_err(|_| budget("APFS name collision map allocation"))?;
                if !names_seen.insert(name.clone()) {
                    return Err(invalid("APFS native name collision"));
                }
                let directory = match entry.kind {
                    ObjectKind::Directory => true,
                    ObjectKind::File => false,
                    _ => return Err(unsupported("APFS authoring special object")),
                };
                let child = if let Some(&old) = ids.get(&entry.object) {
                    if directory || inputs[old].directory {
                        return Err(invalid("APFS directory alias/cycle or conflicting kind"));
                    }
                    old
                } else {
                    if inputs.len() == o.limits.objects {
                        return Err(budget("APFS object ceiling"));
                    }
                    if directory && depth >= o.limits.depth {
                        return Err(budget("APFS directory depth ceiling"));
                    }
                    let child = inputs.len();
                    ids.insert(entry.object.clone(), child);
                    inputs.push(Input {
                        identity: entry.object.clone(),
                        directory,
                        parent: index,
                        primary: name.clone(),
                        children: Vec::new(),
                        data: None,
                        fork: None,
                        data_length: 0,
                        fork_length: 0,
                        extents: Vec::new(),
                        named: Vec::new(),
                    });
                    if directory {
                        queue.push_back((child, depth + 1));
                    }
                    child
                };
                inputs[index]
                    .children
                    .try_reserve(1)
                    .map_err(|_| budget("APFS directory links allocation"))?;
                inputs[index].children.push((name, child));
            }
            continuation = page.next.clone();
            if let Some(token) = &continuation {
                tokens
                    .try_reserve(1)
                    .map_err(|_| budget("APFS continuation map allocation"))?;
                if token.len() > 4096 || !tokens.insert(token.clone()) {
                    return Err(invalid("APFS source continuation cycle or oversized token"));
                }
            } else {
                break;
            }
        }
        source.revalidate(&id, r)?;
    }
    inputs = canonical_inventory(inputs, w, r)?;
    for input in &mut inputs {
        w.tick(1, r)?;
        let metadata = source.metadata(&input.identity, r)?;
        metadata_outcomes(&input.identity, &metadata, &mut outcomes)?;
        drop(metadata);
        let streams = source.streams(&input.identity, r)?;
        for info in streams.iter() {
            w.tick(1, r)?;
            if let StreamKind::Named(name) = &info.kind {
                let l = named_limits.ok_or_else(|| {
                    unsupported("APFS named-stream mapping requires explicit user-xattr profile")
                })?;
                let NativeName::Bytes(bytes) = name else {
                    return Err(unsupported(
                        "APFS named xattr exact UTF8 byte name required",
                    ));
                };
                if bytes.is_empty()
                    || bytes.len() > 821
                    || bytes.contains(&0)
                    || std::str::from_utf8(bytes).is_err()
                {
                    return Err(invalid("APFS named xattr native name"));
                }
                if matches!(
                    bytes.as_slice(),
                    b"com.apple.ResourceFork"
                        | b"com.apple.FinderInfo"
                        | b"com.apple.decmpfs"
                        | b"com.apple.system.Security"
                ) || bytes.starts_with(b"com.apple.fs.")
                {
                    return Err(unsupported("APFS named system xattr semantics"));
                }
                named_bytes = named_bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| budget("APFS named xattr name overflow"))?;
                if named_outcomes.len() >= l.streams
                    || named_bytes > l.name_bytes
                    || info.length > o.image_bytes
                {
                    return Err(budget("APFS named xattr inventory ceiling"));
                }
                if input.named.iter().any(|old| old.name == *bytes) {
                    return Err(invalid("APFS duplicate named xattr stream"));
                }
                let file = source.open_stream(&input.identity, &info.kind, r)?;
                if file.identity() != &input.identity || file.len() != info.length {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "APFS named xattr source binding changed",
                    ));
                }
                let mut end = 0;
                file.visit_extents(r, &mut |e| {
                    w.tick(1, r)?;
                    if e.offset != end || e.length == 0 || e.kind != ExtentKind::Data {
                        return Err(unsupported("APFS dense named xattr extent profile"));
                    }
                    end = end
                        .checked_add(e.length)
                        .filter(|n| *n <= info.length)
                        .ok_or_else(|| invalid("APFS named xattr extents bounds"))?;
                    Ok(())
                })?;
                if end != info.length {
                    return Err(invalid("APFS named xattr extents incomplete"));
                }
                input
                    .named
                    .try_reserve(1)
                    .map_err(|_| budget("APFS named xattr input allocation"))?;
                named_outcomes
                    .try_reserve(1)
                    .map_err(|_| budget("APFS named xattr outcome allocation"))?;
                input.named.push(NamedInput {
                    name: bytes.clone(),
                    file,
                    length: info.length,
                });
                named_outcomes.push(ApfsNamedStreamOutcome {
                    object: input.identity.clone(),
                    name: name.clone(),
                    length: info.length,
                    decision: Preservation::Preserve,
                });
                continue;
            }
            if info.length > o.image_bytes {
                return Err(budget("APFS source stream exceeds target byte ceiling"));
            }
            if input.directory {
                return Err(unsupported("APFS directory-owned payload stream"));
            }
            let slot = match info.kind {
                StreamKind::Data => {
                    input.data_length = info.length;
                    &mut input.data
                }
                StreamKind::ResourceFork => {
                    input.fork_length = info.length;
                    &mut input.fork
                }
                _ => return Err(unsupported("APFS authoring named/system stream")),
            };
            if slot.is_some() {
                return Err(invalid("APFS duplicate source stream"));
            }
            let file = source.open_stream(&input.identity, &info.kind, r)?;
            if file.identity() != &input.identity || file.len() != info.length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS source stream binding changed",
                ));
            }
            *slot = Some(file);
        }
        if !input.directory && input.data.is_none() {
            return Err(unsupported("APFS ordinary data stream unavailable"));
        }
        if let Some(file) = &input.data {
            let mut end = 0;
            file.visit_extents(r, &mut |e| {
                w.tick(1, r)?;
                if e.offset != end || e.length == 0 {
                    return Err(invalid("APFS source extents incomplete/noncontiguous"));
                }
                end = end
                    .checked_add(e.length)
                    .ok_or_else(|| invalid("APFS source extent overflow"))?;
                if end > file.len() {
                    return Err(invalid("APFS source extent beyond EOF"));
                }
                if matches!(e.kind, ExtentKind::Unwritten) {
                    return Err(unsupported(
                        "APFS unwritten allocation preservation unavailable",
                    ));
                }
                if input.extents.len() >= o.limits.blocks as usize {
                    return Err(budget("APFS source extent ceiling"));
                }
                input
                    .extents
                    .try_reserve(1)
                    .map_err(|_| budget("APFS extent allocation"))?;
                input.extents.push(e);
                Ok(())
            })?;
            if end != file.len() {
                return Err(invalid("APFS source extent coverage incomplete"));
            }
        }
        source.revalidate(&input.identity, r)?;
    }
    Ok(Inventory {
        source,
        inputs,
        defaults,
        transformed_names,
        outcomes,
        named_outcomes,
        _lease: lease,
    })
}
