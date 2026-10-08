//! Deterministic new-image JFFS2 logical NOR authoring from a bounded common tree.
use crate::{
    fs_core::*,
    fs_flash::{FlashGeometry, FlashLayout, FlashProgramming},
    fs_jffs2::Jffs2Endian,
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    sync::Arc,
};
#[path = "fs_jffs2_builder_compression.rs"]
mod compression;
pub use compression::Jffs2BuildCompression;
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
fn cap(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn copy(b: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(b.len())
        .map_err(|_| cap("JFFS2 build bytes"))?;
    v.extend_from_slice(b);
    Ok(v)
}
fn id(o: &ObjectId) -> Result<ObjectId> {
    if o.native.len() > 256 {
        return Err(cap("JFFS2 input identity exceeds 256 bytes"));
    }
    Ok(ObjectId {
        source: o.source,
        generation: o.generation,
        native: copy(&o.native)?,
    })
}
fn crc(mut c: u32, b: &[u8]) -> u32 {
    for &v in b {
        c ^= u32::from(v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    c
}
/// Explicit conversion to the destination's native byte namespace.
#[derive(Clone, Copy, Debug)]
pub enum Jffs2BuildNamePolicy {
    /// Preserve byte names; reject UTF-16 names.
    NativeBytesOnly,
    /// Preserve byte names and encode well-formed UTF-16 as UTF-8.
    Utf16ToUtf8,
}
/// Explicit replacement of source ownership, permissions and timestamps.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2BuildMetadata {
    /// Native 16-bit uid.
    pub uid: u16,
    /// Native 16-bit gid.
    pub gid: u16,
    /// Permission bits no greater than 0777.
    pub file_permissions: u16,
    /// Directory permission bits no greater than 0777.
    pub directory_permissions: u16,
    /// Symlink permission bits no greater than 0777.
    pub symlink_permissions: u16,
    /// Unsigned Unix seconds for access/modification/change times.
    pub timestamp: u32,
}
/// Source metadata is never silently dropped.
#[derive(Clone, Copy, Debug)]
pub enum Jffs2BuildMetadataPolicy {
    /// Authorize replacement of all metadata except exact symlink target.
    ReplaceWithDefaults(Jffs2BuildMetadata),
    /// Preservation of arbitrary source metadata is unsupported and fails preflight.
    RequirePreservation,
}
/// Exact new-image profile, supplied by the caller before mutation.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2BuildOptions {
    /// Explicit logical NOR erase/program geometry.
    pub geometry: FlashGeometry,
    /// Explicit native node byte order.
    pub endian: Jffs2Endian,
    /// Explicit byte-name conversion.
    pub names: Jffs2BuildNamePolicy,
    /// Explicit metadata transformation.
    pub metadata: Jffs2BuildMetadataPolicy,
    /// Encode all-zero payload chunks using native ZERO nodes; offsets reserve worst-case space.
    pub zero_nodes: bool,
}
/// Independent retained-inventory and streaming bounds.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2BuildLimits {
    /// Unique reachable objects including root.
    pub objects: usize,
    /// Namespace names, including hardlinks.
    pub entries: usize,
    /// Total converted native name and symlink bytes.
    pub native_bytes: usize,
    /// Total authored inode/dirent/cleanmarker records.
    pub records: usize,
    /// Maximum output length in bytes.
    pub image_bytes: u64,
    /// Maximum directory depth.
    pub depth: usize,
    /// Inventory/layout work bound.
    pub work: u64,
    /// Maximum bytes in each file data node, at least 128.
    pub node_data_bytes: usize,
    /// Streaming output/readback buffer, at least 512.
    pub scratch_bytes: usize,
}
struct Node {
    identity: ObjectId,
    kind: ObjectKind,
    file: Option<Arc<dyn FileRead>>,
    length: u64,
    target: Vec<u8>,
    children: Vec<(Vec<u8>, usize)>,
    inode: u32,
}
struct Pending {
    identity: ObjectId,
    kind: ObjectKind,
    name: Vec<u8>,
}
#[derive(Clone, Copy)]
enum RecordKind {
    Clean,
    Directory(usize),
    Data {
        node: usize,
        logical: u32,
        length: u32,
        version: u32,
    },
    Dirent {
        parent: usize,
        entry: usize,
        version: u32,
    },
}
struct Record {
    offset: u64,
    span: usize,
    kind: RecordKind,
}
/// Complete preflight retaining source identities, deferred streams and budget leases.
pub struct Jffs2BuildPlan {
    compression: Option<Jffs2BuildCompression>,
    source: Arc<dyn TreeSource>,
    nodes: Vec<Node>,
    records: Vec<Record>,
    length: u64,
    options: Jffs2BuildOptions,
    defaults: Jffs2BuildMetadata,
    limits: Jffs2BuildLimits,
    converted: usize,
    links: usize,
    resources: Resources,
    _inventory: Reservation,
    _layout: Reservation,
}
/// Fully initialized, flushed, regenerated and read-back staged image.
#[derive(Debug)]
pub struct Jffs2BuildReport {
    /// Actual source isolation assurance; readback does not establish snapshot isolation.
    pub source_stability: SourceStability,
    /// Explicit authored ownership/permissions/time defaults.
    pub metadata_defaults: Jffs2BuildMetadata,
    /// Explicit namespace conversion policy.
    pub name_policy: Jffs2BuildNamePolicy,
    /// Full image bytes independently regenerated and compared.
    pub verified_bytes: u64,
    /// SHA256 of the complete initialized image.
    pub sha256: [u8; 32],
    /// Unique regular files.
    pub files: usize,
    /// Additional names sharing already-defined non-directory objects.
    pub hardlink_names: usize,
    /// Names encoded from UTF-16 to UTF-8.
    pub converted_names: usize,
    /// Source objects whose metadata was explicitly replaced.
    pub transformed_objects: usize,
    /// Source sparse allocation is transformed into logical bytes or ZERO nodes.
    pub sparse_allocation_transformed: bool,
}
/// Failure separates causal errors from staged-target mutation uncertainty.
#[derive(Debug)]
pub struct Jffs2BuildFailure {
    /// Original failure, including causal I/O error.
    pub source: Error,
    /// A write was attempted; an error may conceal partial mutation.
    pub mutation_attempted: bool,
    /// Bytes the backend explicitly reported accepted.
    pub accepted_bytes: u64,
    /// Bytes successfully compared during full readback.
    pub verified_bytes: u64,
    /// The explicit final flush returned success.
    pub flush_completed: bool,
}
impl fmt::Display for Jffs2BuildFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JFFS2 staged authoring: {}", self.source)
    }
}
impl std::error::Error for Jffs2BuildFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
fn append<T>(v: &mut Vec<T>, value: T, limit: usize) -> Result<()> {
    if v.len() >= limit {
        return Err(cap("JFFS2 build record cap"));
    }
    v.try_reserve(1)
        .map_err(|_| cap("JFFS2 build allocation"))?;
    v.push(value);
    Ok(())
}
fn step(work: &mut u64, n: u64, limit: u64) -> Result<()> {
    *work = work
        .checked_add(n)
        .ok_or_else(|| cap("JFFS2 build work overflow"))?;
    if *work > limit {
        return Err(cap("JFFS2 build work cap"));
    }
    Ok(())
}
fn name(input: &NativeName, policy: Jffs2BuildNamePolicy) -> Result<(Vec<u8>, bool)> {
    let (v, converted) = match input {
        NativeName::Bytes(b) => {
            if b.len() > 254 {
                return Err(invalid("JFFS2 input byte name limit"));
            }
            (copy(b)?, false)
        }
        NativeName::Utf16(units) => {
            if !matches!(policy, Jffs2BuildNamePolicy::Utf16ToUtf8) {
                return Err(invalid("JFFS2 byte name conversion policy required"));
            }
            if units.len() > 254 {
                return Err(invalid("JFFS2 input UTF-16 name limit"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(
                    units
                        .len()
                        .checked_mul(3)
                        .ok_or_else(|| cap("JFFS2 UTF8 accounting"))?,
                )
                .map_err(|_| cap("JFFS2 UTF8 allocation"))?;
            for c in char::decode_utf16(units.iter().copied()) {
                let c = c.map_err(|_| invalid("JFFS2 malformed UTF16 name"))?;
                let mut b = [0; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
            (bytes, true)
        }
    };
    if v.is_empty()
        || v.len() > 254
        || v.contains(&0)
        || v.contains(&b'/')
        || v == b"."
        || v == b".."
    {
        return Err(invalid("JFFS2 invalid native name"));
    }
    Ok((v, converted))
}
fn place(at: &mut u64, span: usize, erase: u64, length: u64) -> Result<()> {
    if *at % erase < 12 {
        *at = (*at / erase)
            .checked_mul(erase)
            .and_then(|p| p.checked_add(12))
            .ok_or_else(|| cap("JFFS2 output overflow"))?;
    }
    let end = at
        .checked_add(span as u64)
        .ok_or_else(|| cap("JFFS2 output overflow"))?;
    if (end - 1) / erase != *at / erase {
        *at = (*at / erase)
            .checked_add(1)
            .and_then(|b| b.checked_mul(erase))
            .and_then(|p| p.checked_add(12))
            .ok_or_else(|| cap("JFFS2 output overflow"))?;
    }
    if at.checked_add(span as u64).is_none_or(|e| e > length) {
        return Err(cap("JFFS2 image has insufficient space"));
    }
    Ok(())
}
impl Jffs2BuildPlan {
    /// Inventory a caller-stable common tree and prove worst-case node fit before writes.
    pub fn from_tree(
        source: Arc<dyn TreeSource>,
        length: u64,
        options: Jffs2BuildOptions,
        limits: Jffs2BuildLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let g = options.geometry;
        if g.layout != FlashLayout::LogicalNor
            || g.erased_byte != 255
            || g.programming != FlashProgramming::ClearBitsOnly
            || g.erase_bytes < 4096
            || !g.erase_bytes.is_power_of_two()
            || g.program_bytes == 0
            || !g.program_bytes.is_power_of_two()
            || g.program_bytes > 4
        {
            return Err(invalid("JFFS2 build explicit logical NOR geometry"));
        }
        if length == 0
            || !length.is_multiple_of(u64::from(g.erase_bytes))
            || length > limits.image_bytes
        {
            return Err(invalid("JFFS2 build image geometry/size limit"));
        }
        if limits.objects == 0
            || limits.objects > u32::MAX as usize
            || limits.node_data_bytes < 128
            || limits.node_data_bytes > 32768
            || limits.node_data_bytes + 68 > g.erase_bytes as usize - 12
            || !(512..=65536).contains(&limits.scratch_bytes)
        {
            return Err(invalid("JFFS2 build buffer/object profile"));
        }
        let defaults = match options.metadata {
            Jffs2BuildMetadataPolicy::ReplaceWithDefaults(d) => d,
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "JFFS2 arbitrary metadata preservation unsupported",
                ));
            }
        };
        if defaults.file_permissions > 0o777
            || defaults.directory_permissions > 0o777
            || defaults.symlink_permissions > 0o777
        {
            return Err(invalid("JFFS2 default permission bits"));
        }
        let charge = limits.objects as u128 * 1536
            + limits.entries as u128 * 1536
            + limits.native_bytes as u128 * 3
            + 4096;
        let inventory = r
            .memory
            .reserve(u64::try_from(charge).map_err(|_| cap("JFFS2 inventory accounting"))?)?;
        let mut nodes = Vec::new();
        let mut index = HashMap::new();
        index
            .try_reserve(limits.objects)
            .map_err(|_| cap("JFFS2 identity index"))?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve(limits.objects)
            .map_err(|_| cap("JFFS2 directory queue"))?;
        let root = source.root();
        source.revalidate(&root, r)?;
        let root_id = id(&root)?;
        if !source.streams(&root, r)?.is_empty() {
            return Err(invalid("JFFS2 root additional streams"));
        }
        append(
            &mut nodes,
            Node {
                identity: id(&root)?,
                kind: ObjectKind::Directory,
                file: None,
                length: 0,
                target: Vec::new(),
                children: Vec::new(),
                inode: 1,
            },
            limits.objects,
        )?;
        index.insert(root_id, 0);
        queue.push_back((0, 0usize));
        let mut entries = 0usize;
        let mut bytes = 0usize;
        let mut work = 0;
        let mut converted = 0;
        let mut hardlinks = 0;
        while let Some((parent, depth)) = queue.pop_front() {
            r.cancellation.check()?;
            source.revalidate(&nodes[parent].identity, r)?;
            if depth > limits.depth {
                return Err(cap("JFFS2 tree depth"));
            }
            let mut pending = Vec::new();
            let mut token = None;
            let mut tokens = 0usize;
            loop {
                step(&mut work, 1, limits.work)?;
                let page =
                    source.directory_page(&nodes[parent].identity, token.as_deref(), 128, r)?;
                if page.entries.is_empty() && page.next.is_some() {
                    return Err(invalid("JFFS2 source pagination makes no progress"));
                }
                for entry in &page.entries {
                    step(&mut work, 1, limits.work)?;
                    entries = entries
                        .checked_add(1)
                        .ok_or_else(|| cap("JFFS2 entry overflow"))?;
                    if entries > limits.entries {
                        return Err(cap("JFFS2 entry cap"));
                    }
                    let (native, c) = name(&entry.name, options.names)?;
                    bytes = bytes
                        .checked_add(native.len())
                        .ok_or_else(|| cap("JFFS2 native bytes overflow"))?;
                    if bytes > limits.native_bytes {
                        return Err(cap("JFFS2 native byte cap"));
                    }
                    converted += usize::from(c);
                    append(
                        &mut pending,
                        Pending {
                            identity: id(&entry.object)?,
                            kind: entry.kind.clone(),
                            name: native,
                        },
                        limits.entries,
                    )?;
                }
                if let Some(next) = page.next {
                    if next.len() > 256 || token.as_ref() == Some(&next) {
                        return Err(invalid("JFFS2 malformed continuation"));
                    }
                    tokens += 1;
                    if tokens > limits.entries {
                        return Err(cap("JFFS2 pagination cap"));
                    }
                    token = Some(next);
                } else {
                    break;
                }
            }
            pending.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            if pending.windows(2).any(|p| p[0].name == p[1].name) {
                return Err(invalid("JFFS2 converted sibling collision"));
            }
            for p in pending {
                r.cancellation.check()?;
                let child = if let Some(&child) = index.get(&p.identity) {
                    if nodes[child].kind != p.kind || p.kind == ObjectKind::Directory {
                        return Err(invalid(
                            "JFFS2 directory alias/cycle or identity type mismatch",
                        ));
                    }
                    hardlinks += 1;
                    child
                } else {
                    if p.kind == ObjectKind::Special {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "JFFS2 special object unsupported",
                        ));
                    }
                    source.revalidate(&p.identity, r)?;
                    let metadata = source.metadata(&p.identity, r)?;
                    let streams = source.streams(&p.identity, r)?;
                    let mut target = Vec::new();
                    let (file, length) = match p.kind {
                        ObjectKind::File => {
                            if streams.len() != 1 || streams[0].kind != StreamKind::Data {
                                return Err(Error::new(
                                    ErrorKind::Unsupported,
                                    "JFFS2 additional/missing regular data streams",
                                ));
                            }
                            let f = source.open_stream(&p.identity, &StreamKind::Data, r)?;
                            if f.identity() != &p.identity
                                || f.len() != streams[0].length
                                || f.len() > u64::from(u32::MAX)
                            {
                                return Err(invalid("JFFS2 file identity or size"));
                            }
                            (Some(f), streams[0].length)
                        }
                        ObjectKind::Directory => {
                            if !streams.is_empty() {
                                return Err(invalid("JFFS2 directory extra streams"));
                            }
                            (None, 0)
                        }
                        ObjectKind::Symlink => {
                            if !streams.is_empty() {
                                return Err(invalid("JFFS2 symlink extra streams"));
                            }
                            let MetadataField::Known(NativeName::Bytes(b)) =
                                &metadata.symlink_target
                            else {
                                return Err(Error::new(
                                    ErrorKind::Unsupported,
                                    "JFFS2 exact byte symlink target required",
                                ));
                            };
                            if b.is_empty() || b.len() > 254 || b.contains(&0) {
                                return Err(invalid("JFFS2 symlink target profile"));
                            }
                            target = copy(b)?;
                            bytes = bytes
                                .checked_add(target.len())
                                .ok_or_else(|| cap("JFFS2 target accounting"))?;
                            if bytes > limits.native_bytes {
                                return Err(cap("JFFS2 native byte cap"));
                            }
                            (None, b.len() as u64)
                        }
                        _ => return Err(invalid("JFFS2 object kind")),
                    };
                    let child = nodes.len();
                    let key = id(&p.identity)?;
                    append(
                        &mut nodes,
                        Node {
                            identity: p.identity,
                            kind: p.kind.clone(),
                            file,
                            length,
                            target,
                            children: Vec::new(),
                            inode: u32::try_from(child + 1)
                                .map_err(|_| cap("JFFS2 inode numbers"))?,
                        },
                        limits.objects,
                    )?;
                    index.insert(key, child);
                    if p.kind == ObjectKind::Directory {
                        queue.push_back((
                            child,
                            depth
                                .checked_add(1)
                                .ok_or_else(|| cap("JFFS2 depth overflow"))?,
                        ));
                    }
                    child
                };
                append(&mut nodes[parent].children, (p.name, child), limits.entries)?;
            }
        }
        let erase = u64::from(g.erase_bytes);
        let blocks = length / erase;
        let mut count = blocks;
        for n in &nodes {
            count = count
                .checked_add(match n.kind {
                    ObjectKind::File => n.length.div_ceil(limits.node_data_bytes as u64).max(1),
                    _ => 1,
                })
                .and_then(|c| c.checked_add(n.children.len() as u64))
                .ok_or_else(|| cap("JFFS2 planned records overflow"))?;
        }
        if count > limits.records as u64 {
            return Err(cap("JFFS2 authored record cap"));
        }
        let layout = r.memory.reserve(
            count
                .checked_mul(96)
                .and_then(|v| v.checked_add(256))
                .ok_or_else(|| cap("JFFS2 layout accounting"))?,
        )?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(count as usize)
            .map_err(|_| cap("JFFS2 layout allocation"))?;
        for block in 0..blocks {
            records.push(Record {
                offset: block * erase,
                span: 12,
                kind: RecordKind::Clean,
            });
        }
        let mut at = 12u64;
        for (i, n) in nodes.iter().enumerate() {
            let chunks = if n.kind == ObjectKind::File {
                n.length.div_ceil(limits.node_data_bytes as u64).max(1)
            } else {
                1
            };
            for chunk in 0..chunks {
                step(&mut work, 1, limits.work)?;
                let logical = chunk * limits.node_data_bytes as u64;
                let data = match n.kind {
                    ObjectKind::Directory => 0,
                    ObjectKind::Symlink => n.length,
                    _ => n
                        .length
                        .saturating_sub(logical)
                        .min(limits.node_data_bytes as u64),
                };
                let span = (68 + data as usize).next_multiple_of(4);
                place(&mut at, span, erase, length)?;
                let kind = if n.kind == ObjectKind::Directory {
                    RecordKind::Directory(i)
                } else {
                    RecordKind::Data {
                        node: i,
                        logical: logical as u32,
                        length: data as u32,
                        version: u32::try_from(chunk + 1)
                            .map_err(|_| cap("JFFS2 node versions"))?,
                    }
                };
                records.push(Record {
                    offset: at,
                    span,
                    kind,
                });
                at += span as u64;
            }
            for (entry, (name, _)) in n.children.iter().enumerate() {
                step(&mut work, 1, limits.work)?;
                let span = (40 + name.len()).next_multiple_of(4);
                place(&mut at, span, erase, length)?;
                records.push(Record {
                    offset: at,
                    span,
                    kind: RecordKind::Dirent {
                        parent: i,
                        entry,
                        version: u32::try_from(entry + 1)
                            .map_err(|_| cap("JFFS2 dirent versions"))?,
                    },
                });
                at += span as u64;
            }
        }
        records.sort_unstable_by_key(|r| r.offset);
        if records
            .windows(2)
            .any(|r| r[0].offset + r[0].span as u64 > r[1].offset)
        {
            return Err(invalid("JFFS2 planned node overlap"));
        }
        let plan = Self {
            compression: None,
            source,
            nodes,
            records,
            length,
            options,
            defaults,
            limits,
            converted,
            links: hardlinks,
            resources: r.clone(),
            _inventory: inventory,
            _layout: layout,
        };
        plan.check(r)?;
        Ok(plan)
    }
    /// Opt-in bounded regular-file compression; layout reserves NONE worst-case bytes.
    /// Data nodes use the selected codec only when smaller, preserving exact ZERO handling.
    pub fn from_tree_compressed(
        source: Arc<dyn TreeSource>,
        length: u64,
        options: Jffs2BuildOptions,
        limits: Jffs2BuildLimits,
        compression: Jffs2BuildCompression,
        r: &Resources,
    ) -> Result<Self> {
        let mut plan = Self::from_tree(source, length, options, limits, r)?;
        plan.compression = Some(compression);
        Ok(plan)
    }
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.resources.cancellation.check()?;
        for n in &self.nodes {
            self.source.revalidate(&n.identity, r)?;
            if let Some(f) = &n.file
                && (f.identity() != &n.identity || f.len() != n.length)
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 deferred file changed",
                ));
            }
            if n.kind == ObjectKind::Symlink {
                let metadata = self.source.metadata(&n.identity, r)?;
                if metadata.symlink_target
                    != MetadataField::Known(NativeName::Bytes(copy(&n.target)?))
                {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "JFFS2 symlink target changed",
                    ));
                }
            }
        }
        Ok(())
    }
    fn w(&self, b: &mut [u8], p: usize, v: u16) {
        b[p..p + 2].copy_from_slice(&match self.options.endian {
            Jffs2Endian::Little => v.to_le_bytes(),
            Jffs2Endian::Big => v.to_be_bytes(),
        });
    }
    fn d(&self, b: &mut [u8], p: usize, v: u32) {
        b[p..p + 4].copy_from_slice(&match self.options.endian {
            Jffs2Endian::Little => v.to_le_bytes(),
            Jffs2Endian::Big => v.to_be_bytes(),
        });
    }
    fn read(&self, node: usize, p: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        let n = &self.nodes[node];
        self.source.revalidate(&n.identity, r)?;
        let f = n
            .file
            .as_ref()
            .ok_or_else(|| invalid("JFFS2 missing file handle"))?;
        if f.identity() != &n.identity || f.len() != n.length {
            return Err(Error::new(ErrorKind::StalePlan, "JFFS2 file changed"));
        }
        let mut done = 0;
        while done < out.len() {
            r.cancellation.check()?;
            self.resources.cancellation.check()?;
            self.source.revalidate(&n.identity, r)?;
            if f.identity() != &n.identity || f.len() != n.length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 file changed before short read",
                ));
            }
            let count = f.read_at(p + done as u64, &mut out[done..], r)?;
            self.source.revalidate(&n.identity, r)?;
            if f.identity() != &n.identity || f.len() != n.length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 file changed after short read",
                ));
            }
            if count == 0 || count > out.len() - done {
                return Err(Error::io(
                    "JFFS2 short deferred source",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            done += count;
        }
        self.source.revalidate(&n.identity, r)?;
        if f.identity() != &n.identity || f.len() != n.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 file changed during read",
            ));
        }
        Ok(())
    }
    fn node(&self, record: &Record, out: &mut [u8], r: &Resources) -> Result<()> {
        out.fill(255);
        let mut len;
        let typ;
        match record.kind {
            RecordKind::Clean => {
                out[..12].fill(0);
                typ = 0x2003;
                len = 12;
            }
            RecordKind::Dirent {
                parent,
                entry,
                version,
            } => {
                let (name, child) = &self.nodes[parent].children[entry];
                len = 40 + name.len();
                out[..len].fill(0);
                typ = 0xe001;
                self.d(out, 12, self.nodes[parent].inode);
                self.d(out, 16, version);
                self.d(out, 20, self.nodes[*child].inode);
                self.d(out, 24, self.defaults.timestamp);
                out[28] = name.len() as u8;
                out[29] = match self.nodes[*child].kind {
                    ObjectKind::Directory => 4,
                    ObjectKind::File => 8,
                    ObjectKind::Symlink => 10,
                    _ => return Err(invalid("JFFS2 node type")),
                };
                out[40..len].copy_from_slice(name);
                self.d(out, 36, crc(0, name));
            }
            RecordKind::Directory(node) | RecordKind::Data { node, .. } => {
                let n = &self.nodes[node];
                let (logical, data, version) = match record.kind {
                    RecordKind::Directory(_) => (0, 0, 1),
                    RecordKind::Data {
                        logical,
                        length,
                        version,
                        ..
                    } => (logical, length, version),
                    _ => unreachable!(),
                };
                len = 68 + data as usize;
                out[..len].fill(0);
                typ = 0xe002;
                self.d(out, 12, n.inode);
                self.d(out, 16, version);
                self.d(
                    out,
                    20,
                    match n.kind {
                        ObjectKind::Directory => {
                            0x4000 | u32::from(self.defaults.directory_permissions)
                        }
                        ObjectKind::File => 0x8000 | u32::from(self.defaults.file_permissions),
                        ObjectKind::Symlink => {
                            0xa000 | u32::from(self.defaults.symlink_permissions)
                        }
                        _ => return Err(invalid("JFFS2 node mode")),
                    },
                );
                self.w(out, 24, self.defaults.uid);
                self.w(out, 26, self.defaults.gid);
                self.d(out, 28, n.length as u32);
                for p in [32, 36, 40] {
                    self.d(out, p, self.defaults.timestamp);
                }
                self.d(out, 44, logical);
                self.d(out, 52, data);
                if n.kind == ObjectKind::File && data > 0 {
                    self.read(node, u64::from(logical), &mut out[68..len], r)?;
                } else if n.kind == ObjectKind::Symlink {
                    out[68..len].copy_from_slice(&n.target);
                }
                let zero = self.options.zero_nodes
                    && n.kind == ObjectKind::File
                    && data > 0
                    && out[68..len].iter().all(|v| *v == 0);
                if zero {
                    len = 68;
                    out[56] = 1;
                    out[68..].fill(255);
                } else {
                    let mut encoded = data;
                    if n.kind == ObjectKind::File
                        && data > 0
                        && let Some(codec) = self.compression
                        && let Some(bytes) = codec.encode(&out[68..len], r)?
                    {
                        encoded = bytes.len() as u32;
                        len = 68 + bytes.len();
                        out[68..len].copy_from_slice(&bytes);
                        out[len..].fill(255);
                        out[56] = codec.native();
                    }
                    self.d(out, 48, encoded);
                    let checksum = crc(0, &out[68..len]);
                    self.d(out, 60, checksum);
                }
            }
        }
        self.w(out, 0, 0x1985);
        self.w(out, 2, typ);
        self.d(out, 4, len as u32);
        let c = crc(0, &out[..8]);
        self.d(out, 8, c);
        match typ {
            0xe001 => {
                let c = crc(0, &out[..32]);
                self.d(out, 32, c);
            }
            0xe002 => {
                let c = crc(0, &out[..60]);
                self.d(out, 64, c);
            }
            _ => {}
        }
        Ok(())
    }
    fn render(&self, p: u64, out: &mut [u8], node: &mut [u8], r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.resources.cancellation.check()?;
        out.fill(255);
        let end = p + out.len() as u64;
        let mut i = self
            .records
            .partition_point(|rec| rec.offset + rec.span as u64 <= p);
        while let Some(rec) = self.records.get(i) {
            if rec.offset >= end {
                break;
            }
            self.node(rec, &mut node[..rec.span], r)?;
            let start = p.max(rec.offset);
            let stop = end.min(rec.offset + rec.span as u64);
            out[(start - p) as usize..(stop - p) as usize].copy_from_slice(
                &node[(start - rec.offset) as usize..(stop - rec.offset) as usize],
            );
            i += 1;
        }
        Ok(())
    }
    /// Author only an exclusively owned unpublished fixed-size regular image. One flush, then full regeneration/readback.
    pub fn emit(
        &self,
        target: &mut (impl Storage + ?Sized),
        r: &Resources,
    ) -> std::result::Result<Jffs2BuildReport, Jffs2BuildFailure> {
        let mut mutated = false;
        let mut accepted = 0u64;
        let mut verified = 0u64;
        let mut flushed = false;
        let result = (|| {
            self.check(r)?;
            if target
                .len()
                .map_err(|e| Error::io("JFFS2 target length", e))?
                != self.length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 target size changed",
                ));
            }
            let n = self.limits.scratch_bytes;
            let node_size = (68 + self.limits.node_data_bytes.max(254)).next_multiple_of(4);
            let codec_bytes = self
                .compression
                .map_or(0, |c| c.workspace() + self.limits.node_data_bytes as u64);
            let _lease = r
                .memory
                .reserve((n as u64 * 2) + node_size as u64 + 256 + codec_bytes)?;
            let zero = |n: usize| -> Result<Vec<u8>> {
                let mut v = Vec::new();
                v.try_reserve_exact(n)
                    .map_err(|_| cap("JFFS2 streaming scratch"))?;
                v.resize(n, 0);
                Ok(v)
            };
            let mut expected = zero(n)?;
            let mut actual = zero(n)?;
            let mut node = zero(node_size)?;
            let mut digest = Sha256::new();
            let mut p = 0;
            while p < self.length {
                let count = (self.length - p).min(n as u64) as usize;
                self.render(p, &mut expected[..count], &mut node, r)?;
                digest.update(&expected[..count]);
                let mut done = 0;
                while done < count {
                    r.cancellation.check()?;
                    self.resources.cancellation.check()?;
                    mutated = true;
                    let written = target
                        .write_at(p + done as u64, &expected[done..count])
                        .map_err(|e| Error::io("JFFS2 staged write", e))?;
                    if written == 0 || written > count - done {
                        return Err(Error::io(
                            "JFFS2 invalid write count",
                            io::ErrorKind::WriteZero.into(),
                        ));
                    }
                    done += written;
                    accepted += written as u64;
                }
                p += count as u64;
            }
            self.check(r)?;
            target.flush().map_err(|e| {
                let mut e = Error::io("JFFS2 staged flush", e);
                e.kind = ErrorKind::UncertainDurability;
                e
            })?;
            flushed = true;
            let sha256: [u8; 32] = digest.finalize().into();
            let mut hash = Sha256::new();
            p = 0;
            while p < self.length {
                let count = (self.length - p).min(n as u64) as usize;
                self.render(p, &mut expected[..count], &mut node, r)?;
                target
                    .read_exact_at(p, &mut actual[..count])
                    .map_err(|e| Error::io("JFFS2 full readback", e))?;
                if actual[..count] != expected[..count] {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "JFFS2 regenerated bytes differ from readback",
                    ));
                }
                hash.update(&actual[..count]);
                verified += count as u64;
                p += count as u64;
            }
            self.check(r)?;
            if target
                .len()
                .map_err(|e| Error::io("JFFS2 final target length", e))?
                != self.length
                || <[u8; 32]>::from(hash.finalize()) != sha256
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 source/target changed",
                ));
            }
            Ok(Jffs2BuildReport {
                source_stability: self.source.stability(),
                metadata_defaults: self.defaults,
                name_policy: self.options.names,
                verified_bytes: verified,
                sha256,
                files: self
                    .nodes
                    .iter()
                    .filter(|n| n.kind == ObjectKind::File)
                    .count(),
                hardlink_names: self.links,
                converted_names: self.converted,
                transformed_objects: self.nodes.len(),
                sparse_allocation_transformed: true,
            })
        })();
        result.map_err(|source| Jffs2BuildFailure {
            source,
            mutation_attempted: mutated,
            accepted_bytes: accepted,
            verified_bytes: verified,
            flush_completed: flushed,
        })
    }
}
