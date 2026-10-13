//! Exact-byte classic ext2 namespace planning on an audited owned session.
use super::allocation::{Phase, Planner, data_blocks, mapped_inode, publish_map};
use super::transaction::{OrderedOperation, SymlinkAction, SymlinkEvidence};
use super::*;
use crate::fs_ext::{ExtDirectory, ExtEntry};
use crate::fs_file::ExtentKind;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}
fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
pub(super) fn zeros(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("ext2 namespace allocation"))?;
    v.resize(n, 0);
    Ok(v)
}
fn copied(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| budget("ext2 native name allocation"))?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn name(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| *b == 0 || *b == b'/')
    {
        return Err(bad(
            "ext2 name requires 1..255 exact bytes without dots, slash or NUL",
        ));
    }
    Ok(())
}
/// Caller native Linux 128-byte inode creation template; no clock or owner is inferred.
pub struct ExtCreateMetadata {
    /// Exact native inode bytes. Size, links, sector count, pointers, deletion time and generation must be zero.
    /// Mode explicitly selects the requested regular-file/directory kind. Other supported fields are copied.
    pub raw: [u8; 128],
}
impl ExtCreateMetadata {
    /// Exact zero native timestamp and numeric UID/GID fields, with caller Unix mode.
    pub fn zeroed(mode: u16) -> Self {
        let mut raw = [0; 128];
        raw[..2].copy_from_slice(&mode.to_le_bytes());
        Self { raw }
    }
}
/// Namespace operation represented by the reviewable owned batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtNamespaceOperation {
    /// Create a regular file.
    CreateFile,
    /// Create a canonical unfollowed symlink.
    CreateSymlink,
    /// Replace an unfollowed symlink target.
    ReplaceSymlinkTarget,
    /// Rename a symlink without following its target.
    RenameSymlink,
    /// Unlink a symlink name; release only after its last alias.
    DeleteSymlink,
    /// Create a directory with native dot entries.
    CreateDirectory,
    /// Add one regular-file name referencing an existing inode.
    CreateHardlink,
    /// Rename or move without replacing an existing destination.
    Rename,
    /// Unlink a regular file name; allocation releases only after its last name.
    DeleteFile,
    /// Unlink an empty directory.
    DeleteDirectory,
}
/// Native namespace and metadata decisions; no alias, Unicode or time conversion occurs.
#[derive(Clone, Debug)]
pub struct ExtNamespaceReport {
    /// Operation performed.
    pub operation: ExtNamespaceOperation,
    /// Native object inode number, shared by existing hardlinks.
    pub inode: u32,
    /// Fresh native generation for newly assigned inode slots.
    pub assigned_inode_generation: Option<u32>,
    /// Exact resulting native byte name, absent on deletion.
    pub new_name: Option<Vec<u8>>,
    /// True when deletion also removes the inode's final namespace ownership.
    pub released_inode: bool,
    /// Explicit caller deletion time recorded for a released inode, absent otherwise.
    pub deletion_time: Option<u32>,
    /// Existing atime, mtime and ctime fields are preserved; creation copies the supplied fields.
    pub native_times_preserved: bool,
}
/// Source/generation-scoped directory facts with no independent backend capability.
pub struct ExtEditDirectory {
    identity: ObjectId,
    inode: ExtInode,
    map: ExtDecodedFileMap,
    directory: ExtDirectory,
    ancestors: Vec<u32>,
    _metadata: Reservation,
}
impl ExtEditDirectory {
    /// Editor scope, handle generation and native inode key.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Exact decoded native entries, including the validated dots.
    pub fn entries(&self) -> &[ExtEntry] {
        self.directory.entries()
    }
    /// Native inode metadata inspected for this directory.
    pub fn inode(&self) -> &ExtInode {
        &self.inode
    }
}
impl allocation::PlanningContext<'_> {
    fn check_directory(&self, d: &ExtEditDirectory, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if d.identity.source != self.scope || d.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated ext2 directory handle",
            ));
        }
        Ok(())
    }
    fn directory_handle(
        &self,
        number: u32,
        ancestors: Vec<u32>,
        r: &Resources,
    ) -> Result<ExtEditDirectory> {
        let metadata = r.memory.reserve(512 + ancestors.len() as u64 * 4)?;
        let decoder = self.decoder(r)?;
        let inode = decoder.inode(number, r).map_err(native)?;
        if inode.mode() & 0xf000 != 0x4000 {
            return Err(bad("ext2 namespace parent is not a directory"));
        }
        let map = decoder
            .file_map(number, self.limits.file_blocks, r, false)
            .map_err(native)?;
        let directory = decoder
            .directory(
                number,
                self.limits.file_blocks,
                self.limits.directory_entries,
                r,
            )
            .map_err(native)?;
        let mut identity = decoder.identity(number, r).map_err(native)?;
        identity.generation = self.generation;
        Ok(ExtEditDirectory {
            identity,
            inode,
            map,
            directory,
            ancestors,
            _metadata: metadata,
        })
    }
    /// Open root (empty path) or an exact native byte directory path without following symlinks.
    pub fn open_directory(&self, path: &[NativeName], r: &Resources) -> Result<ExtEditDirectory> {
        self.ready(r)?;
        if path.len() > self.limits.work {
            return Err(budget("ext2 directory path ceiling"));
        }
        let _path = r.memory.reserve((path.len() as u64 + 1) * 4)?;
        let mut ancestors = Vec::new();
        ancestors
            .try_reserve_exact(path.len() + 1)
            .map_err(|_| budget("ext2 path ancestry"))?;
        ancestors.push(2);
        let mut d = self.directory_handle(2, ancestors, r)?;
        let mut work = 0usize;
        for component in path {
            let NativeName::Bytes(bytes) = component else {
                return Err(bad("ext2 directory path requires exact byte names"));
            };
            name(bytes)?;
            work = work
                .checked_add(d.entries().len() + 1)
                .filter(|n| *n <= self.limits.work)
                .ok_or_else(|| budget("ext2 directory lookup work"))?;
            let number = d
                .entries()
                .iter()
                .find(|e| &e.name == component)
                .ok_or_else(|| bad("ext2 directory path not found"))?
                .inode;
            if d.ancestors.contains(&number) {
                return Err(invalid("ext2 directory alias/cycle"));
            }
            let mut ancestors = Vec::new();
            ancestors
                .try_reserve_exact(d.ancestors.len() + 1)
                .map_err(|_| budget("ext2 child ancestry"))?;
            ancestors.extend_from_slice(&d.ancestors);
            ancestors.push(number);
            let child = self.directory_handle(number, ancestors, r)?;
            dots(&child, d.inode.number())?;
            d = child;
        }
        if path.is_empty() {
            dots(&d, 2)?;
        }
        Ok(d)
    }
}
fn dots(d: &ExtEditDirectory, parent: u32) -> Result<()> {
    let get = |bytes: &[u8]| {
        d.entries()
            .iter()
            .find(|e| matches!(&e.name,NativeName::Bytes(n) if n==bytes))
            .map(|e| e.inode)
    };
    if get(b".") != Some(d.inode.number()) || get(b"..") != Some(parent) {
        return Err(invalid("ext2 dot references disagree with actual topology"));
    }
    Ok(())
}
struct Row {
    at: u64,
    inode: u32,
    record: usize,
    name: Vec<u8>,
}
struct Layout {
    rows: Vec<Row>,
    _lease: Reservation,
}
fn layout(d: &ExtEditDirectory, p: &mut Planner<'_>) -> Result<Layout> {
    let max =
        usize::try_from(d.map.length / 8).map_err(|_| budget("ext2 directory slot host bound"))?;
    if max > p.limits.work {
        return Err(budget("ext2 directory record ceiling"));
    }
    let lease =
        p.r.memory
            .reserve(max as u64 * (crate::platform::mem::size_of::<Row>() as u64 + 255))?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(max)
        .map_err(|_| budget("ext2 directory rows"))?;
    let bs = p.g.block_size as usize;
    let _scratch = p.r.memory.reserve(bs as u64)?;
    let mut block = zeros(bs)?;
    for extent in &d.map.extents {
        let ExtentKind::Data(physical) = extent.kind else {
            return Err(invalid("ext2 directory cannot contain holes"));
        };
        p.current(physical, &mut block)?;
        let mut at = 0;
        while at < bs {
            p.tick(1)?;
            if bs - at < 8 {
                return Err(invalid("ext2 directory header boundary"));
            }
            let record = u16le(&block, at + 4) as usize;
            let length = if p.g.filetype {
                block[at + 6] as usize
            } else {
                u16le(&block, at + 6) as usize
            };
            if record < 8
                || !record.is_multiple_of(4)
                || record > bs - at
                || length > 255
                || length > record - 8
            {
                return Err(invalid("ext2 directory native record geometry"));
            }
            rows.push(Row {
                at: physical + at as u64,
                inode: u32le(&block, at),
                record,
                name: copied(&block[at + 8..at + 8 + length])?,
            });
            at += record;
        }
    }
    Ok(Layout {
        rows,
        _lease: lease,
    })
}
fn row<'a>(l: &'a Layout, name: &[u8]) -> Result<&'a Row> {
    l.rows
        .iter()
        .find(|r| r.inode != 0 && r.name == name)
        .ok_or_else(|| bad("ext2 native namespace entry not found"))
}
fn record_header(
    g: &ExtGeometry,
    inode: u32,
    record: usize,
    bytes: &[u8],
    kind: u8,
) -> Result<Vec<u8>> {
    let mut b = zeros(8 + bytes.len())?;
    b[..4].copy_from_slice(&inode.to_le_bytes());
    b[4..6].copy_from_slice(
        &u16::try_from(record)
            .map_err(|_| bad("ext2 directory record size overflow"))?
            .to_le_bytes(),
    );
    if g.filetype {
        b[6] = bytes.len() as u8;
        b[7] = kind;
    } else {
        b[6..8].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    }
    b[8..].copy_from_slice(bytes);
    Ok(b)
}
impl Planner<'_> {
    fn allocate_inode(&mut self, directory: bool) -> Result<(u32, u32)> {
        for number in 11..=self.g.inodes {
            self.tick(1)?;
            let group = (number - 1) / self.g.inodes_per_group;
            let within = (number - 1) % self.g.inodes_per_group;
            let mut descriptor = [0; 12];
            self.current(
                (u64::from(self.g.first) + 1) * u64::from(self.g.block_size)
                    + u64::from(group) * 32,
                &mut descriptor,
            )?;
            let mut b = [0];
            self.current(
                u64::from(u32le(&descriptor, 4)) * u64::from(self.g.block_size)
                    + u64::from(within / 8),
                &mut b,
            )?;
            if b[0] & (1u8 << (within % 8)) != 0 {
                continue;
            }
            let at = self.inode_offset(number)?;
            let mut native_generation = [0; 4];
            self.current(at + 100, &mut native_generation)?;
            let generation = u32le(&native_generation, 0)
                .checked_add(1)
                .ok_or_else(|| budget("ext2 native inode generation exhausted"))?;
            self.bitmap(number, true, true)?;
            if directory {
                self.directory_count(number, 1, Phase::Allocate)?;
            }
            return Ok((number, generation));
        }
        Err(bad("ext2 no audited free inode slots"))
    }
    fn directory_count(&mut self, number: u32, delta: i64, phase: Phase) -> Result<()> {
        let group = (number - 1) / self.g.inodes_per_group;
        self.counter(
            (u64::from(self.g.first) + 1) * u64::from(self.g.block_size)
                + u64::from(group) * 32
                + 16,
            delta,
            2,
            phase,
        )
    }
    fn link_count(&mut self, number: u32, delta: i64) -> Result<()> {
        let at = self.inode_offset(number)?;
        self.counter(at + 26, delta, 2, Phase::Publish)
    }
}
fn insert(
    d: &ExtEditDirectory,
    bytes: &[u8],
    inode: u32,
    kind: u8,
    p: &mut Planner<'_>,
) -> Result<()> {
    let minimum = (8 + bytes.len()).next_multiple_of(4);
    let l = layout(d, p)?;
    if l.rows.iter().any(|r| r.inode != 0 && r.name == bytes) {
        return Err(bad("ext2 exact native name collision"));
    }
    for r in &l.rows {
        p.tick(1)?;
        if r.inode == 0 && r.record >= minimum {
            let header = record_header(p.g, inode, r.record, bytes, kind)?;
            return p.edit(r.at, &header, Phase::Publish);
        }
        let used = (8 + r.name.len()).next_multiple_of(4);
        if r.inode != 0 && r.record >= used + minimum {
            p.edit(r.at + 4, &(used as u16).to_le_bytes(), Phase::Publish)?;
            let header = record_header(p.g, inode, r.record - used, bytes, kind)?;
            return p.edit(r.at + used as u64, &header, Phase::Publish);
        }
    }
    let bs = u64::from(p.g.block_size);
    let length = d
        .map
        .length
        .checked_add(bs)
        .filter(|n| *n <= u64::from(u32::MAX))
        .ok_or_else(|| bad("ext2 parent directory size overflow"))?;
    let count = length.div_ceil(bs) as usize;
    if count > p.limits.file_blocks {
        return Err(budget("ext2 parent directory growth block ceiling"));
    }
    let block = p.allocate()?;
    let _scratch = p.r.memory.reserve(bs)?;
    let mut body = zeros(bs as usize)?;
    let header = record_header(p.g, inode, bs as usize, bytes, kind)?;
    body[..header.len()].copy_from_slice(&header);
    p.patch(u64::from(block) * bs, body, Phase::Initialize)?;
    let (mut data, _lease) = data_blocks(&d.map, p.g.block_size, p.r)?;
    let _extra = p.r.memory.reserve(4)?;
    data.try_reserve_exact(1)
        .map_err(|_| budget("ext2 parent grown map"))?;
    data.push(block);
    publish_map(p, &d.inode, &data, length)?;
    Ok(())
}
fn creation_inode(
    meta: &ExtCreateMetadata,
    number: u32,
    generation: u32,
    directory: bool,
) -> Result<ExtInode> {
    let mut raw = meta.raw;
    if u16le(&raw, 0) & 0xf000 != if directory { 0x4000 } else { 0x8000 }
        || raw[4..8] != [0; 4]
        || raw[20..24] != [0; 4]
        || raw[26..32] != [0; 6]
        || raw[40..104] != [0; 64]
    {
        return Err(bad(
            "ext2 creation template must explicitly select kind and zero managed fields",
        ));
    }
    raw[26..28].copy_from_slice(&(if directory { 2u16 } else { 1 }).to_le_bytes());
    raw[100..104].copy_from_slice(&generation.to_le_bytes());
    ExtInode::decode_raw(number, raw).map_err(native)
}
impl allocation::PlanningContext<'_> {
    /// Create a regular file with bounded caller bytes and exact native metadata/name.
    pub fn plan_create_file(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        metadata: &ExtCreateMetadata,
        payload: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.create(parent, bytes, metadata, Some(payload), r)
    }
    /// Create an initialized directory with exact native dots and caller metadata.
    pub fn plan_create_directory(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        metadata: &ExtCreateMetadata,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.create(parent, bytes, metadata, None, r)
    }
    fn create(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        meta: &ExtCreateMetadata,
        payload: Option<&[u8]>,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(parent, r)?;
        name(bytes)?;
        if parent
            .entries()
            .iter()
            .any(|e| matches!(&e.name,NativeName::Bytes(n) if n==bytes))
        {
            return Err(bad("ext2 exact native name collision"));
        }
        let directory = payload.is_none();
        let mut p = Planner::new(self, r)?;
        let (number, generation) = p.allocate_inode(directory)?;
        let inode = creation_inode(meta, number, generation, directory)?;
        let bs = u64::from(self.geometry.block_size);
        let length = payload.map_or(bs, |b| b.len() as u64);
        if length > u64::from(u32::MAX) {
            return Err(bad("ext2 native create size overflow"));
        }
        if length > i32::MAX as u64 {
            let mut features = [0; 4];
            self.target
                .read_exact_at(1124, &mut features)
                .map_err(native)?;
            if u32le(&features, 0) & 2 == 0 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "ext2 large file feature must already be enabled",
                ));
            }
        }
        if !directory {
            p.begin_ordered(OrderedOperation::Create {
                inode: number,
                inode_generation: generation,
                length,
            })?;
        }
        let count = length.div_ceil(bs) as usize;
        if count > self.limits.file_blocks {
            return Err(budget("ext2 create block ceiling"));
        }
        let _map = r.memory.reserve(count as u64 * 4)?;
        let mut data = Vec::new();
        data.try_reserve_exact(count)
            .map_err(|_| budget("ext2 create data map"))?;
        for logical in 0..count {
            p.tick(1)?;
            let fresh = if directory {
                None
            } else {
                Some(p.allocate_regular(logical as u64)?)
            };
            let block = if let Some(token) = &fresh {
                Planner::regular_block(token)
            } else {
                p.allocate()?
            };
            data.push(block);
            let _scratch = r.memory.reserve(bs)?;
            let mut body = zeros(bs as usize)?;
            if let Some(payload) = payload {
                let at = logical * bs as usize;
                let n = (payload.len() - at).min(bs as usize);
                body[..n].copy_from_slice(&payload[at..at + n]);
            } else {
                let dot = record_header(p.g, number, 12, b".", 2)?;
                body[..dot.len()].copy_from_slice(&dot);
                let parent_dot =
                    record_header(p.g, parent.inode.number(), bs as usize - 12, b"..", 2)?;
                body[12..12 + parent_dot.len()].copy_from_slice(&parent_dot);
            }
            if let Some(token) = fresh {
                p.patch_regular_fresh(token, body)?;
            } else {
                p.patch(u64::from(block) * bs, body, Phase::Initialize)?;
            }
        }
        let (raw, _, _) = mapped_inode(&mut p, &inode, &data, length)?;
        let inode_at = p.inode_offset(number)?;
        if self.geometry.inode_size == 256 {
            // Private native profile: caller supplies the exact classic prefix;
            // the new extension is explicitly zeroed, with its required layout size.
            // Existing inode extensions are never routed through this birth path.
            let _birth = r.memory.reserve(256)?;
            let mut body = zeros(256)?;
            body[..128].copy_from_slice(&raw);
            body[128..130].copy_from_slice(&self.geometry.minimum_extra_size.to_le_bytes());
            p.patch(inode_at, body, Phase::Initialize)?;
        } else {
            p.patch(inode_at, raw.to_vec(), Phase::Initialize)?;
        }
        insert(parent, bytes, number, if directory { 2 } else { 1 }, &mut p)?;
        if directory {
            p.link_count(parent.inode.number(), 1)?;
        }
        let report = ExtNamespaceReport {
            operation: if directory {
                ExtNamespaceOperation::CreateDirectory
            } else {
                ExtNamespaceOperation::CreateFile
            },
            inode: number,
            assigned_inode_generation: Some(generation),
            new_name: Some(copied(bytes)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        };
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(report);
        Ok(batch)
    }
    /// Add an exact regular-file name without replacing any destination.
    ///
    /// The source inode retains mapping, payload, ownership and timestamps.
    /// The classic compatibility profile permits at most 32000 links.
    pub fn plan_hardlink(
        &self,
        source: &ExtEditDirectory,
        source_name: &[u8],
        destination: &ExtEditDirectory,
        destination_name: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(source, r)?;
        self.check_directory(destination, r)?;
        name(source_name)?;
        name(destination_name)?;
        let mut p = Planner::new(self, r)?;
        let mut source_number = None;
        for entry in source.entries() {
            p.tick(1)?;
            if matches!(&entry.name, NativeName::Bytes(n) if n == source_name) {
                source_number = Some(entry.inode);
                break;
            }
        }
        for entry in destination.entries() {
            p.tick(1)?;
            if matches!(&entry.name, NativeName::Bytes(n) if n == destination_name) {
                return Err(bad("ext2 hardlink destination already exists"));
            }
        }
        let number = source_number.ok_or_else(|| bad("ext2 hardlink source not found"))?;
        let decoder = self.decoder(r)?;
        let inode = decoder.inode(number, r).map_err(native)?;
        if inode.mode() & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 hardlink requires a regular source inode",
            ));
        }
        let links = u16le(inode.raw_metadata(), 26);
        if links == 0 {
            return Err(invalid("ext2 hardlink source has zero links"));
        }
        // Linux EXT2_LINK_MAX, deliberately narrower than u16/e2fsprogs limits.
        if links >= 32000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 hardlink classic link limit reached",
            ));
        }
        insert(destination, destination_name, number, 1, &mut p)?;
        p.link_count(number, 1)?;
        let report = ExtNamespaceReport {
            operation: ExtNamespaceOperation::CreateHardlink,
            inode: number,
            assigned_inode_generation: None,
            new_name: Some(copied(destination_name)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        };
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(report);
        Ok(batch)
    }
    /// Rename or move one exact byte name; existing native times/owner/mode remain exact.
    pub fn plan_rename(
        &self,
        source: &ExtEditDirectory,
        old_name: &[u8],
        destination: &ExtEditDirectory,
        new_name: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(source, r)?;
        self.check_directory(destination, r)?;
        name(old_name)?;
        name(new_name)?;
        let same = source.inode.number() == destination.inode.number();
        if same && old_name == new_name {
            return Err(bad("ext2 rename target equals source name"));
        }
        if destination
            .entries()
            .iter()
            .any(|e| matches!(&e.name,NativeName::Bytes(n) if n==new_name))
        {
            return Err(bad("ext2 rename destination already exists"));
        }
        let decoder = self.decoder(r)?;
        let entry = source
            .entries()
            .iter()
            .find(|e| matches!(&e.name,NativeName::Bytes(n) if n==old_name))
            .ok_or_else(|| bad("ext2 rename source not found"))?;
        let inode = decoder.inode(entry.inode, r).map_err(native)?;
        let directory = inode.mode() & 0xf000 == 0x4000;
        if !directory && !matches!(inode.mode() & 0xf000, 0x8000 | 0xa000) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 rename kind unsupported",
            ));
        }
        if directory && destination.ancestors.contains(&inode.number()) {
            return Err(bad("ext2 directory move would create a cycle"));
        }
        let symlink = inode.mode() & 0xf000 == 0xa000;
        let mut p = Planner::new(self, r)?;
        let proof = if symlink {
            p.begin_symlink_metadata()?;
            Some(capture_symlink(&mut p, &inode, SymlinkAction::Rename)?)
        } else {
            None
        };
        let l = layout(source, &mut p)?;
        let old = row(&l, old_name)?;
        if same && old.record >= 8 + new_name.len() {
            let header = record_header(
                p.g,
                inode.number(),
                old.record,
                new_name,
                if directory {
                    2
                } else if symlink {
                    7
                } else {
                    1
                },
            )?;
            p.edit(old.at, &header, Phase::Publish)?;
        } else {
            p.edit(old.at, &[0; 4], Phase::Publish)?;
            insert(
                destination,
                new_name,
                inode.number(),
                if directory {
                    2
                } else if symlink {
                    7
                } else {
                    1
                },
                &mut p,
            )?;
        }
        if directory && !same {
            let mut ancestry = source.ancestors.clone();
            ancestry.push(inode.number());
            let child = self.directory_handle(inode.number(), ancestry, r)?;
            dots(&child, source.inode.number())?;
            let child_layout = layout(&child, &mut p)?;
            let dotdot = row(&child_layout, b"..")?;
            p.edit(
                dotdot.at,
                &destination.inode.number().to_le_bytes(),
                Phase::Publish,
            )?;
            p.link_count(source.inode.number(), -1)?;
            p.link_count(destination.inode.number(), 1)?;
        }
        let report = ExtNamespaceReport {
            operation: if symlink {
                ExtNamespaceOperation::RenameSymlink
            } else {
                ExtNamespaceOperation::Rename
            },
            inode: inode.number(),
            assigned_inode_generation: None,
            new_name: Some(copied(new_name)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        };
        if let Some(proof) = proof {
            p.set_symlink_evidence(proof)?;
        }
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(report);
        Ok(batch)
    }
    /// Unlink a file name or empty directory. Caller supplies exact nonzero native deletion time.
    /// Existing hardlinks retain inode/allocation until the final name is removed.
    pub fn plan_delete(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        deletion_time: u32,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.plan_delete_kind(parent, bytes, deletion_time, None, r)
    }
    // Check the requested kind against the same audited native observation used
    // to construct the deletion plan, before allocating or publishing patches.
    pub(crate) fn plan_delete_kind(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        deletion_time: u32,
        expected_directory: Option<bool>,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.plan_delete_inner(parent, bytes, deletion_time, expected_directory, false, r)
    }
    #[cfg(feature = "std")]
    pub(crate) fn plan_unlink_symlink(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        deletion_time: u32,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.plan_delete_inner(parent, bytes, deletion_time, None, true, r)
    }
    fn plan_delete_inner(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        deletion_time: u32,
        expected_directory: Option<bool>,
        symlink_requested: bool,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(parent, r)?;
        name(bytes)?;
        if deletion_time == 0 {
            return Err(bad(
                "ext2 final unlink requires explicit nonzero native deletion time",
            ));
        }
        if deletion_time < self.geometry.inodes {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext deletion time aliases the native orphan inode-number domain",
            ));
        }
        let decoder = self.decoder(r)?;
        let entry = parent
            .entries()
            .iter()
            .find(|e| matches!(&e.name,NativeName::Bytes(n) if n==bytes))
            .ok_or_else(|| bad("ext2 unlink source not found"))?;
        let inode = decoder.inode(entry.inode, r).map_err(native)?;
        let directory = inode.mode() & 0xf000 == 0x4000;
        let symlink = inode.mode() & 0xf000 == 0xa000;
        if symlink != symlink_requested {
            return Err(bad(
                "unlink actual kind differs from requested symlink operation",
            ));
        }
        if !directory && !matches!(inode.mode() & 0xf000, 0x8000 | 0xa000) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 unlink kind unsupported",
            ));
        }
        if expected_directory.is_some_and(|expected| expected != directory) {
            return Err(bad(
                "ext unlink target kind differs from requested operation",
            ));
        }
        let mut p = Planner::new(self, r)?;
        let mut proof = if symlink {
            p.begin_symlink_metadata()?;
            Some(capture_symlink(&mut p, &inode, SymlinkAction::Unlink)?)
        } else {
            None
        };
        let l = layout(parent, &mut p)?;
        let target = row(&l, bytes)?;
        p.edit(target.at, &[0; 4], Phase::Publish)?;
        let released = directory || u16le(inode.raw_metadata(), 26) == 1;
        if directory {
            let mut ancestors = parent.ancestors.clone();
            ancestors.push(inode.number());
            let child = self.directory_handle(inode.number(), ancestors, r)?;
            dots(&child, parent.inode.number())?;
            if child
                .entries()
                .iter()
                .any(|e| !matches!(&e.name,NativeName::Bytes(n) if n==b"."||n==b".."))
            {
                return Err(bad("ext2 directory is not empty"));
            }
            p.link_count(parent.inode.number(), -1)?;
        }
        if released {
            if symlink {
                if let Some((at, _)) = proof.as_ref().and_then(|e| e.original_slow.as_ref()) {
                    p.free_block((*at / u64::from(self.geometry.block_size)) as u32)?;
                }
                let at = p.inode_offset(inode.number())?;
                p.edit(at + 4, &[0; 4], Phase::Publish)?;
                p.edit(at + 28, &[0; 4], Phase::Publish)?;
                p.edit(at + 40, &[0; 60], Phase::Publish)?;
            } else {
                let map = decoder
                    .file_map(inode.number(), self.limits.file_blocks, r, false)
                    .map_err(native)?;
                let (data, _map) = data_blocks(&map, self.geometry.block_size, r)?;
                for block in data.iter().filter(|b| **b != 0) {
                    p.free_block(*block)?;
                }
                let empty = [];
                publish_map(&mut p, &inode, &empty, 0)?;
            }
            let at = p.inode_offset(inode.number())?;
            p.edit(at + 26, &[0; 2], Phase::Publish)?;
            p.edit(at + 20, &deletion_time.to_le_bytes(), Phase::Publish)?;
            p.bitmap(inode.number(), true, false)?;
            if directory {
                p.directory_count(inode.number(), -1, Phase::Release)?;
            }
        } else {
            p.link_count(inode.number(), -1)?;
        }
        let report = ExtNamespaceReport {
            operation: if symlink {
                ExtNamespaceOperation::DeleteSymlink
            } else if directory {
                ExtNamespaceOperation::DeleteDirectory
            } else {
                ExtNamespaceOperation::DeleteFile
            },
            inode: inode.number(),
            assigned_inode_generation: None,
            new_name: None,
            released_inode: released,
            deletion_time: released.then_some(deletion_time),
            native_times_preserved: true,
        };
        if let Some(mut evidence) = proof.take() {
            let at = p.inode_offset(inode.number())?;
            p.current(at, &mut evidence.final_inode)?;
            evidence.final_allocated = !released;
            if released {
                evidence.target.clear();
            }
            p.set_symlink_evidence(evidence)?;
        }
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(report);
        Ok(batch)
    }
}

impl<S: Storage, J: Storage> ExtEditor<S, J> {
    /// Open an exact native byte directory path without following symlinks.
    pub fn open_directory(&self, path: &[NativeName], r: &Resources) -> Result<ExtEditDirectory> {
        self.planning_context(r)?.open_directory(path, r)
    }
    /// Create a regular file with exact caller metadata and native name.
    pub fn plan_create_file(
        &self,
        parent: &ExtEditDirectory,
        name: &[u8],
        metadata: &ExtCreateMetadata,
        payload: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?
            .plan_create_file(parent, name, metadata, payload, r)
    }
    /// Create an initialized directory with exact native dots and metadata.
    pub fn plan_create_directory(
        &self,
        parent: &ExtEditDirectory,
        name: &[u8],
        metadata: &ExtCreateMetadata,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?
            .plan_create_directory(parent, name, metadata, r)
    }
    /// Plan another exact name for a regular inode, preserving its native metadata.
    ///
    /// Existing destinations are refused; the classic creation limit is 32000
    /// links. Commit the returned batch through the editor's external-undo path.
    pub fn plan_hardlink(
        &self,
        source: &ExtEditDirectory,
        source_name: &[u8],
        destination: &ExtEditDirectory,
        destination_name: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?.plan_hardlink(
            source,
            source_name,
            destination,
            destination_name,
            r,
        )
    }
    /// Rename or move one exact byte name, preserving native metadata.
    pub fn plan_rename(
        &self,
        source: &ExtEditDirectory,
        old_name: &[u8],
        destination: &ExtEditDirectory,
        new_name: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?
            .plan_rename(source, old_name, destination, new_name, r)
    }
    /// Delete one exact native byte name, releasing only its verified last-link allocations.
    pub fn plan_delete(
        &self,
        parent: &ExtEditDirectory,
        name: &[u8],
        deletion_time: u32,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?
            .plan_delete(parent, name, deletion_time, r)
    }
}

pub(super) fn symlink_source_shape(raw: &[u8; 128], body: Option<&[u8]>, bs: u32) -> Result<()> {
    let length = u32le(raw, 4) as usize;
    if u16le(raw, 0) & 0xf000 != 0xa000
        || length == 0
        || length >= bs as usize
        || u32le(raw, 32) != 0
        || u32le(raw, 104) != 0
        || u32le(raw, 108) != 0
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "unqualified symlink source profile",
        ));
    }
    if u32le(raw, 28) == 0 {
        if length >= 60
            || body.is_some()
            || raw[40 + length] != 0
            || raw[40..40 + length].contains(&0)
        {
            return Err(invalid("fast symlink source framing"));
        }
    } else {
        if length < 60 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "short block-backed symlink unqualified",
            ));
        }
        let body = body.ok_or_else(|| invalid("slow symlink body missing"))?;
        if u32le(raw, 28) != bs / 512
            || u32le(raw, 40) == 0
            || raw[44..100].iter().any(|b| *b != 0)
            || body.len() != bs as usize
            || body[length] != 0
            || body[..length].contains(&0)
        {
            return Err(invalid("slow symlink source framing"));
        }
    }
    Ok(())
}
fn capture_symlink(
    p: &mut Planner<'_>,
    inode: &ExtInode,
    action: SymlinkAction,
) -> Result<SymlinkEvidence> {
    let raw: [u8; 128] = *inode.raw_metadata();
    let size = u32le(&raw, 4) as usize;
    if size == 0 || size >= p.g.block_size as usize {
        return Err(invalid("symlink target length"));
    }
    let lease = p.r.memory.reserve(
        p.g.block_size as u64
            + size as u64
            + 512
            + crate::platform::mem::size_of::<SymlinkEvidence>() as u64,
    )?;
    let slow = if u32le(&raw, 28) == 0 {
        None
    } else {
        let at = u64::from(u32le(&raw, 40)) * u64::from(p.g.block_size);
        let mut body = zeros(p.g.block_size as usize)?;
        if body.capacity() > p.g.block_size as usize {
            return Err(budget("symlink source capacity"));
        }
        p.tick(body.len())?;
        p.target.read_exact_at(at, &mut body).map_err(native)?;
        Some((at, body))
    };
    // Framing scan and target copy are separate from the charged block read.
    p.tick(
        size.checked_mul(2)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(|| budget("symlink capture scan work overflow"))?,
    )?;
    symlink_source_shape(
        &raw,
        slow.as_ref().map(|(_, b)| b.as_slice()),
        p.g.block_size,
    )?;
    let bytes = match &slow {
        Some((_, body)) => &body[..size],
        None => &raw[40..40 + size],
    };
    let target = copied(bytes)?;
    if target.capacity() > size {
        return Err(budget("symlink target capacity"));
    }
    let at = p.inode_offset(inode.number())?;
    Ok(SymlinkEvidence {
        action,
        source: p.scope_for_symlink(),
        generation: p.generation_for_symlink(),
        inode: inode.number(),
        inode_offset: at,
        original_inode: raw,
        final_inode: raw,
        target,
        original_slow: slow,
        fresh_slow: None,
        final_allocated: true,
        _lease: lease,
    })
}

#[cfg(feature = "std")]
fn symlink_target_bytes(p: &mut Planner<'_>, target: &[u8], block_size: u32) -> Result<()> {
    if target.is_empty() || target.len() >= block_size as usize {
        return Err(bad(
            "symlink requires1..blocksize-1 exact non-NUL target bytes",
        ));
    }
    // Debit before inspecting caller bytes; include the retained evidence copy.
    p.tick(
        target
            .len()
            .checked_mul(2)
            .ok_or_else(|| budget("symlink target scan work overflow"))?,
    )?;
    if target.contains(&0) {
        return Err(bad(
            "symlink requires1..blocksize-1 exact non-NUL target bytes",
        ));
    }
    Ok(())
}
#[cfg(feature = "std")]
fn symlink_profile(context: &allocation::PlanningContext<'_>) -> Result<()> {
    if context.geometry.inode_size != 128
        || context.geometry.modern.is_some()
        || !matches!(context.geometry.block_size, 1024 | 2048 | 4096)
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "symlink planner requires admitted classic128 profile",
        ));
    }
    Ok(())
}
#[cfg(feature = "std")]
fn symlink_proof_lease(r: &Resources, bs: usize, target: usize) -> Result<Reservation> {
    let bytes = (bs as u64)
        .checked_add(target as u64)
        .and_then(|n| {
            n.checked_add(512 + crate::platform::mem::size_of::<SymlinkEvidence>() as u64)
        })
        .ok_or_else(|| budget("symlink proof accounting"))?;
    r.memory.reserve(bytes)
}
#[cfg(feature = "std")]
fn symlink_final_raw(
    p: &mut Planner<'_>,
    mut raw: [u8; 128],
    target: &[u8],
) -> Result<([u8; 128], Option<u32>)> {
    p.tick(target.len() + 60)?;
    raw[4..8].copy_from_slice(&(target.len() as u32).to_le_bytes());
    raw[28..32].fill(0);
    raw[40..100].fill(0);
    let slow = if target.len() < 60 {
        raw[40..40 + target.len()].copy_from_slice(target);
        None
    } else {
        // Immutable original audit.free_ranges controls this allocation. It must
        // precede release of the original target, even in net-zero replacement.
        let block = p.allocate()?;
        let bs = p.g.block_size as usize;
        let _scratch = p.r.memory.reserve(bs as u64)?;
        let mut body = zeros(bs)?;
        if body.capacity() > bs {
            return Err(budget("symlink body capacity"));
        }
        body[..target.len()].copy_from_slice(target);
        p.tick(bs)?;
        p.patch(u64::from(block) * bs as u64, body, Phase::Initialize)?;
        raw[40..44].copy_from_slice(&block.to_le_bytes());
        raw[28..32].copy_from_slice(&(p.g.block_size / 512).to_le_bytes());
        Some(block)
    };
    Ok((raw, slow))
}
#[cfg(feature = "std")]
impl allocation::PlanningContext<'_> {
    pub(crate) fn plan_create_symlink(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        target: &[u8],
        metadata: &ExtCreateMetadata,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(parent, r)?;
        symlink_profile(self)?;
        name(bytes)?;
        // Explicit charged scan rather than unbounded `any` over entries.
        let mut p = Planner::new(self, r)?;
        symlink_target_bytes(&mut p, target, self.geometry.block_size)?;
        for entry in parent.entries() {
            p.tick(1)?;
            if matches!(&entry.name,NativeName::Bytes(n) if n==bytes) {
                return Err(bad("symlink destination exists"));
            }
        }
        let _proof_lease = symlink_proof_lease(r, self.geometry.block_size as usize, target.len())?;
        let target = copied(target)?;
        if target.capacity() > target.len() {
            return Err(budget("symlink target proof capacity"));
        }
        p.begin_symlink_metadata()?;
        let (inode, generation) = p.allocate_inode(false)?;
        let at = p.inode_offset(inode)?;
        let mut original_inode = [0; 128];
        p.target
            .read_exact_at(at, &mut original_inode)
            .map_err(native)?;
        let mut raw = metadata.raw;
        if u16le(&raw, 0) & 0xf000 != 0xa000
            || raw[4..8] != [0; 4]
            || raw[20..24] != [0; 4]
            || raw[26..32] != [0; 6]
            || raw[40..104] != [0; 64]
        {
            return Err(bad(
                "symlink template must select symlink and zero managed fields",
            ));
        }
        raw[26..28].copy_from_slice(&1u16.to_le_bytes());
        raw[100..104].copy_from_slice(&generation.to_le_bytes());
        let (final_inode, fresh_slow) = symlink_final_raw(&mut p, raw, &target)?;
        p.patch(at, copied(&final_inode)?, Phase::Initialize)?;
        insert(parent, bytes, inode, 7, &mut p)?;
        p.set_symlink_evidence(SymlinkEvidence {
            action: SymlinkAction::Create,
            source: self.scope,
            generation: self.generation,
            inode,
            inode_offset: at,
            original_inode,
            final_inode,
            target,
            original_slow: None,
            fresh_slow,
            final_allocated: true,
            _lease: _proof_lease,
        })?;
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(ExtNamespaceReport {
            operation: ExtNamespaceOperation::CreateSymlink,
            inode,
            assigned_inode_generation: Some(generation),
            new_name: Some(copied(bytes)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        });
        Ok(batch)
    }
    pub(crate) fn plan_replace_symlink_target(
        &self,
        parent: &ExtEditDirectory,
        bytes: &[u8],
        target: &[u8],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_directory(parent, r)?;
        symlink_profile(self)?;
        name(bytes)?;
        let mut p = Planner::new(self, r)?;
        symlink_target_bytes(&mut p, target, self.geometry.block_size)?;
        let mut number = None;
        for entry in parent.entries() {
            p.tick(1)?;
            if matches!(&entry.name,NativeName::Bytes(n) if n==bytes) {
                number = Some(entry.inode);
                break;
            }
        }
        let decoder = self.decoder(r)?;
        let inode = decoder
            .inode(number.ok_or_else(|| bad("symlink source absent"))?, r)
            .map_err(native)?;
        if inode.mode() & 0xf000 != 0xa000 {
            return Err(bad("target replacement requires actual symlink inode"));
        }
        let original_inode: [u8; 128] = *inode.raw_metadata();
        if u32le(&original_inode, 32) != 0 || u32le(&original_inode, 104) != 0 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "symlink flags/xattr unsupported",
            ));
        }
        let old_len = usize::try_from(inode.len()).map_err(|_| budget("symlink old length"))?;
        if old_len == 0 || old_len >= self.geometry.block_size as usize {
            return Err(invalid("symlink source length"));
        }
        let _proof_lease = symlink_proof_lease(r, self.geometry.block_size as usize, target.len())?;
        // Charge framing and NUL scans before examining the retained source.
        p.tick(
            old_len
                .checked_add(128)
                .ok_or_else(|| budget("symlink replacement scan work overflow"))?,
        )?;
        let original_slow = if u32le(&original_inode, 28) == 0 {
            if old_len >= 60
                || original_inode[40 + old_len] != 0
                || original_inode[40..40 + old_len].contains(&0)
            {
                return Err(invalid("fast source framing"));
            }
            None // Opaque unused inline bytes retained in exact original inode guard.
        } else {
            if old_len < 60 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "short block-backed symlink unqualified",
                ));
            }
            let block = u32le(&original_inode, 40);
            if block == 0
                || u32le(&original_inode, 28) != self.geometry.block_size / 512
                || original_inode[44..100].iter().any(|b| *b != 0)
            {
                return Err(invalid("slow source mapping"));
            }
            let mut body = zeros(self.geometry.block_size as usize)?;
            if body.capacity() > self.geometry.block_size as usize {
                return Err(budget("symlink guard capacity"));
            }
            p.tick(body.len())?;
            p.target
                .read_exact_at(
                    u64::from(block) * u64::from(self.geometry.block_size),
                    &mut body,
                )
                .map_err(native)?;
            if body[old_len] != 0 || body[..old_len].contains(&0) {
                return Err(invalid("slow source terminator"));
            }
            Some((u64::from(block) * u64::from(self.geometry.block_size), body))
        };
        let target = copied(target)?;
        if target.capacity() > target.len() {
            return Err(budget("symlink proof target capacity"));
        }
        // Typed symlink-only metadata purpose coalesces allocation/release counters.
        // Planner finish requires matching evidence and prospective semantic proof.
        p.begin_symlink_metadata()?;
        let (final_inode, fresh_slow) = symlink_final_raw(&mut p, original_inode, &target)?;
        if let Some((at, _)) = &original_slow {
            p.free_block((*at / u64::from(self.geometry.block_size)) as u32)?;
        }
        let at = p.inode_offset(inode.number())?;
        for (index, byte) in final_inode.iter().enumerate() {
            p.tick(1)?;
            if *byte != original_inode[index] {
                p.edit(at + index as u64, &[*byte], Phase::Publish)?;
            }
        }
        p.set_symlink_evidence(SymlinkEvidence {
            action: SymlinkAction::Replace,
            source: self.scope,
            generation: self.generation,
            inode: inode.number(),
            inode_offset: at,
            original_inode,
            final_inode,
            target,
            original_slow,
            fresh_slow,
            final_allocated: true,
            _lease: _proof_lease,
        })?;
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.namespace = Some(ExtNamespaceReport {
            operation: ExtNamespaceOperation::ReplaceSymlinkTarget,
            inode: inode.number(),
            assigned_inode_generation: None,
            new_name: Some(copied(bytes)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        });
        Ok(batch)
    }
}
