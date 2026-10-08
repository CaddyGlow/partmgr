//! Exact-byte classic ext2 namespace planning on an audited owned session.
use super::allocation::{Phase, Planner, data_blocks, mapped_inode, publish_map};
use super::*;
use crate::fs_ext::{ExtDirectory, ExtEntry};
use crate::fs_file::ExtentKind;
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
fn zeros(n: usize) -> Result<Vec<u8>> {
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
    /// Create a directory with native dot entries.
    CreateDirectory,
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
            .reserve(max as u64 * (std::mem::size_of::<Row>() as u64 + 255))?;
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
            let block = p.allocate()?;
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
            p.patch(u64::from(block) * bs, body, Phase::Initialize)?;
        }
        let (raw, _, _) = mapped_inode(&mut p, &inode, &data, length)?;
        let inode_at = p.inode_offset(number)?;
        p.patch(inode_at, raw.to_vec(), Phase::Initialize)?;
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
        if !directory && inode.mode() & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 rename kind unsupported",
            ));
        }
        if directory && destination.ancestors.contains(&inode.number()) {
            return Err(bad("ext2 directory move would create a cycle"));
        }
        let mut p = Planner::new(self, r)?;
        let l = layout(source, &mut p)?;
        let old = row(&l, old_name)?;
        if same && old.record >= 8 + new_name.len() {
            let header = record_header(
                p.g,
                inode.number(),
                old.record,
                new_name,
                if directory { 2 } else { 1 },
            )?;
            p.edit(old.at, &header, Phase::Publish)?;
        } else {
            p.edit(old.at, &[0; 4], Phase::Publish)?;
            insert(
                destination,
                new_name,
                inode.number(),
                if directory { 2 } else { 1 },
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
            operation: ExtNamespaceOperation::Rename,
            inode: inode.number(),
            assigned_inode_generation: None,
            new_name: Some(copied(new_name)?),
            released_inode: false,
            deletion_time: None,
            native_times_preserved: true,
        };
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
        self.check_directory(parent, r)?;
        name(bytes)?;
        if deletion_time == 0 {
            return Err(bad(
                "ext2 final unlink requires explicit nonzero native deletion time",
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
        if !directory && inode.mode() & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 unlink kind unsupported",
            ));
        }
        let mut p = Planner::new(self, r)?;
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
            let map = decoder
                .file_map(inode.number(), self.limits.file_blocks, r, false)
                .map_err(native)?;
            let (data, _map) = data_blocks(&map, self.geometry.block_size, r)?;
            for block in data.iter().filter(|b| **b != 0) {
                p.free_block(*block)?;
            }
            let empty = [];
            publish_map(&mut p, &inode, &empty, 0)?;
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
            operation: if directory {
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
