//! Strict immutable bare HFS profiles with checked catalog and extents B-trees.
use crate::{
    fs_core::*,
    fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
pub(crate) fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
pub(crate) fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(crate) fn be16(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes(b[p..p + 2].try_into().unwrap())
}
pub(crate) fn be32(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes(b[p..p + 4].try_into().unwrap())
}
pub(crate) fn vector<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("HFS allocation"))?;
    Ok(v)
}
fn fold(u: u8) -> u8 {
    u.to_ascii_lowercase()
}
fn name_profile(b: &[u8]) -> Result<()> {
    if b.iter().any(|u| !u.is_ascii_alphanumeric()) {
        return Err(unsupported(
            "classic HFS alphanumeric byte-name comparator profile",
        ));
    }
    Ok(())
}
fn copied<T: Copy>(b: &[T]) -> Result<Vec<T>> {
    let mut out = vector(b.len())?;
    out.extend_from_slice(b);
    Ok(out)
}
/// Explicit proportional allocation and metadata-work ceilings.
#[derive(Clone, Copy, Debug)]
pub struct HfsReadLimits {
    /// Maximum declared allocation blocks.
    pub blocks: u32,
    /// Maximum B-tree nodes summed across all system trees.
    pub nodes: usize,
    /// Maximum leaf records summed across all trees.
    pub records: usize,
    /// Maximum decoded physical extents across all forks.
    pub extents: usize,
    /// Maximum metadata bytes/records/blocks visited (charged before work).
    pub work: u64,
}
/// Native header geometry, relative to the supplied bounded volume.
#[derive(Clone, Debug)]
pub struct HfsGeometry {
    pub(crate) block_size: u32,
    pub(crate) blocks: u32,
    pub(crate) bytes: u64,
    pub(crate) free: u32,
    pub(crate) files: u32,
    pub(crate) folders: u32,
    pub(crate) attributes: u32,
    pub(crate) base: u64,
    pub(crate) root_files: u16,
    pub(crate) root_folders: u16,
    pub(crate) family: Family,
}
impl HfsGeometry {
    /// Native volume attribute bits, including the explicitly checked unmounted/inconsistent state.
    pub fn volume_attributes(&self) -> u32 {
        self.attributes
    }
    /// Native allocation block size.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    /// Declared allocation block count.
    pub fn blocks(&self) -> u32 {
        self.blocks
    }
    /// Selected volume bytes; allocation arena and metadata bounds are checked separately.
    pub fn volume_bytes(&self) -> u64 {
        self.bytes
    }
    /// Byte offset of allocation block zero within the selected volume.
    pub fn allocation_start(&self) -> u64 {
        self.base
    }
    /// Native family/version.
    pub fn family(&self) -> Family {
        self.family
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Allocation {
    pub(crate) start: u32,
    pub(crate) count: u32,
}
#[derive(Clone)]
pub(crate) struct Fork {
    pub(crate) length: u64,
    pub(crate) blocks: u32,
    pub(crate) extents: Vec<Allocation>,
}
#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) id: u32,
    pub(crate) parent: u32,
    pub(crate) name: Vec<u8>,
    pub(crate) raw: Vec<u8>,
    pub(crate) directory: bool,
    pub(crate) forks: [Fork; 2],
}
pub(crate) struct Thread {
    pub(crate) directory: bool,
    pub(crate) parent: u32,
    pub(crate) name: Vec<u8>,
}
struct Source {
    raw: Arc<dyn ReadAt>,
    length: u64,
    resources: Resources,
}
impl Source {
    fn stable(&self) -> io::Result<u64> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        let len = self.raw.len();
        if len != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "HFS source length changed",
            )));
        }
        Ok(len)
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let len = self.stable()?;
        if at.checked_add(out.len() as u64).is_none_or(|n| n > len) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.raw.read_exact_at(at, out)?;
        self.stable()?;
        Ok(())
    }
}

struct Work {
    limits: HfsReadLimits,
    work: u64,
    nodes: usize,
    records: usize,
    extents: usize,
}
impl Work {
    fn tick(&mut self, n: u64, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("HFS work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("HFS metadata work ceiling"));
        }
        Ok(())
    }
    fn extent(&mut self) -> Result<()> {
        if self.extents == self.limits.extents {
            return Err(budget("HFS extent ceiling"));
        }
        self.extents += 1;
        Ok(())
    }
}
fn read(source: &dyn ReadAt, at: u64, b: &mut [u8], r: &Resources) -> Result<()> {
    r.cancellation.check()?;
    source
        .read_exact_at(at, b)
        .map_err(|e| Error::io("HFS positional metadata", e))?;
    r.cancellation.check()
}
fn descriptors(b: &[u8], g: &HfsGeometry, w: &mut Work) -> Result<Vec<Allocation>> {
    if b.len() != 12 {
        return Err(bad("HFS extent record size"));
    }
    let mut out = vector(3)?;
    let mut ended = false;
    for i in 0..3 {
        let start = u32::from(be16(b, i * 4));
        let count = u32::from(be16(b, i * 4 + 2));
        if count == 0 {
            ended = true;
            if start != 0 {
                return Err(bad("HFS empty extent start"));
            }
        } else {
            if ended || start.checked_add(count).is_none_or(|n| n > g.blocks) {
                return Err(bad("HFS physical extent bounds/order"));
            }
            w.extent()?;
            out.push(Allocation { start, count });
        }
    }
    Ok(out)
}
fn initial(length: u64, physical: u64, b: &[u8], g: &HfsGeometry, w: &mut Work) -> Result<Fork> {
    if length > 0x7fffffff
        || physical > 0x7fffffff
        || !physical.is_multiple_of(u64::from(g.block_size))
        || length > physical
    {
        return Err(bad("HFS fork signed EOF/allocation bounds"));
    }
    let blocks = (physical / u64::from(g.block_size)) as u32;
    if blocks > g.blocks {
        return Err(bad("HFS fork allocation exceeds volume"));
    }
    let extents = descriptors(b, g, w)?;
    let sum = extents.iter().map(|e| e.count).sum::<u32>();
    if sum > blocks || sum < blocks && extents.len() != 3 {
        return Err(bad("HFS inline extent allocation total"));
    }
    Ok(Fork {
        length,
        blocks,
        extents,
    })
}
fn map(source: Arc<dyn ReadAt>, fork: &Fork, g: &HfsGeometry, max: usize) -> Result<ExtentFile> {
    let mut extents = vector(fork.extents.len())?;
    let mut at = 0;
    for e in &fork.extents {
        let physical = g.base + u64::from(e.start) * u64::from(g.block_size);
        let bytes = u64::from(e.count) * u64::from(g.block_size);
        let n = bytes.min(fork.length.saturating_sub(at));
        if n > 0 {
            extents.push(FileExtent {
                offset: at,
                length: n,
                kind: MapKind::Data(physical),
            });
            at += n;
        }
    }
    ExtentFile::new(source, fork.length, extents, max).map_err(|e| Error::io("HFS indexed fork", e))
}
fn mapped_read(file: &ExtentFile, at: u64, b: &mut [u8], r: &Resources) -> Result<()> {
    r.cancellation.check()?;
    if file
        .read_at(at, b)
        .map_err(|e| Error::io("HFS mapped metadata", e))?
        != b.len()
    {
        return Err(bad("HFS short metadata fork"));
    }
    r.cancellation.check()
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key(Vec<u32>);
struct Record {
    key: Vec<u8>,
    data: Vec<u8>,
}
struct Tree {
    records: Vec<Record>,
}
fn key(b: &[u8], kind: u8) -> Result<Key> {
    if kind == 0 {
        if b.len() < 6 || b[0] != 0 || b[5] > 31 || b.len() < 6 + usize::from(b[5]) {
            return Err(bad("HFS catalog key bounds"));
        }
        let name = &b[6..6 + usize::from(b[5])];
        name_profile(name)?;
        let mut out = vector(1 + name.len())?;
        out.push(be32(b, 1));
        out.extend(name.iter().map(|u| u32::from(fold(*u))));
        Ok(Key(out))
    } else {
        if b.len() != 7 || ![0, 255].contains(&b[0]) {
            return Err(bad("HFS extent key"));
        }
        Ok(Key(vec![
            be32(b, 1),
            u32::from(b[0]),
            u32::from(be16(b, 5)),
        ]))
    }
}
fn offsets(b: &[u8]) -> Result<Vec<(usize, usize)>> {
    if b.len() < 512 {
        return Err(bad("HFS short B-tree node"));
    }
    let count = usize::from(be16(b, 10));
    let table = count
        .checked_add(1)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| b.len().checked_sub(n))
        .ok_or_else(|| bad("HFS record-offset table bounds"))?;
    if table < 14 {
        return Err(bad("HFS B-tree record count"));
    }
    let mut ranges = vector(count)?;
    let mut previous = usize::from(be16(b, b.len() - 2));
    if previous != 14 {
        return Err(bad("HFS first B-tree record offset"));
    }
    for i in 0..count {
        let next = usize::from(be16(b, b.len() - (i + 2) * 2));
        if next <= previous || next > table {
            return Err(bad("HFS B-tree record offset bounds/order"));
        }
        ranges.push((previous, next));
        previous = next;
    }
    Ok(ranges)
}
struct Walker<'a> {
    file: &'a ExtentFile,
    node_size: usize,
    total: u32,
    bitmap: Vec<u8>,
    visited: BTreeSet<u32>,
    records: Vec<Record>,
    kind: u8,
    levels: BTreeMap<u8, (u32, u32, Key)>,
    first_leaf: u32,
    last_leaf: u32,
    w: &'a mut Work,
    r: &'a Resources,
}
impl Walker<'_> {
    fn node(&mut self, id: u32) -> Result<Vec<u8>> {
        if id >= self.total {
            return Err(bad("HFS B-tree child bounds"));
        }
        self.w.tick(self.node_size as u64, self.r)?;
        let mut b = vector(self.node_size)?;
        b.resize(self.node_size, 0);
        mapped_read(
            self.file,
            u64::from(id) * self.node_size as u64,
            &mut b,
            self.r,
        )?;
        Ok(b)
    }
    fn allocated(&self, id: u32) -> bool {
        self.bitmap[id as usize / 8] & (0x80 >> (id % 8)) != 0
    }
    fn visit(&mut self, id: u32, height: u8) -> Result<Key> {
        if id == 0 || id >= self.total || !self.allocated(id) || !self.visited.insert(id) {
            return Err(bad("HFS B-tree free/duplicate/cyclic child"));
        }
        let b = self.node(id)?;
        if b[9] != height || b[8] != if height == 1 { 255 } else { 0 } || be16(&b, 12) != 0 {
            return Err(bad("HFS B-tree node kind/height"));
        }
        let ranges = offsets(&b)?;
        if ranges.is_empty() || height > 1 && ranges.len() < 2 {
            return Err(bad("HFS empty/short keyed node"));
        }
        let mut first = None;
        let mut previous: Option<Key> = None;
        for (start, end) in ranges {
            self.w.tick(1, self.r)?;
            let rec = &b[start..end];
            if rec.len() < 2 {
                return Err(bad("HFS short keyed record"));
            }
            let n = usize::from(rec[0]);
            if n == 0 || n + 1 > rec.len() {
                return Err(bad("HFS keyed-record bounds"));
            }
            let native_key = &rec[1..n + 1];
            if self.kind == 0
                && native_key.len() >= 6
                && height == 1
                && n != ((6 + usize::from(native_key[5])) | 1)
            {
                return Err(bad("HFS canonical leaf key length"));
            }
            if self.kind == 0 && height > 1 && n != 37 {
                return Err(bad("HFS fixed index key size"));
            }
            let k = key(native_key, self.kind)?;
            if previous.as_ref().is_some_and(|p| *p >= k) {
                return Err(bad("HFS B-tree keys not strictly ordered"));
            }
            if first.is_none() {
                first = Some(k.clone());
            }
            previous = Some(k.clone());
            let data_at = (n + 2) & !1;
            if data_at > rec.len() {
                return Err(bad("HFS key padding bounds"));
            }
            let data = &rec[data_at..];
            if height > 1 {
                if data.len() != 4 {
                    return Err(bad("HFS index child encoding"));
                }
                let child = be32(data, 0);
                let lower = self.visit(child, height - 1)?;
                if lower != k {
                    return Err(bad("HFS index key differs from child minimum"));
                }
            } else {
                if self.kind == 0 && data.len() > 102 || self.kind == 1 && data.len() != 12 {
                    return Err(bad("HFS leaf record profile length"));
                }
                if self.w.records == self.w.limits.records {
                    return Err(budget("HFS leaf-record ceiling"));
                }
                self.w.records += 1;
                self.records.push(Record {
                    key: copied(native_key)?,
                    data: copied(data)?,
                });
            }
        }
        let first = first.unwrap();
        let last = previous.unwrap();
        if let Some((old, forward, old_key)) = self.levels.get(&height) {
            if *forward != id || be32(&b, 4) != *old || *old_key >= first {
                return Err(bad("HFS B-tree sibling links/key range"));
            }
        } else {
            if be32(&b, 4) != 0 {
                return Err(bad("HFS first sibling backward link"));
            }
            if height == 1 {
                self.first_leaf = id;
            }
        }
        self.levels.insert(height, (id, be32(&b, 0), last));
        if height == 1 {
            self.last_leaf = id;
        }
        Ok(first)
    }
}
fn tree(file: &ExtentFile, kind: u8, w: &mut Work, r: &Resources) -> Result<Tree> {
    if file.len() < 512 {
        return Err(bad("HFS short B-tree fork"));
    }
    w.tick(512, r)?;
    let mut head = [0; 512];
    mapped_read(file, 0, &mut head, r)?;
    let size = usize::from(be16(&head, 32));
    if size != 512 {
        return Err(bad("HFS B-tree node size"));
    }
    let scratch = r.memory.reserve(
        (size as u64)
            .checked_mul(192)
            .and_then(|n| n.checked_add((w.limits.records as u64).checked_mul(1024)?))
            .and_then(|n| n.checked_add((w.limits.nodes as u64).checked_mul(160)?))
            .ok_or_else(|| budget("HFS B-tree scratch charge overflow"))?,
    )?;
    w.tick(size as u64, r)?;
    let mut header = vector(size)?;
    header.resize(size, 0);
    mapped_read(file, 0, &mut header, r)?;
    if header[8] != 1 || header[9] != 0 || be16(&header, 10) != 3 || be32(&header, 4) != 0 {
        return Err(bad("HFS B-tree header descriptor"));
    }
    let ranges = offsets(&header)?;
    let (s, e) = ranges[0];
    let h = &header[s..e];
    if h.len() != 106 || ranges[1].1 - ranges[1].0 != 128 {
        return Err(bad("HFS B-tree header record size"));
    }
    let depth = be16(h, 0);
    let root = be32(h, 2);
    let leaves = be32(h, 6);
    let first = be32(h, 10);
    let last = be32(h, 14);
    let total = be32(h, 22);
    let free = be32(h, 26);

    if total == 0
        || free > total
        || depth > 8
        || u64::from(total) * size as u64 != file.len()
        || be16(h, 18) as usize != size
        || be16(h, 20) != if kind == 0 { 37 } else { 7 }
        || h[30..].iter().any(|v| *v != 0)
    {
        return Err(bad("HFS B-tree header geometry/flags"));
    }
    w.nodes = w
        .nodes
        .checked_add(total as usize)
        .ok_or_else(|| budget("HFS node count overflow"))?;
    if w.nodes > w.limits.nodes {
        return Err(budget("HFS B-tree node ceiling"));
    }
    let mut bitmap = vector(total.div_ceil(8) as usize)?;
    bitmap
        .try_reserve_exact(ranges[2].1 - ranges[2].0)
        .map_err(|_| budget("HFS header bitmap allocation"))?;
    bitmap.extend_from_slice(&header[ranges[2].0..ranges[2].1]);
    let mut map_nodes = BTreeSet::new();
    map_nodes.insert(0);
    let mut next = be32(&header, 0);
    while next != 0 {
        r.cancellation.check()?;
        if bitmap.len() >= total.div_ceil(8) as usize {
            return Err(bad("HFS redundant node map chain"));
        }
        if next >= total || !map_nodes.insert(next) {
            return Err(bad("HFS map node bounds/cycle"));
        }
        w.tick(size as u64, r)?;
        let mut b = vector(size)?;
        b.resize(size, 0);
        mapped_read(file, u64::from(next) * size as u64, &mut b, r)?;
        if b[8] != 2 || b[9] != 0 || be16(&b, 10) != 1 || be32(&b, 4) != 0 {
            return Err(bad("HFS map node descriptor"));
        }
        let spans = offsets(&b)?;
        let bytes = &b[spans[0].0..spans[0].1];
        if bitmap
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > file.len() as usize)
        {
            return Err(bad("HFS excessive node bitmap"));
        }
        bitmap
            .try_reserve_exact(bytes.len())
            .map_err(|_| budget("HFS node-map allocation"))?;
        bitmap.extend_from_slice(bytes);
        next = be32(&b, 0);
    }
    if bitmap.len() < total.div_ceil(8) as usize {
        return Err(bad("HFS truncated node bitmap"));
    }
    let mut walk = Walker {
        file,
        node_size: size,
        total,
        bitmap,
        visited: map_nodes,
        records: vector(w.limits.records.saturating_sub(w.records))?,
        kind,
        levels: BTreeMap::new(),
        first_leaf: 0,
        last_leaf: 0,
        w,
        r,
    };
    for &id in &walk.visited {
        if !walk.allocated(id) {
            return Err(bad("HFS free header/map node"));
        }
    }
    if leaves == 0 {
        if [u32::from(depth), root, first, last]
            .iter()
            .any(|n| *n != 0)
        {
            return Err(bad("HFS empty tree root fields"));
        }
    } else {
        if depth == 0 {
            return Err(bad("HFS zero keyed tree depth"));
        }
        walk.visit(root, depth as u8)?;
    }
    if walk.records.len() != leaves as usize
        || walk.first_leaf != first
        || walk.last_leaf != last
        || walk.levels.values().any(|(_, forward, _)| *forward != 0)
    {
        return Err(bad("HFS leaf totals or final sibling link"));
    }
    let mut allocated = 0;
    for id in 0..total {
        walk.w.tick(1, r)?;
        if walk.allocated(id) {
            allocated += 1;
            if !walk.visited.contains(&id) {
                return Err(bad("HFS unreachable allocated B-tree node"));
            }
        }
    }
    if allocated != total - free {
        return Err(bad("HFS B-tree free-node count"));
    }
    drop(scratch);
    Ok(Tree {
        records: walk.records,
    })
}
type Overflow = BTreeMap<(u32, u8, u32), Vec<Allocation>>;
fn complete(
    f: &mut Fork,
    id: u32,
    kind: u8,
    overflow: &Overflow,
    used: &mut BTreeSet<(u32, u8, u32)>,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let mut blocks = f.extents.iter().map(|e| u64::from(e.count)).sum::<u64>();
    while blocks < u64::from(f.blocks) {
        w.tick(1, r)?;
        let key = (id, kind, blocks as u32);
        let more = overflow
            .get(&key)
            .ok_or_else(|| bad("HFS missing/gapped overflow extent"))?;
        if more.is_empty() || !used.insert(key) {
            return Err(bad("HFS empty/reused overflow record"));
        }
        if f.extents
            .len()
            .checked_add(more.len())
            .is_none_or(|n| n > w.limits.extents)
        {
            return Err(budget("HFS indexed fork extent ceiling"));
        }
        f.extents
            .try_reserve_exact(more.len())
            .map_err(|_| budget("HFS fork allocation"))?;
        for e in more {
            blocks = blocks
                .checked_add(u64::from(e.count))
                .ok_or_else(|| bad("HFS overflow block total"))?;
            f.extents.push(*e);
        }
        if blocks > u64::from(f.blocks) {
            return Err(bad("HFS excess overflow allocation"));
        }
    }
    Ok(())
}
pub(crate) struct Inner {
    source: Arc<Source>,
    pub(crate) geometry: HfsGeometry,
    pub(crate) nodes: BTreeMap<u32, Node>,
    children: Vec<u32>,
    _children_lease: Reservation,
    pub(crate) threads: BTreeMap<u32, Thread>,
    pub(crate) system: Vec<Fork>,
    pub(crate) bad_blocks: Vec<Allocation>,
    pub(crate) bitmap: Vec<u8>,
    header: [u8; 512],
    pub(crate) scope: u128,
    pub(crate) limits: HfsReadLimits,
    _lease: Reservation,
}
/// Fully bounded immutable metadata inventory; opening does not grant ownership proof.
#[derive(Clone)]
pub struct HfsVolume {
    pub(crate) inner: Arc<Inner>,
}
impl HfsVolume {
    /// Open a bare classic HFS volume; caller retains immutable bytes through all handles.
    pub fn open(raw: Arc<dyn ReadAt>, limits: HfsReadLimits, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        let length = raw.len();
        if length < 2048 {
            return Err(bad("HFS short volume"));
        }
        let source = Arc::new(Source {
            raw,
            length,
            resources: r.clone(),
        });
        let mut header = [0; 512];
        read(source.as_ref(), 1024, &mut header, r)?;
        if be16(&header, 0) != 0x4244 {
            return Err(unsupported("bare classic HFS signature"));
        }
        if matches!(be16(&header, 124), 0x482b | 0x4858) {
            return Err(unsupported("HFS wrapper containing HFS+/HFSX"));
        }
        let attributes = u32::from(be16(&header, 10));
        if attributes & 0x100 == 0 || attributes & 0x800 != 0 {
            return Err(unsupported("HFS dirty/inconsistent state"));
        }
        if attributes & !0x8380 != 0 {
            return Err(unsupported("HFS unknown volume attribute profile"));
        }
        let block_size = be32(&header, 20);
        let blocks = u32::from(be16(&header, 18));
        let free = u32::from(be16(&header, 34));
        let base = u64::from(be16(&header, 28)) * 512;
        let bitmap_at = u64::from(be16(&header, 14)) * 512;
        let bitmap_bytes = u64::from(blocks.div_ceil(8));
        if block_size < 512
            || !block_size.is_multiple_of(512)
            || blocks == 0
            || free > blocks
            || length < 2560
            || !length.is_multiple_of(512)
            || bitmap_at < 1536
            || bitmap_at.checked_add(bitmap_bytes).is_none_or(|n| n > base)
            || base
                .checked_add(u64::from(blocks) * u64::from(block_size))
                .is_none_or(|n| n > length - 1024)
            || header[36] == 0
            || header[36] > 27
        {
            return Err(bad("HFS MDB/bitmap/allocation-arena bounds"));
        }
        name_profile(&header[37..37 + usize::from(header[36])])?;
        let bytes = length;
        if blocks > limits.blocks {
            return Err(budget("HFS allocation-block ceiling"));
        }
        let charge = (limits.records as u64)
            .checked_mul(3072)
            .and_then(|n| n.checked_add((limits.extents as u64).checked_mul(64)?))
            .and_then(|n| n.checked_add(u64::from(blocks.div_ceil(8))))
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| budget("HFS metadata charge overflow"))?;
        let lease = r.memory.reserve(charge)?;
        let geometry = HfsGeometry {
            block_size,
            blocks,
            bytes,
            free,
            base,
            files: be32(&header, 84),
            folders: be32(&header, 88),
            root_files: be16(&header, 12),
            root_folders: be16(&header, 82),
            attributes,
            family: Family::Hfs,
        };
        let mut w = Work {
            limits,
            work: 0,
            nodes: 0,
            records: 0,
            extents: 0,
        };
        let mut system = vector(2)?;
        for (size_at, ext_at) in [(130, 134), (146, 150)] {
            let length = u64::from(be32(&header, size_at));
            // System fork sizes describe the allocated, node-addressable byte span.
            system.push(initial(
                length,
                length,
                &header[ext_at..ext_at + 12],
                &geometry,
                &mut w,
            )?);
        }
        if system[0].extents.iter().map(|e| e.count).sum::<u32>() != system[0].blocks {
            return Err(unsupported("HFS extents-tree self-overflow bootstrap"));
        }
        let source_dyn: Arc<dyn ReadAt> = source.clone();
        let extmap = map(source_dyn.clone(), &system[0], &geometry, limits.extents)?;
        let extree = tree(&extmap, 1, &mut w, r)?;
        let mut overflow = Overflow::new();
        for record in extree.records {
            let k = key(&record.key, 1)?.0;
            let extents = descriptors(&record.data, &geometry, &mut w)?;
            if overflow.insert((k[0], k[1] as u8, k[2]), extents).is_some() {
                return Err(bad("HFS repeated overflow key"));
            }
        }
        let mut used = BTreeSet::new();
        for (i, id) in [3, 4].iter().enumerate() {
            complete(&mut system[i], *id, 0, &overflow, &mut used, &mut w, r)?;
        }
        let catalog = map(source_dyn, &system[1], &geometry, limits.extents)?;
        let catalog = tree(&catalog, 0, &mut w, r)?;
        let mut nodes = BTreeMap::new();
        let mut threads = BTreeMap::new();
        for record in catalog.records {
            w.tick(record.data.len() as u64, r)?;
            let parent = be32(&record.key, 1);
            let count = usize::from(record.key[5]);
            let name = copied(&record.key[6..6 + count])?;
            if record.data.len() < 2 || record.data[1] != 0 {
                return Err(bad("HFS catalog record tag"));
            }
            let kind = record.data[0];
            match kind {
                1 | 2 => {
                    let dir = kind == 1;
                    if record.data.len() != if dir { 70 } else { 102 } || name.is_empty() {
                        return Err(bad("HFS catalog object size/name"));
                    }
                    let raw = record.data;
                    let id = be32(&raw, if dir { 6 } else { 20 });
                    if id != 2 && id < 16 {
                        return Err(bad("HFS reserved object CNID"));
                    }
                    if !dir && (raw[2] & !0x43 != 0 || raw[3] != 0) {
                        return Err(unsupported("HFS file open/version/flag profile"));
                    }
                    if dir && be16(&raw, 2) & !0x3f != 0 {
                        return Err(unsupported("HFS directory flag profile"));
                    }
                    if !dir && matches!(&raw[4..12], b"hlnkhfs+" | b"slnkrhap") {
                        return Err(unsupported("HFS nonclassic special Finder type"));
                    }
                    let mut forks = [
                        Fork {
                            length: 0,
                            blocks: 0,
                            extents: Vec::new(),
                        },
                        Fork {
                            length: 0,
                            blocks: 0,
                            extents: Vec::new(),
                        },
                    ];
                    if !dir {
                        for (i, fork) in forks.iter_mut().enumerate() {
                            let (logical, physical, extent) =
                                if i == 0 { (26, 30, 74) } else { (36, 40, 86) };
                            *fork = initial(
                                u64::from(be32(&raw, logical)),
                                u64::from(be32(&raw, physical)),
                                &raw[extent..extent + 12],
                                &geometry,
                                &mut w,
                            )?;
                            complete(
                                fork,
                                id,
                                if i == 0 { 0 } else { 255 },
                                &overflow,
                                &mut used,
                                &mut w,
                                r,
                            )?;
                        }
                    }
                    if nodes
                        .insert(
                            id,
                            Node {
                                id,
                                parent,
                                name,
                                raw,
                                directory: dir,
                                forks,
                            },
                        )
                        .is_some()
                    {
                        return Err(bad("HFS duplicate CNID"));
                    }
                }
                3 | 4 => {
                    let b = &record.data;
                    if !name.is_empty() || b.len() != 46 || b[14] > 31 {
                        return Err(bad("HFS thread key/size/name"));
                    }
                    let name = copied(&b[15..15 + usize::from(b[14])])?;
                    name_profile(&name)?;
                    if threads
                        .insert(
                            parent,
                            Thread {
                                directory: kind == 3,
                                parent: be32(b, 10),
                                name,
                            },
                        )
                        .is_some()
                    {
                        return Err(bad("HFS duplicate thread CNID"));
                    }
                }
                _ => return Err(unsupported("HFS catalog record type")),
            }
        }
        let mut bad_blocks = vector(limits.extents)?;
        let mut bad_offset = 0u32;
        for (&k, extents) in &overflow {
            if k.0 == 5 {
                if k.1 != 0 || k.2 != bad_offset || extents.is_empty() {
                    return Err(bad("HFS bad-block file sequence"));
                }
                for e in extents {
                    bad_offset = bad_offset
                        .checked_add(e.count)
                        .ok_or_else(|| bad("HFS bad-block count overflow"))?;
                    bad_blocks.push(*e);
                }
                used.insert(k);
            }
        }
        if used.len() != overflow.len() {
            return Err(bad("HFS orphan overflow extent record"));
        }
        if (attributes & 0x200 != 0) != !bad_blocks.is_empty() {
            return Err(bad("HFS spared-block flag differs from bad-block file"));
        }
        w.tick(bitmap_bytes, r)?;
        let mut bitmap = vector(bitmap_bytes as usize)?;
        bitmap.resize(bitmap_bytes as usize, 0);
        read(source.as_ref(), bitmap_at, &mut bitmap, r)?;
        // Bits after drNmAlBlks do not designate allocation blocks and are never offered as free.
        let scope = (14u128 << 64)
            | u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                    .map_err(|_| budget("HFS source scope exhausted"))?,
            );
        // Retain only node IDs; native names stay owned by the catalog inventory.
        let children_lease = r.memory.reserve(
            (nodes.len() as u64)
                .checked_mul(4)
                .ok_or_else(|| budget("HFS child index charge"))?,
        )?;
        let mut children = vector(nodes.len())?;
        for node in nodes.values() {
            r.cancellation.check()?;
            children.push(node.id);
        }
        children.sort_unstable_by(|a, b| {
            let a = &nodes[a];
            let b = &nodes[b];
            a.parent.cmp(&b.parent).then_with(|| {
                a.name
                    .iter()
                    .map(|u| fold(*u))
                    .cmp(b.name.iter().map(|u| fold(*u)))
            })
        });
        Ok(Self {
            inner: Arc::new(Inner {
                source,
                geometry,
                nodes,
                children,
                _children_lease: children_lease,
                threads,
                system,
                bad_blocks,
                bitmap,
                header,
                scope,
                limits,
                _lease: lease,
            }),
        })
    }
    /// Validated native geometry.
    pub fn geometry(&self) -> &HfsGeometry {
        &self.inner.geometry
    }
    /// Native root CNID (2) bound to this source.
    pub fn root_identity(&self) -> ObjectId {
        self.identity(2)
    }
    pub(crate) fn identity(&self, id: u32) -> ObjectId {
        ObjectId {
            source: self.inner.scope,
            generation: 0,
            native: id.to_be_bytes().to_vec(),
        }
    }
    pub(crate) fn node(&self, id: &ObjectId) -> Result<&Node> {
        if id.source != self.inner.scope || id.generation != 0 || id.native.len() != 4 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign HFS object identity",
            ));
        }
        self.inner
            .nodes
            .get(&be32(&id.native, 0))
            .ok_or_else(|| bad("HFS catalog object missing"))
    }
    /// Recheck source length and retained primary header; caller still guarantees byte stability.
    pub fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.node(id)?;
        let mut b = [0; 512];
        read(self.inner.source.as_ref(), 1024, &mut b, r)?;
        if b != self.inner.header {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "HFS primary header changed",
            ));
        }
        Ok(())
    }
    /// Enumerate exact native children without host path reconstruction.
    pub fn directory(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<DirectoryEntry>>> {
        self.revalidate(id, r)?;
        let n = self.directory_len(id)?;
        let charge = (n as u64)
            .checked_mul(768)
            .ok_or_else(|| budget("HFS directory charge"))?;
        Budgeted::try_new(&r.memory, charge, || self.directory_entries(id, 0..n, r))
    }
    fn child_ids(&self, id: &ObjectId) -> Result<&[u32]> {
        let node = self.node(id)?;
        if !node.directory {
            return Err(Error::new(ErrorKind::InvalidOperation, "HFS non-directory"));
        }
        let ids = &self.inner.children;
        let start = ids.partition_point(|id| self.inner.nodes[id].parent < node.id);
        let end = ids.partition_point(|id| self.inner.nodes[id].parent <= node.id);
        Ok(&ids[start..end])
    }
    pub(crate) fn directory_len(&self, id: &ObjectId) -> Result<usize> {
        Ok(self.child_ids(id)?.len())
    }
    pub(crate) fn directory_entries(
        &self,
        id: &ObjectId,
        range: std::ops::Range<usize>,
        r: &Resources,
    ) -> Result<Vec<DirectoryEntry>> {
        let ids = self.child_ids(id)?;
        let mut out = vector(range.len())?;
        for id in &ids[range] {
            r.cancellation.check()?;
            let entry = &self.inner.nodes[id];
            out.push(DirectoryEntry {
                name: NativeName::Bytes(copied(&entry.name)?),
                object: self.identity(entry.id),
                kind: if entry.directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        Ok(out)
    }
    /// Lookup native path components under the selected actual catalog comparator.
    pub fn lookup(&self, path: &[NativeName], r: &Resources) -> Result<ObjectId> {
        let mut id = self.root_identity();
        if path.len() > self.inner.nodes.len() {
            return Err(budget("HFS path depth ceiling"));
        }
        for name in path {
            let NativeName::Bytes(name) = name else {
                return Err(unsupported("HFS lookup requires native bytes"));
            };
            if name.is_empty() || name.len() > 31 {
                return Err(bad("HFS lookup name bounds"));
            }
            name_profile(name)?;
            self.revalidate(&id, r)?;
            r.cancellation.check()?;
            let children = self.child_ids(&id)?;
            let index = children
                .binary_search_by(|child| {
                    let n = &self.inner.nodes[child].name;
                    n.iter()
                        .map(|u| fold(*u))
                        .cmp(name.iter().map(|u| fold(*u)))
                })
                .map_err(|_| bad("HFS native component missing"))?;
            id = self.identity(children[index]);
        }
        self.revalidate(&id, r)?;
        Ok(id)
    }
    /// Open one indexed data or resource fork without reading its payload.
    pub fn open_fork(&self, id: &ObjectId, kind: &StreamKind, r: &Resources) -> Result<HfsFile> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        if node.directory {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "HFS directory fork",
            ));
        }
        let i = match kind {
            StreamKind::Data => 0,
            StreamKind::ResourceFork => 1,
            _ => return Err(unsupported("HFS named/system stream profile")),
        };
        let fork = &node.forks[i];
        let protected = self
            .inner
            .system
            .iter()
            .map(|f| f.extents.len())
            .sum::<usize>()
            .checked_add(self.inner.bad_blocks.len())
            .ok_or_else(|| budget("HFS protected index size"))?;
        let work = (fork.extents.len() as u64)
            .checked_mul(protected as u64)
            .and_then(|n| n.checked_add(u64::from(fork.blocks)))
            .ok_or_else(|| budget("HFS local fork work overflow"))?;
        if work > self.inner.limits.work {
            return Err(budget("HFS local fork work ceiling"));
        }
        // Local access cannot read allocations declared free or overlapping native metadata.
        for extent in &fork.extents {
            for block in extent.start..extent.start + extent.count {
                r.cancellation.check()?;
                if self.inner.bitmap[block as usize / 8] & (0x80 >> (block % 8)) == 0 {
                    return Err(bad("HFS fork references a free allocation block"));
                }
            }
            let end = extent.start + extent.count;
            if self
                .inner
                .system
                .iter()
                .flat_map(|f| &f.extents)
                .chain(&self.inner.bad_blocks)
                .any(|system| extent.start < system.start + system.count && system.start < end)
            {
                return Err(bad("HFS fork overlaps protected native metadata"));
            }
        }
        let lease = r.memory.reserve(
            (fork.extents.len() as u64)
                .checked_mul(96)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("HFS fork index charge"))?,
        )?;
        let source: Arc<dyn ReadAt> = self.inner.source.clone();
        let file = map(
            source,
            fork,
            &self.inner.geometry,
            self.inner.limits.extents,
        )?;
        Ok(HfsFile {
            volume: self.clone(),
            identity: id.clone(),
            file,
            _lease: lease,
        })
    }
    /// Native catalog timestamps and opaque Finder/catalog metadata; no POSIX conversion.
    pub fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        Budgeted::try_new(&r.memory, 4096, || {
            let b = &node.raw;
            let at = if node.directory { 10 } else { 44 };
            let time = |p| {
                MetadataField::Known(NativeTimestamp {
                    ticks: i128::from(be32(b, p)),
                    ticks_per_second: 1,
                    epoch:
                        "1904-01-01; native classic Mac local-time seconds, timezone unavailable"
                            .into(),
                })
            };
            let mut native_key = vector(5 + node.name.len())?;
            native_key.extend_from_slice(&node.parent.to_be_bytes());
            native_key.push(node.name.len() as u8);
            native_key.extend_from_slice(&node.name);
            Ok(Metadata{created:time(at),modified:time(at+4),accessed:MetadataField::Absent,
                owner:MetadataField::Absent,mode:MetadataField::Absent,security:MetadataField::Uninspectable{reason:"Classic HFS external sharing/security metadata is not established by the catalog record".into()},
                attributes:vec![
                    (NativeName::Bytes(b"hfs.catalog-record".to_vec()),MetadataField::Opaque{bytes:copied(b)?,interpretation:"Native classic HFS catalog bytes including Finder/type/creator, backup timestamp, clump and physical fork locations; requires relocation policy".into()}),
                    (NativeName::Bytes(b"hfs.catalog-key".to_vec()),MetadataField::Opaque{bytes:native_key,interpretation:"Parent CNID:u32 BE, byte-name length:u8 and exact native bytes; script encoding unspecified".into()})],
                native_flags:MetadataField::Known(copied(&b[2..if node.directory{4}else{3}])?),symlink_target:MetadataField::Absent,reparse_data:MetadataField::Absent})
        })
    }
    pub(crate) fn alternate(&self, r: &Resources) -> Result<[u8; 512]> {
        let mut b = [0; 512];
        read(
            self.inner.source.as_ref(),
            self.inner.geometry.bytes - 1024,
            &mut b,
            r,
        )?;
        Ok(b)
    }
    pub(crate) fn header(&self) -> &[u8; 512] {
        &self.inner.header
    }
}
/// Deferred positional native fork access retaining the volume and all resource leases.
pub struct HfsFile {
    volume: HfsVolume,
    identity: ObjectId,
    file: ExtentFile,
    _lease: Reservation,
}
impl FileRead for HfsFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, at: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        self.volume.revalidate(&self.identity, r)?;
        if at >= self.file.len() || b.is_empty() {
            return Ok(0);
        }
        let n = self
            .file
            .read_at(at, b)
            .map_err(|e| Error::io("HFS deferred fork", e))?;
        self.volume.revalidate(&self.identity, r)?;
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        f: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.volume.revalidate(&self.identity, r)?;
        for e in self.file.extents() {
            r.cancellation.check()?;
            f(LogicalExtent {
                offset: e.offset,
                length: e.length,
                kind: ExtentKind::Data,
            })?;
        }
        Ok(())
    }
}
