//! Deterministic classic Linux ext2 authoring, exclusively for unpublished new images.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
};
use crate::{
    fs_core::{Error, ErrorKind, FileRead, ObjectId, Reservation, Resources, Result},
    storage::Storage,
};
use sha2::{Digest, Sha256};
/// Deferred caller-stabilized logical bytes. Sparse streams are materialized.
#[derive(Clone)]
pub enum ExtBuildSource {
    /// Positional source.
    ReadAt(Arc<dyn ReadAt>),
    /// Indexed stream with its engine's logical zero semantics.
    File(Arc<dyn FileRead>),
}
impl ExtBuildSource {
    fn len(&self) -> u64 {
        match self {
            Self::ReadAt(s) => s.len(),
            Self::File(s) => s.len(),
        }
    }
    fn read(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        match self {
            Self::ReadAt(s) => s
                .read_exact_at(at, out)
                .map_err(|e| Error::io("ext2 deferred source", e)),
            Self::File(s) => {
                let mut done = 0;
                while done < out.len() {
                    r.cancellation.check()?;
                    let n = s.read_at(at + done as u64, &mut out[done..], r)?;
                    if n == 0 || n > out.len() - done {
                        return Err(Error::io(
                            "ext2 short source",
                            io::ErrorKind::UnexpectedEof.into(),
                        ));
                    }
                    done += n;
                }
                Ok(())
            }
        }
    }
}
/// Unique object definition. Directory aliases and special objects are unsupported.
pub struct ExtBuildObject {
    /// Scoped stable identity, defined exactly once.
    pub identity: ObjectId,
    /// None denotes a directory; Some denotes a regular file.
    pub source: Option<ExtBuildSource>,
}
/// Namespace link. Several links to one regular object preserve hardlinks.
pub struct ExtBuildLink {
    /// Previously defined object identity.
    pub object: ObjectId,
    /// Directory identity; None means the implicit root inode 2.
    pub parent: Option<ObjectId>,
    /// Exact native bytes, excluding NUL, slash, dot and dot-dot.
    pub name: Vec<u8>,
}
/// Fixed classic revision-1 Linux geometry, with filetype and sparse-super only.
#[derive(Clone, Copy, Debug)]
pub struct ExtBuildOptions {
    /// 1024, 2048 or 4096 bytes.
    pub block_size: u32,
    /// Multiple of eight, no greater than block_size*8.
    pub blocks_per_group: u32,
    /// Deterministic native UUID.
    pub uuid: [u8; 16],
}
/// Explicit transformation of all source metadata to these caller-selected defaults.
#[derive(Clone, Copy, Debug)]
pub struct ExtBuildMetadata {
    /// Regular permission bits, at most 0777.
    pub file_permissions: u16,
    /// Directory permission bits, at most 0777.
    pub directory_permissions: u16,
    /// Linux owner, including its high 16 bits.
    pub uid: u32,
    /// Linux group, including its high 16 bits.
    pub gid: u32,
    /// Native seconds for access, modification and change time.
    pub timestamp: u32,
}
/// Independent planning caps, checked before target mutation.
#[derive(Clone, Copy, Debug)]
pub struct ExtBuildLimits {
    /// Maximum unique input objects.
    pub objects: usize,
    /// Maximum namespace links.
    pub links: usize,
    /// Maximum retained native-name bytes, including identity keys.
    pub name_bytes: usize,
    /// Maximum volume blocks.
    pub blocks: u32,
    /// Conservative planning work bound including inode bits, sorting and parent walks.
    pub work: u64,
    /// Maximum parent depth.
    pub depth: usize,
}
struct Node {
    source: Option<ExtBuildSource>,
    source_identity: Option<ObjectId>,
    length: u64,
    inode: u32,
    parent: usize,
    links: u16,
    children: Vec<(Vec<u8>, usize)>,
}
/// Complete preflight; payloads remain deferred and the metadata lease remains retained.
pub struct ExtBuildPlan {
    length: u64,
    bs: u32,
    nodes: Vec<Node>,
    metadata: BlockMap<Vec<u8>>,
    payload: BlockMap<(usize, u64)>,
    _lease: Reservation,
}
/// Flushed and fully regenerated/read-back image; publication remains the caller's task.
#[derive(Debug)]
pub struct ExtBuildReport {
    /// Entire initialized image length.
    pub verified_bytes: u64,
    /// Whole-image SHA-256.
    pub sha256: [u8; 32],
    /// Unique regular objects, counting hardlinked objects once.
    pub files: usize,
    /// Logical sparse holes are materialized; original allocation is not preserved.
    pub materialized_sparse: bool,
}
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
fn cap(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn zero(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| cap("ext2 allocation"))?;
    v.resize(n, 0);
    Ok(v)
}
fn w(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes())
}
fn d(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes())
}
fn backup(g: u32) -> bool {
    g <= 1
        || [3, 5, 7].iter().any(|&n| {
            let mut x = g;
            while x > 1 && x.is_multiple_of(n) {
                x /= n;
            }
            x == 1
        })
}
struct Alloc {
    used: Vec<bool>,
    next: u32,
    allocated: usize,
}
struct BlockMap<T> {
    entries: Vec<Option<T>>,
}
impl<T> BlockMap<T> {
    fn new(blocks: u32) -> Result<Self> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(blocks as usize)
            .map_err(|_| cap("ext2 indexed block map"))?;
        entries.resize_with(blocks as usize, || None);
        Ok(Self { entries })
    }
    fn insert(&mut self, block: u32, value: T) {
        self.entries[block as usize] = Some(value);
    }
    fn get(&self, block: &u32) -> Option<&T> {
        self.entries[*block as usize].as_ref()
    }
    fn get_mut(&mut self, block: &u32) -> Option<&mut T> {
        self.entries[*block as usize].as_mut()
    }
}
impl Alloc {
    fn take(&mut self, r: &Resources) -> Result<u32> {
        r.cancellation.check()?;
        while (self.next as usize) < self.used.len() && self.used[self.next as usize] {
            self.next += 1;
        }
        if self.next as usize == self.used.len() {
            return Err(invalid("ext2 insufficient space"));
        }
        let b = self.next;
        self.used[b as usize] = true;
        self.allocated += 1;
        self.next += 1;
        Ok(b)
    }
}
fn indirect(
    level: u32,
    data: &[u32],
    bs: u32,
    a: &mut Alloc,
    m: &mut BlockMap<Vec<u8>>,
    r: &Resources,
) -> Result<u32> {
    let block = a.take(r)?;
    let mut bytes = zero(bs as usize)?;
    let width = bs as usize / 4;
    let span = width.pow(level - 1);
    for (i, chunk) in data.chunks(span).enumerate() {
        let p = if level == 1 {
            chunk[0]
        } else {
            indirect(level - 1, chunk, bs, a, m, r)?
        };
        d(&mut bytes, i * 4, p);
    }
    m.insert(block, bytes);
    Ok(block)
}
impl ExtBuildPlan {
    /// Validate the complete namespace, geometry and allocation before any output write.
    pub fn new(
        length: u64,
        o: ExtBuildOptions,
        mut objects: Vec<ExtBuildObject>,
        links: Vec<ExtBuildLink>,
        defaults: ExtBuildMetadata,
        limits: ExtBuildLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let bs = o.block_size;
        if ![1024, 2048, 4096].contains(&bs)
            || o.blocks_per_group < 32
            || !o.blocks_per_group.is_multiple_of(8)
            || o.blocks_per_group > bs * 8
            || !length.is_multiple_of(u64::from(bs))
            || defaults.file_permissions > 0o777
            || defaults.directory_permissions > 0o777
        {
            return Err(invalid("ext2 geometry or metadata defaults"));
        }
        let blocks = u32::try_from(length / u64::from(bs))
            .map_err(|_| invalid("ext2 block count overflow"))?;
        let first = u32::from(bs == 1024);
        if blocks > u32::MAX - o.blocks_per_group - 1 {
            return Err(invalid("ext2 geometry exceeds checked group-end profile"));
        }
        if blocks <= first
            || blocks > limits.blocks
            || objects.len() > limits.objects
            || links.len() > limits.links
        {
            return Err(cap("ext2 inventory/block limit"));
        }
        let groups = (blocks - first).div_ceil(o.blocks_per_group);
        if groups > u16::MAX as u32 {
            return Err(invalid(
                "ext2 group count exceeds supported backup encoding",
            ));
        }
        let total_names = links
            .iter()
            .try_fold(0usize, |n, l| {
                n.checked_add(l.name.capacity())
                    .and_then(|n| n.checked_add(l.object.native.capacity()))
                    .and_then(|n| {
                        n.checked_add(l.parent.as_ref().map_or(0, |p| p.native.capacity()))
                    })
            })
            .and_then(|n| {
                objects.iter().try_fold(n, |n, o| {
                    n.checked_add(o.identity.native.capacity()).and_then(|n| {
                        n.checked_add(match &o.source {
                            Some(ExtBuildSource::File(f)) => f.identity().native.len(),
                            _ => 0,
                        })
                    })
                })
            })
            .ok_or_else(|| cap("ext2 name count overflow"))?;
        if total_names > limits.name_bytes {
            return Err(cap("ext2 name limit"));
        }
        let required = objects
            .len()
            .checked_add(10)
            .ok_or_else(|| cap("ext2 inode count"))?;
        let quantum = bs / 128;
        let needed = u32::try_from(required.div_ceil(groups as usize))
            .map_err(|_| cap("ext2 inode count"))?
            .max(quantum);
        if needed > bs * 8 {
            return Err(invalid("ext2 insufficient inode capacity"));
        }
        let ipg = needed.div_ceil(quantum) * quantum;
        if ipg > bs * 8 {
            return Err(invalid("ext2 insufficient inode capacity"));
        }
        let inodes = ipg
            .checked_mul(groups)
            .ok_or_else(|| invalid("ext2 inode count overflow"))?;
        let desc_blocks = (u64::from(groups) * 32).div_ceil(u64::from(bs)) as u32;
        let table_blocks = ipg * 128 / bs;
        let work = u128::from(blocks) * 4
            + u128::from(groups) * u128::from(ipg)
            + u128::from(groups) * u128::from(groups)
            + objects.len() as u128 * (limits.depth.min(objects.len() + 1) as u128 + 64)
            + links.len() as u128 * 64
            + total_names as u128 * 64;
        if work > u128::from(limits.work) {
            return Err(cap("ext2 planning work limit"));
        }
        let charge = u128::from(blocks) * 128
            + (objects.len() as u128 + 1) * (u128::from(bs) + 4096)
            + total_names as u128 * 32
            + u128::from(groups)
                * (u128::from(ipg) * 128 + u128::from(bs) * 4 + u128::from(groups) * 32);
        let lease = r
            .memory
            .reserve(u64::try_from(charge).map_err(|_| cap("ext2 planning memory overflow"))?)?;
        objects.sort_unstable_by(|a, b| {
            (a.identity.source, a.identity.generation, &a.identity.native).cmp(&(
                b.identity.source,
                b.identity.generation,
                &b.identity.native,
            ))
        });
        let mut ids = HashMap::new();
        ids.try_reserve(objects.len())
            .map_err(|_| cap("ext2 identity map"))?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(objects.len() + 1)
            .map_err(|_| cap("ext2 node map"))?;
        nodes.push(Node {
            source: None,
            source_identity: None,
            length: 0,
            inode: 2,
            parent: 0,
            links: 2,
            children: Vec::new(),
        });
        for (i, obj) in objects.into_iter().enumerate() {
            if ids.insert(obj.identity, i + 1).is_some() {
                return Err(invalid("ext2 duplicate object definition"));
            }
            let length = obj.source.as_ref().map_or(0, ExtBuildSource::len);
            if length > i32::MAX as u64 {
                return Err(invalid(
                    "ext2 builder file size exceeds signed-32-bit profile",
                ));
            }
            let is_directory = obj.source.is_none();
            let source_identity = if let Some(ExtBuildSource::File(file)) = &obj.source {
                let identity = file.identity();
                let mut native = zero(identity.native.len())?;
                native.copy_from_slice(&identity.native);
                Some(ObjectId {
                    source: identity.source,
                    generation: identity.generation,
                    native,
                })
            } else {
                None
            };
            nodes.push(Node {
                source: obj.source,
                source_identity,
                length,
                inode: i as u32 + 11,
                parent: usize::MAX,
                links: if is_directory { 2 } else { 0 },
                children: Vec::new(),
            });
        }
        for l in links {
            r.cancellation.check()?;
            if l.name.is_empty()
                || l.name.len() > 255
                || l.name == b"."
                || l.name == b".."
                || l.name.contains(&0)
                || l.name.contains(&b'/')
            {
                return Err(invalid("ext2 invalid native name"));
            }
            let &child = ids
                .get(&l.object)
                .ok_or_else(|| invalid("ext2 undefined object"))?;
            let parent = match l.parent {
                None => 0,
                Some(id) => *ids
                    .get(&id)
                    .ok_or_else(|| invalid("ext2 undefined parent"))?,
            };
            if nodes[parent].source.is_some() {
                return Err(invalid("ext2 regular parent"));
            }
            if nodes[child].source.is_none() {
                if nodes[child].parent != usize::MAX {
                    return Err(invalid("ext2 directory aliases unsupported"));
                }
                nodes[child].parent = parent;
                nodes[parent].links = nodes[parent]
                    .links
                    .checked_add(1)
                    .filter(|n| *n <= 32000)
                    .ok_or_else(|| invalid("ext2 directory link count"))?;
            } else {
                nodes[child].links = nodes[child]
                    .links
                    .checked_add(1)
                    .filter(|n| *n <= 32000)
                    .ok_or_else(|| invalid("ext2 file link count"))?;
            }
            nodes[parent]
                .children
                .try_reserve(1)
                .map_err(|_| cap("ext2 directory inventory"))?;
            nodes[parent].children.push((l.name, child));
        }
        for i in 0..nodes.len() {
            nodes[i].children.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            if nodes[i].children.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(invalid("ext2 duplicate native directory name"));
            }
            if i != 0 && nodes[i].links == 0 {
                return Err(invalid("ext2 unlinked object"));
            }
            if nodes[i].source.is_none() {
                let mut p = i;
                let mut depth = 0;
                while p != 0 {
                    if depth >= limits.depth || depth >= nodes.len() {
                        return Err(cap("ext2 parent cycle/depth"));
                    }
                    p = nodes[p].parent;
                    if p == usize::MAX {
                        return Err(invalid("ext2 disconnected directory"));
                    }
                    depth += 1;
                }
            }
        }
        let mut used = Vec::new();
        used.try_reserve_exact(blocks as usize)
            .map_err(|_| cap("ext2 allocation map"))?;
        used.resize(blocks as usize, false);
        if first != 0 {
            used[0] = true;
        }
        let mut descriptor = zero(groups as usize * 32)?;
        let mut metadata = BlockMap::new(blocks)?;
        for g in 0..groups {
            r.cancellation.check()?;
            let start = first + g * o.blocks_per_group;
            let reserved = if backup(g) { 1 + desc_blocks } else { 0 };
            let bm = start + reserved;
            let ib = bm + 1;
            let it = ib + 1;
            let end = it + table_blocks;
            if end > blocks.min(start + o.blocks_per_group) {
                return Err(invalid("ext2 final group lacks metadata space"));
            }
            for b in start..end {
                used[b as usize] = true;
            }
            let at = g as usize * 32;
            d(&mut descriptor, at, bm);
            d(&mut descriptor, at + 4, ib);
            d(&mut descriptor, at + 8, it);
            for b in it..end {
                metadata.insert(b, zero(bs as usize)?);
            }
        }
        let allocated = used.iter().filter(|&&u| u).count();
        let mut a = Alloc {
            used,
            next: first,
            allocated,
        };
        let mut payload = BlockMap::new(blocks)?;
        for i in 0..nodes.len() {
            r.cancellation.check()?;
            let mut directory = Vec::new();
            if nodes[i].source.is_none() {
                directory
                    .try_reserve_exact(nodes[i].children.len() + 2)
                    .map_err(|_| cap("ext2 directory block inventory"))?;
                let mut records = Vec::new();
                records
                    .try_reserve_exact(nodes[i].children.len() + 2)
                    .map_err(|_| cap("ext2 records"))?;
                records.push((b".".as_slice(), i));
                records.push((b"..".as_slice(), nodes[i].parent));
                for (name, n) in &nodes[i].children {
                    records.push((name.as_slice(), *n));
                }
                let mut bytes = zero(bs as usize)?;
                let mut pos = 0;
                let mut previous = 0;
                for (name, n) in records {
                    let size = (8 + name.len()).next_multiple_of(4);
                    if pos + size > bs as usize {
                        w(&mut bytes, previous + 4, (bs as usize - previous) as u16);
                        directory.push(bytes);
                        bytes = zero(bs as usize)?;
                        pos = 0;
                    }
                    d(&mut bytes, pos, nodes[n].inode);
                    w(&mut bytes, pos + 4, size as u16);
                    bytes[pos + 6] = name.len() as u8;
                    bytes[pos + 7] = if nodes[n].source.is_none() { 2 } else { 1 };
                    bytes[pos + 8..pos + 8 + name.len()].copy_from_slice(name);
                    previous = pos;
                    pos += size;
                }
                w(&mut bytes, previous + 4, (bs as usize - previous) as u16);
                directory.push(bytes);
                nodes[i].length = directory.len() as u64 * u64::from(bs);
                if nodes[i].length > i32::MAX as u64 {
                    return Err(invalid("ext2 directory size exceeds signed-32-bit profile"));
                }
            }
            let count = nodes[i].length.div_ceil(u64::from(bs)) as usize;
            if count > blocks as usize {
                return Err(invalid("ext2 file exceeds whole-volume capacity"));
            }
            let mut data = Vec::new();
            data.try_reserve_exact(count)
                .map_err(|_| cap("ext2 file block map"))?;
            for n in 0..count {
                let b = a.take(r)?;
                data.push(b);
                if nodes[i].source.is_some() {
                    payload.insert(b, (i, n as u64 * u64::from(bs)));
                }
            }
            for (b, bytes) in data.iter().zip(directory) {
                metadata.insert(*b, bytes);
            }
            let before = a.allocated;
            let mut pointers = [0u32; 15];
            for (p, b) in pointers[..12].iter_mut().zip(&data) {
                *p = *b;
            }
            let width = bs as usize / 4;
            let mut done = data.len().min(12);
            for level in 1..=3 {
                if done == data.len() {
                    break;
                }
                let end = data.len().min(done + width.pow(level));
                pointers[11 + level as usize] =
                    indirect(level, &data[done..end], bs, &mut a, &mut metadata, r)?;
                done = end;
            }
            if done != data.len() {
                return Err(invalid("ext2 indirect capacity"));
            }
            let indirect_count = a.allocated - before;
            let inode = nodes[i].inode;
            let group = (inode - 1) / ipg;
            let slot = (inode - 1) % ipg;
            let desc = group as usize * 32;
            let it = u32::from_le_bytes(descriptor[desc + 8..desc + 12].try_into().unwrap());
            let block = it + slot * 128 / bs;
            let at = (slot * 128 % bs) as usize;
            let raw = &mut metadata.get_mut(&block).unwrap()[at..at + 128];
            let dir = nodes[i].source.is_none();
            w(
                raw,
                0,
                if dir {
                    0x4000 | defaults.directory_permissions
                } else {
                    0x8000 | defaults.file_permissions
                },
            );
            w(raw, 2, defaults.uid as u16);
            d(raw, 4, nodes[i].length as u32);
            for at in [8, 12, 16] {
                d(raw, at, defaults.timestamp);
            }
            w(raw, 24, defaults.gid as u16);
            w(raw, 26, nodes[i].links);
            d(
                raw,
                28,
                u32::try_from((count + indirect_count) as u64 * u64::from(bs) / 512)
                    .map_err(|_| invalid("ext2 sector count"))?,
            );
            for (n, p) in pointers.iter().enumerate() {
                d(raw, 40 + n * 4, *p);
            }
            w(raw, 120, (defaults.uid >> 16) as u16);
            w(raw, 122, (defaults.gid >> 16) as u16);
        }
        let mut allocated_inodes = HashSet::new();
        allocated_inodes
            .try_reserve(nodes.len() + 10)
            .map_err(|_| cap("ext2 inode inventory"))?;
        allocated_inodes.extend(nodes.iter().map(|n| n.inode).chain(1..=10));
        let mut directory_counts = zero(groups as usize * 2)?;
        for node in &nodes {
            if node.source.is_none() {
                let offset = ((node.inode - 1) / ipg) as usize * 2;
                let count =
                    u16::from_le_bytes(directory_counts[offset..offset + 2].try_into().unwrap());
                w(
                    &mut directory_counts,
                    offset,
                    count
                        .checked_add(1)
                        .ok_or_else(|| invalid("ext2 directory count"))?,
                );
            }
        }
        let mut free_blocks = 0;
        let mut free_inodes = 0;
        for g in 0..groups {
            let start = first + g * o.blocks_per_group;
            let end = blocks.min(start + o.blocks_per_group);
            let at = g as usize * 32;
            let mut bitmap = zero(bs as usize)?;
            bitmap.fill(255);
            let mut fb = 0u16;
            for b in start..end {
                if !a.used[b as usize] {
                    let bit = (b - start) as usize;
                    bitmap[bit / 8] &= !(1 << (bit % 8));
                    fb += 1;
                }
            }
            let mut ibitmap = zero(bs as usize)?;
            ibitmap.fill(255);
            let mut fi = 0u16;
            for slot in 0..ipg {
                if !allocated_inodes.contains(&(g * ipg + slot + 1)) {
                    ibitmap[slot as usize / 8] &= !(1 << (slot % 8));
                    fi += 1;
                }
            }
            w(&mut descriptor, at + 12, fb);
            w(&mut descriptor, at + 14, fi);
            descriptor[at + 16..at + 18]
                .copy_from_slice(&directory_counts[g as usize * 2..g as usize * 2 + 2]);
            free_blocks += u32::from(fb);
            free_inodes += u32::from(fi);
            let bm = u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
            metadata.insert(bm, bitmap);
            metadata.insert(bm + 1, ibitmap);
        }
        let mut sb = zero(1024)?;
        d(&mut sb, 0, inodes);
        d(&mut sb, 4, blocks);
        d(&mut sb, 12, free_blocks);
        d(&mut sb, 16, free_inodes);
        d(&mut sb, 20, first);
        let log = bs.trailing_zeros() - 10;
        d(&mut sb, 24, log);
        d(&mut sb, 28, log);
        d(&mut sb, 32, o.blocks_per_group);
        d(&mut sb, 36, o.blocks_per_group);
        d(&mut sb, 40, ipg);
        d(&mut sb, 48, defaults.timestamp);
        w(&mut sb, 54, u16::MAX);
        w(&mut sb, 56, 0xef53);
        w(&mut sb, 58, 1);
        w(&mut sb, 60, 1);
        d(&mut sb, 64, defaults.timestamp);
        d(&mut sb, 76, 1);
        d(&mut sb, 84, 11);
        w(&mut sb, 88, 128);
        d(&mut sb, 96, 2);
        d(&mut sb, 100, 1);
        sb[104..120].copy_from_slice(&o.uuid);
        for g in 0..groups {
            if !backup(g) {
                continue;
            }
            let start = first + g * o.blocks_per_group;
            let mut block = zero(bs as usize)?;
            w(&mut sb, 90, g as u16);
            let offset = if g == 0 && bs > 1024 { 1024 } else { 0 };
            block[offset..offset + 1024].copy_from_slice(&sb);
            metadata.insert(start, block);
            for n in 0..desc_blocks {
                let mut block = zero(bs as usize)?;
                let offset = n as usize * bs as usize;
                let count = (descriptor.len() - offset).min(bs as usize);
                block[..count].copy_from_slice(&descriptor[offset..offset + count]);
                metadata.insert(start + 1 + n, block);
            }
        }
        Ok(Self {
            length,
            bs,
            nodes,
            metadata,
            payload,
            _lease: lease,
        })
    }
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self
            .nodes
            .iter()
            .any(|n| n.source.as_ref().is_some_and(|s| s.len() != n.length))
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 source length changed",
            ));
        }
        if self
            .nodes
            .iter()
            .any(|n| match (&n.source, &n.source_identity) {
                (Some(ExtBuildSource::File(file)), Some(identity)) => file.identity() != identity,
                _ => false,
            })
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 indexed source identity changed",
            ));
        }
        Ok(())
    }
    fn render(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        out.fill(0);
        let mut done = 0;
        while done < out.len() {
            r.cancellation.check()?;
            let pos = at + done as u64;
            let block = (pos / u64::from(self.bs)) as u32;
            let within = (pos % u64::from(self.bs)) as usize;
            let count = (out.len() - done).min(self.bs as usize - within);
            if let Some(b) = self.metadata.get(&block) {
                out[done..done + count].copy_from_slice(&b[within..within + count]);
            } else if let Some(&(node, off)) = self.payload.get(&block) {
                let n = &self.nodes[node];
                let offset = off + within as u64;
                let bytes = n.length.saturating_sub(offset).min(count as u64) as usize;
                if bytes != 0 {
                    n.source
                        .as_ref()
                        .unwrap()
                        .read(offset, &mut out[done..done + bytes], r)?;
                }
            }
            done += count;
        }
        Ok(())
    }
    /// Initialize every byte, flush once, then regenerate and compare every staged byte.
    pub fn emit(
        &self,
        storage: &mut (impl Storage + ?Sized),
        r: &Resources,
    ) -> Result<ExtBuildReport> {
        self.check(r)?;
        if storage
            .len()
            .map_err(|e| Error::io("ext2 target length", e))?
            != self.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 target length changed",
            ));
        }
        let _lease = r.memory.reserve(131072)?;
        let mut expected = zero(65536)?;
        let mut actual = zero(65536)?;
        let mut mutated = false;
        let result = (|| {
            let mut hash = Sha256::new();
            let mut at = 0;
            while at < self.length {
                let n = (self.length - at).min(65536) as usize;
                self.render(at, &mut expected[..n], r)?;
                hash.update(&expected[..n]);
                crate::fs_build_io::write_all(
                    storage,
                    at,
                    &expected[..n],
                    r,
                    &mut mutated,
                    "ext2 staged write",
                )?;
                at += n as u64;
            }
            crate::fs_build_io::flush(storage, r, "ext2 staged flush")?;
            let digest: [u8; 32] = hash.finalize().into();
            let mut verified = Sha256::new();
            at = 0;
            while at < self.length {
                let n = (self.length - at).min(65536) as usize;
                self.render(at, &mut expected[..n], r)?;
                crate::fs_build_io::verify(
                    storage,
                    at,
                    &expected[..n],
                    &mut actual[..n],
                    r,
                    "ext2 staged verification",
                    "ext2 readback mismatch",
                )?;
                verified.update(&actual[..n]);
                at += n as u64;
            }
            self.check(r)?;
            if storage
                .len()
                .map_err(|e| Error::io("ext2 final target length", e))?
                != self.length
                || <[u8; 32]>::from(verified.finalize()) != digest
            {
                return Err(Error::new(ErrorKind::StalePlan, "ext2 image changed"));
            }
            Ok(ExtBuildReport {
                verified_bytes: self.length,
                sha256: digest,
                files: self.nodes.iter().filter(|n| n.source.is_some()).count(),
                materialized_sparse: true,
            })
        })();
        result.map_err(|error| {
            if mutated && error.kind != ErrorKind::UncertainDurability {
                Error {
                    kind: ErrorKind::InterruptedWrite,
                    context: "ext2 staged emission interrupted".into(),
                    source: Some(io::Error::other(error)),
                }
            } else {
                error
            }
        })
    }
}
