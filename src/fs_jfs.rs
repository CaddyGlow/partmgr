//! Strict immutable Linux JFS baseline, with native inode maps and bounded extent/directory trees.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use crate::{
    fs_core::*,
    fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent},
};
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
pub(crate) fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(crate) fn le16(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
pub(crate) fn le32(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
pub(crate) fn le64(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
pub(crate) fn vector<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("JFS allocation"))?;
    Ok(v)
}
fn copied<T: Copy>(b: &[T]) -> Result<Vec<T>> {
    let mut v = vector(b.len())?;
    v.extend_from_slice(b);
    Ok(v)
}
/// Independent metadata allocation/traversal ceilings.
#[derive(Clone, Copy, Debug)]
pub struct JfsReadLimits {
    /// Maximum selected physical blocks.
    pub blocks: u64,
    /// Maximum live fileset inodes.
    pub inodes: usize,
    /// Maximum directory entries across all directories.
    pub entries: usize,
    /// Maximum external extent/directory pages.
    pub pages: usize,
    /// Maximum indexed extent descriptors, including metadata.
    pub extents: usize,
    /// Maximum metadata bytes/records/block visits, charged before work.
    pub work: u64,
}
/// Checked native geometry; the allocation map excludes separately reserved log/fsck tails.
#[derive(Clone, Debug)]
pub struct JfsGeometry {
    pub(crate) blocks: u64,
    pub(crate) mapped: u64,
    pub(crate) free: u64,
    pub(crate) flags: u32,
}
impl JfsGeometry {
    /// Native family.
    pub fn family(&self) -> Family {
        Family::Jfs
    }
    /// Supported native allocation block size.
    pub fn block_size(&self) -> u32 {
        4096
    }
    /// Selected physical volume size.
    pub fn volume_bytes(&self) -> u64 {
        self.blocks * 4096
    }
    /// Blocks represented by the aggregate bitmap.
    pub fn allocation_blocks(&self) -> u64 {
        self.mapped
    }
    /// Native superblock profile flags.
    pub fn volume_flags(&self) -> u32 {
        self.flags
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Physical {
    pub(crate) start: u64,
    pub(crate) count: u64,
}
fn pxd(b: &[u8], at: usize, blocks: u64) -> Result<Physical> {
    let count = u64::from(le32(b, at) & 0xffffff);
    let start = u64::from(le32(b, at) >> 24) << 32 | u64::from(le32(b, at + 4));
    if start.checked_add(count).is_none_or(|v| v > blocks) || count == 0 && start != 0 {
        return Err(bad("JFS physical extent bounds"));
    }
    Ok(Physical { start, count })
}
#[derive(Clone)]
pub(crate) struct Run {
    pub(crate) logical: u64,
    pub(crate) physical: Physical,
    pub(crate) unwritten: bool,
}
#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) name: Vec<u16>,
    pub(crate) ino: u32,
    pub(crate) index: u32,
    pub(crate) page: u64,
    pub(crate) slot: u8,
}
pub(crate) struct Inode {
    pub(crate) raw: Vec<u8>,
    pub(crate) ino: u32,
    pub(crate) generation: u32,
    pub(crate) length: u64,
    pub(crate) directory: bool,
    pub(crate) runs: Vec<Run>,
    pub(crate) pages: Vec<Physical>,
    pub(crate) entries: Vec<Entry>,
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
                "JFS source length changed",
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

// Metadata decoding is deliberately independent of immutable ReadAt ownership.
pub(crate) trait DecodeRead {
    fn length(&self) -> Result<u64>;
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()>;
}
impl DecodeRead for Source {
    fn length(&self) -> Result<u64> {
        self.stable()
            .map_err(|e| Error::io("JFS source stability", e))
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        ReadAt::read_exact_at(self, at, out).map_err(|e| Error::io("JFS metadata", e))
    }
}
struct MetadataMap<'a> {
    source: &'a dyn DecodeRead,
    length: u64,
    runs: &'a [Run],
}
struct Work {
    limits: JfsReadLimits,
    work: u64,
    pages: usize,
    extents: usize,
    entries: usize,
}
impl Work {
    fn tick(&mut self, n: u64, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("JFS metadata work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("JFS metadata work ceiling"));
        }
        Ok(())
    }
    fn page(&mut self) -> Result<()> {
        if self.pages == self.limits.pages {
            return Err(budget("JFS page ceiling"));
        }
        self.pages += 1;
        Ok(())
    }
    fn extent(&mut self) -> Result<()> {
        if self.extents == self.limits.extents {
            return Err(budget("JFS extent ceiling"));
        }
        self.extents += 1;
        Ok(())
    }
}
fn read(source: &dyn DecodeRead, at: u64, b: &mut [u8], w: &mut Work, r: &Resources) -> Result<()> {
    w.tick(b.len() as u64, r)?;
    source.exact(at, b)?;
    r.cancellation.check()
}
fn xtree(
    root: &[u8],
    source: &dyn DecodeRead,
    blocks: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<(Vec<Run>, Vec<Physical>)> {
    struct Walker<'a> {
        source: &'a dyn DecodeRead,
        blocks: u64,
        w: &'a mut Work,
        r: &'a Resources,
        seen: BTreeSet<u64>,
        levels: BTreeMap<usize, (u64, u64, u64)>,
        runs: Vec<Run>,
        pages: Vec<Physical>,
    }
    impl Walker<'_> {
        fn visit(&mut self, b: &[u8], address: Option<u64>, depth: usize) -> Result<u64> {
            if depth > 8 {
                return Err(bad("JFS extent tree depth"));
            }
            let flag = b[16];
            let leaf = flag & 2 != 0;
            let max = usize::from(le16(b, 20));
            let next = usize::from(le16(b, 18));
            if flag & !0xb7 != 0
                || flag & 6 != if leaf { 2 } else { 4 }
                || flag & 1 != if address.is_none() { 1 } else { 0 }
                || next < 2
                || next > max
                || max * 16 > b.len()
                || address.is_some() && max != 256
                || address.is_none() && ![6, 10, 18].contains(&max)
            {
                return Err(bad("JFS extent node flags/slots"));
            }
            if address.is_none() && (le64(b, 0) != 0 || le64(b, 8) != 0) {
                return Err(bad("JFS inline extent siblings"));
            }
            if let Some(at) = address
                && pxd(b, 24, self.blocks)?
                    != (Physical {
                        start: at,
                        count: 1,
                    })
            {
                return Err(bad("JFS extent self descriptor"));
            }
            let mut minimum = None;
            let mut previous = None;
            let mut previous_end = 0;
            for index in 2..next {
                self.w.tick(1, self.r)?;
                let at = index * 16;
                let logical = (u64::from(b[at + 3]) << 32) | u64::from(le32(b, at + 4));
                let physical = pxd(b, at + 8, self.blocks)?;
                if physical.count == 0
                    || previous.is_some_and(|v| v >= logical)
                    || leaf && logical < previous_end
                {
                    return Err(bad("JFS extent keys/count/order"));
                }
                if minimum.is_none() {
                    minimum = Some(logical);
                }
                previous = Some(logical);
                if b[at] & !8 != 0 {
                    return Err(unsupported("JFS transient/compressed/COW extent flags"));
                }
                if leaf {
                    self.w.extent()?;
                    previous_end = logical
                        .checked_add(physical.count)
                        .ok_or_else(|| bad("JFS logical extent overflow"))?;
                    self.runs
                        .try_reserve(1)
                        .map_err(|_| budget("JFS run allocation"))?;
                    self.runs.push(Run {
                        logical,
                        physical,
                        unwritten: b[at] & 8 != 0,
                    });
                } else {
                    if b[at] != 0 || physical.count != 1 || !self.seen.insert(physical.start) {
                        return Err(bad("JFS extent child descriptor/cycle"));
                    }
                    self.w.page()?;
                    self.w.extent()?;
                    self.pages
                        .try_reserve(1)
                        .map_err(|_| budget("JFS page allocation"))?;
                    self.pages.push(physical);
                    let mut child = [0; 4096];
                    read(
                        self.source,
                        physical.start * 4096,
                        &mut child,
                        self.w,
                        self.r,
                    )?;
                    let lower = self.visit(&child, Some(physical.start), depth + 1)?;
                    if lower != logical {
                        return Err(bad("JFS extent child lower key"));
                    }
                }
            }
            if !leaf && next == 2 {
                return Err(bad("JFS empty extent index"));
            }
            if let Some(at) = address {
                let first = minimum.ok_or_else(|| bad("JFS empty external extent node"))?;
                if let Some((old, fwd, last)) = self.levels.get(&depth) {
                    if *fwd != at || le64(b, 8) != *old || *last >= first {
                        return Err(bad("JFS extent sibling order"));
                    }
                } else if le64(b, 8) != 0 {
                    return Err(bad("JFS extent left sibling"));
                }
                self.levels
                    .insert(depth, (at, le64(b, 0), previous.unwrap()));
            }
            Ok(minimum.unwrap_or(0))
        }
    }
    let mut walk = Walker {
        source,
        blocks,
        w,
        r,
        seen: BTreeSet::new(),
        levels: BTreeMap::new(),
        runs: vector(0)?,
        pages: vector(0)?,
    };
    walk.visit(root, None, 0)?;
    if walk.levels.values().any(|(_, n, _)| *n != 0) {
        return Err(bad("JFS extent terminal sibling"));
    }
    for pair in walk.runs.windows(2) {
        if pair[0].logical + pair[0].physical.count > pair[1].logical {
            return Err(bad("JFS overlapping extent leaves"));
        }
    }
    Ok((walk.runs, walk.pages))
}
fn mapping(
    source: Arc<dyn ReadAt>,
    length: u64,
    runs: &[Run],
    maximum: usize,
) -> Result<ExtentFile> {
    let mut extents = vector(
        runs.len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| budget("JFS mapping count"))?,
    )?;
    let mut offset = 0;
    for run in runs {
        let start = run
            .logical
            .checked_mul(4096)
            .ok_or_else(|| bad("JFS logical byte overflow"))?;
        if start >= length {
            break;
        }
        if start > offset {
            extents.push(FileExtent {
                offset,
                length: start - offset,
                kind: MapKind::Hole,
            });
        }
        let end = start
            .checked_add(run.physical.count * 4096)
            .ok_or_else(|| bad("JFS logical extent bytes"))?
            .min(length);
        extents.push(FileExtent {
            offset: start,
            length: end - start,
            kind: if run.unwritten {
                MapKind::Unwritten
            } else {
                MapKind::Data(run.physical.start * 4096)
            },
        });
        offset = end;
    }
    if offset < length {
        extents.push(FileExtent {
            offset,
            length: length - offset,
            kind: MapKind::Hole,
        });
    }
    ExtentFile::new(
        source,
        length,
        extents,
        maximum
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| budget("JFS map ceiling"))?,
    )
    .map_err(|e| Error::io("JFS extent map", e))
}
fn mapread(
    file: &MetadataMap<'_>,
    at: u64,
    b: &mut [u8],
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    w.tick(b.len() as u64, r)?;
    let end = at
        .checked_add(b.len() as u64)
        .filter(|end| *end <= file.length)
        .ok_or_else(|| bad("JFS system map bounds"))?;
    let mut cursor = at;
    while cursor < end {
        w.tick(1, r)?;
        let mut selected = None;
        for run in file.runs {
            w.tick(1, r)?;
            if run.logical * 4096 <= cursor && cursor < (run.logical + run.physical.count) * 4096 {
                selected = Some(run);
                break;
            }
        }
        let run = selected.ok_or_else(|| bad("JFS hole in system map"))?;
        if run.unwritten {
            return Err(bad("JFS unwritten system map"));
        }
        let logical = run.logical * 4096;
        let next = end.min((run.logical + run.physical.count) * 4096);
        let offset = (cursor - at) as usize;
        file.source.exact(
            run.physical.start * 4096 + cursor - logical,
            &mut b[offset..offset + (next - cursor) as usize],
        )?;
        cursor = next;
    }
    r.cancellation.check()
}

fn dtree(
    root: &[u8],
    source: &dyn DecodeRead,
    blocks: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<(Vec<Entry>, Vec<Physical>)> {
    struct Walker<'a> {
        source: &'a dyn DecodeRead,
        blocks: u64,
        w: &'a mut Work,
        r: &'a Resources,
        seen: BTreeSet<u64>,
        levels: BTreeMap<usize, (u64, u64, Vec<u16>)>,
        entries: Vec<Entry>,
        pages: Vec<Physical>,
    }
    impl Walker<'_> {
        fn visit(
            &mut self,
            b: &[u8],
            address: Option<u64>,
            depth: usize,
        ) -> Result<(Vec<u16>, Vec<u16>)> {
            if depth > 8 {
                return Err(bad("JFS directory tree depth"));
            }
            let flag = b[16];
            let leaf = flag & 2 != 0;
            let count = usize::from(b[17]);
            let (max, table, table_slots) = if address.is_none() {
                (9, 24, 0)
            } else {
                let max = usize::from(b[20]);
                if ![16, 32, 64, 128].contains(&max) {
                    return Err(bad("JFS directory page size"));
                }
                let table = usize::from(b[21]);
                let slots = max.div_ceil(32);
                if table == 0 || table.checked_add(slots).is_none_or(|n| n > max) {
                    return Err(bad("JFS directory slot table bounds"));
                }
                (max, table * 32, slots)
            };
            if flag & !0xb7 != 0
                || flag & 6 != if leaf { 2 } else { 4 }
                || flag & 1 != if address.is_none() { 1 } else { 0 }
                || count > if address.is_none() { 8 } else { max }
                || max * 32 > b.len()
                || table.checked_add(count).is_none_or(|n| n > max * 32)
            {
                return Err(bad("JFS directory node flags/table"));
            }
            if let Some(at) = address
                && pxd(b, 24, self.blocks)?
                    != (Physical {
                        start: at,
                        count: 1,
                    })
            {
                return Err(bad("JFS directory page self"));
            }
            let mut occupied = [false; 128];
            occupied[0] = true;
            if address.is_some() {
                occupied[table / 32..table / 32 + table_slots].fill(true);
            }
            let mut minimum = None;
            let mut previous: Option<Vec<u16>> = None;
            let mut maximum = None;
            for index in 0..count {
                self.w.tick(1, self.r)?;
                let slot = usize::from(b[table + index]);
                if slot >= max || occupied[slot] {
                    return Err(bad("JFS duplicate/out-of-range directory slot"));
                }
                occupied[slot] = true;
                let head = &b[slot * 32..slot * 32 + 32];
                let (nameat, nextat) = if leaf { (6, 4) } else { (10, 8) };
                let n = usize::from(head[nextat + 1]);
                if n > 255 || leaf && n == 0 {
                    return Err(bad("JFS directory name size"));
                }
                let mut name = vector(n)?;
                let first = n.min(11);
                for i in 0..first {
                    name.push(le16(head, nameat + i * 2));
                }
                let mut next = head[nextat];
                while name.len() < n {
                    let nextslot = usize::from(next);
                    if nextslot >= max || occupied[nextslot] {
                        return Err(bad("JFS directory name chain cycle/bounds"));
                    }
                    occupied[nextslot] = true;
                    let more = &b[nextslot * 32..nextslot * 32 + 32];
                    let remaining = (n - name.len()).min(15);
                    if more[1] != 1 {
                        return Err(bad("JFS directory segment count"));
                    }
                    for i in 0..remaining {
                        name.push(le16(more, 2 + i * 2));
                    }
                    next = more[0];
                }
                if next != 255 || name.iter().any(|u| matches!(*u, 0 | 47)) {
                    return Err(bad("JFS directory name terminator/units"));
                }
                if previous.as_ref().is_some_and(|p| *p >= name) {
                    return Err(bad("JFS directory key order"));
                }
                if !leaf && maximum.as_ref().is_some_and(|last| *last >= name) {
                    return Err(bad("JFS directory separator upper bound"));
                }
                if leaf && minimum.is_none() {
                    minimum = Some(copied(&name)?);
                }
                previous = Some(copied(&name)?);
                if leaf {
                    if self.w.entries == self.w.limits.entries {
                        return Err(budget("JFS directory entry ceiling"));
                    }
                    self.w.entries += 1;
                    self.entries
                        .try_reserve(1)
                        .map_err(|_| budget("JFS entry allocation"))?;
                    self.entries.push(Entry {
                        name: copied(&name)?,
                        ino: le32(head, 0),
                        index: le32(head, 28),
                        page: address.unwrap_or(0),
                        slot: index as u8,
                    });
                    maximum = Some(name);
                } else {
                    let physical = pxd(head, 0, self.blocks)?;
                    if physical.count != 1 || !self.seen.insert(physical.start) {
                        return Err(bad("JFS directory child extent/cycle"));
                    }
                    self.w.page()?;
                    self.w.extent()?;
                    self.pages
                        .try_reserve(1)
                        .map_err(|_| budget("JFS page allocation"))?;
                    self.pages.push(physical);
                    let mut child = [0; 4096];
                    read(
                        self.source,
                        physical.start * 4096,
                        &mut child,
                        self.w,
                        self.r,
                    )?;
                    let (lower, last) = self.visit(&child, Some(physical.start), depth + 1)?;
                    if name > lower {
                        return Err(bad("JFS directory separator lower bound"));
                    }
                    if minimum.is_none() {
                        minimum = Some(lower);
                    }
                    maximum = Some(last);
                }
            }
            if !leaf && count == 0 {
                return Err(bad("JFS empty directory index"));
            }
            let mut free = 0usize;
            let mut next = b[19];
            while next != 255 {
                let slot = usize::from(next);
                if slot >= max || occupied[slot] {
                    return Err(bad("JFS directory free-slot chain"));
                }
                occupied[slot] = true;
                free += 1;
                next = b[slot * 32];
            }
            if free != usize::from(b[18]) || occupied[..max].iter().any(|v| !*v) {
                return Err(bad("JFS directory slot partition/free count"));
            }
            if let Some(at) = address {
                let first = minimum
                    .as_ref()
                    .ok_or_else(|| bad("JFS empty directory external page"))?;
                if let Some((old, fwd, last)) = self.levels.get(&depth) {
                    if *fwd != at || le64(b, 8) != *old || *last >= *first {
                        return Err(bad("JFS directory sibling order"));
                    }
                } else if le64(b, 8) != 0 {
                    return Err(bad("JFS directory first sibling"));
                }
                self.levels
                    .insert(depth, (at, le64(b, 0), copied(maximum.as_ref().unwrap())?));
            }
            Ok((minimum.unwrap_or_default(), maximum.unwrap_or_default()))
        }
    }
    let mut walk = Walker {
        source,
        blocks,
        w,
        r,
        seen: BTreeSet::new(),
        levels: BTreeMap::new(),
        entries: vector(0)?,
        pages: vector(0)?,
    };
    walk.visit(root, None, 0)?;
    if walk.levels.values().any(|(_, n, _)| *n != 0) {
        return Err(bad("JFS directory terminal sibling"));
    }
    for pair in walk.entries.windows(2) {
        if pair[0].name >= pair[1].name {
            return Err(bad("JFS directory cross-leaf order"));
        }
    }
    Ok((walk.entries, walk.pages))
}
// Independently recompute the aligned free-buddy representation and quaternary summaries.
fn summaries(mut leaves: Vec<i8>, minimum: i8) -> Result<Vec<i8>> {
    let count = leaves.len();
    if !count.is_power_of_two() {
        return Err(bad("JFS buddy leaf count"));
    }
    let mut width = 2;
    while width <= count {
        for start in (0..count).step_by(width) {
            let expected = minimum + width.ilog2() as i8 - 1;
            if leaves[start] == expected && leaves[start + width / 2] == expected {
                leaves[start] = expected + 1;
                leaves[start + width / 2] = -1;
            }
        }
        width *= 2;
    }
    let total = (count * 4 - 1) / 3;
    let first = total - count;
    let mut tree = vector(total)?;
    tree.resize(total, -1);
    tree[first..].copy_from_slice(&leaves);
    for i in (0..first).rev() {
        tree[i] = *tree[4 * i + 1..4 * i + 5].iter().max().unwrap();
    }
    Ok(tree)
}
fn word_buddy(word: u32) -> i8 {
    for power in (0..=5).rev() {
        let count = 1usize << power;
        for start in (0..32).step_by(count) {
            let mask = if count == 32 {
                u32::MAX
            } else {
                ((1u32 << count) - 1) << (32 - start - count)
            };
            if word & mask == 0 {
                return power as i8;
            }
        }
    }
    -1
}
fn verify_summary(
    b: &[u8],
    at: usize,
    leaf_count: usize,
    minimum: i8,
    leaves: Vec<i8>,
) -> Result<i8> {
    checked_summary(b, at, leaf_count, minimum, leaves, true)
}
fn checked_summary(
    b: &[u8],
    at: usize,
    leaf_count: usize,
    minimum: i8,
    leaves: Vec<i8>,
    agreement: bool,
) -> Result<i8> {
    let first = (leaf_count - 1) / 3;
    let height = leaf_count.ilog2() / 2;
    if le32(b, at) != leaf_count as u32
        || le32(b, at + 4) != leaf_count.ilog2()
        || le32(b, at + 8) != first as u32
        || le32(b, at + 12) != height
        || b[at + 16] != minimum as u8
    {
        return Err(bad("JFS buddy tree geometry"));
    }
    let expected = summaries(leaves, minimum)?;
    if agreement
        && b[at + 17..at + 17 + expected.len()]
            .iter()
            .zip(&expected)
            .any(|(a, b)| *a != *b as u8)
    {
        return Err(bad("JFS buddy summary differs from allocation bitmap"));
    }
    Ok(expected[0])
}
struct Imap {
    extents: Vec<Physical>,
    allocated: BTreeSet<u32>,
    raw: Vec<u8>,
    pages: Vec<Physical>,
}
fn inode_map(
    raw: &[u8],
    source: &dyn DecodeRead,
    blocks: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<Imap> {
    if le64(raw, 24) != 8192 {
        return Err(unsupported("JFS single-IAG inode-map profile"));
    }
    let (runs, mut pages) = xtree(&raw[224..512], source, blocks, w, r)?;
    if runs.iter().any(|r| r.unwritten)
        || runs.len() != 1
        || runs[0].logical != 0
        || runs[0].physical.count != 2
    {
        return Err(unsupported("JFS contiguous two-page inode-map profile"));
    }
    pages
        .try_reserve(1)
        .map_err(|_| budget("JFS map extent allocation"))?;
    pages.push(runs[0].physical);
    if le64(raw, 32) != pages.iter().map(|p| p.count).sum::<u64>() {
        return Err(bad("JFS inode-map block accounting"));
    }
    let file = MetadataMap {
        source,
        length: 8192,
        runs: &runs,
    };
    let mut control = [0; 4096];
    mapread(&file, 0, &mut control, w, r)?;
    if le32(&control, 0) != u32::MAX
        || le32(&control, 4) != 1
        || le32(&control, 16) != 4
        || le32(&control, 20) != 2
    {
        return Err(bad("JFS inode map control geometry"));
    }
    let mut iag = [0; 4096];
    mapread(&file, 4096, &mut iag, w, r)?;
    if le32(&iag, 8) != 0
        || le64(&iag, 0) != 0
        || [12, 16, 20, 24, 28]
            .iter()
            .any(|at| le32(&iag, *at) != u32::MAX)
    {
        return Err(bad("JFS IAG number"));
    }
    let mut extents = vector(128)?;
    let mut allocated = BTreeSet::new();
    let mut backed = 0u32;
    let mut free = 0u32;
    for i in 0..128 {
        w.tick(1, r)?;
        let extent = pxd(&iag, 3072 + i * 8, blocks)?;
        let word = le32(&iag, 2048 + i * 4);
        if word != le32(&iag, 2560 + i * 4) {
            return Err(bad("JFS inode working/persistent bitmap mismatch"));
        }
        if extent.count == 0 && word != 0 || extent.count != 0 && extent.count != 4 {
            return Err(bad("JFS inode extent/bitmap bounds"));
        }
        let bit = 0x80000000 >> (i % 32);
        let summary = le32(&iag, 32 + (i / 32) * 4) & bit != 0;
        let extsummary = le32(&iag, 48 + (i / 32) * 4) & bit != 0;
        if summary != (extent.count == 0 || word == u32::MAX) || extsummary != (extent.count != 0) {
            return Err(bad("JFS inode summary bitmap"));
        }
        if extent.count != 0 {
            w.extent()?;
            backed += 32;
            free += 32 - word.count_ones();
            extents.push(extent);
            for bit in 0..32 {
                if word & (0x80000000 >> bit) != 0 {
                    allocated.insert((i * 32 + bit) as u32);
                }
            }
        }
    }
    if backed != le32(&control, 8)
        || free != le32(&control, 12)
        || free != le32(&iag, 64)
        || 128 - extents.len() as u32 != le32(&iag, 68)
    {
        return Err(bad("JFS inode bitmap counts"));
    }
    if le32(&control, 2048) != if free > 0 { 0 } else { u32::MAX }
        || le32(&control, 2052) != if extents.len() < 128 { 0 } else { u32::MAX }
        || le32(&control, 2048 + 8) != backed
        || le32(&control, 2048 + 12) != free
        || (1..128).any(|ag| {
            le32(&control, 2048 + ag * 16) != u32::MAX
                || le32(&control, 2052 + ag * 16) != u32::MAX
                || le64(&control, 2056 + ag * 16) != 0
        })
    {
        return Err(unsupported("JFS inode allocation group profile"));
    }
    Ok(Imap {
        extents,
        allocated,
        raw: copied(&iag)?,
        pages,
    })
}
pub(crate) struct Decoded {
    pub(crate) header: [u8; 4096],
    pub(crate) geometry: JfsGeometry,
    pub(crate) nodes: BTreeMap<u32, Inode>,
    pub(crate) system: Vec<Physical>,
    pub(crate) bitmap: Vec<bool>,
    pub(crate) allocation_agreement: bool,
    #[cfg(all(test, feature = "std"))]
    map_length: u64,
    #[cfg(all(test, feature = "std"))]
    map_runs: Vec<Run>,
    pub(crate) mirror_valid: bool,
    limits: JfsReadLimits,
    _lease: Reservation,
}
pub(crate) struct Inner {
    source: Arc<Source>,
    pub(crate) scope: u128,
    decoded: Decoded,
}
impl crate::platform::ops::Deref for Inner {
    type Target = Decoded;
    fn deref(&self) -> &Decoded {
        &self.decoded
    }
}
pub(crate) fn decode(
    source: &dyn DecodeRead,
    limits: JfsReadLimits,
    r: &Resources,
) -> Result<Decoded> {
    decode_inner(source, limits, r, None)
}
#[cfg(all(test, feature = "std"))]
fn decode_recovery(
    source: &dyn DecodeRead,
    limits: JfsReadLimits,
    r: &Resources,
    changes: &[(u64, bool)],
) -> Result<Decoded> {
    decode_inner(source, limits, r, Some(changes))
}
fn decode_inner(
    source: &dyn DecodeRead,
    limits: JfsReadLimits,
    r: &Resources,
    changes: Option<&[(u64, bool)]>,
) -> Result<Decoded> {
    r.cancellation.check()?;
    let length = source.length()?;
    if length < 65536 || !length.is_multiple_of(4096) {
        return Err(bad("JFS bounded volume size"));
    }
    let blocks = length / 4096;
    if blocks > limits.blocks {
        return Err(budget("JFS block ceiling"));
    }
    let charge = blocks
        .checked_add(
            (limits.inodes as u64)
                .checked_mul(12288)
                .ok_or_else(|| budget("JFS inode charge"))?,
        )
        .and_then(|n| n.checked_add((limits.entries as u64).checked_mul(2048)?))
        .and_then(|n| n.checked_add((limits.extents as u64).checked_mul(256)?))
        .and_then(|n| n.checked_add((limits.pages as u64).checked_mul(256)?))
        .and_then(|n| n.checked_add(512 * 1024))
        .ok_or_else(|| budget("JFS metadata charge"))?;
    let lease = r.memory.reserve(charge)?;
    let mut w = Work {
        limits,
        work: 0,
        pages: 0,
        extents: 0,
        entries: 0,
    };
    let mut header = [0; 4096];
    read(source, 32768, &mut header, &mut w, r)?;
    if &header[..4] != b"JFS1" || ![1, 2].contains(&le32(&header, 4)) {
        return Err(unsupported("JFS superblock version"));
    }
    let flags = le32(&header, 36);
    if flags & 0x10200900 != 0x10200900
        || flags & !0x10220900 != 0
        || le32(&header, 44) != 0
        || le32(&header, 64) != 0
    {
        return Err(unsupported("JFS Linux inline-log/no-compression profile"));
    }
    if le32(&header, 40) != 0 {
        return Err(unsupported("JFS dirty/mounted/recovery/extend state"));
    }
    if le32(&header, 16) != 4096
        || le16(&header, 20) != 12
        || le16(&header, 22) != 3
        || le32(&header, 24) != 512
        || le16(&header, 28) != 9
        || !le64(&header, 8).is_multiple_of(8)
    {
        return Err(unsupported("JFS 4KiB/512-byte-sector profile"));
    }
    let mapped = le64(&header, 8) / 8;
    if mapped < 16 || mapped > blocks || mapped > 1 << 23 {
        return Err(unsupported("JFS level-zero aggregate map profile"));
    }
    let ait2 = pxd(&header, 48, blocks)?;
    let aim2 = pxd(&header, 56, blocks)?;
    let log = pxd(&header, 72, blocks)?;
    let fsck = pxd(&header, 80, blocks)?;
    if ait2.count != 4
        || aim2.count != 2
        || log.count < 3
        || fsck.count == 0
        || fsck.start != mapped
        || fsck.start + fsck.count != log.start
        || log.start + log.count != blocks
    {
        return Err(bad("JFS reserved/mirror/log geometry"));
    }
    let mut logs = [0; 4096];
    read(source, (log.start + 1) * 4096, &mut logs, &mut w, r)?;
    if le32(&logs, 0) != 0x87654321
        || le32(&logs, 4) != 1
        || u64::from(le32(&logs, 12)) != log.count
        || le32(&logs, 16) != 4096
        || le32(&logs, 20) != 12
        || le32(&logs, 28) != 1
        || le32(&logs, 8) != le32(&header, 68)
        || le32(&header, 4) == 2 && logs[36..52] != header[168..184]
        || logs[68..68 + 128 * 16].iter().any(|v| *v != 0)
    {
        return Err(unsupported(
            "JFS inline log not established shutdown/redone/unused",
        ));
    }
    let mut system = vector(
        limits
            .extents
            .checked_add(16)
            .ok_or_else(|| budget("JFS system index capacity"))?,
    )?;
    system.push(Physical { start: 0, count: 9 });
    system.push(Physical {
        start: 15,
        count: 1,
    });
    system.push(Physical {
        start: 11,
        count: 4,
    });
    system.extend([ait2, aim2, log, fsck]);
    let mut table = [0; 16384];
    read(source, 45056, &mut table, &mut w, r)?;
    let aggregate = inode_map(&table[512..1024], source, blocks, &mut w, r)?;
    if aggregate.extents
        != [Physical {
            start: 11,
            count: 4,
        }]
        || aggregate.allocated != BTreeSet::from([0, 1, 2, 3, 4, 16])
    {
        return Err(unsupported("JFS aggregate special-inode profile"));
    }
    system.extend_from_slice(&aggregate.pages);
    let mut secondary = [0; 16384];
    read(source, ait2.start * 4096, &mut secondary, &mut w, r)?;
    let secondmap = inode_map(&secondary[512..1024], source, blocks, &mut w, r)?;
    let mut mirror_valid =
        secondmap.extents == [ait2] && secondmap.allocated == aggregate.allocated;
    let mut alternate = [0; 4096];
    read(source, 61440, &mut alternate, &mut w, r)?;
    mirror_valid &= alternate[..184] == header[..184];
    for id in [0, 1, 2, 3, 4, 16] {
        let raw = &table[id * 512..(id + 1) * 512];
        let other = &secondary[id * 512..(id + 1) * 512];
        if id != 0
            && (le32(raw, 4) != 1
                || le32(raw, 8) != id as u32
                || pxd(raw, 16, blocks)?
                    != (Physical {
                        start: 11,
                        count: 4,
                    }))
        {
            return Err(bad("JFS aggregate inode identity"));
        }
        if id == 1 {
            mirror_valid &= raw[..16] == other[..16] && raw[24..224] == other[24..224];
        } else if id != 0 {
            mirror_valid &= raw[..16] == other[..16] && raw[24..] == other[24..];
        }
    }
    for raw in [&table[..512], &secondary[..512]] {
        if raw[24..40]
            .iter()
            .chain(raw[88..120].iter())
            .chain(raw[224..512].iter())
            .any(|v| *v != 0)
        {
            return Err(unsupported("JFS aggregate reserved inode payload"));
        }
    }
    // Special system inodes cannot hide unaccounted ACL/EA or payload profiles.
    for id in [1, 2, 3, 4, 16] {
        let raw = &table[id * 512..(id + 1) * 512];
        if raw[88..120].iter().any(|v| *v != 0) {
            return Err(unsupported("JFS aggregate EA/ACL"));
        }
    }
    let mut systemfiles = BTreeMap::new();
    for id in [2, 3, 4] {
        let raw = &table[id * 512..(id + 1) * 512];
        let (runs, pages) = xtree(&raw[224..512], source, blocks, &mut w, r)?;
        if runs.iter().any(|r| r.unwritten) {
            return Err(bad("JFS unwritten system file"));
        }
        if id == 3 && (le64(raw, 24) != 0 || !runs.is_empty()) {
            return Err(unsupported("JFS inline-log inode payload"));
        }
        if le64(raw, 32)
            != pages.iter().map(|p| p.count).sum::<u64>()
                + runs.iter().map(|p| p.physical.count).sum::<u64>()
        {
            return Err(bad("JFS system inode block accounting"));
        }
        system.extend(pages);
        system.extend(runs.iter().map(|r| r.physical));
        systemfiles.insert(id, (le64(raw, 24), runs));
    }
    let (maplength, mapruns) = systemfiles.get(&2).unwrap();
    let blockmap = MetadataMap {
        source,
        length: *maplength,
        runs: mapruns,
    };
    let mut control = [0; 4096];
    mapread(&blockmap, 0, &mut control, &mut w, r)?;
    let free = le64(&control, 8);
    let agsize = le64(&control, 1080);
    let numag = le32(&control, 20);
    let aglog = le32(&control, 52);
    if le64(&control, 0) != mapped
        || (changes.is_none() && free > mapped)
        || le32(&control, 16) != 0
        || le32(&control, 24) != 0
        || agsize != 8192
        || !agsize.is_power_of_two()
        || aglog != agsize.ilog2()
        || u64::from(numag) != mapped.div_ceil(agsize)
        || numag > 128
        || le32(&control, 28) >= numag
        || le32(&control, 32) >= numag
        || le32(&control, 36) != 0
        || le32(&control, 40) != 0
        || le32(&control, 44) != 1
        || le32(&control, 48) != 341
        || u64::from(le32(&header, 32)) != agsize
    {
        return Err(bad("JFS aggregate allocation descriptor"));
    }
    if let Some(changes) = changes {
        if changes.len() as u64 > mapped {
            return Err(budget("JFS recovery allocation ceiling"));
        }
        w.tick(changes.len() as u64 * 3, r)?;
        if changes.is_empty()
            || changes.iter().any(|(block, _)| *block >= mapped)
            || changes.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(bad("JFS recovery allocation authorization"));
        }
    }
    let mut change_cursor = 0;
    let mut bitmap = vector(mapped as usize)?;
    bitmap.resize(mapped as usize, false);
    let dmaps = mapped.div_ceil(8192);
    let mut roots = vector(1024)?;
    roots.resize(1024, -1);
    let mut totalfree = 0u64;
    let mut agfree = [0u64; 128];
    for number in 0..dmaps {
        let mut page = [0; 4096];
        mapread(&blockmap, (4 + number) * 4096, &mut page, &mut w, r)?;
        let first = number * 8192;
        let covered = (mapped - first).min(8192);
        if u64::from(le32(&page, 0)) != covered
            || le64(&page, 8) != first
            || (changes.is_none() && page[2048..3072] != page[3072..4096])
        {
            return Err(bad("JFS dmap bounds/working-persistent maps"));
        }
        let mut leaves = vector(256)?;
        let mut pagefree = 0;
        for word in 0..256 {
            let persistent = le32(&page, 3072 + word * 4);
            let working = le32(&page, 2048 + word * 4);
            let mut value = persistent;
            let mut mask = 0u32;
            if let Some(changes) = changes {
                let start = first + word as u64 * 32;
                while let Some(&(block, allocated)) = changes.get(change_cursor) {
                    if block >= start + 32 {
                        break;
                    }
                    w.tick(1, r)?;
                    let bit = 0x80000000 >> (block - start);
                    mask |= bit;
                    value = if allocated { value | bit } else { value & !bit };
                    change_cursor += 1;
                }
                if (working ^ persistent) & !mask != 0 {
                    return Err(bad("JFS unauthorized recovery bitmap difference"));
                }
            }
            leaves.push(word_buddy(value));
            for bit in 0..32 {
                let relative = word as u64 * 32 + bit;
                let allocated = value & (0x80000000 >> bit) != 0;
                if relative < covered {
                    w.tick(1, r)?;
                    bitmap[(first + relative) as usize] = allocated;
                    if !allocated {
                        pagefree += 1;
                        agfree[((first + relative) / agsize) as usize] += 1;
                    }
                } else if !allocated {
                    return Err(bad("JFS dmap tail padding allocated bits"));
                }
            }
        }
        if changes.is_none() && pagefree != le32(&page, 4) {
            return Err(bad("JFS dmap free summary"));
        }
        totalfree += u64::from(pagefree);
        roots[number as usize] = if changes.is_none() {
            verify_summary(&page, 16, 256, 5, leaves)?
        } else {
            checked_summary(&page, 16, 256, 5, leaves, false)?
        };
    }
    if changes.is_none()
        && (totalfree != free || (0..128).any(|i| le64(&control, 56 + i * 8) != agfree[i]))
    {
        return Err(bad("JFS aggregate/group free counts"));
    }
    let mut summary = [0; 4096];
    mapread(&blockmap, 3 * 4096, &mut summary, &mut w, r)?;
    let buddy = checked_summary(&summary, 0, 1024, 13, roots, changes.is_none())?;
    if changes.is_none() && control[1088] != buddy as u8 {
        return Err(bad("JFS aggregate maximum buddy"));
    }
    for at in [4096, 8192] {
        let mut unused = [0; 4096];
        mapread(&blockmap, at, &mut unused, &mut w, r)?;
        if unused.iter().any(|v| *v != 0) {
            return Err(unsupported("JFS inactive higher allocation controls"));
        }
    }
    if *maplength != (5 + dmaps) * 4096 {
        return Err(unsupported(
            "JFS allocation map growth/reserve page profile",
        ));
    }
    let mut spare = [0; 4096];
    mapread(&blockmap, (4 + dmaps) * 4096, &mut spare, &mut w, r)?;
    if spare.iter().any(|v| *v != 0) {
        return Err(unsupported("JFS populated future dmap page"));
    }
    let fileset = inode_map(&table[16 * 512..17 * 512], source, blocks, &mut w, r)?;
    if fileset.allocated.len() > limits.inodes {
        return Err(budget("JFS inode ceiling"));
    }
    system.extend(fileset.pages.iter().copied());
    system.extend(fileset.extents.iter().copied());
    let stamp = le32(&table, 512);
    let mut nodes = BTreeMap::new();
    for &ino in &fileset.allocated {
        let descriptor = pxd(&fileset.raw, 3072 + (ino as usize / 32) * 8, blocks)?;
        let mut raw = [0; 512];
        read(
            source,
            descriptor.start * 4096 + u64::from(ino % 32) * 512,
            &mut raw,
            &mut w,
            r,
        )?;
        if le32(&raw, 0) != stamp
            || le32(&raw, 4) != 16
            || le32(&raw, 8) != ino
            || pxd(&raw, 16, blocks)? != descriptor
            || le32(&raw, 40) == 0
        {
            return Err(bad("JFS fileset inode identity/links"));
        }
        if raw[88..120].iter().any(|v| *v != 0) {
            return Err(unsupported("JFS populated ACL/EA descriptors"));
        }
        let mode = le32(&raw, 52);
        let directory = mode & 0xf000 == 0x4000;
        if !matches!(mode & 0xf000, 0x4000 | 0x8000) || mode & !0x2007ffff != 0 {
            return Err(unsupported("JFS special inode/extended mode profile"));
        }
        for at in [56, 64, 72, 80] {
            if le32(&raw, at + 4) >= 1_000_000_000 {
                return Err(bad("JFS native timestamp nanoseconds"));
            }
        }
        let length = le64(&raw, 24);
        if length > 1 << 52 {
            return Err(bad("JFS file size"));
        }
        let (runs, pages, entries) = if directory {
            if !(2..=14).contains(&le32(&raw, 120)) {
                return Err(unsupported("JFS external persistent directory-index table"));
            }
            let (entries, pages) = dtree(&raw[224..512], source, blocks, &mut w, r)?;
            (Vec::new(), pages, entries)
        } else if ino < 4 {
            if length != 0 || le64(&raw, 32) != 0 {
                return Err(unsupported("JFS fileset special inode payload"));
            }
            if raw[224..512].iter().any(|v| *v != 0) {
                let (runs, pages) = xtree(&raw[224..512], source, blocks, &mut w, r)?;
                if !runs.is_empty() || !pages.is_empty() {
                    return Err(unsupported("JFS fileset special inode hidden allocation"));
                }
            }
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            if mode & 0x40000 != 0 && le16(&raw, 224 + 20) > 10 {
                return Err(bad("JFS inline EA overlaps extent root"));
            }
            let (runs, pages) = xtree(&raw[224..512], source, blocks, &mut w, r)?;
            (runs, pages, Vec::new())
        };
        nodes.insert(
            ino,
            Inode {
                ino,
                generation: le32(&raw, 12),
                length,
                directory,
                runs,
                pages,
                entries,
                raw: copied(&raw)?,
            },
        );
    }
    if ![0, 1, 2, 3].iter().all(|id| nodes.contains_key(id)) {
        return Err(bad("JFS required fileset inodes"));
    }
    #[cfg(all(test, feature = "std"))]
    let (map_length, map_runs) = {
        let mut retained = vector(mapruns.len())?;
        retained.extend(mapruns.iter().cloned());
        (*maplength, retained)
    };
    source.length()?;
    Ok(Decoded {
        header,
        geometry: JfsGeometry {
            blocks,
            mapped,
            free,
            flags,
        },
        nodes,
        system,
        bitmap,
        allocation_agreement: changes.is_none(),
        #[cfg(all(test, feature = "std"))]
        map_length,
        #[cfg(all(test, feature = "std"))]
        map_runs,
        mirror_valid,
        limits,
        _lease: lease,
    })
}
/// Owned immutable indexed metadata; a separate allocation audit establishes clean ownership.
#[derive(Clone)]
pub struct JfsVolume {
    pub(crate) inner: Arc<Inner>,
}
impl JfsVolume {
    /// Open an actual bare, clean Linux JFS volume with an inspected shutdown inline log.
    /// Caller guarantees all bytes remain immutable through every indexed/deferred handle.
    pub fn open(raw: Arc<dyn ReadAt>, limits: JfsReadLimits, r: &Resources) -> Result<Self> {
        let source = Arc::new(Source {
            length: raw.len(),
            raw,
            resources: r.clone(),
        });
        let decoded = decode(source.as_ref(), limits, r)?;
        let scope = (15u128 << 64)
            | u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                    .map_err(|_| budget("JFS source scope exhausted"))?,
            );
        Ok(Self {
            inner: Arc::new(Inner {
                source,
                scope,
                decoded,
            }),
        })
    }
    /// Native geometry.
    pub fn geometry(&self) -> &JfsGeometry {
        &self.inner.geometry
    }
    /// Fileset root inode 2.
    pub fn root_identity(&self) -> ObjectId {
        self.identity(2)
    }
    pub(crate) fn identity(&self, ino: u32) -> ObjectId {
        let generation = self.inner.nodes.get(&ino).map_or(0, |n| n.generation);
        let mut native = ino.to_be_bytes().to_vec();
        native.extend_from_slice(&generation.to_be_bytes());
        ObjectId {
            source: self.inner.scope,
            generation: 0,
            native,
        }
    }
    pub(crate) fn node(&self, id: &ObjectId) -> Result<&Inode> {
        if !self.inner.allocation_agreement {
            return Err(unsupported("JFS recovery index has no payload authority"));
        }
        if id.source != self.inner.scope || id.generation != 0 || id.native.len() != 8 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign JFS object identity",
            ));
        }
        let ino = u32::from_be_bytes(id.native[..4].try_into().unwrap());
        let node = self
            .inner
            .nodes
            .get(&ino)
            .ok_or_else(|| bad("JFS object missing"))?;
        if id.native[4..] != node.generation.to_be_bytes() {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS native inode generation",
            ));
        }
        Ok(node)
    }
    /// Recheck primary superblock and source length; backing bytes still require caller stability.
    pub fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.node(id)?;
        r.cancellation.check()?;
        let mut b = [0; 4096];
        self.inner
            .source
            .read_exact_at(32768, &mut b)
            .map_err(|e| Error::io("JFS source validation", e))?;
        if b != self.inner.header {
            return Err(Error::new(ErrorKind::StalePlan, "JFS superblock changed"));
        }
        r.cancellation.check()
    }
    /// Enumerate indexed native names without display-path reconstruction.
    pub fn directory(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<DirectoryEntry>>> {
        self.revalidate(id, r)?;
        let n = self.directory_len(id)?;
        let charge = (n as u64)
            .checked_mul(1024)
            .ok_or_else(|| budget("JFS directory charge"))?;
        Budgeted::try_new(&r.memory, charge, || self.directory_entries(id, 0..n, r))
    }
    pub(crate) fn directory_len(&self, id: &ObjectId) -> Result<usize> {
        let node = self.node(id)?;
        if !node.directory {
            return Err(Error::new(ErrorKind::InvalidOperation, "JFS non-directory"));
        }
        Ok(node.entries.len())
    }
    pub(crate) fn directory_entries(
        &self,
        id: &ObjectId,
        range: crate::platform::ops::Range<usize>,
        r: &Resources,
    ) -> Result<Vec<DirectoryEntry>> {
        let node = self.node(id)?;
        let mut out = vector(range.len())?;
        for entry in &node.entries[range] {
            r.cancellation.check()?;
            let child = self
                .inner
                .nodes
                .get(&entry.ino)
                .ok_or_else(|| bad("JFS directory missing target"))?;
            out.push(DirectoryEntry {
                name: NativeName::Utf16(copied(&entry.name)?),
                object: self.identity(entry.ino),
                kind: if child.directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        Ok(out)
    }
    /// Lookup exact case-sensitive native UTF16 components.
    pub fn lookup(&self, path: &[NativeName], r: &Resources) -> Result<ObjectId> {
        if path.len() > self.inner.nodes.len() {
            return Err(budget("JFS lookup depth"));
        }
        let mut id = self.root_identity();
        for name in path {
            let NativeName::Utf16(name) = name else {
                return Err(unsupported("JFS native UTF16 lookup"));
            };
            self.revalidate(&id, r)?;
            self.directory_len(&id)?;
            let mut found = None;
            for entry in &self.node(&id)?.entries {
                r.cancellation.check()?;
                if &entry.name == name {
                    found = Some(entry.ino);
                    break;
                }
            }
            id = self.identity(found.ok_or_else(|| bad("JFS name missing"))?);
        }
        self.revalidate(&id, r)?;
        Ok(id)
    }
    /// Create a deferred indexed regular-file map, preserving holes and unwritten semantics.
    pub fn open_file(&self, id: &ObjectId, r: &Resources) -> Result<JfsFile> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        if node.directory || node.ino < 4 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "JFS non-user-file content",
            ));
        }
        let visits = node
            .runs
            .iter()
            .try_fold(0u64, |n, x| n.checked_add(x.physical.count))
            .ok_or_else(|| budget("JFS local block work"))?;
        let protected = self
            .inner
            .system
            .len()
            .checked_add(
                self.inner
                    .nodes
                    .values()
                    .map(|n| n.pages.len())
                    .sum::<usize>(),
            )
            .ok_or_else(|| budget("JFS protected extent count"))?;
        let work = visits
            .checked_mul(protected as u64 + 1)
            .ok_or_else(|| budget("JFS local ownership work"))?;
        if work > self.inner.limits.work {
            return Err(budget("JFS local file work ceiling"));
        }
        for run in &node.runs {
            for block in run.physical.start..run.physical.start + run.physical.count {
                r.cancellation.check()?;
                if block >= self.inner.geometry.mapped
                    || !self.inner.bitmap[block as usize]
                    || self
                        .inner
                        .system
                        .iter()
                        .chain(self.inner.nodes.values().flat_map(|n| n.pages.iter()))
                        .any(|p| block >= p.start && block < p.start + p.count)
                {
                    return Err(bad("JFS file free/protected allocation"));
                }
            }
        }
        let lease = r.memory.reserve(
            (node.runs.len() as u64)
                .checked_mul(256)
                .and_then(|n| n.checked_add(512))
                .ok_or_else(|| budget("JFS file map charge"))?,
        )?;
        let source: Arc<dyn ReadAt> = self.inner.source.clone();
        let file = mapping(source, node.length, &node.runs, self.inner.limits.extents)?;
        Ok(JfsFile {
            volume: self.clone(),
            identity: id.clone(),
            file,
            _lease: lease,
        })
    }
    /// Native POSIX fields and timestamps plus opaque catalog/security provenance.
    pub fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        Budgeted::try_new(&r.memory, 8192, || {
            let b = &node.raw;
            let time = |p| {
                MetadataField::Known(NativeTimestamp {
                    ticks: i128::from(le32(b, p)) * 1_000_000_000 + i128::from(le32(b, p + 4)),
                    ticks_per_second: 1_000_000_000,
                    epoch: "1970-01-01 UTC; native unsigned JFS seconds/nanoseconds".into(),
                })
            };
            Ok(Metadata{created:time(80),modified:time(72),accessed:time(56),owner:MetadataField::Known(copied(&b[44..52])?),mode:MetadataField::Known(le32(b,52)&0xffff),security:MetadataField::Absent,attributes:vec![(NativeName::Bytes(b"jfs.dinode".to_vec()),MetadataField::Opaque{bytes:copied(b)?,interpretation:"Native 512-byte inode including generation, ctime, flags and allocation/tree/index locations; requires relocation policy".into()})],native_flags:MetadataField::Known(copied(&b[52..56])?),symlink_target:MetadataField::Absent,reparse_data:MetadataField::Absent})
        })
    }
}
/// Deferred positional reader retaining the source, inode inventory and leases.
pub struct JfsFile {
    volume: JfsVolume,
    identity: ObjectId,
    file: ExtentFile,
    _lease: Reservation,
}
impl FileRead for JfsFile {
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
            .map_err(|e| Error::io("JFS deferred file", e))?;
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
                kind: match e.kind {
                    MapKind::Data(_) => ExtentKind::Data,
                    MapKind::Hole => ExtentKind::Hole,
                    MapKind::Unwritten => ExtentKind::Unwritten,
                },
            })?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
#[path = "fs_jfs_edit.rs"]
mod edit;
