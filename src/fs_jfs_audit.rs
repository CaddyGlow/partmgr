//! Complete physical/reference proof for the explicitly accepted JFS Linux profile.
use crate::{
    fs_core::*,
    fs_jfs::{Decoded, JfsVolume, bad, budget, le32, le64, vector},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
/// Independent global work/report/memory ceilings.
#[derive(Clone, Copy, Debug)]
pub struct JfsAuditLimits {
    /// Maximum physical blocks represented by ownership map.
    pub blocks: u64,
    /// Maximum indexed inodes and namespace occurrences.
    pub objects: usize,
    /// Maximum directory depth.
    pub depth: usize,
    /// Maximum physical/reference visits.
    pub work: u64,
    /// Maximum retained findings; exhaustion fails the whole operation.
    pub findings: usize,
}
/// Native profile defects; all suppress free-space ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JfsAuditFinding {
    /// Physical allocations overlap.
    CrossLink {
        /// Physical block.
        block: u64,
    },
    /// Owner references a free bitmap block.
    ReferencedFree {
        /// Physical block.
        block: u64,
    },
    /// Allocated block has no indexed supported-profile owner.
    LostAllocation {
        /// Physical block.
        block: u64,
    },
    /// Namespace, parent, link, persistent index or block-count mismatch.
    InodeReference {
        /// Native fileset inode.
        inode: u32,
    },
    /// Primary and secondary native metadata disagree.
    Mirror,
}
/// Retained complete profile proof, without mutation/discard authority.
pub struct JfsAuditReport {
    findings: Vec<JfsAuditFinding>,
    free: Vec<LogicalExtent>,
    allocated: u64,
    _lease: Reservation,
}
impl JfsAuditReport {
    /// All physical allocations and supported-profile native references were visited.
    pub fn is_complete(&self) -> bool {
        true
    }
    /// Complete profile proof with no defects.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
    /// Bounded native defects.
    pub fn findings(&self) -> &[JfsAuditFinding] {
        &self.findings
    }
    /// Physically free byte ranges, empty on any defect and excluding log/fsck/metadata/tail.
    pub fn free_ranges(&self) -> &[LogicalExtent] {
        &self.free
    }
    /// Allocated bitmap blocks plus separately reserved log/fsck tail blocks.
    pub fn allocated_blocks(&self) -> u64 {
        self.allocated
    }
}
struct Audit<'a> {
    limits: JfsAuditLimits,
    r: &'a Resources,
    work: u64,
    owners: Vec<u8>,
    findings: Vec<JfsAuditFinding>,
}
impl Audit<'_> {
    fn tick(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("JFS audit work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("JFS audit work ceiling"));
        }
        Ok(())
    }
    fn finding(&mut self, f: JfsAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("JFS audit findings ceiling"));
        }
        self.findings.push(f);
        Ok(())
    }
    fn claim(&mut self, start: u64, count: u64) -> Result<()> {
        self.tick(count)?;
        let end = start
            .checked_add(count)
            .ok_or_else(|| bad("JFS audit physical overflow"))?;
        if end > self.owners.len() as u64 {
            return Err(bad("JFS audit physical bounds"));
        }
        for block in start..end {
            if self.owners[block as usize] != 0 {
                self.finding(JfsAuditFinding::CrossLink { block })?;
            }
            self.owners[block as usize] = 1;
        }
        Ok(())
    }
}
/// Account system maps, mirrors, inode extents, full user allocations including beyond EOF,
/// external tree pages, inline log and fsck workspace, all inode/namespace references and bitmap bits.
pub fn audit_jfs(
    volume: &JfsVolume,
    limits: JfsAuditLimits,
    r: &Resources,
) -> Result<JfsAuditReport> {
    volume.revalidate(&volume.root_identity(), r)?;
    let report = audit_decoded(&volume.inner, limits, r)?;
    volume.revalidate(&volume.root_identity(), r)?;
    Ok(report)
}
pub(crate) fn audit_decoded(
    inner: &Decoded,
    limits: JfsAuditLimits,
    r: &Resources,
) -> Result<JfsAuditReport> {
    r.cancellation.check()?;
    let g = &inner.geometry;
    let occurrences = inner
        .nodes
        .values()
        .try_fold(0usize, |n, i| n.checked_add(i.entries.len()))
        .ok_or_else(|| budget("JFS reference count"))?;
    if g.blocks > limits.blocks
        || inner.nodes.len() > limits.objects
        || occurrences > limits.objects
    {
        return Err(budget("JFS audit blocks/objects ceiling"));
    }
    let charge = g
        .blocks
        .checked_mul(34)
        .and_then(|n| n.checked_add((limits.objects as u64).checked_mul(1024)?))
        .and_then(|n| n.checked_add((limits.findings as u64).checked_mul(64)?))
        .ok_or_else(|| budget("JFS audit charge"))?;
    let lease = r.memory.reserve(charge)?;
    let mut owners = vector(g.blocks as usize)?;
    owners.resize(g.blocks as usize, 0);
    let mut a = Audit {
        limits,
        r,
        work: 0,
        owners,
        findings: vector(limits.findings)?,
    };
    for physical in &inner.system {
        a.claim(physical.start, physical.count)?;
    }
    if !inner.mirror_valid {
        a.finding(JfsAuditFinding::Mirror)?;
    }
    let mut references = BTreeMap::<u32, u32>::new();
    let mut parents = BTreeMap::<u32, u32>::new();
    let mut subdirectories = BTreeMap::<u32, u32>::new();
    for node in inner.nodes.values() {
        a.tick(1)?;
        let mut blocks = 0;
        for p in &node.pages {
            a.claim(p.start, p.count)?;
            blocks += p.count;
        }
        for run in &node.runs {
            a.claim(run.physical.start, run.physical.count)?;
            blocks += run.physical.count;
        }
        if le64(&node.raw, 32) != blocks {
            a.finding(JfsAuditFinding::InodeReference { inode: node.ino })?;
        }
        if node.directory {
            let next = le32(&node.raw, 120);
            let mut indexes = BTreeSet::new();
            for e in &node.entries {
                a.tick(1)?;
                if e.ino < 4 || e.index < 2 || e.index >= next || !indexes.insert(e.index) {
                    a.finding(JfsAuditFinding::InodeReference { inode: node.ino })?;
                } else {
                    let at = 128 + (e.index as usize - 2) * 8;
                    let address =
                        (u64::from(node.raw[at + 3]) << 32) | u64::from(le32(&node.raw, at + 4));
                    if node.raw[at + 1] != 1 || node.raw[at + 2] != e.slot || address != e.page {
                        a.finding(JfsAuditFinding::InodeReference { inode: node.ino })?;
                    }
                }
                if let Some(target) = inner.nodes.get(&e.ino) {
                    *references.entry(e.ino).or_default() += 1;
                    if target.directory {
                        *subdirectories.entry(node.ino).or_default() += 1;
                        if parents.insert(e.ino, node.ino).is_some()
                            || le32(&target.raw, 244) != node.ino
                        {
                            a.finding(JfsAuditFinding::InodeReference { inode: e.ino })?;
                        }
                    }
                } else {
                    a.finding(JfsAuditFinding::InodeReference { inode: e.ino })?;
                }
            }
            for index in 2..next {
                a.tick(1)?;
                let at = 128 + (index as usize - 2) * 8;
                if node.raw[at + 1] > 1 || node.raw[at + 1] == 1 && !indexes.contains(&index) {
                    a.finding(JfsAuditFinding::InodeReference { inode: node.ino })?;
                }
            }
        }
    }
    let mut queue = VecDeque::new();
    queue
        .try_reserve(limits.objects)
        .map_err(|_| budget("JFS namespace queue"))?;
    queue.push_back((2u32, 0usize));
    let mut seen = BTreeSet::new();
    while let Some((ino, depth)) = queue.pop_front() {
        a.tick(1)?;
        let Some(node) = inner.nodes.get(&ino) else {
            a.finding(JfsAuditFinding::InodeReference { inode: ino })?;
            continue;
        };
        if !seen.insert(ino) {
            if node.directory {
                a.finding(JfsAuditFinding::InodeReference { inode: ino })?;
            }
            continue;
        }
        if node.directory {
            if depth > limits.depth {
                return Err(budget("JFS audit depth ceiling"));
            }
            for e in &node.entries {
                let next = depth
                    .checked_add(1)
                    .ok_or_else(|| budget("JFS audit depth overflow"))?;
                if next > limits.depth && inner.nodes.get(&e.ino).is_some_and(|n| n.directory) {
                    return Err(budget("JFS audit depth ceiling"));
                }
                if queue.len() == limits.objects {
                    return Err(budget("JFS audit queue ceiling"));
                }
                queue.push_back((e.ino, next));
            }
        }
    }
    for node in inner.nodes.values().filter(|n| n.ino == 2 || n.ino >= 4) {
        a.tick(1)?;
        let links = if node.directory {
            2 + subdirectories.get(&node.ino).copied().unwrap_or(0)
        } else {
            references.get(&node.ino).copied().unwrap_or(0)
        };
        if !seen.contains(&node.ino)
            || le32(&node.raw, 40) != links
            || node.ino == 2 && (le32(&node.raw, 244) != 2 || references.contains_key(&2))
        {
            a.finding(JfsAuditFinding::InodeReference { inode: node.ino })?;
        }
    }
    let mut free = vector(g.mapped as usize)?;
    let mut start = None;
    let mut allocated = g.blocks - g.mapped;
    for block in 0..g.blocks {
        a.tick(1)?;
        let used = block >= g.mapped || inner.bitmap[block as usize];
        let owned = a.owners[block as usize] != 0;
        if block < g.mapped && used {
            allocated += 1;
        }
        if used && !owned {
            a.finding(JfsAuditFinding::LostAllocation { block })?;
        }
        if !used && owned {
            a.finding(JfsAuditFinding::ReferencedFree { block })?;
        }
        if !used && !owned {
            start.get_or_insert(block);
        } else if let Some(s) = start.take() {
            free.push(LogicalExtent {
                offset: s * 4096,
                length: (block - s) * 4096,
                kind: ExtentKind::Hole,
            });
        }
    }
    if let Some(s) = start {
        free.push(LogicalExtent {
            offset: s * 4096,
            length: (g.mapped - s) * 4096,
            kind: ExtentKind::Hole,
        });
    }
    if allocated != g.blocks - g.free {
        return Err(bad(
            "JFS audit bitmap count differs from retained complete map",
        ));
    }
    if !a.findings.is_empty() {
        free.clear();
    }
    r.cancellation.check()?;
    Ok(JfsAuditReport {
        findings: a.findings,
        free,
        allocated,
        _lease: lease,
    })
}
