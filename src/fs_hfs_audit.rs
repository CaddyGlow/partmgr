//! Complete allocation and native-reference proof for the declared classic HFS baseline.
use crate::platform::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_core::*,
    fs_hfs::{HfsVolume, bad, be16, budget, vector},
};
/// Independent global traversal/report ceilings.
#[derive(Clone, Copy, Debug)]
pub struct HfsAuditLimits {
    /// Maximum volume blocks in ownership map.
    pub blocks: u32,
    /// Maximum catalog objects and references.
    pub objects: usize,
    /// Maximum namespace directory depth.
    pub depth: usize,
    /// Maximum physical ownership/bitmap/reference visits.
    pub work: u64,
    /// Maximum retained defects; exhaustion fails the operation.
    pub findings: usize,
}
/// Supported-profile defect. Every defect suppresses physical free ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HfsAuditFinding {
    /// Distinct physical allocations overlap.
    CrossLink {
        /// Native allocation block.
        block: u32,
    },
    /// Referenced allocation is free in the native bitmap.
    ReferencedFree {
        /// Native allocation block.
        block: u32,
    },
    /// Allocated block has no supported-profile owner.
    LostAllocation {
        /// Native allocation block.
        block: u32,
    },
    /// Catalog object/thread/parent/valence/root topology mismatch.
    CatalogReference {
        /// Native catalog node identifier.
        cnid: u32,
    },
    /// Global native counts differ from complete inventory.
    SummaryCounts,
    /// Alternate header geometry/system forks disagree with primary.
    AlternateHeader,
}
/// Retained complete profile audit, without mutation/discard authority.
pub struct HfsAuditReport {
    findings: Vec<HfsAuditFinding>,
    free: Vec<LogicalExtent>,
    allocated: u32,
    _lease: Reservation,
}
impl HfsAuditReport {
    /// Every physical allocation and native catalog reference was covered.
    pub fn is_complete(&self) -> bool {
        true
    }
    /// Complete profile proof without defects.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
    /// Bounded retained defects.
    pub fn findings(&self) -> &[HfsAuditFinding] {
        &self.findings
    }
    /// Physically free byte ranges, empty on any defect; excludes headers/reservations/tails.
    pub fn free_ranges(&self) -> &[LogicalExtent] {
        &self.free
    }
    /// Native allocated bitmap count.
    pub fn allocated_blocks(&self) -> u32 {
        self.allocated
    }
}
struct Audit<'a> {
    volume: &'a HfsVolume,
    limits: HfsAuditLimits,
    r: &'a Resources,
    work: u64,
    owners: Vec<u8>,
    findings: Vec<HfsAuditFinding>,
}
impl Audit<'_> {
    fn tick(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("HFS audit work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("HFS audit work ceiling"));
        }
        Ok(())
    }
    fn finding(&mut self, f: HfsAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("HFS audit finding ceiling"));
        }
        self.findings.push(f);
        Ok(())
    }
    fn claim(&mut self, start: u32, count: u32) -> Result<()> {
        self.tick(u64::from(count))?;
        for block in start
            ..start
                .checked_add(count)
                .ok_or_else(|| bad("HFS audit allocation overflow"))?
        {
            let slot = self
                .owners
                .get_mut(block as usize)
                .ok_or_else(|| bad("HFS audit allocation bounds"))?;
            if *slot != 0 {
                self.finding(HfsAuditFinding::CrossLink { block })?;
            }
            self.owners[block as usize] = 1;
        }
        Ok(())
    }
}
/// Account all retained native allocations (including bytes beyond fork EOF), system files,
/// bad blocks, reserved regions, allocation bits and catalog threads/references. No repair authority.
pub fn audit_hfs(
    volume: &HfsVolume,
    limits: HfsAuditLimits,
    r: &Resources,
) -> Result<HfsAuditReport> {
    r.cancellation.check()?;
    volume.revalidate(&volume.root_identity(), r)?;
    let inner = &volume.inner;
    let g = volume.geometry();
    if g.blocks > limits.blocks || inner.nodes.len() > limits.objects {
        return Err(budget("HFS audit physical/object ceiling"));
    }
    let charge = u64::from(g.blocks)
        .checked_mul(34)
        .and_then(|n| n.checked_add((limits.objects as u64).checked_mul(512)?))
        .and_then(|n| n.checked_add((limits.findings as u64).checked_mul(64)?))
        .ok_or_else(|| budget("HFS audit charge overflow"))?;
    let lease = r.memory.reserve(charge)?;
    let mut owners = vector(g.blocks as usize)?;
    owners.resize(g.blocks as usize, 0);
    let findings = vector(limits.findings)?;
    let mut a = Audit {
        volume,
        limits,
        r,
        work: 0,
        owners,
        findings,
    };
    for fork in &inner.system {
        for e in &fork.extents {
            a.claim(e.start, e.count)?;
        }
    }
    for e in &inner.bad_blocks {
        a.claim(e.start, e.count)?;
    }
    for node in inner.nodes.values() {
        for fork in &node.forks {
            for e in &fork.extents {
                a.claim(e.start, e.count)?;
            }
        }
    }
    let alternate = volume.alternate(r)?;
    let primary = volume.header();
    // Apple documents that alternate counts/dates can be stale. Only immutable geometry
    // and current system forks are compared; a changed fork must update the alternate MDB.
    if alternate[..2] != primary[..2]
        || alternate[14..16] != primary[14..16]
        || alternate[18..24] != primary[18..24]
        || alternate[28..30] != primary[28..30]
        || alternate[130..162] != primary[130..162]
    {
        a.finding(HfsAuditFinding::AlternateHeader)?;
    }
    if inner
        .nodes
        .get(&2)
        .is_none_or(|n| n.name != primary[37..37 + usize::from(primary[36])])
    {
        a.finding(HfsAuditFinding::CatalogReference { cnid: 2 })?;
    }
    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    let mut counts = BTreeMap::<u32, u32>::new();
    let mut folders = 0u32;
    let mut files = 0u32;
    for node in inner.nodes.values() {
        a.tick(1)?;
        if node.directory {
            folders += 1;
        } else {
            files += 1;
        }
        let thread = inner.threads.get(&node.id);
        if (node.directory || node.raw[2] & 2 != 0 || thread.is_some())
            && thread.is_none_or(|t| {
                t.directory != node.directory || t.parent != node.parent || t.name != node.name
            })
            || node.id == 2 && (!node.directory || node.parent != 1)
            || node.id != 2 && inner.nodes.get(&node.parent).is_none_or(|n| !n.directory)
        {
            a.finding(HfsAuditFinding::CatalogReference { cnid: node.id })?;
        }
        if node.id != 2 {
            let v = children.entry(node.parent).or_default();
            v.try_reserve(1)
                .map_err(|_| budget("HFS audit child index allocation"))?;
            v.push(node.id);
            *counts.entry(node.parent).or_default() += 1;
        }
    }
    for &id in inner.threads.keys() {
        a.tick(1)?;
        if !inner.nodes.contains_key(&id) {
            a.finding(HfsAuditFinding::CatalogReference { cnid: id })?;
        }
    }
    let mut queue = VecDeque::new();
    queue
        .try_reserve(limits.objects)
        .map_err(|_| budget("HFS audit queue allocation"))?;
    queue.push_back((2u32, 0usize));
    let mut seen = BTreeSet::new();
    while let Some((id, depth)) = queue.pop_front() {
        a.tick(1)?;
        if depth > limits.depth {
            return Err(budget("HFS audit depth ceiling"));
        }
        if !seen.insert(id) {
            a.finding(HfsAuditFinding::CatalogReference { cnid: id })?;
            continue;
        }
        if let Some(node) = inner.nodes.get(&id) {
            if node.directory
                && u32::from(be16(&node.raw, 4)) != counts.get(&id).copied().unwrap_or(0)
            {
                a.finding(HfsAuditFinding::CatalogReference { cnid: id })?;
            }
        } else {
            a.finding(HfsAuditFinding::CatalogReference { cnid: id })?;
        }
        if let Some(v) = children.get(&id) {
            for child in v {
                if queue.len() == limits.objects {
                    return Err(budget("HFS audit queue ceiling"));
                }
                let next = depth
                    .checked_add(1)
                    .ok_or_else(|| budget("HFS audit depth overflow"))?;
                if next > limits.depth && inner.nodes.get(child).is_some_and(|n| n.directory) {
                    return Err(budget("HFS audit depth ceiling"));
                }
                queue.push_back((*child, next));
            }
        }
    }
    for &id in inner.nodes.keys() {
        a.tick(1)?;
        if !seen.contains(&id) {
            a.finding(HfsAuditFinding::CatalogReference { cnid: id })?;
        }
    }
    let mut allocated = 0u32;
    let mut free = vector(g.blocks as usize)?;
    let mut start = None;
    for block in 0..g.blocks {
        a.tick(1)?;
        let used = inner.bitmap[block as usize / 8] & (0x80 >> (block % 8)) != 0;
        let owned = a.owners[block as usize] != 0;
        if used {
            allocated += 1;
        }
        if used && !owned {
            a.finding(HfsAuditFinding::LostAllocation { block })?;
        }
        if !used && owned {
            a.finding(HfsAuditFinding::ReferencedFree { block })?;
        }
        if !used && !owned {
            start.get_or_insert(block);
        } else if let Some(s) = start.take() {
            free.push(LogicalExtent {
                offset: g.base + u64::from(s) * u64::from(g.block_size),
                length: u64::from(block - s) * u64::from(g.block_size),
                kind: ExtentKind::Hole,
            });
        }
    }
    if let Some(s) = start {
        free.push(LogicalExtent {
            offset: g.base + u64::from(s) * u64::from(g.block_size),
            length: u64::from(g.blocks - s) * u64::from(g.block_size),
            kind: ExtentKind::Hole,
        });
    }
    if allocated != g.blocks - g.free || files != g.files || folders.saturating_sub(1) != g.folders
    {
        a.finding(HfsAuditFinding::SummaryCounts)?;
    }
    let root_children = children.get(&2);
    let root_dirs = root_children.map_or(0, |ids| {
        ids.iter()
            .filter(|id| inner.nodes.get(id).is_some_and(|n| n.directory))
            .count()
    });
    let root_files = root_children.map_or(0, |ids| {
        ids.iter()
            .filter(|id| inner.nodes.get(id).is_some_and(|n| !n.directory))
            .count()
    });
    if root_dirs != usize::from(g.root_folders) || root_files != usize::from(g.root_files) {
        a.finding(HfsAuditFinding::SummaryCounts)?;
    }
    if !a.findings.is_empty() {
        free.clear();
    }
    a.volume.revalidate(&a.volume.root_identity(), r)?;
    Ok(HfsAuditReport {
        findings: a.findings,
        free,
        allocated,
        _lease: lease,
    })
}
