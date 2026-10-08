//! Complete allocation/reference accounting for the explicitly indexed XFS leaf baseline.
//! An immutable result grants no discard or mutation authority.
use crate::{
    fs_core::*,
    fs_xfs::{XfsVolume, budget, invalid},
};
use std::collections::VecDeque;
/// Independent full-audit traversal and retained-findings ceilings.
#[derive(Clone, Copy, Debug)]
pub struct XfsAuditLimits {
    /// Maximum volume blocks represented by the ownership index.
    pub blocks: u64,
    /// Maximum namespace entries visited.
    pub entries: usize,
    /// Maximum work units including allocation and namespace scans.
    pub work: u64,
    /// Maximum retained defects; exhaustion returns an error, never a clean result.
    pub findings: usize,
}
/// Defect discovered by complete baseline accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XfsAuditFinding {
    /// Two distinct allocations claim one block.
    CrossLink {
        /// Physical data-device block.
        block: u64,
    },
    /// A referenced allocation is declared free by the bnobt/cntbt.
    ReferencedFree {
        /// Physical data-device block.
        block: u64,
    },
    /// An allocated block has no system/metadata/data owner.
    LostAllocation {
        /// Physical data-device block.
        block: u64,
    },
    /// A live allocated inode lacks a reachable namespace reference.
    UnreachableInode {
        /// Native inode number.
        inode: u64,
    },
    /// An inode reference is unallocated or has the wrong directory filetype.
    InvalidReference {
        /// Containing native directory inode.
        parent: u64,
        /// Referenced native inode.
        inode: u64,
    },
    /// Directory parent, directory alias/cycle or native root topology disagrees.
    DirectoryTopology {
        /// Native directory inode.
        inode: u64,
    },
    /// Stored link count differs from complete native namespace references.
    LinkCount {
        /// Native inode.
        inode: u64,
        /// Native stored link count.
        recorded: u32,
        /// Complete reachable namespace reference count.
        actual: u64,
    },
    /// Primary free-block summary differs from bnobt plus AGFL accounting.
    FreeBlockCount {
        /// Primary superblock count.
        recorded: u64,
        /// Total bnobt/cntbt free blocks plus AGFL.
        actual: u64,
    },
}
/// Complete immutable audit with free ranges suppressed whenever any defect exists.
pub struct XfsAuditReport {
    findings: Vec<XfsAuditFinding>,
    free: Vec<LogicalExtent>,
    allocated_inodes: usize,
    owned: u64,
    _lease: Reservation,
}
impl XfsAuditReport {
    /// All metadata was explored and no supported-profile defect was found.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
    /// This report only exists after complete baseline traversal.
    pub fn is_complete(&self) -> bool {
        true
    }
    /// Retained complete-audit defects.
    pub fn findings(&self) -> &[XfsAuditFinding] {
        &self.findings
    }
    /// Byte-addressed physically free ranges; empty on every defect.
    /// No immutable report authorizes discard or other writes.
    pub fn free_ranges(&self) -> &[LogicalExtent] {
        &self.free
    }
    /// Live allocated user objects plus the two protected realtime system inodes.
    pub fn allocated_inodes(&self) -> usize {
        self.allocated_inodes
    }
    /// Blocks with an identified system, metadata or file allocation owner.
    pub fn owned_blocks(&self) -> u64 {
        self.owned
    }
}
struct State<'a> {
    volume: &'a XfsVolume,
    r: &'a Resources,
    limits: XfsAuditLimits,
    work: u64,
    owner: Vec<u8>,
    findings: Vec<XfsAuditFinding>,
}
impl State<'_> {
    fn step(&mut self, n: u64) -> Result<()> {
        self.volume.check_stability(self.r)?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("XFS audit work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("XFS audit work cap"));
        }
        Ok(())
    }
    fn finding(&mut self, f: XfsAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("XFS audit findings cap"));
        }
        self.findings
            .try_reserve(1)
            .map_err(|_| budget("XFS findings allocation"))?;
        self.findings.push(f);
        Ok(())
    }
    fn claim(&mut self, start: u64, count: u32) -> Result<()> {
        if start + u64::from(count) > self.volume.geometry.blocks {
            return Err(invalid("XFS audit allocation bounds"));
        }
        for b in start..start + u64::from(count) {
            self.step(1)?;
            let status = self.owner[b as usize];
            if status & 2 != 0 {
                self.finding(XfsAuditFinding::CrossLink { block: b })?;
            }
            if status & 1 != 0 {
                self.finding(XfsAuditFinding::ReferencedFree { block: b })?;
            }
            self.owner[b as usize] |= 2;
        }
        Ok(())
    }
}
/// Audit every indexed AG free record, system block, inode chunk, file extent and name.
/// Unsupported reader profiles and work/cancellation failures produce no partial report.
pub fn audit(volume: &XfsVolume, limits: XfsAuditLimits, r: &Resources) -> Result<XfsAuditReport> {
    volume.check_stability(r)?;
    let blocks = volume.geometry.blocks;
    if blocks > limits.blocks {
        return Err(budget("XFS audit volume block cap"));
    }
    let free_records = volume.groups.iter().map(|g| g.free.len()).sum::<usize>();
    let charge = u128::from(blocks) * 2
        + free_records as u128 * 64
        + (volume.inodes.len() as u128) * 256
        + (limits.findings as u128) * 128
        + (limits.entries as u128) * 64
        + 4096;
    let lease = r
        .memory
        .reserve(u64::try_from(charge).map_err(|_| budget("XFS audit memory overflow"))?)?;
    let mut owner = Vec::new();
    owner
        .try_reserve_exact(usize::try_from(blocks).map_err(|_| budget("XFS ownership index size"))?)
        .map_err(|_| budget("XFS ownership allocation"))?;
    owner.resize(blocks as usize, 0);
    let mut s = State {
        volume,
        r,
        limits,
        work: 0,
        owner,
        findings: Vec::new(),
    };
    let mut total_free = 0u64;
    for group in &volume.groups {
        s.step(1)?;
        for &(first, count) in &group.free {
            for b in
                group.start + u64::from(first)..group.start + u64::from(first) + u64::from(count)
            {
                s.step(1)?;
                s.owner[b as usize] |= 1;
            }
        }
        for &(first, count) in &group.protected {
            s.claim(group.start + u64::from(first), count)?;
        }
        total_free += u64::from(group.free_blocks) + u64::from(group.freelist);
    }
    s.claim(volume.geometry.log_start, volume.geometry.log_blocks)?;
    for inode in &volume.inodes {
        s.step(1)?;
        for e in &inode.extents {
            s.claim(e.physical, e.count)?;
        }
    }
    if total_free != volume.geometry.free_blocks {
        s.finding(XfsAuditFinding::FreeBlockCount {
            recorded: volume.geometry.free_blocks,
            actual: total_free,
        })?;
    }
    let mut owned = 0;
    for b in 0..blocks {
        s.step(1)?;
        let status = s.owner[b as usize];
        if status == 0 {
            s.finding(XfsAuditFinding::LostAllocation { block: b })?;
        }
        if status & 2 != 0 {
            owned += 1;
        }
    }
    let n = volume.inodes.len();
    let mut seen = Vec::new();
    seen.try_reserve_exact(n)
        .map_err(|_| budget("XFS namespace index"))?;
    seen.resize(n, false);
    let mut refs = Vec::new();
    refs.try_reserve_exact(n)
        .map_err(|_| budget("XFS reference index"))?;
    refs.resize(n, 0u64);
    let mut pending = VecDeque::new();
    pending
        .try_reserve(n)
        .map_err(|_| budget("XFS namespace queue"))?;
    let root = volume
        .inodes
        .binary_search_by_key(&volume.geometry.root, |i| i.number())
        .map_err(|_| invalid("XFS root unallocated"))?;
    if !volume.inodes[root].is_directory() {
        return Err(invalid("XFS root regular"));
    }
    seen[root] = true;
    pending.push_back((root, volume.geometry.root));
    let mut entries = 0usize;
    while let Some((index, parent)) = pending.pop_front() {
        s.step(1)?;
        let inode = &volume.inodes[index];
        let number = inode.number();
        if inode.parent_inode() != Some(parent) {
            s.finding(XfsAuditFinding::DirectoryTopology { inode: number })?;
        }
        refs[index] += 1;
        let parent_index = volume
            .inodes
            .binary_search_by_key(&parent, |i| i.number())
            .map_err(|_| invalid("XFS parent reference unallocated"))?;
        refs[parent_index] += 1;
        for entry in inode.directory_entries() {
            s.step(1)?;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| budget("XFS audit entries overflow"))?;
            if entries > limits.entries {
                return Err(budget("XFS audit entry cap"));
            }
            let child = match volume
                .inodes
                .binary_search_by_key(&entry.inode, |i| i.number())
            {
                Ok(n) => n,
                Err(_) => {
                    s.finding(XfsAuditFinding::InvalidReference {
                        parent: number,
                        inode: entry.inode,
                    })?;
                    continue;
                }
            };
            let target = &volume.inodes[child];
            if (target.is_directory() && entry.file_type != 2)
                || (!target.is_directory() && entry.file_type != 1)
                || volume.geometry.system.contains(&entry.inode)
            {
                s.finding(XfsAuditFinding::InvalidReference {
                    parent: number,
                    inode: entry.inode,
                })?;
                continue;
            }
            refs[child] += 1;
            if target.is_directory() {
                if seen[child] {
                    s.finding(XfsAuditFinding::DirectoryTopology { inode: entry.inode })?;
                } else {
                    seen[child] = true;
                    pending.push_back((child, number));
                }
            } else {
                seen[child] = true;
            }
        }
    }
    for (index, inode) in volume.inodes.iter().enumerate() {
        s.step(1)?;
        if volume.geometry.system.contains(&inode.number()) {
            seen[index] = true;
            refs[index] = 1;
        }
        if !seen[index] {
            s.finding(XfsAuditFinding::UnreachableInode {
                inode: inode.number(),
            })?;
        }
        if refs[index] != u64::from(inode.links()) {
            s.finding(XfsAuditFinding::LinkCount {
                inode: inode.number(),
                recorded: inode.links(),
                actual: refs[index],
            })?;
        }
    }
    let mut free = Vec::new();
    if s.findings.is_empty() {
        let count = volume.groups.iter().map(|g| g.free.len()).sum::<usize>();
        free.try_reserve_exact(count)
            .map_err(|_| budget("XFS free ranges"))?;
        for g in &volume.groups {
            for &(b, count) in &g.free {
                let offset = (g.start + u64::from(b)) * 4096;
                let length = u64::from(count) * 4096;
                if let Some(last) = free.last_mut() {
                    let last: &mut LogicalExtent = last;
                    if last.offset + last.length == offset {
                        last.length += length;
                        continue;
                    }
                }
                free.push(LogicalExtent {
                    offset,
                    length,
                    kind: ExtentKind::Hole,
                });
            }
        }
    }
    s.step(1)?;
    Ok(XfsAuditReport {
        findings: s.findings,
        free,
        allocated_inodes: volume.inodes.len(),
        owned,
        _lease: lease,
    })
}
