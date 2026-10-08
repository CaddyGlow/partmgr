//! Complete supported-node scan and reachable namespace audit; no physical erase authority.
use crate::{
    fs_core::*,
    fs_jffs2::{Jffs2Endian, Jffs2Inode, Jffs2Volume, budget, invalid},
};
/// Bounded namespace traversal and diagnostics.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2AuditLimits {
    /// Maximum reachable directory names.
    pub entries: usize,
    /// Maximum traversal work.
    pub work: u64,
    /// Maximum retained findings.
    pub findings: usize,
}
/// Namespace defects prevent free-range reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Jffs2Finding {
    /// Dirent references an inode absent from the checked inventory.
    MissingInode {
        /// Directory inode.
        parent: u32,
        /// Absent target inode.
        inode: u32,
    },
    /// Native dirent type disagrees with inode mode.
    TypeMismatch {
        /// Directory inode.
        parent: u32,
        /// Target inode.
        inode: u32,
    },
    /// Directory alias, including cycles and root links.
    DirectoryAlias {
        /// Aliased native inode.
        inode: u32,
    },
}
/// Bounded complete result for the supported logical node profile.
pub struct Jffs2AuditReport {
    findings: Vec<Jffs2Finding>,
    free: Vec<LogicalExtent>,
    pub(crate) reachable: Vec<bool>,
    live: usize,
    historical: usize,
    nodes: u64,
    obsolete: u64,
    _lease: Reservation,
}
impl Jffs2AuditReport {
    /// Every byte was scanned and the supported namespace was traversed.
    pub fn is_complete(&self) -> bool {
        true
    }
    /// No reachable namespace defect was found.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
    /// Namespace diagnostics.
    pub fn findings(&self) -> &[Jffs2Finding] {
        &self.findings
    }
    /// Only entirely erased blocks; informational, never physical discard authority.
    pub fn free_ranges(&self) -> &[LogicalExtent] {
        &self.free
    }
    /// Unique reachable objects, including root.
    pub fn reachable_inodes(&self) -> usize {
        self.live
    }
    /// Unreachable historical inode numbers; deletion may intentionally retain them.
    pub fn historical_inodes(&self) -> usize {
        self.historical
    }
    /// Padded accurate node bytes, including superseded history.
    pub fn accurate_node_bytes(&self) -> u64 {
        self.nodes
    }
    /// Padded nodes explicitly marked obsolete on NOR.
    pub fn obsolete_node_bytes(&self) -> u64 {
        self.obsolete
    }
}
/// Audit all reachable dirents and aliases after a complete checked node scan.
pub fn audit(v: &Jffs2Volume, l: Jffs2AuditLimits, r: &Resources) -> Result<Jffs2AuditReport> {
    v.check_stability(r)?;
    audit_parts(
        AuditParts {
            inodes: &v.inodes,
            endian: v.endian,
            erased: &v.erased,
            node_bytes: v.node_bytes,
            obsolete_bytes: v.obsolete_bytes,
        },
        l,
        r,
        |r| v.check_stability(r),
    )
}
pub(crate) struct AuditParts<'a> {
    pub(crate) inodes: &'a [Jffs2Inode],
    pub(crate) endian: Jffs2Endian,
    pub(crate) erased: &'a [(u64, u64)],
    pub(crate) node_bytes: u64,
    pub(crate) obsolete_bytes: u64,
}
pub(crate) fn audit_parts(
    parts: AuditParts<'_>,
    l: Jffs2AuditLimits,
    r: &Resources,
    check: impl Fn(&Resources) -> Result<()>,
) -> Result<Jffs2AuditReport> {
    check(r)?;
    let AuditParts {
        inodes,
        endian,
        erased,
        node_bytes,
        obsolete_bytes,
    } = parts;
    let n = inodes.len();
    let charge = n as u128 * 32 + l.findings as u128 * 64 + erased.len() as u128 * 64 + 256;
    let lease = r
        .memory
        .reserve(u64::try_from(charge).map_err(|_| budget("JFFS2 audit accounting"))?)?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(n)
        .map_err(|_| budget("JFFS2 audit index"))?;
    seen.resize(n, false);
    let mut queue = Vec::new();
    queue
        .try_reserve_exact(n)
        .map_err(|_| budget("JFFS2 audit queue"))?;
    let root = inodes
        .binary_search_by_key(&1, |i| i.number)
        .map_err(|_| invalid("JFFS2 absent root"))?;
    if endian.dword(&inodes[root].raw, 20) & 0xf000 != 0x4000 {
        return Err(invalid("JFFS2 root not directory"));
    }
    seen[root] = true;
    queue.push(root);
    let mut findings = Vec::new();
    findings
        .try_reserve_exact(l.findings)
        .map_err(|_| budget("JFFS2 audit findings"))?;
    let mut at = 0;
    let mut work = 0u64;
    let mut entries = 0usize;
    while at < queue.len() {
        check(r)?;
        let parent = &inodes[queue[at]];
        at += 1;
        for e in &parent.children {
            work = work
                .checked_add(1)
                .ok_or_else(|| budget("JFFS2 audit work overflow"))?;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| budget("JFFS2 audit entries overflow"))?;
            if work > l.work || entries > l.entries {
                return Err(budget("JFFS2 audit traversal cap"));
            }
            r.cancellation.check()?;
            let mut finding = None;
            match inodes.binary_search_by_key(&e.inode, |i| i.number) {
                Err(_) => {
                    finding = Some(Jffs2Finding::MissingInode {
                        parent: parent.number,
                        inode: e.inode,
                    })
                }
                Ok(i) => {
                    let mode = endian.dword(&inodes[i].raw, 20) & 0xf000;
                    let expected = match mode {
                        0x4000 => 4,
                        0x8000 => 8,
                        0xa000 => 10,
                        _ => return Err(invalid("JFFS2 audited inode type")),
                    };
                    if e.file_type != expected {
                        finding = Some(Jffs2Finding::TypeMismatch {
                            parent: parent.number,
                            inode: e.inode,
                        });
                    } else if mode == 0x4000 && seen[i] {
                        finding = Some(Jffs2Finding::DirectoryAlias { inode: e.inode });
                    } else if !seen[i] {
                        seen[i] = true;
                        queue.push(i);
                    }
                }
            }
            if let Some(f) = finding {
                if findings.len() >= l.findings {
                    return Err(budget("JFFS2 audit finding cap"));
                }
                findings.push(f);
            }
        }
    }
    let mut free = Vec::new();
    if findings.is_empty() {
        free.try_reserve_exact(erased.len())
            .map_err(|_| budget("JFFS2 erased range inventory"))?;
        for &(offset, length) in erased {
            free.push(LogicalExtent {
                offset,
                length,
                kind: ExtentKind::Hole,
            });
        }
    }
    let live = seen.iter().filter(|v| **v).count();
    Ok(Jffs2AuditReport {
        findings,
        free,
        reachable: seen,
        live,
        historical: n - live,
        nodes: node_bytes,
        obsolete: obsolete_bytes,
        _lease: lease,
    })
}
