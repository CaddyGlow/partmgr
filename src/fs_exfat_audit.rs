//! Complete bounded read-only ownership audit for the strict basic exFAT profile.
use crate::{
    fs_core::{Error, ErrorKind, ObjectId, Reservation, Resources, Result},
    fs_exfat_volume::{ExfatDecoder, ExfatDirectory, ExfatReadLimits},
};
use std::{collections::VecDeque, sync::Arc};
use virtdisk::ReadAt;

/// Independent ceilings for complete inventory and diagnostics.
#[derive(Clone, Copy, Debug)]
pub struct ExfatAuditLimits {
    /// Maximum heap clusters.
    pub clusters: usize,
    /// Maximum namespace objects, including root.
    pub entries: usize,
    /// Maximum aggregate directory slots scanned.
    pub directory_slots: usize,
    /// Maximum cluster visits and directory slots (including heap reconciliation).
    pub work: usize,
    /// Maximum diagnostic records.
    pub findings: usize,
}
/// Allocation/state defects; none confer mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExfatAuditFinding {
    /// Multiple objects (or a system stream) claim this cluster.
    CrossLink {
        /// Volume-relative heap cluster.
        cluster: u32,
    },
    /// A directory overlaps an already visited directory; descendants are not revisited.
    DuplicateDirectory {
        /// Volume-scoped namespace identity.
        identity: ObjectId,
    },
    /// A reachable allocation or directory is malformed; descendants may be unknown.
    InvalidObject {
        /// Volume-scoped namespace identity.
        identity: ObjectId,
        /// Checked codec failure.
        message: String,
    },
    /// Referenced allocation is marked free in the bitmap.
    ReferencedFree {
        /// Volume-relative heap cluster.
        cluster: u32,
    },
    /// Bitmap allocation is neither reachable nor marked bad in the FAT.
    LostAllocation {
        /// Volume-relative heap cluster.
        cluster: u32,
    },
    /// Unowned FAT bad-cluster marker has a free bitmap bit.
    BadClusterFree {
        /// Volume-relative heap cluster.
        cluster: u32,
    },
    /// Main boot PercentInUse differs from the complete bitmap count.
    PercentInUse {
        /// Main boot value.
        recorded: u8,
        /// Bitmap-derived value rounded down.
        calculated: u8,
    },
}
/// Heap-only free byte range; no tail, FAT or boot region is included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExfatFreeRange {
    /// Volume-relative byte offset.
    pub offset: u64,
    /// Byte length.
    pub length: u64,
}
/// Retained report. Free ranges exist only for a complete defect-free audit.
/// This is evidence about a caller-stabilized source, not write/discard authority.
pub struct ExfatAuditReport {
    findings: Vec<ExfatAuditFinding>,
    free: Vec<ExfatFreeRange>,
    complete: bool,
    objects: usize,
    allocated: usize,
    owned: usize,
    bad: usize,
    work: usize,
    _reservation: Reservation,
}
impl ExfatAuditReport {
    /// Retained diagnostics.
    pub fn findings(&self) -> &[ExfatAuditFinding] {
        &self.findings
    }
    /// Safe-to-describe free heap ranges; never grants discard authorization.
    pub fn free_ranges(&self) -> &[ExfatFreeRange] {
        &self.free
    }
    /// Every reachable namespace object and heap bitmap entry was inspected.
    pub fn namespace_complete(&self) -> bool {
        self.complete
    }
    /// Complete and free of diagnosed inconsistencies.
    pub fn is_clean(&self) -> bool {
        self.complete && self.findings.is_empty()
    }
    /// Namespace objects, including root; system streams are excluded.
    pub fn objects(&self) -> usize {
        self.objects
    }
    /// Set bits in the full allocation bitmap.
    pub fn allocated_clusters(&self) -> usize {
        self.allocated
    }
    /// Distinct reachable/system allocation clusters.
    pub fn owned_clusters(&self) -> usize {
        self.owned
    }
    /// Unowned FAT bad markers (contiguous-file FAT values are never interpreted).
    pub fn bad_clusters(&self) -> usize {
        self.bad
    }
    /// Charged deterministic work units.
    pub fn work(&self) -> usize {
        self.work
    }
}
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn allocate<T>(capacity: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| budget("exFAT audit allocation"))?;
    Ok(v)
}
struct State {
    owners: Vec<u8>, // bit 0: allocation owner; bit 1: visited directory
    findings: Vec<ExfatAuditFinding>,
    limits: ExfatAuditLimits,
    work: usize,
    slots: usize,
    complete: bool,
}
impl State {
    fn tick(&mut self, count: usize, resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        self.work = self
            .work
            .checked_add(count)
            .filter(|&n| n <= self.limits.work)
            .ok_or_else(|| budget("exFAT audit work limit"))?;
        Ok(())
    }
    fn finding(&mut self, finding: ExfatAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("exFAT audit finding limit"));
        }
        self.findings.push(finding);
        Ok(())
    }
    fn claim(&mut self, cluster: u32, directory: bool, resources: &Resources) -> Result<bool> {
        self.tick(1, resources)?;
        let i = (cluster - 2) as usize;
        let duplicate_directory = directory && self.owners[i] & 2 != 0;
        if self.owners[i] & 1 != 0 {
            self.finding(ExfatAuditFinding::CrossLink { cluster })?;
        }
        self.owners[i] |= if directory { 3 } else { 1 };
        Ok(duplicate_directory)
    }
    fn directory(
        &mut self,
        directory: &ExfatDirectory,
        cluster_bytes: u32,
        resources: &Resources,
    ) -> Result<()> {
        let slots = directory
            .allocation_clusters()
            .len()
            .checked_mul(cluster_bytes as usize / 32)
            .ok_or_else(|| budget("exFAT audit slot overflow"))?;
        self.slots = self
            .slots
            .checked_add(slots)
            .filter(|&n| n <= self.limits.directory_slots)
            .ok_or_else(|| budget("exFAT audit directory slot limit"))?;
        self.tick(slots, resources)
    }
}
/// Audit a clean, single-FAT revision-1.00 volume using its strict checked codecs.
///
/// Boot/system/root metadata failures, unsupported extensions, cancellation, I/O
/// errors and exhausted limits fail without a report. Malformed descendant
/// allocation/namespace errors are findings and make the report incomplete.
/// FAT entries for contiguous allocations and free clusters are not meaningful;
/// their stale values are deliberately ignored. Unowned bad markers are counted
/// separately and must be allocated in the bitmap.
pub fn audit_exfat(
    source: Arc<dyn ReadAt>,
    read_limits: ExfatReadLimits,
    limits: ExfatAuditLimits,
    resources: &Resources,
) -> Result<ExfatAuditReport> {
    let volume = ExfatDecoder::open(source, read_limits, resources)?;
    audit_decoder(&volume, limits, resources)
}
pub(crate) fn audit_exfat_storage(
    source: &dyn crate::storage::Storage,
    read_limits: ExfatReadLimits,
    limits: ExfatAuditLimits,
    r: &Resources,
) -> Result<ExfatAuditReport> {
    let volume = ExfatDecoder::open(source, read_limits, r)?;
    audit_decoder(&volume, limits, r)
}
fn audit_decoder(
    volume: &ExfatDecoder<impl crate::fs_exfat::ExfatDecodeRead>,
    limits: ExfatAuditLimits,
    resources: &Resources,
) -> Result<ExfatAuditReport> {
    resources.cancellation.check()?;
    if limits.entries == 0 {
        return Err(budget("exFAT audit entry limit"));
    }
    let boot = volume.boot();
    let n = boot.clusters as usize;
    if n > limits.clusters {
        return Err(budget("exFAT audit cluster limit"));
    }
    // Owner byte plus worst-case free-range records; queue/inventories remain
    // covered by their decoder leases. Finding messages and IDs are bounded.
    let charge = (n as u64)
        .checked_mul(32)
        .and_then(|v| v.checked_add((limits.findings as u64).checked_mul(1024)?))
        .and_then(|v| v.checked_add((limits.entries as u64).checked_mul(128)?))
        .and_then(|v| v.checked_add(256))
        .ok_or_else(|| budget("exFAT audit accounting overflow"))?;
    let reservation = resources.memory.reserve(charge)?;
    let mut owners = allocate(n)?;
    owners.resize(n, 0);
    let mut state = State {
        owners,
        findings: allocate(limits.findings)?,
        limits,
        work: 0,
        slots: 0,
        complete: true,
    };
    let root = volume.root_directory(resources)?;
    for cluster in volume.audit_system_clusters() {
        state.claim(cluster, false, resources)?;
    }
    for &cluster in root.allocation_clusters() {
        state.owners[(cluster - 2) as usize] |= 2;
    }
    state.directory(&root, boot.cluster_bytes, resources)?;
    let mut queue = VecDeque::new();
    queue
        .try_reserve(limits.entries)
        .map_err(|_| budget("exFAT audit queue allocation"))?;
    queue.push_back(root);
    let mut objects = 1;
    while let Some(directory) = queue.pop_front() {
        for entry in directory.entries() {
            state.tick(1, resources)?;
            if objects == limits.entries {
                return Err(budget("exFAT audit entry limit"));
            }
            objects += 1;
            // Charge attempted chain traversal too, including malformed chains.
            let expected = entry.len().div_ceil(u64::from(boot.cluster_bytes));
            let attempts = usize::try_from(expected)
                .map_err(|_| budget("exFAT audit allocation work overflow"))?;
            state.tick(attempts, resources)?;
            let mut duplicate = false;
            let allocation = volume.audit_allocation(entry, resources, |cluster| {
                duplicate |= state.claim(cluster, entry.is_directory(), resources)?;
                Ok(())
            });
            if let Err(error) = allocation {
                if error.kind != ErrorKind::InvalidData {
                    return Err(error);
                }
                state.complete = false;
                state.finding(ExfatAuditFinding::InvalidObject {
                    identity: entry.identity().clone(),
                    message: error.to_string(),
                })?;
                continue;
            }
            if entry.is_directory() {
                if duplicate {
                    state.complete = false;
                    state.finding(ExfatAuditFinding::DuplicateDirectory {
                        identity: entry.identity().clone(),
                    })?;
                    continue;
                }
                let slots = usize::try_from(entry.len() / 32)
                    .map_err(|_| budget("exFAT audit directory slot overflow"))?;
                state.slots = state
                    .slots
                    .checked_add(slots)
                    .filter(|&n| n <= limits.directory_slots)
                    .ok_or_else(|| budget("exFAT audit directory slot limit"))?;
                state.tick(slots, resources)?;
                match volume.audit_directory(entry, resources) {
                    Ok(child) => {
                        queue.push_back(child);
                    }
                    Err(error) if error.kind == ErrorKind::InvalidData => {
                        state.complete = false;
                        state.finding(ExfatAuditFinding::InvalidObject {
                            identity: entry.identity().clone(),
                            message: error.to_string(),
                        })?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    let mut free = allocate(n)?;
    let mut allocated = 0;
    let mut owned = 0;
    let mut bad = 0;
    for i in 0..n {
        state.tick(1, resources)?;
        let cluster = i as u32 + 2;
        let (used, fat) = volume.audit_cluster_state(cluster, resources)?;
        allocated += usize::from(used);
        if state.owners[i] & 1 != 0 {
            owned += 1;
            if !used {
                state.finding(ExfatAuditFinding::ReferencedFree { cluster })?;
            }
        } else if fat == 0xffff_fff7 {
            bad += 1;
            if !used {
                state.finding(ExfatAuditFinding::BadClusterFree { cluster })?;
            }
        } else if used && state.complete {
            state.finding(ExfatAuditFinding::LostAllocation { cluster })?;
        }
        if !used && fat != 0xffff_fff7 && state.owners[i] == 0 {
            let offset = boot.cluster_offset(cluster)?;
            if let Some(last) = free
                .last_mut()
                .filter(|last: &&mut ExfatFreeRange| last.offset + last.length == offset)
            {
                last.length += u64::from(boot.cluster_bytes);
            } else {
                free.push(ExfatFreeRange {
                    offset,
                    length: u64::from(boot.cluster_bytes),
                });
            }
        }
    }
    let calculated = (allocated as u64 * 100 / n as u64) as u8;
    if let Some(recorded) = boot
        .percent_in_use
        .filter(|&recorded| recorded != calculated)
    {
        state.finding(ExfatAuditFinding::PercentInUse {
            recorded,
            calculated,
        })?;
    }
    volume.check_stability(resources)?;
    if !state.complete || !state.findings.is_empty() {
        free.clear();
    }
    Ok(ExfatAuditReport {
        findings: state.findings,
        free,
        complete: state.complete,
        objects,
        allocated,
        owned,
        bad,
        work: state.work,
        _reservation: reservation,
    })
}
