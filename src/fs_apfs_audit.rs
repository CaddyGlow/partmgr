//! Complete selected-profile APFS container allocation/reference proof. No repair authority.
use crate::{
    fs_apfs::{
        index::{self, TreeKind},
        *,
    },
    fs_core::*,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[path = "fs_apfs_retention.rs"]
mod retention;
pub use retention::{ApfsRetainedBlock, ApfsRetentionProof, prove_apfs_retention};
/// Explicit global audit work, ownership and report ceilings.
#[derive(Clone, Copy, Debug)]
pub struct ApfsAuditLimits {
    /// Maximum physical container blocks.
    pub blocks: u64,
    /// Maximum namespace objects and occurrences.
    pub objects: usize,
    /// Maximum namespace directory depth.
    pub depth: usize,
    /// Maximum allocation/reference visits and metadata bytes read.
    pub work: u64,
    /// Maximum retained findings; exhaustion fails instead of truncating.
    pub findings: usize,
}
/// A supported-profile allocation or reference defect. Every defect suppresses free ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApfsAuditFinding {
    /// Physical storage has conflicting owners.
    CrossLink {
        /// Native container block.
        block: u64,
    },
    /// An owner references a free native bitmap bit.
    ReferencedFree {
        /// Native container block.
        block: u64,
    },
    /// Native allocation has no supported-profile owner.
    LostAllocation {
        /// Native container block.
        block: u64,
    },
    /// Native inode, stream allocation, namespace, link or extent-reference mismatch.
    Reference {
        /// Native inode, or zero for container metadata.
        inode: u64,
    },
    /// Block-zero copy does not match the selected published checkpoint.
    CheckpointCopy,
}
/// Retained complete accepted-profile proof, without durable discard or mutation authority.
pub struct ApfsAuditReport {
    findings: Vec<ApfsAuditFinding>,
    free: Vec<LogicalExtent>,
    allocated: u64,
    owners: Vec<NativeOwner>,
    bitmap: Vec<bool>,
    pending: Vec<bool>,
    internal_bitmap: Vec<bool>,
    internal_owners: Vec<bool>,
    internal_live: Vec<bool>,
    work: u64,
    objects: usize,
    _lease: Reservation,
}
impl ApfsAuditReport {
    /// All allocation and native references required by the explicitly accepted profile were visited.
    pub fn is_complete(&self) -> bool {
        true
    }
    /// Complete proof without findings.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
    /// Bounded native defects.
    pub fn findings(&self) -> &[ApfsAuditFinding] {
        &self.findings
    }
    /// Physical byte ranges free in the selected checkpoint, empty on any defect.
    pub fn free_ranges(&self) -> &[LogicalExtent] {
        &self.free
    }
    /// Allocated container bitmap blocks, including reserved pools and checkpoint areas.
    pub fn allocated_blocks(&self) -> u64 {
        self.allocated
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct NativeOwner {
    kind: u8,
    volume: u64,
    object: u64,
    logical: u64,
}
struct Audit<'a> {
    r: &'a Resources,
    limits: ApfsAuditLimits,
    used: u64,
    findings: Vec<ApfsAuditFinding>,
    owners: Vec<NativeOwner>,
}
impl Audit<'_> {
    fn tick(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.used = self
            .used
            .checked_add(n)
            .ok_or_else(|| budget("APFS audit work overflow"))?;
        if self.used > self.limits.work {
            return Err(budget("APFS audit work ceiling"));
        }
        Ok(())
    }
    fn finding(&mut self, f: ApfsAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("APFS audit findings ceiling"));
        }
        self.findings.push(f);
        Ok(())
    }
    fn claim(&mut self, start: u64, count: u64) -> Result<()> {
        self.claim_owner(
            start,
            count,
            NativeOwner {
                kind: 1,
                volume: 0,
                object: 0,
                logical: 0,
            },
        )
    }
    fn claim_owner(&mut self, start: u64, count: u64, owner: NativeOwner) -> Result<()> {
        range(start, count, self.owners.len() as u64)?;
        self.tick(count)?;
        for b in start..start + count {
            let mut owner = owner;
            if matches!(owner.kind, 3 | 4) && owner.logical != u64::MAX {
                owner.logical = owner
                    .logical
                    .checked_add((b - start) * 4096)
                    .ok_or_else(|| bad("APFS ownership logical range"))?;
            }
            if self.owners[b as usize].kind != 0
                && !(matches!(owner.kind, 3 | 4) && self.owners[b as usize] == owner)
            {
                self.finding(ApfsAuditFinding::CrossLink { block: b })?;
            }
            self.owners[b as usize] = owner;
        }
        Ok(())
    }
}
fn bit(b: &[u8], n: usize) -> bool {
    b[n / 8] & (1 << (n % 8)) != 0
}
/// Decode one checkpoint's complete volume and allocation ownership before union.
/// Snapshots, active free queues and reaping remain unsupported.
fn audit_checkpoint(
    volume: &ApfsVolume,
    limits: ApfsAuditLimits,
    r: &Resources,
) -> Result<ApfsAuditReport> {
    volume.revalidate(&volume.root_identity(), r)?;
    let c = volume.container();
    let blocks = c.checkpoint().blocks;
    if blocks > limits.blocks
        || volume.inner.nodes.len() > limits.objects
        || volume
            .inner
            .nodes
            .values()
            .map(|n| n.entries.len())
            .sum::<usize>()
            > limits.objects
    {
        return Err(budget("APFS audit blocks/objects ceiling"));
    }
    if c.inner.mappings.iter().any(|m| {
        m.volume != 0
            || !matches!(
                (m.object_type, m.subtype),
                (0x80000005, 0) | (0x80000011, 0) | (0x80000002, 9)
            )
    }) {
        return Err(unsupported(
            "APFS uninspectable checkpoint ephemeral objects",
        ));
    }
    let charge = blocks
        .checked_mul(193)
        .and_then(|n| n.checked_add((limits.objects as u64).checked_mul(4096)?))
        .and_then(|n| n.checked_add((limits.findings as u64).checked_mul(64)?))
        .and_then(|n| n.checked_add(256 * 1024))
        .ok_or_else(|| budget("APFS audit charge"))?;
    let lease = r.memory.reserve(charge)?;
    let mut owners = vector(blocks as usize)?;
    owners.resize(blocks as usize, NativeOwner::default());
    let mut a = Audit {
        r,
        limits: ApfsAuditLimits {
            work: limits.work / 2,
            ..limits
        },
        used: 0,
        findings: vector(limits.findings)?,
        owners,
    };
    let h = &c.inner.header;
    if u64le(&c.inner.boot, 16) == c.checkpoint().xid
        && (c.inner.boot[8..984] != h[8..984]
            || c.inner.boot[1240..1264] != h[1240..1264]
            || c.inner.boot[1272..] != h[1272..])
    {
        a.finding(ApfsAuditFinding::CheckpointCopy)?;
    }
    if h[1240..1256].iter().any(|v| *v != 0)
        || u64le(h, 1256) != 0
        || u64le(h, 1272) != 0
        || h[1376..].iter().any(|v| *v != 0)
    {
        return Err(unsupported(
            "APFS complete audit blocked/eviction/EFI/keylocker/new container structures",
        ));
    }
    a.claim(0, 1)?;
    a.claim(u64le(h, 112), u64::from(u32le(h, 104)))?;
    a.claim(u64le(h, 120), u64::from(u32le(h, 108)))?;
    let sm_mapping = c
        .inner
        .mappings
        .iter()
        .find(|m| m.volume == 0 && m.oid == c.checkpoint().space_manager)
        .unwrap();
    let sm = &c
        .inner
        .bindings
        .iter()
        .find(|(at, _)| *at == sm_mapping.address)
        .unwrap()
        .1;
    if u32le(sm, 32) != 4096
        || u32le(sm, 36) != 32768
        || u32le(sm, 40) != 126
        || u32le(sm, 44) != 507
        || u64le(sm, 48) != blocks
        || sm[96..128]
            .iter()
            .chain(sm[132..144].iter())
            .any(|v| *v != 0)
        || u32le(sm, 144) != 0
        || u32le(sm, 148) != 16
        || u64le(sm, 184) != 0
        || u64le(sm, 192) != 0
    {
        return Err(unsupported(
            "APFS single-store unversioned space-manager profile",
        ));
    }
    let ipcount = u64le(sm, 152);
    let ipbitmap_size = u32le(sm, 160);
    let ipbitmap_count = u32le(sm, 164);
    let bitmapbase = u64le(sm, 168);
    let ipbase = u64le(sm, 176);
    if ipcount == 0 || ipcount > 32768 || ipbitmap_size != 1 || ipbitmap_count != 16 {
        return Err(unsupported("APFS single internal-pool bitmap profile"));
    }
    a.claim(bitmapbase, u64::from(ipbitmap_count))?;
    a.claim(ipbase, ipcount)?;
    let xoff = u32le(sm, 324) as usize;
    let boff = u32le(sm, 328) as usize;
    let foff = u32le(sm, 332) as usize;
    if xoff < 336
        || xoff.checked_add(8).is_none_or(|n| n > 4096)
        || boff < 336
        || boff.checked_add(2).is_none_or(|n| n > 4096)
        || foff < 336
        || foff.checked_add(32).is_none_or(|n| n > 4096)
    {
        return Err(bad("APFS internal pool arrays bounds"));
    }
    let index = u16::from_le_bytes(sm[boff..boff + 2].try_into().unwrap()) as usize;
    if index >= 16 || u64le(sm, xoff) != c.checkpoint().xid {
        return Err(bad("APFS active internal-pool bitmap transaction"));
    }
    if u16::from_le_bytes(
        sm[foff + index * 2..foff + index * 2 + 2]
            .try_into()
            .unwrap(),
    ) != 65535
    {
        return Err(bad("APFS active bitmap listed as free"));
    }
    let mut free_indexes = BTreeSet::new();
    let mut next = u16::from_le_bytes(sm[320..322].try_into().unwrap());
    let tail = u16::from_le_bytes(sm[322..324].try_into().unwrap());
    let mut last = 65535;
    while next != 65535 {
        a.tick(1)?;
        if next >= 16 || usize::from(next) == index || !free_indexes.insert(next) {
            return Err(bad("APFS internal-pool bitmap free list"));
        }
        last = next;
        next = u16::from_le_bytes(
            sm[foff + usize::from(next) * 2..foff + usize::from(next) * 2 + 2]
                .try_into()
                .unwrap(),
        );
    }
    if free_indexes.len() != 15 || last != tail {
        return Err(bad("APFS internal-pool bitmap partition"));
    }
    let mut w = Work {
        limits: ApfsReadLimits {
            work: c.inner.limits.work.min(limits.work / 2),
            ..c.inner.limits
        },
        used: 0,
    };
    let ipbitmap = read_block(
        c.inner.source.as_ref(),
        bitmapbase + index as u64,
        blocks,
        &mut w,
        r,
    )?;
    let mut ipowners = vector(ipcount as usize)?;
    ipowners.resize(ipcount as usize, false);
    let chunks = u64le(sm, 56);
    let cib_count = u32le(sm, 64) as usize;
    let cab_count = u32le(sm, 68);
    let expected_ip = chunks
        .checked_add(cib_count as u64)
        .and_then(|n| n.checked_add(u64::from(cab_count)))
        .and_then(|n| n.checked_mul(3))
        .ok_or_else(|| bad("APFS internal-pool count overflow"))?;
    if ipcount != expected_ip {
        return Err(bad(
            "APFS internal-pool size disagrees with chunk/CIB/CAB topology",
        ));
    }
    let address_offset = u32le(sm, 80) as usize;
    if chunks != blocks.div_ceil(32768)
        || cib_count != chunks.div_ceil(126) as usize
        || cab_count != 0
        || address_offset < 336
        || address_offset
            .checked_add(cib_count * 8)
            .is_none_or(|n| n > 4096)
    {
        return Err(unsupported("APFS direct chunk-information block profile"));
    }
    let intervals = [
        (xoff, xoff + 8),
        (boff, boff + 2),
        (foff, foff + 32),
        (address_offset, address_offset + cib_count * 8),
    ];
    for (i, (start, end)) in intervals.iter().enumerate() {
        for (other_start, other_end) in intervals.iter().skip(i + 1) {
            if start < other_end && other_start < end {
                return Err(bad("APFS overlapping spaceman arrays"));
            }
        }
    }
    let mut bitmap = vector(blocks as usize)?;
    bitmap.resize(blocks as usize, false);
    let mut covered = 0u64;
    let mut totalfree = 0u64;
    let mut pool_owner = |address: u64| -> Result<()> {
        range(address, 1, blocks)?;
        if address < ipbase || address >= ipbase + ipcount {
            return Err(unsupported("APFS chunk metadata outside internal pool"));
        }
        let p = (address - ipbase) as usize;
        if ipowners[p] {
            return Err(bad("APFS shared internal-pool metadata"));
        }
        ipowners[p] = true;
        Ok(())
    };
    for n in 0..cib_count {
        a.tick(1)?;
        let at = u64le(sm, address_offset + n * 8);
        pool_owner(at)?;
        let cib = read_block(c.inner.source.as_ref(), at, blocks, &mut w, r)?;
        check_object(&cib, Some(at), c.checkpoint().xid, Some(0x40000007))?;
        let count = u32le(&cib, 36) as usize;
        if u32le(&cib, 32) != n as u32 || count == 0 || count > 126 {
            return Err(bad("APFS chunk-information index/count"));
        }
        for i in 0..count {
            let p = 40 + i * 32;
            let xid = u64le(&cib, p);
            let start = u64le(&cib, p + 8);
            let count = u64::from(u32le(&cib, p + 16));
            let free = u64::from(u32le(&cib, p + 20));
            let bm = u64le(&cib, p + 24);
            if xid == 0
                || xid > c.checkpoint().xid
                || start != covered
                || covered >= blocks
                || count != blocks.saturating_sub(covered).min(32768)
                || free > count
            {
                return Err(bad("APFS chunk geometry/transaction/free count"));
            }
            if bm == 0 {
                if free != count {
                    return Err(bad("APFS absent allocated chunk bitmap"));
                }
            } else {
                pool_owner(bm)?;
                let bits = read_block(c.inner.source.as_ref(), bm, blocks, &mut w, r)?;
                let mut observed = 0;
                for j in 0..count {
                    a.tick(1)?;
                    let allocated = bit(&bits, j as usize);
                    bitmap[(start + j) as usize] = allocated;
                    if !allocated {
                        observed += 1;
                    }
                }
                if observed != free {
                    return Err(bad("APFS chunk free count bitmap disagreement"));
                }
            }
            totalfree += free;
            covered += count;
        }
    }
    if covered != blocks || totalfree != u64le(sm, 72) {
        return Err(bad("APFS device chunk coverage/free count"));
    }
    for (i, owned) in ipowners.iter().enumerate() {
        a.tick(1)?;
        if *owned && !bit(&ipbitmap, i) {
            a.finding(ApfsAuditFinding::Reference { inode: 0 })?;
        }
    }
    if c.inner
        .mappings
        .iter()
        .any(|m| m.subtype == 9 && !(0..3).any(|i| m.oid == u64le(sm, 208 + i * 40)))
    {
        return Err(unsupported("APFS unreferenced checkpoint free queue"));
    }
    let mut live_ip = vector(ipcount as usize)?;
    live_ip.extend_from_slice(&ipowners);
    let mut pending = vector(blocks as usize)?;
    pending.resize(blocks as usize, false);
    for i in 0..3 {
        let p = 200 + i * 40;
        let count = u64le(sm, p);
        let oid = u64le(sm, p + 8);
        let oldest = u64le(sm, p + 16);
        if sm[p + 26..p + 40].iter().any(|v| *v != 0) {
            return Err(bad("APFS free queue reserved fields"));
        }
        if i == 2
            && (count != 0
                || oid != 0
                || oldest != 0
                || u16::from_le_bytes(sm[p + 24..p + 26].try_into().unwrap()) != 0)
        {
            return Err(unsupported("APFS tier2 free queue"));
        }
        if oid == 0 {
            if count != 0 || oldest != 0 {
                return Err(bad("APFS free queue absent tree"));
            }
            continue;
        }
        let tree = index::tree(c, oid, 0x80000000, TreeKind::FreeQueue, None, &mut w, r)?;
        let node_limit = u16::from_le_bytes(sm[p + 24..p + 26].try_into().unwrap()) as usize;
        if tree.pages.len() > node_limit {
            return Err(budget("APFS native free queue node limit"));
        }
        let mut observed = 0u64;
        let mut first = 0u64;
        for record in tree.records {
            a.tick(1)?;
            if record.key.len() != 16 {
                return Err(bad("APFS free queue key size"));
            }
            let xid = u64le(&record.key, 0);
            let address = u64le(&record.key, 8);
            let length = match record.value.len() {
                0 => 1,
                8 => {
                    let n = u64le(&record.value, 0);
                    if n <= 1 {
                        return Err(bad("APFS explicit free queue length"));
                    }
                    n
                }
                _ => return Err(bad("APFS free queue value size")),
            };
            if xid == 0 || xid > c.checkpoint().xid {
                return Err(bad("APFS retirement transaction"));
            }
            range(address, length, blocks)?;
            observed = observed
                .checked_add(length)
                .ok_or_else(|| budget("APFS queued block count overflow"))?;
            if observed > blocks {
                return Err(budget("APFS queued block ceiling"));
            }
            first = if first == 0 { xid } else { first.min(xid) };
            for block in address..address + length {
                a.tick(1)?;
                let inside = block >= ipbase && block < ipbase + ipcount;
                if inside != (i == 0) {
                    return Err(bad("APFS free queue IP/main domain"));
                }
                if i == 0 {
                    let index = (block - ipbase) as usize;
                    if ipowners[index] || !bit(&ipbitmap, index) {
                        return Err(bad("APFS queued IP duplicate/current/free block"));
                    }
                    ipowners[index] = true;
                } else {
                    let index = block as usize;
                    if pending[index] || !bitmap[index] {
                        return Err(bad("APFS queued main duplicate/free block"));
                    }
                    pending[index] = true;
                }
            }
        }
        if observed != count || first != oldest {
            return Err(bad("APFS free queue count/oldest transaction"));
        }
    }
    let reaper = c
        .inner
        .bindings
        .iter()
        .find(|(at, _)| {
            c.inner
                .mappings
                .iter()
                .any(|m| m.address == *at && m.object_type == 0x80000011)
        })
        .unwrap();
    if reaper.1[48..64].iter().any(|v| *v != 0)
        || u32le(&reaper.1, 68) != 0
        || reaper.1[72..104].iter().any(|v| *v != 0)
    {
        return Err(unsupported("APFS active reaper profile"));
    }
    let mut common_pages = BTreeSet::new();
    let container_pages: BTreeSet<_> = volume
        .inner
        .pages
        .iter()
        .take(volume.inner.container_page_count)
        .map(|(at, _)| *at)
        .collect();
    let mut total_objects = 0usize;
    let mut volume_uuids = BTreeSet::new();
    for &oid in &c.checkpoint().volumes {
        r.cancellation.check()?;
        let peer = if oid == volume.inner.oid {
            volume.clone()
        } else {
            ApfsVolume::open_bounded(c.clone(), oid, a.limits.work.saturating_sub(a.used), r)?
        };
        if !volume_uuids.insert(peer.inner.header[240..256].to_vec()) {
            a.finding(ApfsAuditFinding::Reference { inode: 0 })?;
        }
        if oid != volume.inner.oid {
            a.tick(peer.inner.decode_work)?;
        }
        total_objects = total_objects
            .checked_add(peer.inner.nodes.len())
            .and_then(|n| {
                n.checked_add(
                    peer.inner
                        .nodes
                        .values()
                        .map(|i| i.entries.len())
                        .sum::<usize>(),
                )
            })
            .ok_or_else(|| budget("APFS aggregate volume object count"))?;
        if total_objects > limits.objects {
            return Err(budget("APFS aggregate volume objects ceiling"));
        }
        audit_volume(&peer, &mut a, &mut common_pages, &container_pages)?;
    }
    let mut allocated = 0;
    for (i, b) in bitmap.iter().enumerate() {
        a.tick(1)?;
        if *b {
            allocated += 1;
        } else if a.owners[i].kind != 0 {
            a.finding(ApfsAuditFinding::ReferencedFree { block: i as u64 })?;
        }
    }
    let mut free = vector(blocks as usize)?;
    if a.findings.is_empty() {
        let mut i = 0;
        while i < bitmap.len() {
            if bitmap[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i < bitmap.len() && !bitmap[i] {
                i += 1;
            }
            free.push(LogicalExtent {
                offset: start as u64 * 4096,
                length: (i - start) as u64 * 4096,
                kind: ExtentKind::Hole,
            });
        }
    }
    let mut internal_bitmap = vector(blocks as usize)?;
    internal_bitmap.resize(blocks as usize, false);
    let mut internal_owners = vector(blocks as usize)?;
    internal_owners.resize(blocks as usize, false);
    let mut internal_live = vector(blocks as usize)?;
    internal_live.resize(blocks as usize, false);
    for (i, owned) in ipowners.iter().enumerate() {
        internal_owners[ipbase as usize + i] = *owned;
        internal_live[ipbase as usize + i] = live_ip[i];
        internal_bitmap[ipbase as usize + i] = bit(&ipbitmap, i);
    }
    r.cancellation.check()?;
    volume.revalidate(&volume.root_identity(), r)?;
    for (block, queued) in pending.iter().enumerate() {
        a.tick(1)?;
        if *queued && a.owners[block].kind != 0 {
            a.finding(ApfsAuditFinding::CrossLink {
                block: block as u64,
            })?;
        }
    }
    Ok(ApfsAuditReport {
        findings: a.findings,
        free,
        allocated,
        owners: a.owners,
        bitmap,
        pending,
        internal_bitmap,
        internal_owners,
        internal_live,
        objects: total_objects,
        work: a
            .used
            .checked_add(w.used)
            .ok_or_else(|| budget("APFS checkpoint work overflow"))?,
        _lease: lease,
    })
}

fn audit_volume(
    volume: &ApfsVolume,
    a: &mut Audit<'_>,
    common_pages: &mut BTreeSet<u64>,
    container_pages: &BTreeSet<u64>,
) -> Result<()> {
    let blocks = a.owners.len() as u64;
    let mut unique_pages = BTreeSet::new();
    for (address, bytes) in &volume.inner.pages {
        if !unique_pages.insert(*address) {
            a.finding(ApfsAuditFinding::CrossLink { block: *address })?;
        }
        if common_pages.insert(*address) {
            a.claim_owner(
                *address,
                1,
                NativeOwner {
                    kind: 2,
                    volume: 0,
                    logical: 0,
                    object: u64le(bytes, 8),
                },
            )?;
        } else if !container_pages.contains(address) {
            a.finding(ApfsAuditFinding::CrossLink { block: *address })?;
        }
    }
    let mut extent_origins = vector(blocks as usize)?;
    extent_origins.resize(blocks as usize, 0u64);
    let mut extent_refs = vector(blocks as usize)?;
    extent_refs.resize(blocks as usize, 0u32);
    let mut observed_refs = vector(blocks as usize)?;
    observed_refs.resize(blocks as usize, 0u32);
    let mut stream_owners = vector(blocks as usize)?;
    stream_owners.resize(blocks as usize, 0u64);
    for &(start, count, origin, refs) in &volume.inner.extent_records {
        a.tick(count)?;
        for block in start..start + count {
            if extent_origins[block as usize] != 0 {
                a.finding(ApfsAuditFinding::CrossLink { block })?;
            }
            extent_origins[block as usize] = origin;
            extent_refs[block as usize] = refs;
        }
    }
    let mut seen_streams = BTreeSet::new();

    if u64le(&volume.inner.nodes[&2].raw, 0) != 1 || u64le(&volume.inner.nodes[&3].raw, 0) != 1 {
        a.finding(ApfsAuditFinding::Reference { inode: 0 })?;
    }
    let mut references = BTreeMap::<u64, u32>::new();
    let mut directories = 0u64;
    let mut files = 0u64;
    let mut physical_payload = 0u64;
    for node in volume.inner.nodes.values() {
        a.tick(1)?;
        if node.directory {
            if node.id >= 16 {
                directories += 1;
            }
            if u32le(&node.raw, 56) as usize != node.entries.len() {
                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
            }
        } else {
            files += 1;
        }
        let mut names = BTreeSet::new();
        for e in &node.entries {
            a.tick(1)?;
            if !names.insert(&e.name) {
                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
            }
            if let Some(target) = volume.inner.nodes.get(&e.inode) {
                *references.entry(e.inode).or_default() += 1;
                if (e.kind == 4) != target.directory
                    || e.sibling.is_none() && u64le(&target.raw, 0) != node.id
                {
                    a.finding(ApfsAuditFinding::Reference { inode: e.inode })?;
                }
            } else {
                a.finding(ApfsAuditFinding::Reference { inode: e.inode })?;
            }
        }
        for stream in &node.streams {
            let first_stream = stream.inline.is_none() && seen_streams.insert(stream.id);
            let mut allocated = 0u64;
            let mut sparse = 0u64;
            for run in stream.runs.iter() {
                allocated = allocated
                    .checked_add(run.length)
                    .ok_or_else(|| bad("APFS native stream allocation overflow"))?;
                if run.physical != 0 {
                    let count = run.length / 4096;
                    if first_stream {
                        for block in run.physical..run.physical + count {
                            a.tick(1)?;
                            let index = block as usize;
                            // Reserved root owner2 is only justified by an actual
                            // current root xattr mapping, processed before user inodes.
                            if extent_origins[index] == 2
                                && (stream.kind == StreamKind::Data
                                    || node.id != 2 && observed_refs[index] == 0)
                            {
                                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
                            }
                            if extent_origins[index] == 0 {
                                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
                            }
                            if stream.kind == crate::fs_core::StreamKind::Data
                                && extent_refs[index] > 1
                                && u64le(&node.raw, 48) & 0x410 == 0
                            {
                                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
                            }
                            if stream_owners[index] != stream.id {
                                if observed_refs[index] == 0 {
                                    physical_payload = physical_payload
                                        .checked_add(1)
                                        .ok_or_else(|| bad("APFS physical allocation overflow"))?;
                                }
                                observed_refs[index] = observed_refs[index]
                                    .checked_add(1)
                                    .ok_or_else(|| bad("APFS physical reference overflow"))?;
                                stream_owners[index] = stream.id;
                            }
                            a.claim_owner(
                                block,
                                1,
                                NativeOwner {
                                    kind: if stream.kind != crate::fs_core::StreamKind::Data {
                                        4
                                    } else {
                                        3
                                    },
                                    volume: volume.inner.oid,
                                    object: extent_origins[index],
                                    logical: u64::MAX,
                                },
                            )?;
                        }
                    }
                } else {
                    sparse = sparse
                        .checked_add(run.length)
                        .ok_or_else(|| bad("APFS sparse byte count overflow"))?;
                }
            }
            if allocated != stream.allocated {
                a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
            }
            if stream.kind == StreamKind::Data {
                let recorded = node
                    .attrs
                    .iter()
                    .find(|(name, _)| name == b"apfs.inode-xfield.13")
                    .map(|(_, b)| b);
                if recorded.is_some_and(|b| b.len() != 8 || u64le(b, 0) != sparse)
                    || recorded.is_none() && sparse != 0
                    || (u64le(&node.raw, 48) & 0x200 != 0) != (sparse != 0)
                {
                    a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
                }
            }
        }
        let has_fork = node
            .streams
            .iter()
            .any(|s| s.kind == StreamKind::ResourceFork);
        if (u64le(&node.raw, 48) & 0x4000 != 0) != has_fork
            || has_fork && u64le(&node.raw, 48) & 0x8000 != 0
        {
            a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
        }
    }
    if files != u64le(&volume.inner.header, 184) || directories != u64le(&volume.inner.header, 192)
    {
        a.finding(ApfsAuditFinding::Reference { inode: 0 })?;
    }
    if physical_payload
        .checked_add(volume.inner.pages.len() as u64)
        .and_then(|n| n.checked_sub(volume.inner.container_page_count as u64 + 1))
        != Some(u64le(&volume.inner.header, 88))
    {
        a.finding(ApfsAuditFinding::Reference { inode: 0 })?;
    }
    for i in 0..blocks as usize {
        a.tick(1)?;
        if extent_refs[i] != observed_refs[i] {
            a.finding(if observed_refs[i] > extent_refs[i] {
                ApfsAuditFinding::CrossLink { block: i as u64 }
            } else {
                ApfsAuditFinding::Reference { inode: 0 }
            })?;
        }
    }
    let mut queue = VecDeque::new();
    queue.push_back((2u64, 0usize));
    let mut visited = BTreeSet::from([3]);
    while let Some((id, depth)) = queue.pop_front() {
        a.tick(1)?;
        if depth > a.limits.depth {
            return Err(budget("APFS audit namespace depth"));
        }
        if !visited.insert(id) {
            a.finding(ApfsAuditFinding::Reference { inode: id })?;
            continue;
        }
        let node = &volume.inner.nodes[&id];
        for e in &node.entries {
            if let Some(child) = volume.inner.nodes.get(&e.inode) {
                if child.directory {
                    if depth == a.limits.depth {
                        return Err(budget("APFS child directory depth"));
                    }
                    queue.push_back((e.inode, depth + 1));
                } else {
                    visited.insert(e.inode);
                }
            }
        }
    }
    for node in volume.inner.nodes.values() {
        if !visited.contains(&node.id)
            || node.id >= 16
                && references.get(&node.id).copied().unwrap_or(0)
                    != if node.directory {
                        1
                    } else {
                        u32le(&node.raw, 56)
                    }
        {
            a.finding(ApfsAuditFinding::Reference { inode: node.id })?;
        }
    }
    Ok(())
}

/// Audit every listed volume and every structurally retained checkpoint before publishing free space.
/// Unsupported historical state fails the whole proof without selecting an older checkpoint.
pub fn audit_apfs(
    volume: &ApfsVolume,
    limits: ApfsAuditLimits,
    r: &Resources,
) -> Result<ApfsAuditReport> {
    let mut report = audit_checkpoint(volume, limits, r)?;
    let c = volume.container();
    let mut remaining = limits
        .work
        .checked_sub(report.work)
        .ok_or_else(|| budget("APFS aggregate checkpoint work"))?;
    for (address, header) in &c.inner.retained_headers {
        if *address == c.checkpoint().superblock {
            continue;
        }
        r.cancellation.check()?;
        let Some(old) = c.historical(*address, header, remaining, r)? else {
            continue;
        };
        let oid = *old
            .checkpoint()
            .volumes
            .first()
            .ok_or_else(|| bad("APFS historical checkpoint has no volumes"))?;
        remaining = remaining
            .checked_sub(old.inner.discovery_work)
            .ok_or_else(|| budget("APFS historical discovery work"))?;
        let oldvolume = ApfsVolume::open_bounded(old, oid, remaining, r)?;
        remaining = remaining
            .checked_sub(oldvolume.inner.decode_work)
            .ok_or_else(|| budget("APFS historical volume work"))?;
        let history = audit_checkpoint(
            &oldvolume,
            ApfsAuditLimits {
                work: remaining,
                objects: limits.objects.saturating_sub(report.objects),
                ..limits
            },
            r,
        )?;
        remaining = remaining
            .checked_sub(history.work)
            .ok_or_else(|| budget("APFS aggregate historical work"))?;
        report.objects = report
            .objects
            .checked_add(history.objects)
            .ok_or_else(|| budget("APFS historical objects overflow"))?;
        for finding in history.findings {
            if report.findings.len() == limits.findings {
                return Err(budget("APFS aggregate findings"));
            }
            report.findings.push(finding);
        }
        for (i, owner) in history.owners.iter().enumerate() {
            r.cancellation.check()?;
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| budget("APFS historical union work"))?;
            // A historical retirement reservation is not a historical live reference.
            // Each historical queue is checked against its own immutable bitmap above;
            // only actual historical owners constrain allocation in the selected checkpoint.
            // The selected checkpoint's pending entries remain allocated and protected.
            report.internal_owners[i] |= history.internal_live[i];
            report.internal_live[i] |= history.internal_live[i];
            if owner.kind == 0 {
                continue;
            }
            if report.owners[i].kind != 0 && report.owners[i] != *owner {
                if report.findings.len() == limits.findings {
                    return Err(budget("APFS historical conflict findings"));
                }
                report
                    .findings
                    .push(ApfsAuditFinding::CrossLink { block: i as u64 });
            } else {
                report.owners[i] = *owner;
            }
        }
    }
    for (i, allocated) in report.bitmap.iter().enumerate() {
        r.cancellation.check()?;
        remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| budget("APFS aggregate bitmap work"))?;
        let owner = report.owners[i].kind != 0 || report.pending[i];
        let finding = if report.internal_owners[i] != report.internal_bitmap[i] {
            Some(ApfsAuditFinding::Reference { inode: 0 })
        } else if *allocated && !owner {
            Some(ApfsAuditFinding::LostAllocation { block: i as u64 })
        } else if !*allocated && owner {
            Some(ApfsAuditFinding::ReferencedFree { block: i as u64 })
        } else {
            None
        };
        if let Some(f) = finding {
            if report.findings.len() == limits.findings {
                return Err(budget("APFS aggregate ownership findings"));
            }
            report.findings.push(f);
        }
    }
    if !report.findings.is_empty() {
        report.free.clear();
    }
    volume.revalidate(&volume.root_identity(), r)?;
    report.work = limits.work - remaining;
    Ok(report)
}
