//! Complete bounded read-only NTFS3.1 base-record allocation and index-reference audit.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::Arc;
use crate::{
    fs_core::*,
    fs_file::ExtentKind as MapKind,
    fs_ntfs::{NtfsDirectoryLimits, NtfsFile, NtfsReadLimits, NtfsRecord, NtfsVolume},
};
/// Independent ceilings; exhaustion returns an error, never a partial free proof.
#[derive(Clone, Copy, Debug)]
pub struct NtfsAuditLimits {
    /// Maximum complete allocation clusters (backup-sector and container tails excluded).
    pub clusters: usize,
    /// Maximum declared MFT record slots.
    pub records: usize,
    /// Maximum attributes across every allocated record, including resident metadata.
    pub attributes: usize,
    /// Maximum full physical run intervals retained across all attributes.
    pub ranges: usize,
    /// Maximum index occurrences across all allocated directories.
    pub entries: usize,
    /// Maximum index-allocation blocks across all allocated directories.
    pub index_blocks: usize,
    /// Maximum B-tree and namespace traversal depth.
    pub depth: usize,
    /// Maximum deterministic record/attribute/run/bitmap/reference/sweep work units.
    pub work: usize,
    /// Maximum retained diagnostics.
    pub findings: usize,
    /// Maximum retained contiguous free ranges.
    pub free_ranges: usize,
}
/// Native attribute owner; hard-linked occurrences share this one owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsAllocationOwner {
    /// MFT record number.
    pub record: u64,
    /// Native attribute instance ID.
    pub attribute: u16,
    /// Native attribute type.
    pub kind: u32,
}
/// Verified inconsistency or unsupported state; no finding grants repair authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NtfsAuditFinding {
    /// Native dirty marker, independently of other volume flags.
    Dirty,
    /// Other volume state flags require functionality outside this profile.
    VolumeFlags {
        /// Flags excluding the dirty bit.
        flags: u16,
    },
    /// MFT allocation bitmap and FILE in-use flag disagree.
    RecordBitmap {
        /// Native record number.
        record: u64,
        /// MFT bitmap allocation bit.
        allocated: bool,
        /// FILE header flag.
        in_use: bool,
    },
    /// Required system record 0..11 is unavailable.
    MissingSystemRecord {
        /// Native system record.
        record: u64,
    },
    /// Different attribute owners overlap physical allocation.
    CrossLink {
        /// First overlapping cluster.
        cluster: u64,
        /// Contiguous overlap length in clusters.
        length: u64,
        /// First attribute owner.
        first: NtfsAllocationOwner,
        /// Second attribute owner.
        second: NtfsAllocationOwner,
    },
    /// Bitmap allocation has no owner after a complete raw-map scan.
    LostAllocation {
        /// First cluster.
        cluster: u64,
        /// Contiguous cluster length.
        length: u64,
    },
    /// Verified ownership is marked free in the volume bitmap.
    ReferencedFree {
        /// Cluster number.
        cluster: u64,
    },
    /// An index targets a record not allocated in the MFT bitmap.
    ReferenceToFreeRecord {
        /// Directory record.
        directory: u64,
        /// Target record.
        record: u64,
    },
    /// An allocated named record is not reachable through native indexes.
    UnreachableRecord {
        /// Native record.
        record: u64,
    },
    /// A directory has multiple non-DOS non-dot incoming references or a cycle.
    DirectoryAlias {
        /// Native directory record.
        record: u64,
    },
    /// A native FILE_NAME parent is unavailable, has a wrong sequence, or is not a directory.
    InvalidNameParent {
        /// Child record.
        record: u64,
        /// Stored parent record.
        parent: u64,
    },
    /// Native hard-link count disagrees with index references (DOS aliases excluded).
    LinkCount {
        /// Native record.
        record: u64,
        /// FILE link count.
        stored: u16,
        /// Index reference count.
        actual: u64,
    },
    /// FILE_NAME occurrences disagree with native hard-link count or DOS index count.
    NameCount {
        /// Native record.
        record: u64,
    },
    /// Boot pointer and mirror stream mapping or size disagree.
    MirrorGeometry,
    /// A fixed-up mirrored FILE record differs from the primary.
    MirrorRecord {
        /// Native record.
        record: u64,
    },
    /// The backup boot sector is missing or differs from the primary.
    BootMirror,
}
/// Complete-cluster free bytes only; backup sectors, metadata and all tails are excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsFreeRange {
    /// Volume-relative byte offset.
    pub offset: u64,
    /// Byte length.
    pub length: u64,
}
/// Leased evidence about a stabilized source; no discard, mutation or durability authority.
pub struct NtfsAuditReport {
    findings: Vec<NtfsAuditFinding>,
    free: Vec<NtfsFreeRange>,
    complete: bool,
    clusters: u64,
    allocated: u64,
    owned: u64,
    bad: u64,
    records: usize,
    attributes: usize,
    work: usize,
    flags: u16,
    _reservation: Reservation,
}
impl NtfsAuditReport {
    /// All retained diagnostics.
    pub fn findings(&self) -> &[NtfsAuditFinding] {
        &self.findings
    }
    /// Empty unless allocation, reference, mirrors and clean-state checks all succeed.
    pub fn free_ranges(&self) -> &[NtfsFreeRange] {
        &self.free
    }
    /// Every in-use slot and attribute plus all allocated directory indexes was inspected.
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    /// Complete and without findings; excludes journal/hibernation and recovery assurance.
    pub fn is_clean(&self) -> bool {
        self.complete && self.findings.is_empty()
    }
    /// Full allocation cluster domain.
    pub fn clusters(&self) -> u64 {
        self.clusters
    }
    /// Volume bitmap set bits in that domain.
    pub fn allocated_clusters(&self) -> u64 {
        self.allocated
    }
    /// Distinct physically owned clusters, including metadata and bad allocations.
    pub fn owned_clusters(&self) -> u64 {
        self.owned
    }
    /// Physical $BadClus::$Bad allocations; holes are not owners.
    pub fn bad_clusters(&self) -> u64 {
        self.bad
    }
    /// Parsed in-use FILE records, not namespace occurrences.
    pub fn allocated_records(&self) -> usize {
        self.records
    }
    /// All attributes inspected, including named/resident system metadata.
    pub fn attributes(&self) -> usize {
        self.attributes
    }
    /// Native volume flags inspected without rewriting the marker.
    pub fn volume_flags(&self) -> u16 {
        self.flags
    }
    /// Deterministic charged work.
    pub fn work(&self) -> usize {
        self.work
    }
}
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| budget("NTFS audit allocation"))?;
    Ok(v)
}
#[derive(Clone, Copy, Default)]
struct Record {
    present: bool,
    allocated: bool,
    directory: bool,
    sequence: u16,
    links: u16,
    names: usize,
    dos_names: usize,
    references: u64,
    dos_references: usize,
    edge_start: usize,
    edge_count: usize,
    reached: bool,
    incoming: usize,
    color: u8,
}
#[derive(Clone, Copy)]
struct Interval {
    start: u64,
    end: u64,
    owner: NtfsAllocationOwner,
    bad: bool,
}
struct State {
    limits: NtfsAuditLimits,
    work: usize,
    findings: Vec<NtfsAuditFinding>,
}
impl State {
    fn tick(&mut self, n: usize, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("NTFS audit work limit"))?;
        Ok(())
    }
    fn finding(&mut self, f: NtfsAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("NTFS audit finding limit"));
        }
        self.findings.push(f);
        Ok(())
    }
}
struct Bitmap {
    file: NtfsFile,
    page: [u8; 4096],
    page_number: u64,
    valid: usize,
}
impl Bitmap {
    fn new(file: NtfsFile, bits: usize, r: &Resources) -> Result<Self> {
        let minimum = bits.div_ceil(8) as u64;
        let maximum = minimum
            .checked_add(7)
            .ok_or_else(|| budget("NTFS bitmap size overflow"))?
            & !7;
        if file.len() < minimum || file.len() > maximum {
            return Err(invalid("NTFS bitmap logical size"));
        }
        file.visit_extents(r, &mut |e| {
            if e.kind != ExtentKind::Data {
                return Err(invalid("NTFS bitmap sparse/uninitialized"));
            }
            Ok(())
        })?;
        Ok(Self {
            file,
            page: [0; 4096],
            page_number: u64::MAX,
            valid: 0,
        })
    }
    fn bit(&mut self, bit: usize, r: &Resources) -> Result<bool> {
        let byte = (bit / 8) as u64;
        let page = byte / 4096;
        if page != self.page_number {
            let offset = page * 4096;
            self.valid = usize::try_from((self.file.len() - offset).min(4096))
                .map_err(|_| invalid("NTFS bitmap page size"))?;
            if self.file.read_at(offset, &mut self.page[..self.valid], r)? != self.valid {
                return Err(invalid("NTFS bitmap truncated"));
            }
            self.page_number = page;
        }
        let index = (byte % 4096) as usize;
        if index >= self.valid {
            return Err(invalid("NTFS bitmap bit outside stream"));
        }
        Ok(self.page[index] & (1 << (bit % 8)) != 0)
    }
}
fn stream(volume: &NtfsVolume, record: &NtfsRecord, kind: u32, r: &Resources) -> Result<NtfsFile> {
    let mut found = None;
    for a in record.audit_attributes() {
        if a.kind == kind && a.name.is_empty() && found.replace(a).is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "split NTFS audit stream",
            ));
        }
    }
    volume.audit_stream(
        record,
        found.ok_or_else(|| invalid("missing NTFS audit stream"))?,
        r,
    )
}
fn fixed_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let au = u16::from_le_bytes([a[4], a[5]]) as usize;
    let bu = u16::from_le_bytes([b[4], b[5]]) as usize;
    a.iter()
        .zip(b)
        .enumerate()
        .all(|(i, (x, y))| *x == *y || (i >= au && i < au + 2 && i >= bu && i < bu + 2))
}
/// Audit every base FILE allocation and all actual $I30 directory references.
/// Unsupported attributes/indexes fail the operation. Dirty markers are reported read-only.
/// Free proof requires complete defect-free accounting, not just namespace reachability.
pub fn audit_ntfs(
    source: Arc<dyn ReadAt>,
    read_limits: NtfsReadLimits,
    limits: NtfsAuditLimits,
    r: &Resources,
) -> Result<NtfsAuditReport> {
    r.cancellation.check()?;
    let volume = NtfsVolume::open_for_audit(source, read_limits, r)?;
    let clusters = volume.geometry().volume_bytes() / volume.geometry().cluster_bytes();
    let cluster_count =
        usize::try_from(clusters).map_err(|_| budget("NTFS cluster address space"))?;
    let record_count =
        usize::try_from(volume.record_count()).map_err(|_| budget("NTFS record address space"))?;
    if cluster_count > limits.clusters || record_count > limits.records {
        return Err(budget("NTFS audit geometry limits"));
    }
    if record_count < 16 {
        return Err(invalid("NTFS reserved MFT record domain"));
    }
    let report_charge = (limits.findings as u64)
        .checked_mul(256)
        .and_then(|n| n.checked_add((limits.free_ranges as u64).checked_mul(32)?))
        .ok_or_else(|| budget("NTFS report envelope"))?;
    let report_reservation = r.memory.reserve(report_charge)?;
    let scratch_charge = (record_count as u64)
        .checked_mul(256)
        .and_then(|n| n.checked_add((limits.ranges as u64).checked_mul(128)?))
        .and_then(|n| n.checked_add((limits.entries as u64).checked_mul(64)?))
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| budget("NTFS audit scratch envelope"))?;
    let _scratch = r.memory.reserve(scratch_charge)?;
    let mut state = State {
        limits,
        work: 0,
        findings: vector(limits.findings)?,
    };
    let mut records = vector(record_count)?;
    records.resize(record_count, Record::default());
    let mut intervals = vector(limits.ranges)?;
    let mut edges = vector(limits.entries)?;
    let mut free = vector(limits.free_ranges)?;
    let mut complete = true;
    let mut attributes = 0usize;
    let mut allocated_records = 0usize;
    let flags = volume.audit_flags();
    if flags & 1 != 0 {
        state.finding(NtfsAuditFinding::Dirty)?;
    }
    if flags & !1 != 0 {
        state.finding(NtfsAuditFinding::VolumeFlags { flags: flags & !1 })?;
    }
    if !volume.audit_boot_mirror(r)? {
        state.finding(NtfsAuditFinding::BootMirror)?;
    }
    let mft = volume.record(0, r)?;
    let mut mft_bitmap = Bitmap::new(stream(&volume, &mft, 0xb0, r)?, record_count, r)?;
    let padded_bits = usize::try_from(
        mft_bitmap
            .file
            .len()
            .checked_mul(8)
            .ok_or_else(|| budget("MFT bitmap padded bit count"))?,
    )
    .map_err(|_| budget("MFT bitmap padded address space"))?;
    for number in record_count..padded_bits {
        state.tick(1, r)?;
        if mft_bitmap.bit(number, r)? {
            return Err(invalid("NTFS MFT bitmap marks slot beyond data stream"));
        }
    }
    drop(mft);
    let bitmap_record = volume.record(6, r)?;
    let mut bitmap = Bitmap::new(stream(&volume, &bitmap_record, 0x80, r)?, cluster_count, r)?;
    drop(bitmap_record);
    for (number, slot) in records.iter_mut().enumerate() {
        state.tick(1, r)?;
        let allocated = mft_bitmap.bit(number, r)?;
        let in_use = volume.audit_slot_in_use(number as u64, r)?;
        slot.allocated = allocated;
        if allocated != in_use {
            state.finding(NtfsAuditFinding::RecordBitmap {
                record: number as u64,
                allocated,
                in_use,
            })?;
            if allocated && !in_use {
                complete = false;
            }
        }
        if number < 12 && (!allocated || !in_use) {
            state.finding(NtfsAuditFinding::MissingSystemRecord {
                record: number as u64,
            })?;
            complete = false;
        }
        if !in_use {
            continue;
        }
        let record = volume.record(number as u64, r)?;
        allocated_records += 1;
        slot.present = true;
        slot.directory = record.is_directory();
        slot.sequence = record.identity().generation as u16;
        slot.links = record.audit_links();
        slot.names = record.names().iter().filter(|n| n.namespace != 2).count();
        slot.dos_names = record.names().len() - slot.names;
        for a in record.audit_attributes() {
            state.tick(1, r)?;
            attributes = attributes
                .checked_add(1)
                .filter(|n| *n <= limits.attributes)
                .ok_or_else(|| budget("NTFS aggregate attribute limit"))?;
            if !a.nonresident {
                continue;
            }
            let mapping = volume.audit_mapping(a, r)?;
            state.tick(mapping.runs, r)?;
            if mapping.physical.len() > limits.ranges - intervals.len() {
                return Err(budget("NTFS physical range limit"));
            }
            let owner = NtfsAllocationOwner {
                record: number as u64,
                attribute: a.instance,
                kind: a.kind,
            };
            let bad = number == 8 && a.kind == 0x80 && a.name == [36, 0, 66, 0, 97, 0, 100, 0];
            for (offset, length) in &mapping.physical {
                intervals.push(Interval {
                    start: offset / volume.geometry().cluster_bytes(),
                    end: (offset + length) / volume.geometry().cluster_bytes(),
                    owner,
                    bad,
                });
            }
        }
    }
    let mut used_blocks = 0usize;
    let mut used_entries = 0usize;
    for number in 0..records.len() {
        if !records[number].present {
            continue;
        }
        state.tick(1, r)?;
        let record = volume.record(number as u64, r)?;
        for name in record.names() {
            state.tick(1, r)?;
            let valid = usize::try_from(name.parent_record)
                .ok()
                .and_then(|n| records.get(n))
                .is_some_and(|p| {
                    p.present && p.allocated && p.directory && p.sequence == name.parent_sequence
                });
            if !valid {
                state.finding(NtfsAuditFinding::InvalidNameParent {
                    record: number as u64,
                    parent: name.parent_record,
                })?;
            }
        }
        if !records[number].directory {
            continue;
        }
        let index_limits = NtfsDirectoryLimits {
            blocks: limits.index_blocks - used_blocks,
            entries: limits.entries - used_entries,
            depth: limits.depth,
        };
        let directory = volume.directory(record.identity(), index_limits, r)?;
        used_blocks = used_blocks
            .checked_add(directory.audit_blocks())
            .filter(|n| *n <= limits.index_blocks)
            .ok_or_else(|| budget("NTFS aggregate index-block limit"))?;
        state.tick(directory.audit_blocks() + directory.entries().len(), r)?;
        used_entries = used_entries
            .checked_add(directory.entries().len())
            .filter(|n| *n <= limits.entries)
            .ok_or_else(|| budget("NTFS aggregate index-entry limit"))?;
        records[number].edge_start = edges.len();
        for entry in directory.entries() {
            let target = u64::from_le_bytes(
                entry
                    .identity
                    .native
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("NTFS index identity"))?,
            );
            let index =
                usize::try_from(target).map_err(|_| invalid("NTFS index target address space"))?;
            if !records[index].allocated {
                state.finding(NtfsAuditFinding::ReferenceToFreeRecord {
                    directory: number as u64,
                    record: target,
                })?;
            }
            if entry.namespace == 2 {
                records[index].dos_references += 1;
            } else {
                records[index].references += 1;
            }
            let root_dot = number == 5 && target == 5 && entry.name == NativeName::Utf16(vec![46]);
            if entry.namespace != 2 && !root_dot {
                if records[index].directory {
                    records[index].incoming += 1;
                }
                if edges.len() == limits.entries {
                    return Err(budget("NTFS aggregate namespace entry limit"));
                }
                edges.push(index);
            }
        }
        records[number].edge_count = edges.len() - records[number].edge_start;
    }
    if !records[5].present || !records[5].directory {
        return Err(invalid("NTFS audit root unavailable"));
    }
    let mut pending = vector(record_count)?;
    pending.push((5usize, 0usize));
    records[5].reached = true;
    let mut head = 0;
    while head < pending.len() {
        let (parent, depth) = pending[head];
        head += 1;
        state.tick(1, r)?;
        for target in &edges
            [records[parent].edge_start..records[parent].edge_start + records[parent].edge_count]
        {
            state.tick(1, r)?;
            if !records[*target].reached {
                records[*target].reached = true;
                if records[*target].directory {
                    if depth >= limits.depth {
                        return Err(budget("NTFS namespace depth limit"));
                    }
                    pending.push((*target, depth + 1));
                }
            }
        }
    }
    for (number, record) in records.iter().enumerate() {
        state.tick(1, r)?;
        if !record.present {
            continue;
        }
        if record.directory && record.incoming > usize::from(number != 5) {
            state.finding(NtfsAuditFinding::DirectoryAlias {
                record: number as u64,
            })?;
        }
        if !record.reached && !(12..16).contains(&number) {
            state.finding(NtfsAuditFinding::UnreachableRecord {
                record: number as u64,
            })?;
        }
        if u64::from(record.links) != record.references {
            state.finding(NtfsAuditFinding::LinkCount {
                record: number as u64,
                stored: record.links,
                actual: record.references,
            })?;
        }
        if record.names != usize::from(record.links) || record.dos_names != record.dos_references {
            state.finding(NtfsAuditFinding::NameCount {
                record: number as u64,
            })?;
        }
    }
    let mut path = vector(record_count)?;
    for start in 0..record_count {
        if !records[start].present || !records[start].directory || records[start].color != 0 {
            continue;
        }
        records[start].color = 1;
        path.push((start, 0usize));
        while let Some((parent, next)) = path.last_mut() {
            state.tick(1, r)?;
            let parent = *parent;
            if *next == records[parent].edge_count {
                records[parent].color = 2;
                path.pop();
                continue;
            }
            let target = edges[records[parent].edge_start + *next];
            *next += 1;
            if !records[target].directory {
                continue;
            }
            match records[target].color {
                1 => state.finding(NtfsAuditFinding::DirectoryAlias {
                    record: target as u64,
                })?,
                2 => {}
                _ => {
                    if path.len() > limits.depth {
                        return Err(budget("NTFS complete namespace depth limit"));
                    }
                    records[target].color = 1;
                    path.push((target, 0));
                }
            }
        }
    }
    let mirror = volume.record(1, r)?;
    let mirror_attr = mirror
        .audit_attributes()
        .find(|a| a.kind == 0x80 && a.name.is_empty())
        .ok_or_else(|| invalid("missing MFT mirror data"))?;
    if !mirror_attr.nonresident {
        return Err(invalid("resident MFT mirror data"));
    }
    let map = volume.audit_mapping(mirror_attr, r)?;
    let copies =
        4u64.max(volume.geometry().cluster_bytes() / volume.geometry().record_bytes() as u64);
    let bytes = copies
        .checked_mul(volume.geometry().record_bytes() as u64)
        .ok_or_else(|| invalid("MFT mirror size overflow"))?;
    if copies > volume.record_count() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "MFT mirror exceeds logical MFT record profile",
        ));
    }
    if map.length != bytes
        || map.extents.first().is_none_or(|e| {
            e.kind
                != MapKind::Data(volume.audit_mirror_cluster() * volume.geometry().cluster_bytes())
        })
        || map
            .extents
            .iter()
            .any(|e| !matches!(e.kind, MapKind::Data(_)))
    {
        state.finding(NtfsAuditFinding::MirrorGeometry)?;
    } else {
        let mirror_stream = volume.audit_stream(&mirror, mirror_attr, r)?;
        for number in 0..copies {
            state.tick(1, r)?;
            let primary = volume.audit_record_bytes(number, r)?;
            let mirrored = volume.audit_mirror_bytes(&mirror_stream, number, r)?;
            if !fixed_equal(&primary, &mirrored) {
                state.finding(NtfsAuditFinding::MirrorRecord { record: number })?;
            }
        }
    }
    let sort_work = intervals
        .len()
        .checked_mul((intervals.len().max(1).ilog2() as usize) + 1)
        .ok_or_else(|| budget("NTFS interval sort work"))?;
    state.tick(sort_work, r)?;
    intervals.sort_unstable_by_key(|a| (a.start, a.end));
    let mut active: Vec<usize> = vector(intervals.len())?;
    for (index, range) in intervals.iter().enumerate() {
        state.tick(active.len() + 1, r)?;
        active.retain(|i| intervals[*i].end > range.start);
        for old in &active {
            let previous = intervals[*old];
            state.finding(NtfsAuditFinding::CrossLink {
                cluster: range.start,
                length: previous.end.min(range.end) - range.start,
                first: previous.owner,
                second: range.owner,
            })?;
        }
        active.push(index);
    }
    let mut allocated = 0u64;
    let mut owned = 0u64;
    let mut bad = 0u64;
    let mut cursor = 0usize;
    let mut owned_end = 0u64;
    let mut bad_end = 0u64;
    let mut lost_start = None;
    let mut free_start = None;
    for cluster in 0..cluster_count {
        state.tick(1, r)?;
        let c = cluster as u64;
        while cursor < intervals.len() && intervals[cursor].start <= c {
            owned_end = owned_end.max(intervals[cursor].end);
            if intervals[cursor].bad {
                bad_end = bad_end.max(intervals[cursor].end);
            }
            cursor += 1;
        }
        let set = bitmap.bit(cluster, r)?;
        let owner = c < owned_end;
        if set {
            allocated += 1;
        }
        if owner {
            owned += 1;
        }
        if c < bad_end {
            bad += 1;
        }
        if owner && !set {
            state.finding(NtfsAuditFinding::ReferencedFree { cluster: c })?;
        }
        let lost = complete && set && !owner;
        if lost {
            lost_start.get_or_insert(c);
        } else if let Some(start) = lost_start.take() {
            state.finding(NtfsAuditFinding::LostAllocation {
                cluster: start,
                length: c - start,
            })?;
        }
        let available = complete && !set && !owner && c != 0;
        if available {
            free_start.get_or_insert(c);
        } else if let Some(start) = free_start.take() {
            push_free(
                &mut free,
                start,
                c,
                volume.geometry().cluster_bytes(),
                limits.free_ranges,
            )?;
        }
    }
    if let Some(start) = lost_start {
        state.finding(NtfsAuditFinding::LostAllocation {
            cluster: start,
            length: clusters - start,
        })?;
    }
    if let Some(start) = free_start {
        push_free(
            &mut free,
            start,
            clusters,
            volume.geometry().cluster_bytes(),
            limits.free_ranges,
        )?;
    }
    if !complete || !state.findings.is_empty() {
        free.clear();
    }
    volume.audit_check_source(r)?;
    Ok(NtfsAuditReport {
        findings: state.findings,
        free,
        complete,
        clusters,
        allocated,
        owned,
        bad,
        records: allocated_records,
        attributes,
        work: state.work,
        flags,
        _reservation: report_reservation,
    })
}
fn push_free(
    free: &mut Vec<NtfsFreeRange>,
    start: u64,
    end: u64,
    cluster_bytes: u64,
    maximum: usize,
) -> Result<()> {
    if free.len() == maximum {
        return Err(budget("NTFS free range limit"));
    }
    free.push(NtfsFreeRange {
        offset: start * cluster_bytes,
        length: (end - start) * cluster_bytes,
    });
    Ok(())
}
