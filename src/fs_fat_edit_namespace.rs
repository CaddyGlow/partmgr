//! Bounded namespace changes on the exclusively owned, audited FAT volume.
use super::resize::{Planner, zeros};
use super::*;
use crate::fs_fat::{FatDirectory, FatEntry, FatFamily};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

/// Collision policy for exact caller-provided native names. No alias is generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatNamePolicy {
    /// Compare ASCII names case-insensitively; reject undecodable/non-ASCII context.
    AsciiCaseInsensitive,
    /// Caller independently verifies native OEM/Unicode case distinctness.
    /// Exact and ASCII-folded collisions still reject; no native encoding is transformed.
    CallerVerifiedNativeCaseDistinct,
}
/// Exact on-disk short alias plus optional exact VFAT UTF-16 spelling.
pub struct FatEditName {
    /// Eleven bytes including space padding and any encoded 0x05 first byte.
    pub alias: [u8; 11],
    /// Optional native long name, at most 255 UTF-16 code units.
    pub long_name: Option<Vec<u16>>,
    /// Explicit comparison contract.
    pub policy: FatNamePolicy,
}
/// Native creation fields supplied by the caller, without clock/codepage guesses.
pub struct FatCreateMetadata {
    /// Slot template. Name, first-cluster and size bytes must be zero; other fields are retained.
    /// Attributes must explicitly match file/directory kind, and volume labels are unsupported.
    pub raw: [u8; 32],
}
impl FatCreateMetadata {
    /// Explicit unknown/zero native times with the caller's exact attributes.
    pub fn zeroed(attributes: u8) -> Self {
        let mut raw = [0; 32];
        raw[11] = attributes;
        Self { raw }
    }
}
/// Native namespace operation represented by a reviewable batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatNamespaceOperation {
    /// Create a regular file.
    CreateFile,
    /// Create a directory with initialized dot entries.
    CreateDirectory,
    /// Rename or move an existing object.
    Rename,
    /// Unlink a file and release its owned chain.
    DeleteFile,
    /// Unlink an empty directory and release its owned chain.
    DeleteDirectory,
}
/// Exact operation policy and allocation changes; creation never invents aliases or times.
#[derive(Clone, Debug)]
pub struct FatNamespaceReport {
    /// Operation performed.
    pub operation: FatNamespaceOperation,
    /// New allocation including any parent directory expansion.
    pub allocated_clusters: usize,
    /// Verified owned allocation freed.
    pub freed_clusters: usize,
    /// New parent-directory clusters initialized before linking.
    pub parent_growth_clusters: usize,
    /// Native metadata fields are preserved for rename/delete; creation uses caller fields.
    pub existing_metadata_preserved: bool,
    /// Known stale FSInfo count reconciled using the complete audit.
    pub reconciled_fsinfo: bool,
    /// Explicit comparison contract, absent on delete.
    pub name_policy: Option<FatNamePolicy>,
    /// Exact new short alias, absent on unlink.
    pub alias: Option<[u8; 11]>,
    /// Exact new long spelling, with no UTF-8/OEM round trip.
    pub long_name: Option<Vec<u16>>,
}
/// Scoped immutable directory facts; no independent backend capability.
pub struct FatEditDirectory {
    identity: ObjectId,
    chain: Vec<u32>,
    ancestors: Vec<u32>,
    directory: FatDirectory,
    _reservation: Reservation,
}
impl FatEditDirectory {
    /// Editor scope and current generation. Root has an empty native slot key.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Exact decoded children excluding dots, deleted slots and volume labels.
    pub fn entries(&self) -> &[FatEntry] {
        self.directory.entries()
    }
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}
fn corrupt(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn first(raw: &[u8; 32]) -> u32 {
    u32::from(u16::from_le_bytes([raw[26], raw[27]]))
        | (u32::from(u16::from_le_bytes([raw[20], raw[21]])) << 16)
}
fn set_first(raw: &mut [u8; 32], cluster: u32) {
    raw[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    raw[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
}
fn slot(entry: &FatEntry) -> Result<u64> {
    Ok(u64::from_le_bytes(
        entry
            .identity()
            .native
            .as_slice()
            .try_into()
            .map_err(|_| corrupt("FAT namespace slot identity"))?,
    ))
}
fn eoc(g: &FatGeometry) -> u32 {
    match g.family() {
        FatFamily::Fat12 => 0xfff,
        FatFamily::Fat16 => 0xffff,
        FatFamily::Fat32 => 0x0fff_ffff,
    }
}
#[derive(Clone, Copy)]
struct Slot {
    at: u64,
    raw: [u8; 32],
}
struct Layout {
    rows: Vec<Slot>,
    capacity: usize,
    ended: Option<usize>,
    _reservation: Reservation,
}
impl<S: Storage, J: Storage> FatEditor<S, J> {
    fn check_directory(&self, directory: &FatEditDirectory, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if directory.identity.source != self.scope
            || directory.identity.generation != self.generation
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated FAT directory",
            ));
        }
        Ok(())
    }
    fn directory_chain(&self, first: Option<u32>, r: &Resources) -> Result<Vec<u32>> {
        let decoder = FatStorageDecoder::open_storage(&self.target, self.scope).map_err(native)?;
        let mut chain = Vec::new();
        chain
            .try_reserve_exact(self.limits.file_clusters)
            .map_err(exhausted)?;
        let Some(mut current) = first else {
            return Ok(chain);
        };
        let mut work = 0usize;
        loop {
            r.cancellation.check()?;
            work = work
                .checked_add(chain.len() + 1)
                .ok_or_else(|| exhausted("FAT directory traversal work overflow"))?;
            if chain.len() == self.limits.file_clusters || work > self.limits.work {
                return Err(exhausted("FAT namespace directory chain ceiling"));
            }
            if !(2..=self.geometry.cluster_count() + 1).contains(&current)
                || chain.contains(&current)
            {
                return Err(corrupt("FAT namespace invalid/cyclic directory chain"));
            }
            chain.push(current);
            let copy = self.geometry.active_fat().unwrap_or(0);
            let next = decoder.read_fat_entry(copy, current).map_err(native)?;
            if next >= eoc(&self.geometry) - 7 {
                return Ok(chain);
            }
            current = next;
        }
    }
    fn directory_slot(&self, d: &FatEditDirectory, index: usize) -> Result<u64> {
        let g = &self.geometry;
        let at = if d.chain.is_empty() {
            g.root_offset()
                .ok_or_else(|| corrupt("FAT namespace missing fixed root"))?
                + (index as u64) * 32
        } else {
            let slots = (g.cluster_bytes() / 32) as usize;
            let cluster = *d
                .chain
                .get(index / slots)
                .ok_or_else(|| invalid("FAT directory slot beyond allocation"))?;
            g.data_offset()
                + u64::from(cluster - 2) * g.cluster_bytes()
                + (index % slots) as u64 * 32
        };
        Ok(at)
    }
    fn layout(&self, d: &FatEditDirectory, r: &Resources) -> Result<Layout> {
        self.check_directory(d, r)?;
        let capacity = if d.chain.is_empty() {
            (self.geometry.root_bytes() / 32) as usize
        } else {
            d.chain
                .len()
                .checked_mul((self.geometry.cluster_bytes() / 32) as usize)
                .ok_or_else(|| exhausted("FAT namespace slot overflow"))?
        };
        let max = capacity.min(self.limits.audit.directory_slots);
        let reservation = r.memory.reserve(
            (max as u64)
                .checked_mul(crate::platform::mem::size_of::<Slot>() as u64)
                .ok_or_else(|| exhausted("FAT namespace slot reservation overflow"))?,
        )?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(max).map_err(exhausted)?;
        let mut ended = None;
        for index in 0..capacity {
            r.cancellation.check()?;
            if index == max || index >= self.limits.work {
                return Err(exhausted("FAT namespace directory slot ceiling"));
            }
            let at = self.directory_slot(d, index)?;
            let mut raw = [0; 32];
            self.target.read_exact_at(at, &mut raw).map_err(native)?;
            rows.push(Slot { at, raw });
            if raw[0] == 0 {
                ended = Some(index);
                break;
            }
        }
        Ok(Layout {
            rows,
            capacity,
            ended,
            _reservation: reservation,
        })
    }
    fn verify_dots(&self, d: &FatEditDirectory, parent: u32, r: &Resources) -> Result<()> {
        let layout = self.layout(d, r)?;
        for (index, name, cluster) in [(0, b".          ", d.chain[0]), (1, b"..         ", parent)]
        {
            let raw = &layout
                .rows
                .get(index)
                .ok_or_else(|| corrupt("FAT directory lacks dot entries"))?
                .raw;
            if &raw[..11] != name
                || raw[11] != 0x10
                || first(raw) != cluster
                || raw[28..32] != [0; 4]
            {
                return Err(corrupt("FAT directory dot topology mismatch"));
            }
        }
        Ok(())
    }
    /// Capture root (empty path) or a writable native directory with scoped checked ancestry.
    /// Dot links are validated along the path; they are never followed as authority.
    pub fn open_directory(&self, path: &[NativeName], r: &Resources) -> Result<FatEditDirectory> {
        self.ready(r)?;
        if path.len() > self.limits.audit.entries {
            return Err(exhausted("FAT namespace path ceiling"));
        }
        let charge = (self.limits.file_clusters as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add((self.limits.audit.entries as u64).checked_mul(4)?))
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| exhausted("FAT directory handle reservation overflow"))?;
        let reservation = r.memory.reserve(charge)?;
        let decoder = FatStorageDecoder::open_storage(&self.target, self.scope).map_err(native)?;
        let mut directory = decoder
            .root_directory(
                self.limits.file_clusters,
                self.limits.audit.directory_slots,
                r,
            )
            .map_err(native)?;
        directory.set_generation(self.generation);
        let chain = self.directory_chain(self.geometry.root_cluster(), r)?;
        let mut ancestors = Vec::new();
        ancestors
            .try_reserve_exact(
                self.limits
                    .audit
                    .entries
                    .checked_add(1)
                    .ok_or_else(|| exhausted("FAT directory ancestry overflow"))?,
            )
            .map_err(exhausted)?;
        if let Some(first) = chain.first() {
            ancestors.push(*first);
        }
        let mut d = FatEditDirectory {
            identity: ObjectId {
                source: self.scope,
                generation: self.generation,
                native: Vec::new(),
            },
            chain,
            ancestors,
            directory,
            _reservation: reservation,
        };
        for name in path {
            bounded_native(name)?;
            let entry = d
                .directory
                .lookup(name)
                .map_err(native)?
                .ok_or_else(|| invalid("FAT namespace directory path missing"))?;
            if !entry.is_directory() || entry.raw_metadata()[11] & 1 != 0 {
                return Err(invalid("FAT namespace requires a writable directory"));
            }
            let parent = if d.identity.native.is_empty() {
                0
            } else {
                d.chain[0]
            };
            let child_first = first(entry.raw_metadata());
            let identity = ObjectId {
                source: self.scope,
                generation: self.generation,
                native: copied(&entry.identity().native)?,
            };
            let mut directory = decoder
                .read_directory(
                    entry,
                    self.limits.file_clusters,
                    self.limits.audit.directory_slots,
                    r,
                )
                .map_err(native)?;
            directory.set_generation(self.generation);
            let chain = self.directory_chain(Some(child_first), r)?;
            if d.ancestors.contains(&child_first) {
                return Err(corrupt("FAT directory ancestry cycle"));
            }
            d.identity = identity;
            d.directory = directory;
            d.chain = chain;
            d.ancestors.push(child_first);
            self.verify_dots(&d, parent, r)?;
        }
        Ok(d)
    }
}
struct AllocationDelta<'a> {
    allocated: &'a [u32],
    freed: &'a [u32],
    free_count: u64,
}
struct Placement {
    start: usize,
    growth: usize,
}
fn placement(
    d: &FatEditDirectory,
    l: &Layout,
    count: usize,
    p: &mut Planner<'_, impl Storage>,
    g: &FatGeometry,
) -> Result<Placement> {
    let mut run = 0;
    for (i, row) in l.rows.iter().enumerate() {
        p.tick(1)?;
        if row.raw[0] == 0 {
            if l.capacity - i >= count {
                return Ok(Placement {
                    start: i,
                    growth: 0,
                });
            }
            break;
        }
        if row.raw[0] == 0xe5 {
            run += 1;
        } else {
            run = 0;
        }
        if run >= count {
            return Ok(Placement {
                start: i + 1 - count,
                growth: 0,
            });
        }
    }
    if d.chain.is_empty() {
        return Err(invalid("FAT fixed root has no contiguous free slots"));
    }
    let growth = count.div_ceil((g.cluster_bytes() / 32) as usize);
    if d.chain
        .len()
        .checked_add(growth)
        .is_none_or(|n| n > p.limits.file_clusters)
    {
        return Err(exhausted("FAT parent directory growth ceiling"));
    }
    Ok(Placement {
        start: l.capacity,
        growth,
    })
}
fn placement_budget(
    l: &Layout,
    place: &Placement,
    count: usize,
    g: &FatGeometry,
    p: &mut Planner<'_, impl Storage>,
) -> Result<()> {
    let capacity = l
        .capacity
        .checked_add(
            place
                .growth
                .checked_mul((g.cluster_bytes() / 32) as usize)
                .ok_or_else(|| exhausted("FAT namespace expanded capacity overflow"))?,
        )
        .ok_or_else(|| exhausted("FAT namespace expanded capacity overflow"))?;
    let end = place
        .start
        .checked_add(count)
        .ok_or_else(|| exhausted("FAT namespace slot span overflow"))?;
    let scanned = if l.ended.is_some_and(|old| end > old) || place.growth != 0 {
        end + usize::from(end < capacity)
    } else {
        l.rows.len()
    };
    p.tick(1)?;
    if scanned > p.limits.audit.directory_slots {
        return Err(exhausted(
            "FAT namespace publication exceeds audit directory slot ceiling",
        ));
    }
    Ok(())
}
fn metadata(raw: &[u8; 32], directory: bool) -> Result<()> {
    if raw[..11] != [0; 11]
        || raw[20..22] != [0; 2]
        || raw[26..32] != [0; 6]
        || raw[11] & 0xc8 != 0
        || (raw[11] & 16 != 0) != directory
        || raw[12] & !0x18 != 0
        || raw[13] > 199
    {
        return Err(invalid("FAT caller creation metadata profile"));
    }
    for at in [14, 22] {
        let time = u16::from_le_bytes([raw[at], raw[at + 1]]);
        if time >> 11 > 23 || (time >> 5) & 63 > 59 || time & 31 > 29 {
            return Err(invalid("FAT native creation time range"));
        }
    }
    for at in [16, 18, 24] {
        let date = u16::from_le_bytes([raw[at], raw[at + 1]]);
        if date == 0 {
            continue;
        }
        let day = date & 31;
        let month = (date >> 5) & 15;
        let year = 1980 + (date >> 9);
        let max = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
                {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        };
        if day == 0 || day > max {
            return Err(invalid("FAT native creation date range"));
        }
    }
    Ok(())
}
impl<S: Storage, J: Storage> FatEditor<S, J> {
    fn namespace_planner<'a>(&'a self, r: &'a Resources) -> Result<(Planner<'a, S>, Reservation)> {
        let charge = self
            .limits
            .affected_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add((self.limits.work as u64).checked_mul(32)?))
            .and_then(|n| n.checked_add((self.limits.file_clusters as u64).checked_mul(8)?))
            .and_then(|n| {
                n.checked_add(
                    (self.limits.undo.patches as u64)
                        .checked_mul(crate::platform::mem::size_of::<WriteRange>() as u64)?,
                )
            })
            .and_then(|n| n.checked_add(2048))
            .ok_or_else(|| exhausted("FAT namespace planning reservation overflow"))?;
        let reservation = r.memory.reserve(charge)?;
        let mut p = Planner {
            target: &self.target,
            limits: self.limits,
            resources: r,
            edits: Vec::new(),
            patches: Vec::new(),
            bytes: 0,
            work: 0,
        };
        p.edits
            .try_reserve_exact(self.limits.work)
            .map_err(exhausted)?;
        p.patches
            .try_reserve_exact(self.limits.undo.patches as usize)
            .map_err(exhausted)?;
        Ok((p, reservation))
    }
    fn free_clusters(&self, count: usize, p: &mut Planner<'_, S>) -> Result<(Vec<u32>, u64)> {
        let audit = self
            .audit
            .as_ref()
            .ok_or_else(|| invalid("FAT namespace requires current audit"))?;
        let mut chosen = Vec::new();
        chosen.try_reserve_exact(count).map_err(exhausted)?;
        let mut free = 0u64;
        for range in audit.free_ranges() {
            p.tick(1)?;
            let clusters = range.length / self.geometry.cluster_bytes();
            free = free
                .checked_add(clusters)
                .ok_or_else(|| exhausted("FAT free count overflow"))?;
            for i in 0..clusters.min(count.saturating_sub(chosen.len()) as u64) {
                p.tick(1)?;
                chosen.push(
                    ((range.offset - self.geometry.data_offset()) / self.geometry.cluster_bytes()
                        + i
                        + 2) as u32,
                );
            }
        }
        if chosen.len() != count {
            return Err(invalid("FAT namespace has insufficient free clusters"));
        }
        Ok((chosen, free))
    }
    fn link_chain(&self, chain: &[u32], last: Option<u32>, p: &mut Planner<'_, S>) -> Result<()> {
        if chain.is_empty() {
            return Ok(());
        }
        for copy in 0..self.geometry.fat_count() {
            if self
                .geometry
                .active_fat()
                .is_some_and(|active| active != copy)
            {
                continue;
            }
            if let Some(last) = last {
                p.fat(&self.geometry, copy, last, chain[0])?;
            }
            for (i, cluster) in chain.iter().copied().enumerate() {
                p.fat(
                    &self.geometry,
                    copy,
                    cluster,
                    chain.get(i + 1).copied().unwrap_or(eoc(&self.geometry)),
                )?;
            }
        }
        Ok(())
    }
    fn insert_slots(
        &self,
        d: &FatEditDirectory,
        l: &Layout,
        place: &Placement,
        slots: &[[u8; 32]],
        growth: &[u32],
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        let g = &self.geometry;
        if growth.is_empty() {
            for (i, raw) in slots.iter().enumerate() {
                let at = self.directory_slot(d, place.start + i)?;
                p.patch(at + 1, copied(&raw[1..])?)?; // retain old free/deleted first byte until publication
                p.edit(at, &raw[..1])?;
            }
            if l.ended.is_some_and(|end| place.start + slots.len() > end)
                && place.start + slots.len() < l.capacity
            {
                let at = self.directory_slot(d, place.start + slots.len())?;
                p.patch(at, vec![0])?;
            }
        } else {
            let per = (g.cluster_bytes() / 32) as usize;
            for (i, &cluster) in growth.iter().enumerate() {
                if p.bytes
                    .checked_add(g.cluster_bytes())
                    .is_none_or(|bytes| bytes > p.limits.affected_bytes)
                {
                    return Err(exhausted("FAT parent growth initialization ceiling"));
                }
                let mut body = zeros(g.cluster_bytes() as usize)?;
                for (j, raw) in slots.iter().enumerate().skip(i * per).take(per) {
                    body[(j % per) * 32..(j % per + 1) * 32].copy_from_slice(raw);
                }
                p.patch(
                    g.data_offset() + u64::from(cluster - 2) * g.cluster_bytes(),
                    body,
                )?;
            }
            if let Some(end) = l.ended {
                for index in end..l.capacity {
                    p.tick(1)?;
                    p.edit(self.directory_slot(d, index)?, &[0xe5])?;
                }
            }
            self.link_chain(growth, d.chain.last().copied(), p)?;
        }
        Ok(())
    }
    fn namespace_finish(
        &self,
        mut p: Planner<'_, S>,
        reservation: Reservation,
        first_stage: usize,
        mut report: FatNamespaceReport,
        delta: AllocationDelta<'_>,
    ) -> Result<FatEditBatch> {
        report.reconciled_fsinfo = p.fsinfo(
            &self.geometry,
            self.audit
                .as_ref()
                .expect("ready retains audit")
                .free_ranges(),
            delta.free_count,
            delta.allocated,
            delta.freed,
        )?;
        p.finish_metadata()?;
        let metadata = p.patches.len() - first_stage;
        let stages = if first_stage == 0 {
            vec![metadata]
        } else if metadata == 0 {
            vec![first_stage]
        } else {
            vec![first_stage, metadata]
        };
        Ok(FatEditBatch {
            source: self.scope,
            generation: self.generation,
            bytes: p.bytes,
            patches: p.patches,
            stages: Some(stages),
            resize: None,
            namespace: Some(report),
            _planning: reservation,
        })
    }
    /// Create a writable-parent regular file with exact caller native name/metadata and bounded data.
    pub fn plan_create_file(
        &self,
        parent: &FatEditDirectory,
        name: &FatEditName,
        metadata: &FatCreateMetadata,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.create(parent, name, metadata, Some(bytes), r)
    }
    /// Create a directory with initialized native dots and a zeroed payload tail.
    pub fn plan_create_directory(
        &self,
        parent: &FatEditDirectory,
        name: &FatEditName,
        metadata: &FatCreateMetadata,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.create(parent, name, metadata, None, r)
    }
    fn create(
        &self,
        parent: &FatEditDirectory,
        name: &FatEditName,
        meta: &FatCreateMetadata,
        bytes: Option<&[u8]>,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.check_directory(parent, r)?;
        metadata(&meta.raw, bytes.is_none())?;
        let (mut p, reservation) = self.namespace_planner(r)?;
        collision(parent, name, None, &mut p)?;
        let layout = self.layout(parent, r)?;
        if self
            .audit
            .as_ref()
            .expect("ready retains audit")
            .objects()
            .checked_add(1)
            .is_none_or(|n| n > self.limits.audit.entries)
        {
            return Err(exhausted(
                "FAT create exceeds complete audit object ceiling",
            ));
        }
        if bytes.is_none() && self.limits.audit.directory_slots < 3 {
            return Err(exhausted("FAT directory dots exceed audit slot ceiling"));
        }
        let length = bytes.map_or(0, |b| b.len() as u64);
        if length > u64::from(u32::MAX) {
            return Err(invalid("FAT create file size is not representable"));
        }
        let count = if bytes.is_none() {
            1
        } else {
            length.div_ceil(self.geometry.cluster_bytes()) as usize
        };
        if count > self.limits.file_clusters {
            return Err(exhausted("FAT create file allocation ceiling"));
        }
        let mut raw = meta.raw;
        raw[28..32].copy_from_slice(&(length as u32).to_le_bytes());
        let slot_count = name
            .long_name
            .as_ref()
            .map_or(1, |u| u.len().div_ceil(13) + 1);
        let place = placement(parent, &layout, slot_count, &mut p, &self.geometry)?;
        placement_budget(&layout, &place, slot_count, &self.geometry, &mut p)?;
        let total = count
            .checked_add(place.growth)
            .ok_or_else(|| exhausted("FAT namespace allocation overflow"))?;
        let (allocated, free) = self.free_clusters(total, &mut p)?;
        set_first(
            &mut raw,
            allocated
                .first()
                .copied()
                .filter(|_| count != 0)
                .unwrap_or(0),
        );
        let slots = name_slots(name, raw)?;
        for (i, &cluster) in allocated[..count].iter().enumerate() {
            p.tick(1)?;
            let size = self.geometry.cluster_bytes() as usize;
            if p.bytes + size as u64 > self.limits.affected_bytes {
                return Err(exhausted("FAT create initialization byte ceiling"));
            }
            let mut body = zeros(size)?;
            if let Some(bytes) = bytes {
                let start = i * size;
                let n = (bytes.len() - start).min(size);
                body[..n].copy_from_slice(&bytes[start..start + n]);
            } else {
                let mut dot = meta.raw;
                dot[11] = 16;
                dot[12] = 0;
                dot[28..32].fill(0);
                dot[..11].copy_from_slice(b".          ");
                set_first(&mut dot, cluster);
                body[..32].copy_from_slice(&dot);
                dot[..11].copy_from_slice(b"..         ");
                set_first(
                    &mut dot,
                    if parent.identity.native.is_empty() {
                        0
                    } else {
                        parent.chain[0]
                    },
                );
                body[32..64].copy_from_slice(&dot);
            }
            p.patch(
                self.geometry.data_offset()
                    + u64::from(cluster - 2) * self.geometry.cluster_bytes(),
                body,
            )?;
        }
        self.insert_slots(parent, &layout, &place, &slots, &allocated[count..], &mut p)?;
        let initialized = p.patches.len();
        self.link_chain(&allocated[..count], None, &mut p)?;
        let report = report(
            if bytes.is_some() {
                FatNamespaceOperation::CreateFile
            } else {
                FatNamespaceOperation::CreateDirectory
            },
            Some(name),
            total,
            0,
            place.growth,
            false,
        )?;
        self.namespace_finish(
            p,
            reservation,
            initialized,
            report,
            AllocationDelta {
                allocated: &allocated,
                freed: &[],
                free_count: free,
            },
        )
    }
}
fn object_slots(
    layout: &Layout,
    entry: &FatEntry,
    p: &mut Planner<'_, impl Storage>,
) -> Result<(usize, usize)> {
    let at = slot(entry)?;
    let mut index = None;
    for (i, row) in layout.rows.iter().enumerate() {
        p.tick(1)?;
        if row.at == at {
            index = Some(i);
            break;
        }
    }
    let index = index.ok_or_else(|| corrupt("FAT object slot missing from scoped parent"))?;
    if layout.rows[index].raw != *entry.raw_metadata() {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "FAT namespace metadata changed",
        ));
    }
    let long = match entry.name() {
        NativeName::Utf16(units) => units.len().div_ceil(13),
        _ => 0,
    };
    if index < long {
        return Err(corrupt("FAT long-name association precedes directory"));
    }
    let checksum = entry
        .short_name()
        .iter()
        .fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
    for ordinal in 1..=long {
        p.tick(1)?;
        let raw = &layout.rows[index - ordinal].raw;
        if raw[11] != 15
            || raw[0] != (ordinal as u8 | if ordinal == long { 0x40 } else { 0 })
            || raw[13] != checksum
        {
            return Err(corrupt("FAT long-name association mismatch"));
        }
    }
    Ok((index - long, long + 1))
}
impl<S: Storage, J: Storage> FatEditor<S, J> {
    fn child_directory(
        &self,
        parent: &FatEditDirectory,
        entry: &FatEntry,
        r: &Resources,
    ) -> Result<FatEditDirectory> {
        if !entry.is_directory() {
            return Err(invalid("FAT namespace object is not a directory"));
        }
        let n = parent
            .ancestors
            .len()
            .checked_add(1)
            .ok_or_else(|| exhausted("FAT namespace ancestry overflow"))?;
        if n > self.limits.audit.entries {
            return Err(exhausted("FAT namespace ancestry ceiling"));
        }
        let lease = r.memory.reserve(
            (self.limits.file_clusters as u64)
                .checked_mul(4)
                .and_then(|v| v.checked_add((n as u64).checked_mul(4)?))
                .and_then(|v| v.checked_add(1024))
                .ok_or_else(|| exhausted("FAT child directory reservation overflow"))?,
        )?;
        let decoder = FatStorageDecoder::open_storage(&self.target, self.scope).map_err(native)?;
        let mut directory = decoder
            .read_directory(
                entry,
                self.limits.file_clusters,
                self.limits.audit.directory_slots,
                r,
            )
            .map_err(native)?;
        directory.set_generation(self.generation);
        let chain = self.directory_chain(Some(first(entry.raw_metadata())), r)?;
        let mut ancestors = Vec::new();
        ancestors.try_reserve_exact(n).map_err(exhausted)?;
        ancestors.extend_from_slice(&parent.ancestors);
        ancestors.push(chain[0]);
        let child = FatEditDirectory {
            identity: ObjectId {
                source: self.scope,
                generation: self.generation,
                native: copied(&entry.identity().native)?,
            },
            chain,
            ancestors,
            directory,
            _reservation: lease,
        };
        self.verify_dots(
            &child,
            if parent.identity.native.is_empty() {
                0
            } else {
                parent.chain[0]
            },
            r,
        )?;
        Ok(child)
    }
    /// Rename or move one exact native object. Same-parent names may reuse their initialized slots.
    /// Metadata, content and allocation are preserved except explicit parent growth and dotdot change.
    pub fn plan_rename(
        &self,
        source: &FatEditDirectory,
        old_name: &NativeName,
        destination: &FatEditDirectory,
        new_name: &FatEditName,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.check_directory(source, r)?;
        self.check_directory(destination, r)?;
        bounded_native(old_name)?;
        let entry = source
            .directory
            .lookup(old_name)
            .map_err(native)?
            .ok_or_else(|| invalid("FAT rename source not found"))?;
        if entry.raw_metadata()[11] & 1 != 0 {
            return Err(invalid("FAT rename source is read-only"));
        }
        let (mut p, reservation) = self.namespace_planner(r)?;
        let same = source.identity == destination.identity;
        collision(
            destination,
            new_name,
            if same { Some(slot(entry)?) } else { None },
            &mut p,
        )?;
        let layout = self.layout(source, r)?;
        let (old_start, old_count) = object_slots(&layout, entry, &mut p)?;
        let slots = name_slots(new_name, *entry.raw_metadata())?;
        if same
            && entry.short_name() == &new_name.alias
            && match (entry.name(), &new_name.long_name) {
                (NativeName::Utf16(a), Some(b)) => a == b,
                (NativeName::Bytes(_), None) => true,
                _ => false,
            }
        {
            return Err(invalid("FAT rename must change the native name or parent"));
        }
        let child = if entry.is_directory() {
            Some(self.child_directory(source, entry, r)?)
        } else {
            None
        };
        if child
            .as_ref()
            .is_some_and(|child| destination.ancestors.contains(&child.chain[0]))
        {
            return Err(invalid("FAT directory move would create a cycle"));
        }
        let (allocated, free, initialized, growth) = if same && slots.len() <= old_count {
            let new_start = old_start + old_count - slots.len();
            for row in &layout.rows[old_start..new_start] {
                p.edit(row.at, &[0xe5])?;
            }
            for (row, raw) in layout.rows[new_start..old_start + old_count]
                .iter()
                .zip(&slots)
            {
                p.patch(row.at, copied(raw)?)?;
            }
            let (allocated, free) = self.free_clusters(0, &mut p)?;
            (allocated, free, 0, 0)
        } else {
            let target_layout = self.layout(destination, r)?;
            let place = placement(
                destination,
                &target_layout,
                slots.len(),
                &mut p,
                &self.geometry,
            )?;
            placement_budget(&target_layout, &place, slots.len(), &self.geometry, &mut p)?;
            let (allocated, free) = self.free_clusters(place.growth, &mut p)?;
            self.insert_slots(
                destination,
                &target_layout,
                &place,
                &slots,
                &allocated,
                &mut p,
            )?;
            let initialized = p.patches.len();
            for row in &layout.rows[old_start..old_start + old_count] {
                p.edit(row.at, &[0xe5])?;
            }
            if let Some(child) = &child {
                let parent = if destination.identity.native.is_empty() {
                    0
                } else {
                    destination.chain[0]
                };
                let at = self.directory_slot(child, 1)?;
                p.edit(at + 26, &(parent as u16).to_le_bytes())?;
                if self.geometry.family() == FatFamily::Fat32 {
                    p.edit(at + 20, &((parent >> 16) as u16).to_le_bytes())?;
                }
            }
            (allocated, free, initialized, place.growth)
        };
        let report = report(
            FatNamespaceOperation::Rename,
            Some(new_name),
            allocated.len(),
            0,
            growth,
            true,
        )?;
        self.namespace_finish(
            p,
            reservation,
            initialized,
            report,
            AllocationDelta {
                allocated: &allocated,
                freed: &[],
                free_count: free,
            },
        )
    }
    /// Unlink a writable file or an empty directory, preserving every freed payload byte.
    /// This does not recursively delete descendants or shrink the parent directory allocation.
    pub fn plan_delete(
        &self,
        parent: &FatEditDirectory,
        name: &NativeName,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.check_directory(parent, r)?;
        bounded_native(name)?;
        let entry = parent
            .directory
            .lookup(name)
            .map_err(native)?
            .ok_or_else(|| invalid("FAT delete source not found"))?;
        if entry.raw_metadata()[11] & 1 != 0 {
            return Err(invalid("FAT delete source is read-only"));
        }
        let (mut p, reservation) = self.namespace_planner(r)?;
        let layout = self.layout(parent, r)?;
        let (start, count) = object_slots(&layout, entry, &mut p)?;
        let mut freed = Vec::new();
        freed
            .try_reserve_exact(self.limits.file_clusters)
            .map_err(exhausted)?;
        if entry.is_directory() {
            let child = self.child_directory(parent, entry, r)?;
            let layout = self.layout(&child, r)?;
            for row in layout.rows.iter().skip(2) {
                p.tick(1)?;
                if row.raw[0] != 0 && row.raw[0] != 0xe5 {
                    return Err(invalid("FAT directory delete requires an empty directory"));
                }
            }
            freed.extend_from_slice(&child.chain);
        } else {
            let decoder =
                FatStorageDecoder::open_storage(&self.target, self.scope).map_err(native)?;
            let map = decoder
                .file_map(entry, self.limits.file_clusters, r)
                .map_err(native)?;
            for extent in &map.extents {
                p.tick(1)?;
                let ExtentKind::Data(at) = extent.kind else {
                    return Err(corrupt("FAT delete file non-data map"));
                };
                freed.push(
                    ((at - self.geometry.data_offset()) / self.geometry.cluster_bytes() + 2) as u32,
                );
            }
        }
        for row in &layout.rows[start..start + count] {
            p.patch(row.at, vec![0xe5])?;
        }
        let unlinked = p.patches.len();
        let sort = freed
            .len()
            .checked_mul((usize::BITS - freed.len().leading_zeros()) as usize)
            .ok_or_else(|| exhausted("FAT delete sort work overflow"))?;
        p.tick(sort)?;
        freed.sort_unstable();
        for copy in 0..self.geometry.fat_count() {
            if self
                .geometry
                .active_fat()
                .is_some_and(|active| active != copy)
            {
                continue;
            }
            for &cluster in &freed {
                p.fat(&self.geometry, copy, cluster, 0)?;
            }
        }
        let (_, free) = self.free_clusters(0, &mut p)?;
        let report = report(
            if entry.is_directory() {
                FatNamespaceOperation::DeleteDirectory
            } else {
                FatNamespaceOperation::DeleteFile
            },
            None,
            0,
            freed.len(),
            0,
            true,
        )?;
        self.namespace_finish(
            p,
            reservation,
            unlinked,
            report,
            AllocationDelta {
                allocated: &[],
                freed: &freed,
                free_count: free,
            },
        )
    }
}
fn report(
    operation: FatNamespaceOperation,
    name: Option<&FatEditName>,
    allocated: usize,
    freed: usize,
    growth: usize,
    preserved: bool,
) -> Result<FatNamespaceReport> {
    let long_name = if let Some(units) = name.and_then(|name| name.long_name.as_ref()) {
        let mut copy = Vec::new();
        copy.try_reserve_exact(units.len()).map_err(exhausted)?;
        copy.extend_from_slice(units);
        Some(copy)
    } else {
        None
    };
    Ok(FatNamespaceReport {
        operation,
        allocated_clusters: allocated,
        freed_clusters: freed,
        parent_growth_clusters: growth,
        existing_metadata_preserved: preserved,
        reconciled_fsinfo: false,
        name_policy: name.map(|n| n.policy),
        alias: name.map(|n| n.alias),
        long_name,
    })
}
fn bounded_native(name: &NativeName) -> Result<()> {
    match name {
        NativeName::Bytes(b) if b.len() == 11 => Ok(()),
        NativeName::Utf16(u) if !u.is_empty() && u.len() <= 255 => Ok(()),
        _ => Err(invalid(
            "FAT namespace requires bounded native alias or UTF16 name",
        )),
    }
}
fn validate_name(name: &FatEditName) -> Result<()> {
    for range in [0..8, 8..11] {
        let mut padding = false;
        for i in range {
            let b = name.alias[i];
            if b == b' ' {
                padding = true;
                continue;
            }
            if padding
                || (b < 0x20 && !(i == 0 && b == 5))
                || b == 0x7f
                || b"\"*+,./:;<=>?[\\]|".contains(&b)
                || b.is_ascii_lowercase()
            {
                return Err(invalid(
                    "FAT alias requires exact legal uppercase/padded native bytes",
                ));
            }
            if name.policy == FatNamePolicy::AsciiCaseInsensitive && !(0x21..=0x7e).contains(&b) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "FAT alias OEM case/encoding requires caller verification",
                ));
            }
        }
    }
    if matches!(name.alias[0], 0 | 0xe5 | b' ') {
        return Err(invalid("FAT alias empty/deleted first byte"));
    }
    if let Some(units) = &name.long_name {
        if units.is_empty()
            || units.len() > 255
            || units.first().is_some_and(|u| *u == 32)
            || units.last().is_some_and(|u| matches!(*u, 32 | 46))
            || units == &[46]
            || units == &[46, 46]
        {
            return Err(invalid("FAT long-name length/trailing/dot profile"));
        }
        if char::decode_utf16(units.iter().copied()).any(|c| c.is_err())
            || units.iter().any(|u| {
                *u < 32
                    || *u == 0xffff
                    || *u == 127
                    || [34, 42, 47, 58, 60, 62, 63, 92, 124].contains(u)
            })
        {
            return Err(invalid("FAT long-name illegal native units"));
        }
        if name.policy == FatNamePolicy::AsciiCaseInsensitive && units.iter().any(|u| *u > 127) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "FAT Unicode case comparison requires caller verification",
            ));
        }
    }
    Ok(())
}
fn display_alias(alias: &[u8; 11]) -> Result<Option<Vec<u16>>> {
    if alias.iter().any(|b| *b > 127 || *b == 5) {
        return Ok(None);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(12).map_err(exhausted)?;
    for b in alias[..8].iter().take_while(|b| **b != b' ') {
        out.push(u16::from(*b));
    }
    if alias[8] != b' ' {
        out.push(46);
        for b in alias[8..].iter().take_while(|b| **b != b' ') {
            out.push(u16::from(*b));
        }
    }
    Ok(Some(out))
}
fn folded_equal(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(&a, &b)| {
            let fold = |u: u16| if (97..=122).contains(&u) { u - 32 } else { u };
            fold(a) == fold(b)
        })
}
fn collision(
    d: &FatEditDirectory,
    name: &FatEditName,
    exclude: Option<u64>,
    p: &mut Planner<'_, impl Storage>,
) -> Result<()> {
    validate_name(name)?;
    let alias = display_alias(&name.alias)?;
    for entry in d.entries() {
        p.tick(1)?;
        if Some(slot(entry)?) == exclude {
            continue;
        }
        if matches!(entry.name(),NativeName::Utf16(u) if u.first().is_some_and(|u|*u==32)||u.last().is_some_and(|u|matches!(*u,32|46)))
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "FAT destination requires unsupported leading/trailing name normalization",
            ));
        }
        if name.policy == FatNamePolicy::AsciiCaseInsensitive
            && (entry.short_name().iter().any(|b| *b > 127 || *b == 5)
                || matches!(entry.name(),NativeName::Utf16(u) if u.iter().any(|u|*u>127)))
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "FAT destination contains unknown OEM/Unicode case context",
            ));
        }
        if entry
            .short_name()
            .iter()
            .zip(name.alias)
            .all(|(&a, b)| a.eq_ignore_ascii_case(&b))
        {
            return Err(invalid("FAT alias collision"));
        }
        let other_alias = display_alias(entry.short_name())?;
        let other_long = match entry.name() {
            NativeName::Utf16(u) => Some(u.as_slice()),
            _ => None,
        };
        for a in [alias.as_deref(), name.long_name.as_deref()]
            .into_iter()
            .flatten()
        {
            for b in [other_alias.as_deref(), other_long].into_iter().flatten() {
                if folded_equal(a, b) {
                    return Err(invalid("FAT native name/alias collision"));
                }
            }
        }
    }
    Ok(())
}
fn name_slots(name: &FatEditName, mut raw: [u8; 32]) -> Result<Vec<[u8; 32]>> {
    raw[..11].copy_from_slice(&name.alias);
    let count = name.long_name.as_ref().map_or(0, |u| u.len().div_ceil(13));
    let mut out = Vec::new();
    out.try_reserve_exact(count + 1).map_err(exhausted)?;
    if let Some(units) = &name.long_name {
        let checksum = name
            .alias
            .iter()
            .fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
        for ordinal in (1..=count).rev() {
            let mut lfn = [0; 32];
            lfn[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
            lfn[11] = 15;
            lfn[13] = checksum;
            for (part, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                let i = (ordinal - 1) * 13 + part;
                let unit = if i == units.len() {
                    0
                } else {
                    units.get(i).copied().unwrap_or(0xffff)
                };
                lfn[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            }
            out.push(lfn);
        }
    }
    out.push(raw);
    Ok(out)
}
