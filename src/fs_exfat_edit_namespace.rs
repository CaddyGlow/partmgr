//! Bounded native exFAT namespace changes under the retained exclusive-session audit.
use super::*;
use crate::fs_exfat_volume::{ExfatDirectory, ExfatEntry};
/// Caller-supplied native creation fields. Type, secondary count and checksum must be zero.
pub struct ExfatCreateMetadata {
    /// Exact primary directory entry template; attributes and native times are retained.
    pub raw: [u8; 32],
}
impl ExfatCreateMetadata {
    /// Explicit 1980-01-01 00:00:00 UTC timestamps; this never reads a host clock.
    pub fn epoch_1980(attributes: u16) -> Self {
        let mut raw = [0; 32];
        raw[4..6].copy_from_slice(&attributes.to_le_bytes());
        for at in [8, 12, 16] {
            raw[at..at + 4].copy_from_slice(&0x0021_0000u32.to_le_bytes());
        }
        raw[22..25].fill(0x80);
        Self { raw }
    }
}
/// Reviewable native namespace operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExfatNamespaceOperation {
    /// Create a regular file with initialized payload and physical tails.
    CreateFile,
    /// Create an empty, fully initialized native directory.
    CreateDirectory,
    /// Rename or move an existing object, retaining its allocation and native metadata.
    Rename,
    /// Unlink a regular file and release its verified owned allocation.
    DeleteFile,
    /// Unlink an empty directory and release its verified owned allocation.
    DeleteDirectory,
}
/// Exact namespace policy and allocation changes represented by one batch.
#[derive(Clone, Debug)]
pub struct ExfatNamespaceReport {
    /// Operation represented by this batch.
    pub operation: ExfatNamespaceOperation,
    /// New object and parent-directory allocation clusters.
    pub allocated_clusters: usize,
    /// Verified owned clusters released after unlink.
    pub freed_clusters: usize,
    /// Parent-directory clusters initialized before linking.
    pub parent_growth_clusters: usize,
    /// Existing timestamps, attributes and allocation semantics were retained.
    pub existing_metadata_preserved: bool,
    /// Exact new native UTF16 units, absent for deletion.
    pub name: Option<Vec<u16>>,
}
struct NativeSet {
    raw: Vec<[u8; 32]>,
    locations: Vec<u64>,
}
/// Generation-bound native directory facts; retains no independent backend capability.
pub struct ExfatEditDirectory {
    identity: ObjectId,
    map: Mapping,
    directory: ExfatDirectory,
    parent_set: Option<NativeSet>,
    ancestors: Vec<u32>,
    _lease: Reservation,
}
impl ExfatEditDirectory {
    /// Same-session directory identity. The implicit root has an empty native key.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Validated live entries; native names are compared through the on-volume up-case table.
    pub fn entries(&self) -> &[ExfatEntry] {
        self.directory.entries()
    }
}
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
fn vector<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("exFAT namespace allocation"))?;
    Ok(v)
}
fn copy_set(entry: &ExfatEntry) -> Result<NativeSet> {
    let mut raw = vector(entry.raw_metadata().len())?;
    raw.extend_from_slice(entry.raw_metadata());
    let mut locations = vector(raw.len())?;
    locations.extend_from_slice(entry.edit_locations());
    Ok(NativeSet { raw, locations })
}
fn readonly(raw: &[u8; 32]) -> bool {
    u16::from_le_bytes(raw[4..6].try_into().unwrap()) & 1 != 0
}
fn seal(raw: &mut [[u8; 32]]) {
    let sum = raw
        .iter()
        .flatten()
        .enumerate()
        .filter(|(i, _)| *i != 2 && *i != 3)
        .fold(0u16, |sum, (_, b)| {
            sum.rotate_right(1).wrapping_add(u16::from(*b))
        });
    raw[0][2..4].copy_from_slice(&sum.to_le_bytes());
}
fn create_metadata(raw: &[u8; 32], directory: bool) -> Result<()> {
    let attrs = u16::from_le_bytes(raw[4..6].try_into().unwrap());
    if raw[..4] != [0; 4]
        || raw[6..8] != [0; 2]
        || raw[25..] != [0; 7]
        || attrs & !0x37 != 0
        || (attrs & 0x10 != 0) != directory
        || raw[20] > 199
        || raw[21] > 199
    {
        return Err(invalid("exFAT caller creation metadata profile"));
    }
    for at in [8, 12, 16] {
        let time = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let date = time >> 16;
        let month = (date >> 5) & 15;
        let day = date & 31;
        let year = 1980 + (date >> 9);
        if time & 31 > 29
            || (time >> 5) & 63 > 59
            || (time >> 11) & 31 > 23
            || !(1..=12).contains(&month)
            || day == 0
        {
            return Err(invalid("exFAT native creation timestamp"));
        }
        let days = match month {
            4 | 6 | 9 | 11 => 30,
            2 if year.is_multiple_of(4)
                && (!year.is_multiple_of(100) || year.is_multiple_of(400)) =>
            {
                29
            }
            2 => 28,
            _ => 31,
        };
        if day > days {
            return Err(invalid("exFAT native creation calendar date"));
        }
    }
    Ok(())
}
fn named_set(
    mut primary: [u8; 32],
    mut stream: [u8; 32],
    name: &[u16],
    hash: u16,
) -> Result<Vec<[u8; 32]>> {
    let mut raw = vector(2 + name.len().div_ceil(15))?;
    primary[0] = 0x85;
    primary[1] = (1 + name.len().div_ceil(15)) as u8;
    stream[0] = 0xc0;
    stream[3] = name.len() as u8;
    stream[4..6].copy_from_slice(&hash.to_le_bytes());
    raw.extend([primary, stream]);
    for part in name.chunks(15) {
        let mut slot = [0; 32];
        slot[0] = 0xc1;
        for (i, u) in part.iter().enumerate() {
            slot[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        raw.push(slot);
    }
    seal(&mut raw);
    Ok(raw)
}
struct Row {
    at: u64,
    raw: [u8; 32],
}
struct Layout {
    rows: Vec<Row>,
    _lease: Reservation,
}
struct Placement {
    start: usize,
    chain: Vec<u32>,
    growth: Vec<u32>,
    buffers: Vec<Vec<u8>>,
    old_slots: usize,
}
impl<S: Storage, J: Storage> ExfatEditor<S, J> {
    /// Resolve a native directory, including the implicit root for an empty path.
    pub fn open_directory(&self, path: &[NativeName], r: &Resources) -> Result<ExfatEditDirectory> {
        self.ready(r)?;
        if path.len() > self.limits.audit.entries {
            return Err(budget("exFAT directory path ceiling"));
        }
        let lease = r.memory.reserve(
            (path.len() as u64)
                .checked_mul(4)
                .and_then(|n| n.checked_add(8192))
                .ok_or_else(|| budget("exFAT directory handle charge"))?,
        )?;
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        let mut directory = decoder.root_directory(r)?;
        directory.set_generation(self.generation);
        let mut ancestors = vector(path.len() + 1)?;
        ancestors.push(self.boot.root_cluster);
        if path.is_empty() {
            let map = decoder.edit_directory_map(None, r)?;
            return Ok(ExfatEditDirectory {
                identity: ObjectId {
                    source: self.scope,
                    generation: self.generation,
                    native: Vec::new(),
                },
                map,
                directory,
                parent_set: None,
                ancestors,
                _lease: lease,
            });
        }
        for (index, name) in path.iter().enumerate() {
            r.cancellation.check()?;
            let NativeName::Utf16(name) = name else {
                return Err(invalid("exFAT directory paths need native UTF16"));
            };
            let entry = directory
                .lookup(name)?
                .ok_or_else(|| invalid("exFAT directory component missing"))?;
            let map = decoder.edit_directory_map(Some(entry), r)?;
            let set = copy_set(entry)?;
            let mut native = vector(8)?;
            native.extend_from_slice(&entry.identity().native);
            ancestors.push(
                *map.clusters
                    .first()
                    .ok_or_else(|| bad("empty exFAT directory allocation"))?,
            );
            let mut next = decoder.read_directory(entry, r)?;
            next.set_generation(self.generation);
            if index + 1 == path.len() {
                return Ok(ExfatEditDirectory {
                    identity: ObjectId {
                        source: self.scope,
                        generation: self.generation,
                        native,
                    },
                    map,
                    directory: next,
                    parent_set: Some(set),
                    ancestors,
                    _lease: lease,
                });
            }
            directory = next;
        }
        unreachable!()
    }
    fn check_directory(&self, parent: &ExfatEditDirectory, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if parent.identity.source != self.scope || parent.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or stale exFAT directory",
            ));
        }
        if let Some(set) = &parent.parent_set {
            if readonly(&set.raw[0]) {
                return Err(invalid("read-only exFAT parent directory"));
            }
            for (at, raw) in set.locations.iter().zip(&set.raw) {
                let mut current = [0; 32];
                self.target
                    .read_exact_at(*at, &mut current)
                    .map_err(native)?;
                if current != *raw {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "exFAT directory owner set changed",
                    ));
                }
            }
        }
        Ok(())
    }
    fn namespace_planner<'a>(&'a self, r: &'a Resources) -> Result<(Planner<'a, S>, Reservation)> {
        let p = self.planner(r)?;
        let lease = r.memory.reserve(
            (self.limits.read.max_chain_clusters as u64)
                // Native indexes, parent buffer descriptors and bounded bitmap tree nodes.
                .checked_mul(192)
                .and_then(|n| n.checked_add(8192))
                .ok_or_else(|| budget("exFAT namespace planning charge"))?,
        )?;
        Ok((p, lease))
    }
    fn layout(&self, parent: &ExfatEditDirectory, p: &mut Planner<'_, S>) -> Result<Layout> {
        let n = usize::try_from(parent.map.file.len() / 32)
            .map_err(|_| budget("exFAT namespace slots"))?;
        if n > self.limits.read.max_directory_slots {
            return Err(budget("exFAT namespace directory ceiling"));
        }
        p.tick(n.checked_mul(2).ok_or_else(|| budget("exFAT slot work"))?)?;
        let lease = p.r.memory.reserve(
            (n as u64)
                .checked_mul(64)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("exFAT slot charge"))?,
        )?;
        let mut rows = vector(n)?;
        for i in 0..n {
            p.r.cancellation.check()?;
            let at = parent.map.physical(i as u64 * 32)?;
            let mut raw = [0; 32];
            self.target.read_exact_at(at, &mut raw).map_err(native)?;
            rows.push(Row { at, raw });
        }
        Ok(Layout {
            rows,
            _lease: lease,
        })
    }
    fn collision(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        skip: Option<u64>,
        decoder: &ExfatDecoder<&dyn Storage>,
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        decoder.edit_name_hash(name)?;
        p.tick(name.len())?;
        for entry in parent.entries() {
            p.tick(1 + entry.name().len())?;
            if skip == entry.edit_locations().first().copied() {
                continue;
            }
            if decoder.names_equal(entry.name(), name) {
                return Err(invalid("exFAT on-volume up-case name collision"));
            }
        }
        Ok(())
    }
    fn lookup_work(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        crate::fs_exfat_volume::validate_name(name)?;
        p.tick(name.len())?;
        for entry in parent.entries() {
            p.tick(1 + entry.name().len())?;
        }
        Ok(())
    }
    fn placement(
        &self,
        parent: &ExfatEditDirectory,
        layout: &Layout,
        count: usize,
        other_initialization: u64,
        taken: &mut Vec<u32>,
        p: &mut Planner<'_, S>,
    ) -> Result<Placement> {
        let mut start = 0;
        let mut run = 0;
        let mut found = None;
        for (index, row) in layout.rows.iter().enumerate() {
            if row.raw[0] < 0x80 {
                if run == 0 {
                    start = index;
                }
                run += 1;
                if run == count {
                    found = Some(start);
                    break;
                }
            } else {
                run = 0;
            }
        }
        let start = found.unwrap_or(if run != 0 { start } else { layout.rows.len() });
        let extra = start
            .checked_add(count)
            .ok_or_else(|| budget("exFAT slot count overflow"))?
            .saturating_sub(layout.rows.len());
        let growth_count = extra
            .checked_mul(32)
            .ok_or_else(|| budget("exFAT slot bytes overflow"))?
            .div_ceil(self.boot.cluster_bytes as usize);
        let total = parent
            .map
            .clusters
            .len()
            .checked_add(growth_count)
            .ok_or_else(|| budget("exFAT directory growth count"))?;
        let slots = total
            .checked_mul(self.boot.cluster_bytes as usize / 32)
            .ok_or_else(|| budget("exFAT directory growth slots"))?;
        if total > self.limits.read.max_chain_clusters
            || slots > self.limits.read.max_directory_slots
        {
            return Err(budget("exFAT parent directory expansion ceiling"));
        }
        let growth = self.take_clusters(growth_count, taken, p)?;
        let bytes = (growth_count as u64) * u64::from(self.boot.cluster_bytes);
        if p.bytes
            .checked_add(bytes)
            .and_then(|n| n.checked_add(other_initialization))
            .is_none_or(|n| n > self.limits.affected_bytes)
        {
            return Err(budget("exFAT parent initialization ceiling"));
        }
        let mut chain = vector(total)?;
        p.tick(parent.map.clusters.len())?;
        chain.extend_from_slice(&parent.map.clusters);
        chain.extend_from_slice(&growth);
        let mut buffers = vector(growth_count)?;
        for _ in &growth {
            buffers.push(zeros(self.boot.cluster_bytes as usize)?);
        }
        Ok(Placement {
            start,
            chain,
            growth,
            buffers,
            old_slots: layout.rows.len(),
        })
    }
    fn take_clusters(
        &self,
        count: usize,
        taken: &mut Vec<u32>,
        p: &mut Planner<'_, S>,
    ) -> Result<Vec<u32>> {
        if count > self.limits.read.max_chain_clusters {
            return Err(budget("exFAT new allocation ceiling"));
        }
        let mut result = vector(count)?;
        if count == 0 {
            return Ok(result);
        }
        for range in self.audit.as_ref().expect("ready audit").free_ranges() {
            let mut at = range.offset;
            while at < range.offset + range.length && result.len() < count {
                p.tick(1 + (taken.len() + 1).ilog2() as usize)?;
                let c =
                    ((at - self.boot.heap_offset) / u64::from(self.boot.cluster_bytes)) as u32 + 2;
                if taken.binary_search(&c).is_err() {
                    if taken.len() >= self.limits.read.max_chain_clusters.saturating_add(2) {
                        return Err(budget("exFAT namespace new-cluster ceiling"));
                    }
                    let i = taken.partition_point(|n| *n < c);
                    taken.insert(i, c);
                    result.push(c);
                }
                at += u64::from(self.boot.cluster_bytes);
            }
            if result.len() == count {
                break;
            }
        }
        if result.len() != count {
            return Err(budget("exFAT insufficient audited free allocation"));
        }
        Ok(result)
    }
    fn fill_new_slots(&self, place: &mut Placement, raw: &[[u8; 32]]) {
        let slots = self.boot.cluster_bytes as usize / 32;
        for (i, entry) in raw.iter().enumerate() {
            let slot = place.start + i;
            if slot >= place.old_slots {
                let relative = slot - place.old_slots;
                place.buffers[relative / slots][relative % slots * 32..relative % slots * 32 + 32]
                    .copy_from_slice(entry);
            }
        }
    }
    fn initialize_parent(&self, place: &mut Placement, p: &mut Planner<'_, S>) -> Result<()> {
        for (&c, b) in place.growth.iter().zip(std::mem::take(&mut place.buffers)) {
            p.patch(self.boot.cluster_offset(c)?, b)?;
        }
        Ok(())
    }
    fn chain(&self, clusters: &[u32], p: &mut Planner<'_, S>) -> Result<()> {
        for (i, &c) in clusters.iter().enumerate() {
            p.tick(1)?;
            p.patch(
                self.boot.fat_offset + u64::from(c) * 4,
                clusters
                    .get(i + 1)
                    .copied()
                    .unwrap_or(u32::MAX)
                    .to_le_bytes()
                    .to_vec(),
            )?;
        }
        Ok(())
    }
    fn growth_fat(
        &self,
        parent: &ExfatEditDirectory,
        place: &Placement,
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        if place.growth.is_empty() {
            return Ok(());
        }
        p.tick(place.chain.len())?;
        let contiguous = place.chain.windows(2).all(|c| c[1] == c[0] + 1);
        let old_contiguous = parent
            .parent_set
            .as_ref()
            .is_some_and(|s| s.raw[1][1] & 2 != 0);
        if parent.parent_set.is_none() || !old_contiguous {
            let old_last = *parent.map.clusters.last().unwrap();
            p.patch(
                self.boot.fat_offset + u64::from(old_last) * 4,
                place.growth[0].to_le_bytes().to_vec(),
            )?;
            self.chain(&place.growth, p)?;
        } else if !contiguous {
            self.chain(&place.chain, p)?;
        }
        Ok(())
    }
    fn bitmap(
        &self,
        clusters: &[u32],
        used: bool,
        decoder: &ExfatDecoder<&dyn Storage>,
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        let mut edits = std::collections::BTreeMap::<u64, u8>::new();
        for &c in clusters {
            p.tick(1 + (edits.len() + 1).ilog2() as usize)?;
            let (at, mask) = decoder.bitmap_position(c)?;
            if !edits.contains_key(&at) && edits.len() >= self.limits.undo.patches as usize {
                return Err(budget("exFAT bitmap publication ceiling"));
            }
            let byte = match edits.entry(at) {
                std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::btree_map::Entry::Vacant(e) => {
                    let mut b = [0];
                    self.target.read_exact_at(at, &mut b).map_err(native)?;
                    e.insert(b[0])
                }
            };
            if used {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
        for (at, b) in edits {
            p.patch(at, vec![b])?;
        }
        Ok(())
    }
    fn parent_metadata(
        &self,
        parent: &ExfatEditDirectory,
        place: &Placement,
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        if place.growth.is_empty() {
            return Ok(());
        }
        if let Some(set) = &parent.parent_set {
            p.tick(set.raw.len() + place.chain.len())?;
            let mut raw = vector(set.raw.len())?;
            raw.extend_from_slice(&set.raw);
            let length = place.chain.len() as u64 * u64::from(self.boot.cluster_bytes);
            raw[1][1] = if place.chain.windows(2).all(|c| c[1] == c[0] + 1) {
                3
            } else {
                1
            };
            raw[1][8..16].copy_from_slice(&length.to_le_bytes());
            raw[1][24..32].copy_from_slice(&length.to_le_bytes());
            seal(&mut raw);
            for (at, b) in set.locations.iter().zip(raw) {
                p.patch(*at, b.to_vec())?;
            }
        }
        Ok(())
    }
    fn publish_existing_slots(
        &self,
        place: &Placement,
        layout: &Layout,
        raw: &[[u8; 32]],
        p: &mut Planner<'_, S>,
    ) -> Result<()> {
        for (i, b) in raw.iter().enumerate() {
            let slot = place.start + i;
            if slot < place.old_slots {
                p.patch(layout.rows[slot].at, b.to_vec())?;
            }
        }
        Ok(())
    }
    fn finish_namespace(
        &self,
        mut p: Planner<'_, S>,
        lease: Reservation,
        report: ExfatNamespaceReport,
    ) -> Result<ExfatEditBatch> {
        let count = self
            .audit
            .as_ref()
            .unwrap()
            .allocated_clusters()
            .checked_add(report.allocated_clusters)
            .and_then(|n| n.checked_sub(report.freed_clusters))
            .ok_or_else(|| bad("exFAT namespace allocation count"))?;
        p.patch(
            112,
            vec![(count as u64 * 100 / u64::from(self.boot.clusters)) as u8],
        )?;
        p.stage("publish audited allocation usage");
        p.final_flags(self.boot.flags)?;
        let mut batch = p.finish(self.scope, self.generation, self.boot.flags)?;
        batch.namespace = Some(report);
        batch._namespace_lease = Some(lease);
        Ok(batch)
    }
    /// Create a regular file with exact native name, caller metadata and bounded initialized data.
    pub fn plan_create_file(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        metadata: &ExfatCreateMetadata,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.create(parent, name, metadata, Some(bytes), r)
    }
    /// Create an empty native directory; exFAT has no on-disk dot entries.
    pub fn plan_create_directory(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        metadata: &ExfatCreateMetadata,
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.create(parent, name, metadata, None, r)
    }
    fn create(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        metadata: &ExfatCreateMetadata,
        bytes: Option<&[u8]>,
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.check_directory(parent, r)?;
        create_metadata(&metadata.raw, bytes.is_none())?;
        let (mut p, lease) = self.namespace_planner(r)?;
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        self.collision(parent, name, None, &decoder, &mut p)?;
        let layout = self.layout(parent, &mut p)?;
        let mut taken = vector(
            self.limits
                .read
                .max_chain_clusters
                .checked_add(2)
                .ok_or_else(|| budget("exFAT allocation index capacity"))?,
        )?;
        let length = bytes.map_or(u64::from(self.boot.cluster_bytes), |b| b.len() as u64);
        let count = length.div_ceil(u64::from(self.boot.cluster_bytes));
        if count > self.limits.read.max_chain_clusters as u64
            || count * u64::from(self.boot.cluster_bytes) > self.limits.affected_bytes
        {
            return Err(budget("exFAT creation initialized-byte ceiling"));
        }
        let clusters = self.take_clusters(count as usize, &mut taken, &mut p)?;
        p.tick(clusters.len())?;
        let contiguous = clusters.windows(2).all(|c| c[1] == c[0] + 1);
        let mut stream = [0; 32];
        stream[1] = if length == 0 {
            1
        } else if contiguous {
            3
        } else {
            1
        };
        stream[8..16].copy_from_slice(&length.to_le_bytes());
        stream[20..24].copy_from_slice(&clusters.first().copied().unwrap_or(0).to_le_bytes());
        stream[24..32].copy_from_slice(&length.to_le_bytes());
        let raw = named_set(metadata.raw, stream, name, decoder.edit_name_hash(name)?)?;
        let mut place = self.placement(
            parent,
            &layout,
            raw.len(),
            count * u64::from(self.boot.cluster_bytes),
            &mut taken,
            &mut p,
        )?;
        self.fill_new_slots(&mut place, &raw);
        p.file_bytes(
            &self.boot,
            &clusters,
            0,
            count * u64::from(self.boot.cluster_bytes),
            bytes.map(|b| (0, b)),
        )?;
        self.initialize_parent(&mut place, &mut p)?;
        p.stage("initialize new object and parent allocation");
        if !contiguous && !clusters.is_empty() {
            self.chain(&clusters, &mut p)?;
        }
        self.growth_fat(parent, &place, &mut p)?;
        p.stage("publish new FAT mapping");
        self.bitmap(&taken, true, &decoder, &mut p)?;
        p.stage("publish new allocation bitmap");
        self.parent_metadata(parent, &place, &mut p)?;
        self.publish_existing_slots(&place, &layout, &raw, &mut p)?;
        p.stage("publish native parent and file entry sets");
        let mut native_name = vector(name.len())?;
        native_name.extend_from_slice(name);
        self.finish_namespace(
            p,
            lease,
            ExfatNamespaceReport {
                operation: if bytes.is_some() {
                    ExfatNamespaceOperation::CreateFile
                } else {
                    ExfatNamespaceOperation::CreateDirectory
                },
                allocated_clusters: taken.len(),
                freed_clusters: 0,
                parent_growth_clusters: place.growth.len(),
                existing_metadata_preserved: false,
                name: Some(native_name),
            },
        )
    }
    /// Rename or move one native object without overwriting another entry or creating directory cycles.
    pub fn plan_rename(
        &self,
        source_parent: &ExfatEditDirectory,
        source_name: &[u16],
        destination_parent: &ExfatEditDirectory,
        destination_name: &[u16],
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.check_directory(source_parent, r)?;
        self.check_directory(destination_parent, r)?;
        let (mut p, lease) = self.namespace_planner(r)?;
        self.lookup_work(source_parent, source_name, &mut p)?;
        let source = source_parent
            .directory
            .lookup(source_name)?
            .ok_or_else(|| invalid("exFAT rename source missing"))?;
        if readonly(&source.raw_metadata()[0]) {
            return Err(invalid("read-only exFAT rename source"));
        }
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        let map = decoder.edit_allocation_map(source, r)?;
        p.tick(destination_parent.ancestors.len())?;
        if source.is_directory()
            && map
                .clusters
                .first()
                .is_some_and(|c| destination_parent.ancestors.contains(c))
        {
            return Err(invalid("exFAT directory move would create a cycle"));
        }
        let same = source_parent.identity.native == destination_parent.identity.native;
        let source_at = source.edit_locations()[0];
        self.collision(
            destination_parent,
            destination_name,
            if same { Some(source_at) } else { None },
            &decoder,
            &mut p,
        )?;
        let raw = named_set(
            source.raw_metadata()[0],
            source.raw_metadata()[1],
            destination_name,
            decoder.edit_name_hash(destination_name)?,
        )?;
        let mut growth = 0;
        if same && raw.len() <= source.raw_metadata().len() {
            for (i, at) in source.edit_locations().iter().enumerate() {
                let mut after = raw.get(i).copied().unwrap_or(source.raw_metadata()[i]);
                if i >= raw.len() {
                    after[0] &= 0x7f;
                }
                p.patch(*at, after.to_vec())?;
            }
            p.stage("publish in-place native rename");
        } else {
            let layout = self.layout(destination_parent, &mut p)?;
            let mut taken = vector(
                self.limits
                    .read
                    .max_chain_clusters
                    .checked_add(2)
                    .ok_or_else(|| budget("exFAT allocation index capacity"))?,
            )?;
            let mut place = self.placement(
                destination_parent,
                &layout,
                raw.len(),
                0,
                &mut taken,
                &mut p,
            )?;
            growth = place.growth.len();
            self.fill_new_slots(&mut place, &raw);
            self.initialize_parent(&mut place, &mut p)?;
            p.stage("initialize relocated parent allocation");
            self.growth_fat(destination_parent, &place, &mut p)?;
            p.stage("publish relocated parent FAT mapping");
            self.bitmap(&taken, true, &decoder, &mut p)?;
            p.stage("publish relocated parent bitmap");
            self.parent_metadata(destination_parent, &place, &mut p)?;
            self.publish_existing_slots(&place, &layout, &raw, &mut p)?;
            p.stage("publish destination native set");
            self.unlink(source, &mut p)?;
            p.stage("unlink original native set");
        }
        let mut name = vector(destination_name.len())?;
        name.extend_from_slice(destination_name);
        self.finish_namespace(
            p,
            lease,
            ExfatNamespaceReport {
                operation: ExfatNamespaceOperation::Rename,
                allocated_clusters: growth,
                freed_clusters: 0,
                parent_growth_clusters: growth,
                existing_metadata_preserved: true,
                name: Some(name),
            },
        )
    }
    fn unlink(&self, entry: &ExfatEntry, p: &mut Planner<'_, S>) -> Result<()> {
        for (at, b) in entry.edit_locations().iter().zip(entry.raw_metadata()) {
            let mut b = *b;
            b[0] &= 0x7f;
            p.patch(*at, b.to_vec())?;
        }
        Ok(())
    }
    /// Unlink a regular file or an empty directory, then release its verified owned allocation.
    pub fn plan_delete(
        &self,
        parent: &ExfatEditDirectory,
        name: &[u16],
        r: &Resources,
    ) -> Result<ExfatEditBatch> {
        self.check_directory(parent, r)?;
        let (mut p, lease) = self.namespace_planner(r)?;
        self.lookup_work(parent, name, &mut p)?;
        let entry = parent
            .directory
            .lookup(name)?
            .ok_or_else(|| invalid("exFAT delete source missing"))?;
        if readonly(&entry.raw_metadata()[0]) {
            return Err(invalid("read-only exFAT delete source"));
        }
        let decoder = ExfatDecoder::open_storage(&self.target, self.scope, self.limits.read, r)?;
        if entry.is_directory() && !decoder.read_directory(entry, r)?.entries().is_empty() {
            return Err(invalid(
                "exFAT directory deletion requires an empty directory",
            ));
        }
        let map = decoder.edit_allocation_map(entry, r)?;
        self.unlink(entry, &mut p)?;
        p.stage("unlink native entry set before allocation release");
        for &c in &map.clusters {
            p.tick(1)?;
            p.patch(self.boot.fat_offset + u64::from(c) * 4, vec![0; 4])?;
        }
        p.stage("release owned FAT entries");
        self.bitmap(&map.clusters, false, &decoder, &mut p)?;
        p.stage("release owned allocation bitmap");
        self.finish_namespace(
            p,
            lease,
            ExfatNamespaceReport {
                operation: if entry.is_directory() {
                    ExfatNamespaceOperation::DeleteDirectory
                } else {
                    ExfatNamespaceOperation::DeleteFile
                },
                allocated_clusters: 0,
                freed_clusters: map.clusters.len(),
                parent_growth_clusters: 0,
                existing_metadata_preserved: true,
                name: None,
            },
        )
    }
}
