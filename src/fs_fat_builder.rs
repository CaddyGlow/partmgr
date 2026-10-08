//! Deterministic FAT new-output authoring. Publication belongs to the caller.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use crate::{
    fs_core::{Error, ErrorKind, ObjectId, Reservation, Resources, Result},
    fs_fat::FatFamily,
    storage::Storage,
};
use sha2::{Digest, Sha256};
const SCRATCH: usize = 65536;

/// Geometry and deterministic serial number for the initial authoring profile.
#[derive(Clone, Copy, Debug)]
pub struct FatBuildOptions {
    /// Required family; cluster-count classification must agree.
    pub family: FatFamily,
    /// Power of two from 1 through 64, using 512-byte sectors.
    pub sectors_per_cluster: u8,
    /// Caller-selected deterministic volume serial number.
    pub volume_id: u32,
}
/// Root file with stable deferred positional content.
pub struct FatBuildFile {
    /// Uppercase ASCII 8.3 name. No directories, long names, or metadata copying.
    pub name: String,
    /// Must remain immutable through planning, emission and verification.
    pub source: Arc<dyn ReadAt>,
}
/// Native tree entry. Directory identities must be unique and parents must be directories.
/// `None` parent denotes a root child; `None` source denotes a directory.
pub struct FatBuildTreeEntry {
    /// Stable source identity retained throughout planning and emission.
    pub identity: ObjectId,
    /// Parent directory identity, or the implicit root.
    pub parent: Option<ObjectId>,
    /// Exact native UTF-16 name (including unpaired surrogates).
    pub name: Vec<u16>,
    /// Immutable direct positional payload for a regular file.
    pub source: Option<Arc<dyn ReadAt>>,
}
/// Explicitly authorized metadata transformation; no metadata preservation is claimed.
#[derive(Clone, Copy, Debug)]
pub enum FatTreeMetadataPolicy {
    /// Omit source metadata and use deterministic dates and ordinary attributes.
    DeterministicDefaults,
}
struct PlannedDirectory {
    first: u32,
    clusters: u32,
    entries: Vec<[u8; 32]>,
}
struct PlannedFile {
    name: [u8; 11],
    source: Arc<dyn ReadAt>,
    length: u32,
    first: u32,
    clusters: u32,
}
/// Preflighted layout retaining its inventory charge; contains no payload buffers.
pub struct FatBuildPlan {
    length: u64,
    options: FatBuildOptions,
    fat_sectors: u32,
    reserved: u32,
    root_sectors: u32,
    clusters: u32,
    allocated: u32,
    files: Vec<PlannedFile>,
    directories: Vec<PlannedDirectory>,
    identities: Vec<ObjectId>,
    allocation_runs: Vec<(u32, u32)>,
    payload_files: Vec<usize>,
    _tree_reservations: Vec<Reservation>,
    _reservation: Reservation,
}
/// A staged image whose complete byte stream was read back after one durable flush.
#[derive(Debug)]
pub struct FatBuildReport {
    /// Bytes initialized, emitted and verified, including free space.
    pub verified_bytes: u64,
    /// Number of root files authored.
    pub files: usize,
    /// Digest of all staged image bytes; no firmware boot assurance is implied.
    pub sha256: [u8; 32],
}
fn invalid(context: &'static str) -> Error {
    Error::new(ErrorKind::InvalidOperation, context)
}
fn short_name(name: &str) -> Result<[u8; 11]> {
    let mut parts = name.split('.');
    let base = parts.next().unwrap_or_default();
    let ext = parts.next().unwrap_or_default();
    let allowed = |s: &str| {
        s.bytes().all(|b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || b"_$~!#%&-{}()@'`".contains(&b)
        })
    };
    if base.is_empty()
        || base.len() > 8
        || ext.len() > 3
        || parts.next().is_some()
        || !allowed(base)
        || !allowed(ext)
        || name.ends_with('.')
    {
        return Err(invalid(
            "initial FAT builder requires canonical uppercase ASCII 8.3 names",
        ));
    }
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Ok(out)
}
impl FatBuildPlan {
    /// Plan nested directories and exact UTF-16 VFAT names. ASCII case collisions
    /// are rejected; non-ASCII comparison is exact, with no Unicode folding claim.
    /// The caller explicitly accepts deterministic metadata defaults and guarantees
    /// that retained identities and positional sources remain unchanged.
    pub fn new_tree(
        length: u64,
        options: FatBuildOptions,
        entries: &[FatBuildTreeEntry],
        _metadata: FatTreeMetadataPolicy,
        resources: &Resources,
    ) -> Result<Self> {
        let mut plan = Self::new(length, options, &[], resources)?;
        let charge = entries.iter().try_fold(1024_u64, |sum, e| {
            let units = e.name.len() as u64;
            let identity = (e.identity.native.len() as u64)
                .checked_add(e.parent.as_ref().map_or(0, |p| p.native.len() as u64));
            units
                .checked_mul(16)
                .and_then(|names| {
                    identity
                        .and_then(|n| n.checked_mul(2))
                        .and_then(|ids| names.checked_add(ids))
                })
                .and_then(|n| n.checked_add(2048))
                .and_then(|n| sum.checked_add(n))
                .ok_or_else(|| invalid("tree inventory charge overflow"))
        })?;
        let inventory_reservation = resources.memory.reserve(charge)?;
        let mut identities = HashMap::new();
        identities
            .try_reserve(entries.len())
            .map_err(|_| inventory_error())?;
        for (index, entry) in entries.iter().enumerate() {
            resources.cancellation.check()?;
            if identities.insert(&entry.identity, index).is_some() {
                return Err(invalid(
                    "duplicate tree identity or hard link requires explicit transformation",
                ));
            }
        }
        let mut parents = inventory_vec(entries.len())?;
        for entry in entries {
            let parent = entry
                .parent
                .as_ref()
                .map(|id| {
                    let index = *identities
                        .get(id)
                        .ok_or_else(|| invalid("missing tree parent"))?;
                    if entries[index].source.is_some() {
                        return Err(invalid("tree parent is not a directory"));
                    }
                    Ok(index)
                })
                .transpose()?;
            parents.push(parent);
        }
        let mut path_reservations = inventory_vec(entries.len().saturating_add(1))?;
        let mut paths = inventory_vec(entries.len())?;
        plan.files
            .try_reserve_exact(entries.len())
            .map_err(|_| inventory_error())?;
        for (index, entry) in entries.iter().enumerate() {
            resources.cancellation.check()?;
            let name = &entry.name;
            if name.is_empty()
                || name.len() > 255
                || name == &[46]
                || name == &[46, 46]
                || matches!(name.last(), Some(32 | 46))
                || name
                    .iter()
                    .any(|c| *c < 32 || [34, 42, 47, 58, 60, 62, 63, 92, 124].contains(c))
            {
                return Err(invalid("invalid native VFAT component"));
            }
            let mut depth = 1usize;
            let mut parent = parents[index];
            while let Some(ancestor) = parent {
                resources.cancellation.check()?;
                depth += 1;
                if depth > entries.len() {
                    return Err(invalid("tree parent cycle"));
                }
                parent = parents[ancestor];
            }
            path_reservations.push(
                resources.memory.reserve(
                    (depth as u64)
                        .checked_mul(crate::platform::mem::size_of::<usize>() as u64)
                        .ok_or_else(|| invalid("tree path charge overflow"))?,
                )?,
            );
            let mut path = inventory_vec(depth)?;
            path.push(index);
            let mut parent = parents[index];
            while let Some(ancestor) = parent {
                path.push(ancestor);
                parent = parents[ancestor];
            }
            path.reverse();
            paths.push((path, index));
        }
        paths.sort_by(|a, b| {
            a.0.iter()
                .map(|i| &entries[*i].name)
                .cmp(b.0.iter().map(|i| &entries[*i].name))
        });
        let mut directories = inventory_vec(entries.len().saturating_add(1))?;
        directories.push(PlannedDirectory {
            first: 0,
            clusters: 0,
            entries: Vec::new(),
        });
        let mut directory_ids: Vec<Option<ObjectId>> =
            inventory_vec(entries.len().saturating_add(1))?;
        directory_ids.push(None);
        for (_, index) in &paths {
            if entries[*index].source.is_none() {
                directory_ids.push(Some(copy_identity(&entries[*index].identity)?));
                directories.push(PlannedDirectory {
                    first: 0,
                    clusters: 0,
                    entries: Vec::new(),
                });
            }
        }
        let mut directory_index = HashMap::new();
        directory_index
            .try_reserve(directory_ids.len())
            .map_err(|_| inventory_error())?;
        for (index, id) in directory_ids.iter().enumerate() {
            directory_index.insert(id.as_ref(), index);
        }
        let mut children_by_directory = inventory_vec(directory_ids.len())?;
        for _ in &directory_ids {
            children_by_directory.push(Vec::new());
        }
        for (_, index) in &paths {
            let directory = directory_index[&entries[*index].parent.as_ref()];
            let children: &mut Vec<usize> = &mut children_by_directory[directory];
            children.try_reserve(1).map_err(|_| inventory_error())?;
            children.push(*index);
        }
        // Determine aliases per directory, reserving canonical names before generated aliases.
        let mut aliases = inventory_vec(entries.len())?;
        aliases.resize(entries.len(), [0; 11]);
        for children in &children_by_directory {
            let fold = |name: &[u16]| -> Result<Vec<u16>> {
                let mut folded = inventory_vec(name.len())?;
                folded.extend(
                    name.iter()
                        .map(|c| if (97..=122).contains(c) { c - 32 } else { *c }),
                );
                Ok(folded)
            };
            let mut names = HashSet::new();
            names
                .try_reserve(children.len())
                .map_err(|_| inventory_error())?;
            for index in children {
                if !names.insert(fold(&entries[*index].name)?) {
                    return Err(invalid("duplicate VFAT name under ASCII case comparison"));
                }
            }
            let mut used = HashSet::new();
            used.try_reserve(children.len())
                .map_err(|_| inventory_error())?;
            for index in children {
                if let Ok(text) = String::from_utf16(&entries[*index].name)
                    && let Ok(name) = short_name(&text)
                {
                    aliases[*index] = name;
                    used.insert(name);
                }
            }
            for &index in children {
                if aliases[index] != [0; 11] {
                    continue;
                }
                let name = &entries[index].name;
                let split = name.iter().rposition(|c| *c == 46).unwrap_or(name.len());
                let clean = |units: &[u16]| {
                    units
                        .iter()
                        .filter_map(|c| {
                            let b = u8::try_from(*c).ok()?.to_ascii_uppercase();
                            (b.is_ascii_uppercase() || b.is_ascii_digit()).then_some(b)
                        })
                        .collect::<Vec<_>>()
                };
                let mut base = clean(&name[..split]);
                if base.is_empty() {
                    base.extend_from_slice(b"FILE");
                }
                let ext = if split < name.len() {
                    clean(&name[split + 1..])
                } else {
                    Vec::new()
                };
                let mut found = None;
                for number in 1..=999999_u32 {
                    let tail = format!("~{number}");
                    let take = base.len().min(8 - tail.len());
                    let mut alias = [b' '; 11];
                    alias[..take].copy_from_slice(&base[..take]);
                    alias[take..take + tail.len()].copy_from_slice(tail.as_bytes());
                    let ext_len = ext.len().min(3);
                    alias[8..8 + ext_len].copy_from_slice(&ext[..ext_len]);
                    let mut display = alias[..8].to_vec();
                    while display.last() == Some(&b' ') {
                        display.pop();
                    }
                    if ext_len != 0 {
                        display.push(b'.');
                        display.extend_from_slice(&alias[8..8 + ext_len]);
                    }
                    let display: Vec<u16> = display.into_iter().map(u16::from).collect();
                    let collides = names.contains(&display);
                    if !used.contains(&alias) && !collides {
                        found = Some(alias);
                        break;
                    }
                }
                aliases[index] = found.ok_or_else(|| invalid("VFAT alias namespace exhausted"))?;
                used.insert(aliases[index]);
            }
        }
        // Size directories before allocation, including canonical dot entries and terminator.
        for (d, _) in directory_ids.iter().enumerate() {
            let mut slots = usize::from(d != 0) * 2 + 1;
            for index in &children_by_directory[d] {
                let canonical = String::from_utf16(&entries[*index].name)
                    .ok()
                    .and_then(|s| short_name(&s).ok())
                    .is_some();
                slots += 1 + if canonical {
                    0
                } else {
                    entries[*index].name.len().div_ceil(13)
                };
            }
            directories[d]
                .entries
                .try_reserve_exact(slots)
                .map_err(|_| inventory_error())?;
            if d == 0 && options.family != FatFamily::Fat32 {
                if slots > 512 {
                    return Err(invalid("fixed FAT root directory capacity exhausted"));
                }
            } else {
                directories[d].clusters = (slots as u64 * 32).div_ceil(plan.cluster_bytes()) as u32;
            }
        }
        let mut allocated = 0_u32;
        for directory in &mut directories {
            if directory.clusters != 0 {
                directory.first = 2 + allocated;
                allocated = allocated
                    .checked_add(directory.clusters)
                    .ok_or_else(|| invalid("tree allocation overflow"))?;
            }
        }
        let mut firsts = inventory_vec(entries.len())?;
        firsts.resize(entries.len(), 0);
        let mut sizes = inventory_vec(entries.len())?;
        sizes.resize(entries.len(), 0);
        for (_, index) in &paths {
            let entry = &entries[*index];
            if let Some(source) = &entry.source {
                let size = u32::try_from(source.len())
                    .map_err(|_| invalid("FAT file exceeds u32 length"))?;
                let clusters = u64::from(size).div_ceil(plan.cluster_bytes()) as u32;
                let first = if clusters == 0 { 0 } else { 2 + allocated };
                allocated = allocated
                    .checked_add(clusters)
                    .ok_or_else(|| invalid("tree allocation overflow"))?;
                firsts[*index] = first;
                sizes[*index] = size;
                plan.files.push(PlannedFile {
                    name: aliases[*index],
                    source: source.clone(),
                    length: size,
                    first,
                    clusters,
                });
            } else {
                let directory = directory_index[&Some(&entry.identity)];
                firsts[*index] = directories[directory].first;
            }
        }
        if allocated > plan.clusters {
            return Err(invalid("insufficient FAT tree clusters"));
        }
        for (d, id) in directory_ids.iter().enumerate() {
            if d != 0 {
                let own = &entries[identities[&id
                    .as_ref()
                    .ok_or_else(|| invalid("missing directory identity"))?]];
                let parent = directory_index[&own.parent.as_ref()];
                let parent_cluster = if parent == 0 {
                    0
                } else {
                    directories[parent].first
                };
                let dot = directory_entry(dot_name(false), true, directories[d].first, 0);
                let dotdot = directory_entry(dot_name(true), true, parent_cluster, 0);
                directories[d].entries.extend([dot, dotdot]);
            }
            for index in &children_by_directory[d] {
                let entry = &entries[*index];
                let canonical = String::from_utf16(&entry.name)
                    .ok()
                    .and_then(|s| short_name(&s).ok())
                    .is_some();
                if !canonical {
                    let checksum = aliases[*index]
                        .iter()
                        .fold(0_u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
                    let count = entry.name.len().div_ceil(13);
                    for ordinal in (1..=count).rev() {
                        let mut long = [0xff; 32];
                        long[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
                        long[11] = 0x0f;
                        long[12] = 0;
                        long[13] = checksum;
                        long[26] = 0;
                        long[27] = 0;
                        for (position, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                            .iter()
                            .enumerate()
                        {
                            let n = (ordinal - 1) * 13 + position;
                            let unit = entry
                                .name
                                .get(n)
                                .copied()
                                .unwrap_or(if n == entry.name.len() { 0 } else { 0xffff });
                            long[*offset..*offset + 2].copy_from_slice(&unit.to_le_bytes());
                        }
                        directories[d].entries.push(long);
                    }
                }
                directories[d].entries.push(directory_entry(
                    aliases[*index],
                    entry.source.is_none(),
                    firsts[*index],
                    sizes[*index],
                ));
            }
        }
        plan.allocated = allocated;
        plan.directories = directories;
        plan.identities = inventory_vec(entries.len())?;
        for entry in entries {
            plan.identities.push(copy_identity(&entry.identity)?);
        }
        path_reservations.push(inventory_reservation);
        plan._tree_reservations = path_reservations;
        plan.index_ranges()?;
        drop(resources.memory.reserve((2 * SCRATCH) as u64)?);
        Ok(plan)
    }

    /// Preflight geometry, names, capacity, source lengths and memory before mutation.
    pub fn new(
        length: u64,
        options: FatBuildOptions,
        files: &[FatBuildFile],
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        if !length.is_multiple_of(512)
            || length / 512 > u64::from(u32::MAX)
            || !options.sectors_per_cluster.is_power_of_two()
            || options.sectors_per_cluster > 64
        {
            return Err(invalid("invalid FAT builder geometry"));
        }
        let total = length / 512;
        let spc = u64::from(options.sectors_per_cluster);
        let reserved = if options.family == FatFamily::Fat32 {
            32
        } else {
            1
        };
        let root_sectors = if options.family == FatFamily::Fat32 {
            0
        } else {
            32
        };
        let upper = total / spc + 2;
        let fat_bytes = match options.family {
            FatFamily::Fat12 => (upper * 3).div_ceil(2),
            FatFamily::Fat16 => upper * 2,
            FatFamily::Fat32 => upper * 4,
        };
        let fat_sectors = fat_bytes.div_ceil(512);
        let data = u64::from(reserved + root_sectors) + 2 * fat_sectors;
        if total <= data {
            return Err(invalid("image leaves no FAT data area"));
        }
        let clusters = (total - data) / spc;
        let valid = match options.family {
            FatFamily::Fat12 => (1..4085).contains(&clusters) && clusters + 1 < 0xff0,
            FatFamily::Fat16 => (4085..65525).contains(&clusters) && clusters + 1 < 0xfff0,
            FatFamily::Fat32 => (65525..0x0fff_ffef).contains(&clusters),
        };
        if !valid || (options.family != FatFamily::Fat32 && fat_sectors > u64::from(u16::MAX)) {
            return Err(invalid(
                "requested family disagrees with FAT cluster geometry",
            ));
        }
        let root_limit = if options.family == FatFamily::Fat32 {
            spc * 512 / 32
        } else {
            512
        };
        if files.len() as u64 >= root_limit {
            return Err(invalid(
                "root directory capacity exhausted (one terminator required)",
            ));
        }
        let charge = (files.len() as u64)
            .checked_mul(
                (crate::platform::mem::size_of::<PlannedFile>()
                    + crate::platform::mem::size_of::<(u32, u32)>()
                    + crate::platform::mem::size_of::<usize>()) as u64,
            )
            .ok_or_else(|| invalid("inventory charge overflow"))?;
        let reservation = resources.memory.reserve(charge)?;
        let mut planned = Vec::new();
        planned.try_reserve_exact(files.len()).map_err(|_| {
            Error::new(
                ErrorKind::BudgetExhausted,
                "FAT inventory allocation failed",
            )
        })?;
        for file in files {
            resources.cancellation.check()?;
            let length = u32::try_from(file.source.len())
                .map_err(|_| invalid("FAT file exceeds u32 length"))?;
            planned.push(PlannedFile {
                name: short_name(&file.name)?,
                source: file.source.clone(),
                length,
                first: 0,
                clusters: u64::from(length).div_ceil(spc * 512) as u32,
            });
        }
        planned.sort_unstable_by_key(|f| f.name);
        if planned.windows(2).any(|p| p[0].name == p[1].name) {
            return Err(invalid("duplicate FAT short name"));
        }
        let mut allocated = u32::from(options.family == FatFamily::Fat32);
        for file in &mut planned {
            if file.clusters != 0 {
                file.first = 2 + allocated;
                allocated = allocated
                    .checked_add(file.clusters)
                    .ok_or_else(|| invalid("allocation overflow"))?;
            }
        }
        if u64::from(allocated) > clusters {
            return Err(invalid("insufficient FAT free clusters"));
        }
        // Verify that bounded emission scratch can be reserved before returning a plan.
        drop(resources.memory.reserve((2 * SCRATCH) as u64)?);
        let mut plan = Self {
            length,
            options,
            fat_sectors: fat_sectors as u32,
            reserved,
            root_sectors,
            clusters: clusters as u32,
            allocated,
            files: planned,
            directories: Vec::new(),
            identities: Vec::new(),
            allocation_runs: Vec::new(),
            payload_files: Vec::new(),
            _tree_reservations: Vec::new(),
            _reservation: reservation,
        };
        plan.index_ranges()?;
        Ok(plan)
    }
    /// Stable input identities retained by a tree plan; empty for the compatibility profile.
    pub fn source_identities(&self) -> &[ObjectId] {
        &self.identities
    }
    fn data_offset(&self) -> u64 {
        u64::from(self.reserved + 2 * self.fat_sectors + self.root_sectors) * 512
    }
    fn cluster_bytes(&self) -> u64 {
        u64::from(self.options.sectors_per_cluster) * 512
    }
    fn index_ranges(&mut self) -> Result<()> {
        let mut runs = inventory_vec(self.directories.len() + self.files.len())?;
        let mut payloads = inventory_vec(self.files.len())?;
        for directory in &self.directories {
            if directory.clusters != 0 {
                runs.push((directory.first, directory.first + directory.clusters));
            }
        }
        for (index, file) in self.files.iter().enumerate() {
            if file.clusters != 0 {
                runs.push((file.first, file.first + file.clusters));
                payloads.push(index);
            }
        }
        runs.sort_unstable_by_key(|run| run.0);
        payloads.sort_unstable_by_key(|index| self.files[*index].first);
        self.allocation_runs = runs;
        self.payload_files = payloads;
        Ok(())
    }
    fn entry(&self, n: u32) -> u32 {
        let eoc = match self.options.family {
            FatFamily::Fat12 => 0xfff,
            FatFamily::Fat16 => 0xffff,
            FatFamily::Fat32 => 0x0fff_ffff,
        };
        if n == 0 {
            return eoc & !7;
        }
        if n == 1
            || (n == 2 && self.options.family == FatFamily::Fat32 && self.directories.is_empty())
        {
            return eoc;
        }
        let index = self.allocation_runs.partition_point(|run| run.1 <= n);
        match self.allocation_runs.get(index) {
            Some(&(start, end)) if n >= start => {
                if n + 1 == end {
                    eoc
                } else {
                    n + 1
                }
            }
            _ => 0,
        }
    }
    fn boot(&self) -> [u8; 512] {
        let mut b = [0; 512];
        b[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
        b[3..11].copy_from_slice(b"PARTMGR ");
        b[11..13].copy_from_slice(&512_u16.to_le_bytes());
        b[13] = self.options.sectors_per_cluster;
        b[14..16].copy_from_slice(&(self.reserved as u16).to_le_bytes());
        b[16] = 2;
        b[21] = 0xf8;
        b[24..26].copy_from_slice(&63_u16.to_le_bytes());
        b[26..28].copy_from_slice(&255_u16.to_le_bytes());
        let total = (self.length / 512) as u32;
        let at = if self.options.family == FatFamily::Fat32 {
            b[32..36].copy_from_slice(&total.to_le_bytes());
            b[36..40].copy_from_slice(&self.fat_sectors.to_le_bytes());
            b[44..48].copy_from_slice(&2_u32.to_le_bytes());
            b[48..50].copy_from_slice(&1_u16.to_le_bytes());
            b[50..52].copy_from_slice(&6_u16.to_le_bytes());
            64
        } else {
            b[17..19].copy_from_slice(&512_u16.to_le_bytes());
            b[22..24].copy_from_slice(&(self.fat_sectors as u16).to_le_bytes());
            if total <= u32::from(u16::MAX) {
                b[19..21].copy_from_slice(&(total as u16).to_le_bytes());
            } else {
                b[32..36].copy_from_slice(&total.to_le_bytes());
            }
            36
        };
        b[at] = 0x80;
        b[at + 2] = 0x29;
        b[at + 3..at + 7].copy_from_slice(&self.options.volume_id.to_le_bytes());
        b[at + 7..at + 18].copy_from_slice(b"NO NAME    ");
        b[at + 18..at + 26].copy_from_slice(match self.options.family {
            FatFamily::Fat12 => b"FAT12   ",
            FatFamily::Fat16 => b"FAT16   ",
            FatFamily::Fat32 => b"FAT32   ",
        });
        b[510..].copy_from_slice(&[0x55, 0xaa]);
        b
    }
    fn render(&self, offset: u64, out: &mut [u8], resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        out.fill(0);
        let overlay = |out: &mut [u8], at: u64, bytes: &[u8]| {
            let start = offset.max(at);
            let end = (offset + out.len() as u64).min(at + bytes.len() as u64);
            if start < end {
                out[(start - offset) as usize..(end - offset) as usize]
                    .copy_from_slice(&bytes[(start - at) as usize..(end - at) as usize]);
            }
        };
        let boot = self.boot();
        overlay(out, 0, &boot);
        if self.options.family == FatFamily::Fat32 {
            overlay(out, 6 * 512, &boot);
            let mut info = [0; 512];
            info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
            info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
            info[488..492].copy_from_slice(&(self.clusters - self.allocated).to_le_bytes());
            let next = if self.allocated < self.clusters {
                2 + self.allocated
            } else {
                u32::MAX
            };
            info[492..496].copy_from_slice(&next.to_le_bytes());
            info[508..].copy_from_slice(&0xaa55_0000_u32.to_le_bytes());
            overlay(out, 512, &info);
            overlay(out, 7 * 512, &info);
        }
        let fat_bytes = u64::from(self.fat_sectors) * 512;
        for copy in 0..2 {
            let at = u64::from(self.reserved) * 512 + copy * fat_bytes;
            let start = offset.max(at);
            let end = (offset + out.len() as u64).min(at + fat_bytes);
            let (width, entries) = match self.options.family {
                FatFamily::Fat12 => (3_u64, 2_u32),
                FatFamily::Fat16 => (2, 1),
                FatFamily::Fat32 => (4, 1),
            };
            if start < end {
                let first = (start - at) / width;
                let last = (end - at).div_ceil(width);
                for unit in first..last {
                    let n = unit as u32 * entries;
                    let packed = if entries == 2 {
                        self.entry(n) | (self.entry(n + 1) << 12)
                    } else {
                        self.entry(n)
                    };
                    let bytes = packed.to_le_bytes();
                    overlay(
                        out,
                        at + unit * width,
                        &bytes[..width.min(fat_bytes - unit * width) as usize],
                    );
                }
            }
        }

        let root = if self.options.family == FatFamily::Fat32 {
            self.data_offset()
        } else {
            u64::from(self.reserved + 2 * self.fat_sectors) * 512
        };
        if self.directories.is_empty() {
            let first = offset.saturating_sub(root) / 32;
            let last = (offset + out.len() as u64)
                .saturating_sub(root)
                .div_ceil(32);
            for index in first as usize..(last as usize).min(self.files.len()) {
                let file = &self.files[index];
                let entry = directory_entry(file.name, false, file.first, file.length);
                overlay(out, root + index as u64 * 32, &entry);
            }
        }
        let data = self.data_offset();
        let cluster_bytes = self.cluster_bytes();
        let first = self.payload_files.partition_point(|index| {
            let file = &self.files[*index];
            data + u64::from(file.first - 2) * cluster_bytes + u64::from(file.length) <= offset
        });
        for index in &self.payload_files[first..] {
            let file = &self.files[*index];
            let at = data + u64::from(file.first - 2) * cluster_bytes;
            if at >= offset + out.len() as u64 {
                break;
            }
            let start = offset.max(at);
            let end = (offset + out.len() as u64).min(at + u64::from(file.length));
            if start < end {
                file.source
                    .read_exact_at(
                        start - at,
                        &mut out[(start - offset) as usize..(end - offset) as usize],
                    )
                    .map_err(|e| Error::io("FAT source read", e))?;
            }
        }
        let directory_at = |directory: &PlannedDirectory| {
            if directory.first == 0 {
                root
            } else {
                data + u64::from(directory.first - 2) * cluster_bytes
            }
        };
        let first = self.directories.partition_point(|directory| {
            directory_at(directory) + directory.entries.len() as u64 * 32 <= offset
        });
        for directory in &self.directories[first..] {
            let at = if directory.first == 0 {
                root
            } else {
                self.data_offset() + u64::from(directory.first - 2) * self.cluster_bytes()
            };
            if at >= offset + out.len() as u64 {
                break;
            }
            let first = offset.saturating_sub(at) / 32;
            let last = (offset + out.len() as u64).saturating_sub(at).div_ceil(32);
            for index in first as usize..(last as usize).min(directory.entries.len()) {
                overlay(out, at + index as u64 * 32, &directory.entries[index]);
            }
        }
        Ok(())
    }
    /// Initialize the whole unpublished destination, flush once and verify every byte.
    /// Errors after mutation are `InterruptedWrite`; failed flush is `UncertainDurability`.
    /// Never publish or retry this image without caller inspection after failure.
    pub fn emit(
        &self,
        storage: &mut (impl Storage + ?Sized),
        resources: &Resources,
    ) -> Result<FatBuildReport> {
        resources.cancellation.check()?;
        if storage
            .len()
            .map_err(|e| Error::io("FAT output length", e))?
            != self.length
            || self
                .files
                .iter()
                .any(|f| f.source.len() != u64::from(f.length))
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "FAT source or destination length changed",
            ));
        }
        let _scratch = resources.memory.reserve((2 * SCRATCH) as u64)?;
        let mut expected = Vec::new();
        let mut actual = Vec::new();
        for b in [&mut expected, &mut actual] {
            b.try_reserve_exact(SCRATCH).map_err(|_| {
                Error::new(ErrorKind::BudgetExhausted, "FAT scratch allocation failed")
            })?;
            b.resize(SCRATCH, 0);
        }
        let mut mutated = false;
        let mut flushed = false;
        let result = (|| {
            let mut digest = Sha256::new();
            let mut offset = 0;
            while offset < self.length {
                let n = (self.length - offset).min(SCRATCH as u64) as usize;
                self.render(offset, &mut expected[..n], resources)?;
                digest.update(&expected[..n]);
                crate::fs_build_io::write_all(
                    storage,
                    offset,
                    &expected[..n],
                    resources,
                    &mut mutated,
                    "FAT staged write",
                )?;
                offset += n as u64;
            }
            crate::fs_build_io::flush(storage, resources, "FAT staged flush")?;
            flushed = true;
            let emitted: [u8; 32] = digest.finalize().into();
            let mut verified = Sha256::new();
            let mut offset = 0;
            while offset < self.length {
                let n = (self.length - offset).min(SCRATCH as u64) as usize;
                self.render(offset, &mut expected[..n], resources)?;
                crate::fs_build_io::verify(
                    storage,
                    offset,
                    &expected[..n],
                    &mut actual[..n],
                    resources,
                    "FAT staged byte verification",
                    "FAT staged byte verification mismatch",
                )?;
                verified.update(&actual[..n]);
                offset += n as u64;
            }
            if self
                .files
                .iter()
                .any(|f| f.source.len() != u64::from(f.length))
                || storage
                    .len()
                    .map_err(|e| Error::io("FAT final geometry", e))?
                    != self.length
                || <[u8; 32]>::from(verified.finalize()) != emitted
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "FAT source or destination changed during emission",
                ));
            }
            Ok(FatBuildReport {
                verified_bytes: self.length,
                files: self.files.len(),
                sha256: emitted,
            })
        })();
        result.map_err(|mut e| {
            if mutated && e.kind != ErrorKind::UncertainDurability {
                e.kind = ErrorKind::InterruptedWrite;
                e.context = format!(
                    "{}; staging modified, durable flush {}",
                    e.context,
                    if flushed { "completed" } else { "unconfirmed" }
                );
            }
            e
        })
    }
}

fn dot_name(parent: bool) -> [u8; 11] {
    let mut name = [b' '; 11];
    name[0] = b'.';
    if parent {
        name[1] = b'.';
    }
    name
}
fn directory_entry(name: [u8; 11], directory: bool, first: u32, size: u32) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(&name);
    entry[11] = if directory { 0x10 } else { 0x20 };
    entry[16..18].copy_from_slice(&0x21_u16.to_le_bytes());
    entry[24..26].copy_from_slice(&0x21_u16.to_le_bytes());
    entry[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

fn inventory_error() -> Error {
    Error::new(
        ErrorKind::BudgetExhausted,
        "FAT tree inventory allocation failed",
    )
}
fn inventory_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| inventory_error())?;
    Ok(v)
}
fn copy_identity(id: &ObjectId) -> Result<ObjectId> {
    let mut native = inventory_vec(id.native.len())?;
    native.extend_from_slice(&id.native);
    Ok(ObjectId {
        source: id.source,
        generation: id.generation,
        native,
    })
}

#[cfg(all(test, feature = "std"))]
mod render_tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    struct Pattern;
    impl ReadAt for Pattern {
        fn len(&self) -> u64 {
            513
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::platform::io::Result<()> {
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = (offset + i as u64) as u8;
            }
            Ok(())
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn partial_render_matches_complete_windows_across_packed_entries_and_regions() {
        let resources = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        for (family, length) in [
            (FatFamily::Fat12, 1440 * 1024),
            (FatFamily::Fat16, 16 * 1024 * 1024),
            (FatFamily::Fat32, 64 * 1024 * 1024),
        ] {
            let plan = FatBuildPlan::new(
                length,
                FatBuildOptions {
                    family,
                    sectors_per_cluster: 1,
                    volume_id: 7,
                },
                &[FatBuildFile {
                    name: "FILE.BIN".into(),
                    source: Arc::new(Pattern),
                }],
                &resources,
            )
            .unwrap();
            let fat = u64::from(plan.reserved) * 512;
            let boundary = fat + u64::from(plan.fat_sectors) * 512;
            for base in [fat, boundary - 17, plan.data_offset().saturating_sub(17)] {
                let mut complete = [0; 2048];
                plan.render(base, &mut complete, &resources).unwrap();
                for start in 0..32 {
                    for count in [1, 2, 3, 4, 7, 31, 513] {
                        let mut partial = vec![0; count];
                        plan.render(base + start as u64, &mut partial, &resources)
                            .unwrap();
                        assert_eq!(partial, complete[start..start + count]);
                    }
                }
            }
        }
    }
}
