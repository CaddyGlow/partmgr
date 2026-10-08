//! Strict immutable single-FAT exFAT namespace and positional file access.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::HashSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use crate::{
    fs_core::{
        Error, ErrorKind, FileRead, LogicalExtent, ObjectId, Reservation, Resources, Result,
    },
    fs_exfat::{ExfatBoot, ExfatDecodeRead},
    fs_file::{ExtentKind, ExtentMap, FileExtent},
};
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);
fn bad(context: &str) -> Error {
    Error::new(ErrorKind::InvalidData, context)
}
fn unsupported(context: &str) -> Error {
    Error::new(ErrorKind::Unsupported, context)
}
fn budget(context: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, context)
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn dword(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn wide(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn allocated<T>(count: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| budget("exFAT allocation failed"))?;
    Ok(result)
}
/// Per-operation traversal and allocation ceilings, enforced before allocation.
#[derive(Clone, Copy, Debug)]
pub struct ExfatReadLimits {
    /// Maximum clusters in any indexed root, system stream, directory or file.
    pub max_chain_clusters: usize,
    /// Maximum slots in the entire allocated directory, including trailing markers.
    pub max_directory_slots: usize,
    /// Maximum serialized up-case bytes (never more than 131072).
    pub max_upcase_bytes: usize,
}
struct CheckedSource<R> {
    source: R,
    length: u64,
    resources: Resources,
}
impl<R: ExfatDecodeRead> CheckedSource<R> {
    fn check(&self) -> Result<()> {
        self.resources.cancellation.check()?;
        if self
            .source
            .len()
            .map_err(|e| Error::io("exFAT source length", e))?
            != self.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "exFAT backing length changed",
            ));
        }
        Ok(())
    }
}
impl<R: ExfatDecodeRead> CheckedSource<R> {
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.check().map_err(io::Error::other)?;
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.source.read_exact_at(offset, out)?;
        self.check().map_err(io::Error::other)
    }
}
pub(crate) struct Mapping {
    pub(crate) file: ExtentMap,
    pub(crate) clusters: Vec<u32>,
    _lease: Reservation,
}
struct Upcase {
    table: Vec<u16>,
    _lease: Reservation,
}
/// Native exFAT file set, bound to one volume-open scope.
pub struct ExfatEntry {
    identity: ObjectId,
    name: Vec<u16>,
    raw: Vec<[u8; 32]>,
    locations: Vec<u64>,
    first: u32,
    length: u64,
    valid: u64,
    flags: u8,
    attributes: u16,
}
impl ExfatEntry {
    /// Exact native UTF-16 units, including unpaired surrogates.
    pub fn name(&self) -> &[u16] {
        &self.name
    }
    /// Volume-scoped directory-slot identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Native file attributes (including directory bit).
    pub fn attributes(&self) -> u16 {
        self.attributes
    }
    /// Whether this set describes a directory.
    pub fn is_directory(&self) -> bool {
        self.attributes & 0x10 != 0
    }
    /// Logical data length, including allocated-uninitialized tail bytes.
    pub fn len(&self) -> u64 {
        self.length
    }
    /// Whether the logical data length is zero.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Initialized payload prefix; reads beyond this point return zeros.
    pub fn valid_data_length(&self) -> u64 {
        self.valid
    }
    /// Whether allocation is contiguous and the FAT entries must be ignored.
    pub fn no_fat_chain(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Entire validated native entry set, retaining timestamp and reserved bytes.
    pub fn raw_metadata(&self) -> &[[u8; 32]] {
        &self.raw
    }
}
/// Bounded native-name directory inventory; allocation stays charged while retained.
pub struct ExfatDirectory {
    clusters: Vec<u32>,
    entries: Vec<ExfatEntry>,
    upcase: Arc<Upcase>,
    _lease: Reservation,
}
impl ExfatDirectory {
    /// Bind borrowed mutable-session inventory to the current owner generation.
    pub(crate) fn set_generation(&mut self, generation: u64) {
        for entry in &mut self.entries {
            entry.identity.generation = generation;
        }
    }
    /// Physical allocation clusters, for whole-tree directory overlap auditing.
    pub fn allocation_clusters(&self) -> &[u32] {
        &self.clusters
    }
    /// File and directory sets; unused slots and system entries are excluded.
    pub fn entries(&self) -> &[ExfatEntry] {
        &self.entries
    }
    /// Compare exact native units through the validated on-volume full up-case table.
    pub fn lookup(&self, name: &[u16]) -> Result<Option<&ExfatEntry>> {
        let mut found = None;
        for entry in &self.entries {
            if names_equal(&self.upcase.table, &entry.name, name) {
                if found.is_some() {
                    return Err(bad("ambiguous exFAT native name"));
                }
                found = Some(entry);
            }
        }
        Ok(found)
    }
}
/// Immutable revision-1.00 single-FAT volume. No ownership audit or source snapshot is implied.
pub(crate) struct ExfatDecoder<R> {
    source: Arc<CheckedSource<R>>,
    boot: ExfatBoot,
    limits: ExfatReadLimits,
    scope: u128,
    root: Arc<Mapping>,
    bitmap: Arc<Mapping>,
    upcase: Arc<Upcase>,
    label: Option<Vec<u16>>,
    protected: HashSet<u32>,
}
impl<R: ExfatDecodeRead> ExfatDecoder<R> {
    /// Validate boot, root/system chains, bitmap allocation, up-case checksum and root sets.
    /// Caller must guarantee immutable bytes until all inventories and file handles drop.
    pub fn open(source: R, limits: ExfatReadLimits, resources: &Resources) -> Result<Self> {
        let boot = ExfatBoot::inspect_decoder(&source, resources)?;
        if boot.fats != 1 {
            return Err(unsupported("TexFAT/two-FAT volumes are unsupported"));
        }
        if boot.flags & !0xf != 0 {
            return Err(unsupported("unknown exFAT volume flags"));
        }
        if boot.is_dirty() || boot.has_media_failure() {
            return Err(unsupported(
                "dirty or media-failure exFAT volume needs recovery",
            ));
        }
        if limits.max_chain_clusters == 0
            || limits.max_directory_slots == 0
            || limits.max_upcase_bytes == 0
            || limits.max_upcase_bytes > 131072
        {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "invalid exFAT read limits",
            ));
        }
        let source = Arc::new(CheckedSource {
            length: source
                .len()
                .map_err(|e| Error::io("exFAT source length", e))?,
            source,
            resources: resources.clone(),
        });
        if fat(&source, &boot, 0, resources)? & 0xffff_ff00 != 0xffff_ff00 {
            return Err(bad("exFAT FAT media entry"));
        }
        let root = Arc::new(mapping(
            &source,
            &boot,
            boot.root_cluster,
            None,
            false,
            limits,
            resources,
        )?);
        let mut bitmap = None;
        let mut table = None;
        let mut label = None;
        scan(&source, &root, limits, resources, |position, entry| {
            match entry[0] {
                0x81 => {
                    if bitmap.is_some() {
                        return Err(bad("duplicate exFAT allocation bitmap"));
                    }
                    if entry[1] != 0 {
                        return Err(unsupported("unsupported exFAT bitmap flags"));
                    }
                    bitmap = Some((dword(&entry, 20), wide(&entry, 24)));
                }
                0x82 => {
                    if table.is_some() {
                        return Err(bad("duplicate exFAT up-case table"));
                    }
                    table = Some((dword(&entry, 20), wide(&entry, 24), dword(&entry, 4)));
                }
                0x83 => {
                    if label.is_some() || entry[1] > 11 {
                        return Err(bad("invalid exFAT volume label"));
                    }
                    let mut units = allocated(entry[1] as usize)?;
                    for at in 0..entry[1] as usize {
                        units.push(word(&entry, 2 + at * 2));
                    }
                    label = Some(units);
                }
                0x85 => {}
                0xc0 | 0xc1 => {} // File sets are fully validated after up-case discovery.
                other => {
                    return Err(unsupported(&format!(
                        "unsupported exFAT directory entry {other:#x} at {position}"
                    )));
                }
            }
            Ok(())
        })?;
        let (first, length) = bitmap.ok_or_else(|| bad("missing exFAT allocation bitmap"))?;
        if length < u64::from(boot.clusters).div_ceil(8) {
            return Err(bad("exFAT bitmap does not cover heap"));
        }
        let bitmap = Arc::new(mapping(
            &source,
            &boot,
            first,
            Some(length),
            false,
            limits,
            resources,
        )?);
        let (first, length, checksum) = table.ok_or_else(|| bad("missing exFAT up-case table"))?;
        if length == 0 || !length.is_multiple_of(2) || length > limits.max_upcase_bytes as u64 {
            return Err(budget("exFAT up-case length exceeds supported envelope"));
        }
        let table_map = mapping(
            &source,
            &boot,
            first,
            Some(length),
            false,
            limits,
            resources,
        )?;
        for map in [&*root, &*bitmap, &table_map] {
            verify_allocated(&source, &bitmap, &map.clusters, resources)?;
        }
        let mut system_clusters = HashSet::new();
        system_clusters
            .try_reserve(root.clusters.len() + bitmap.clusters.len() + table_map.clusters.len())
            .map_err(|_| budget("exFAT system ownership allocation"))?;
        for cluster in root
            .clusters
            .iter()
            .chain(&bitmap.clusters)
            .chain(&table_map.clusters)
        {
            if !system_clusters.insert(*cluster) {
                return Err(bad("exFAT root/bitmap/up-case allocations overlap"));
            }
        }
        let lease = resources
            .memory
            .reserve(limits.max_upcase_bytes as u64 + 131072 + 64)?;
        let mut bytes = allocated(length as usize)?;
        bytes.resize(length as usize, 0);
        table_map
            .file
            .read_at_with(0, &mut bytes, |at, out| source.read_exact_at(at, out))
            .map_err(|e| Error::io("exFAT up-case read", e))?;
        let actual = bytes.iter().fold(0_u32, |sum, b| {
            sum.rotate_right(1).wrapping_add(u32::from(*b))
        });
        if actual != checksum {
            return Err(bad("exFAT up-case checksum mismatch"));
        }
        let upcase = Arc::new(Upcase {
            table: decode_upcase(&bytes)?,
            _lease: lease,
        });
        let scope = (3u128 << 64)
            | u128::from(
                NEXT_SCOPE
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
                    .map_err(|_| budget("exFAT identity scope exhausted"))?,
            );
        let volume = Self {
            source,
            boot,
            limits,
            scope,
            root,
            bitmap,
            upcase,
            label,
            protected: system_clusters,
        };
        drop(volume.root_directory(resources)?);
        Ok(volume)
    }
    /// Check cancellation and observed source length; this does not establish a byte snapshot.
    pub fn check_stability(&self, resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        self.source.check()
    }
    /// Validated boot geometry and status.
    pub fn boot(&self) -> &ExfatBoot {
        &self.boot
    }
    /// Exact native volume label, when present.
    pub fn label(&self) -> Option<&[u16]> {
        self.label.as_deref()
    }
    /// Source-scoped implicit root identity.
    pub fn root_identity(&self) -> ObjectId {
        ObjectId {
            source: self.scope,
            generation: 0,
            native: Vec::new(),
        }
    }
    /// Full up-case comparison, without host Unicode or OEM guesses.
    pub fn names_equal(&self, left: &[u16], right: &[u16]) -> bool {
        names_equal(&self.upcase.table, left, right)
    }
    /// Enumerate the complete root allocation under configured slot limits.
    pub fn root_directory(&self, resources: &Resources) -> Result<ExfatDirectory> {
        self.directory(&self.root, true, resources)
    }
    /// Enumerate one native directory without following any implicit links.
    pub fn read_directory(
        &self,
        entry: &ExfatEntry,
        resources: &Resources,
    ) -> Result<ExfatDirectory> {
        self.check_entry(entry)?;
        if !entry.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT entry is not a directory",
            ));
        }
        let map = mapping(
            &self.source,
            &self.boot,
            entry.first,
            Some(entry.length),
            entry.no_fat_chain(),
            self.limits,
            resources,
        )?;
        verify_allocated(&self.source, &self.bitmap, &map.clusters, resources)?;
        self.check_protected(&map)?;
        self.directory(&map, false, resources)
    }
    /// Index a regular file once, validating all allocated clusters and its exact FAT chain.
    pub(crate) fn file_map(&self, entry: &ExfatEntry, resources: &Resources) -> Result<Mapping> {
        self.check_entry(entry)?;
        if entry.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT directory is not a regular file",
            ));
        }
        let mut map = mapping(
            &self.source,
            &self.boot,
            entry.first,
            Some(entry.length),
            entry.no_fat_chain(),
            self.limits,
            resources,
        )?;
        verify_allocated(&self.source, &self.bitmap, &map.clusters, resources)?;
        self.check_protected(&map)?;
        let mut extents = allocated(map.file.extents().len().saturating_mul(2))?;
        for e in map.file.extents() {
            if e.offset < entry.valid {
                let length = e.length.min(entry.valid - e.offset);
                extents.push(FileExtent {
                    offset: e.offset,
                    length,
                    kind: e.kind,
                });
            }
            let start = e.offset.max(entry.valid);
            let end = e.offset + e.length;
            if start < end {
                extents.push(FileExtent {
                    offset: start,
                    length: end - start,
                    kind: ExtentKind::Unwritten,
                });
            }
        }
        map.file = ExtentMap::new(
            self.source.length,
            entry.length,
            extents,
            self.limits.max_chain_clusters.saturating_mul(2),
        )
        .map_err(|e| Error::io("exFAT initialized extent map", e))?;
        Ok(map)
    }
    pub(crate) fn audit_system_clusters(&self) -> impl Iterator<Item = u32> + '_ {
        self.protected.iter().copied()
    }
    pub(crate) fn audit_cluster_state(
        &self,
        cluster: u32,
        resources: &Resources,
    ) -> Result<(bool, u32)> {
        self.check_stability(resources)?;
        self.boot.cluster_offset(cluster)?;
        let index = u64::from(cluster - 2);
        let mut byte = [0];
        self.bitmap
            .file
            .read_at_with(index / 8, &mut byte, |at, out| {
                self.source.read_exact_at(at, out)
            })
            .map_err(|e| Error::io("exFAT audit bitmap", e))?;
        Ok((
            byte[0] & (1 << (index % 8)) != 0,
            fat(&self.source, &self.boot, cluster, resources)?,
        ))
    }
    pub(crate) fn audit_allocation(
        &self,
        entry: &ExfatEntry,
        resources: &Resources,
        mut visit: impl FnMut(u32) -> Result<()>,
    ) -> Result<()> {
        self.check_entry(entry)?;
        let map = mapping(
            &self.source,
            &self.boot,
            entry.first,
            Some(entry.length),
            entry.no_fat_chain(),
            self.limits,
            resources,
        )?;
        for &cluster in &map.clusters {
            resources.cancellation.check()?;
            visit(cluster)?;
        }
        Ok(())
    }
    pub(crate) fn audit_directory(
        &self,
        entry: &ExfatEntry,
        resources: &Resources,
    ) -> Result<ExfatDirectory> {
        self.check_entry(entry)?;
        let map = mapping(
            &self.source,
            &self.boot,
            entry.first,
            Some(entry.length),
            entry.no_fat_chain(),
            self.limits,
            resources,
        )?;
        self.directory(&map, false, resources)
    }
    fn check_protected(&self, map: &Mapping) -> Result<()> {
        if map
            .clusters
            .iter()
            .any(|cluster| self.protected.contains(cluster))
        {
            return Err(bad(
                "exFAT user allocation overlaps root or system metadata",
            ));
        }
        Ok(())
    }
    fn check_entry(&self, entry: &ExfatEntry) -> Result<()> {
        self.source.check()?;
        if entry.identity.source != self.scope {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "foreign exFAT entry",
            ));
        }
        Ok(())
    }
    fn directory(
        &self,
        map: &Mapping,
        root: bool,
        resources: &Resources,
    ) -> Result<ExfatDirectory> {
        self.source.check()?;
        resources.cancellation.check()?;
        let slots = usize::try_from(map.file.len() / 32)
            .map_err(|_| budget("exFAT directory slot address space"))?;
        if slots > self.limits.max_directory_slots {
            return Err(budget("exFAT directory slot limit"));
        }
        let charge = (slots as u64)
            .checked_mul(2048)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| budget("exFAT directory accounting overflow"))?;
        let lease = resources.memory.reserve(charge)?;
        let mut entries = allocated(slots / 3)?;
        // At least three slots per file set. Canonical keys use the validated
        // full native table, avoiding quadratic comparisons with prior names.
        // Both keys and hash buckets fit the retained per-slot reservation.
        let mut names = HashSet::new();
        names
            .try_reserve(slots / 3)
            .map_err(|_| budget("exFAT name index allocation"))?;
        let mut slot = 0;
        let mut ended = false;
        while slot < slots {
            resources.cancellation.check()?;
            let primary = slot_at(&self.source, map, slot, resources)?;
            if primary[0] == 0 {
                ended = true;
                slot += 1;
                continue;
            }
            if ended {
                return Err(bad("exFAT non-end slot after directory terminator"));
            }
            if primary[0] < 0x80 {
                slot += 1;
                continue;
            }
            if root && [0x81, 0x82, 0x83].contains(&primary[0]) {
                slot += 1;
                continue;
            }
            if primary[0] != 0x85 {
                return Err(unsupported("unsupported/orphan exFAT directory entry"));
            }
            let secondary = usize::from(primary[1]);
            if !(2..=18).contains(&secondary) {
                return Err(unsupported(
                    "exFAT file extensions or invalid secondary count",
                ));
            }
            if slot
                .checked_add(secondary + 1)
                .is_none_or(|end| end > slots)
            {
                return Err(bad("exFAT truncated file entry set"));
            }
            let mut raw = allocated(secondary + 1)?;
            raw.push(primary);
            for i in 1..=secondary {
                raw.push(slot_at(&self.source, map, slot + i, resources)?);
            }
            if set_checksum(&raw) != word(&primary, 2) {
                return Err(bad("exFAT directory set checksum mismatch"));
            }
            let stream = raw[1];
            if stream[0] != 0xc0 {
                return Err(bad("exFAT stream is not first secondary"));
            }
            if ![1, 3].contains(&stream[1]) {
                return Err(unsupported("unsupported exFAT stream flags"));
            }
            let count = usize::from(stream[3]);
            if count == 0 || secondary != 1 + count.div_ceil(15) {
                return Err(unsupported(
                    "exFAT secondary extensions or invalid name length",
                ));
            }
            let mut name = allocated(count)?;
            for part in &raw[2..] {
                if part[0] != 0xc1 || part[1] != 0 {
                    return Err(unsupported("unsupported exFAT filename secondary"));
                }
                for i in 0..15 {
                    if name.len() < count {
                        name.push(word(part, 2 + i * 2));
                    }
                }
            }
            validate_name(&name)?;
            if name_hash(&self.upcase.table, &name) != word(&stream, 4) {
                return Err(bad("exFAT name hash mismatch"));
            }
            let mut canonical = allocated(name.len())?;
            canonical.extend(
                name.iter()
                    .map(|unit| self.upcase.table[usize::from(*unit)]),
            );
            if !names.insert(canonical) {
                return Err(bad("duplicate exFAT up-cased native name"));
            }
            let attributes = word(&primary, 4);
            if attributes & !0x37 != 0 {
                return Err(unsupported("unknown exFAT file attributes"));
            }
            let first = dword(&stream, 20);
            let length = wide(&stream, 24);
            let valid = wide(&stream, 8);
            let flags = stream[1];
            if valid > length
                || (length == 0 && (first != 0 || flags != 1))
                || (length != 0
                    && (first < 2 || u64::from(first) > u64::from(self.boot.clusters) + 1))
            {
                return Err(bad("exFAT stream lengths/first cluster"));
            }
            if attributes & 0x10 != 0
                && (valid != length
                    || !length.is_multiple_of(u64::from(self.boot.cluster_bytes))
                    || length > 256 * 1024 * 1024)
            {
                return Err(bad("exFAT directory data length"));
            }
            let physical = map
                .file
                .extents()
                .iter()
                .find(|e| e.offset <= slot as u64 * 32 && e.offset + e.length > slot as u64 * 32)
                .and_then(|e| match e.kind {
                    ExtentKind::Data(at) => Some(at + slot as u64 * 32 - e.offset),
                    _ => None,
                })
                .ok_or_else(|| bad("exFAT directory slot has no storage"))?;
            let mut native = allocated(8)?;
            native.extend_from_slice(&physical.to_le_bytes());
            let mut locations = allocated(raw.len())?;
            for index in 0..raw.len() {
                locations.push(map.physical((slot + index) as u64 * 32)?);
            }
            entries.push(ExfatEntry {
                locations,
                identity: ObjectId {
                    source: self.scope,
                    generation: 0,
                    native,
                },
                name,
                raw,
                first,
                length,
                valid,
                flags,
                attributes,
            });
            slot += secondary + 1;
        }
        let mut clusters = allocated(map.clusters.len())?;
        clusters.extend_from_slice(&map.clusters);
        Ok(ExfatDirectory {
            clusters,
            entries,
            upcase: self.upcase.clone(),
            _lease: lease,
        })
    }
}
fn fat(
    source: &CheckedSource<impl ExfatDecodeRead>,
    boot: &ExfatBoot,
    cluster: u32,
    resources: &Resources,
) -> Result<u32> {
    resources.cancellation.check()?;
    let mut bytes = [0; 4];
    source
        .read_exact_at(boot.fat_offset + u64::from(cluster) * 4, &mut bytes)
        .map_err(|e| Error::io("exFAT FAT read", e))?;
    Ok(u32::from_le_bytes(bytes))
}
fn mapping(
    source: &Arc<CheckedSource<impl ExfatDecodeRead>>,
    boot: &ExfatBoot,
    first: u32,
    length: Option<u64>,
    contiguous: bool,
    limits: ExfatReadLimits,
    resources: &Resources,
) -> Result<Mapping> {
    let expected = length.map(|length| length.div_ceil(u64::from(boot.cluster_bytes)));
    if expected.is_some_and(|n| n > u64::from(boot.clusters)) {
        return Err(bad("exFAT allocation length exceeds cluster heap"));
    }
    if expected.is_some_and(|n| n > limits.max_chain_clusters as u64) {
        return Err(budget("exFAT cluster-chain limit"));
    }
    // Known-length chains cannot grow beyond this capacity: the next FAT link is
    // rejected before another cluster is inserted. Charge the full temporary and
    // retained map envelope, including the replacement ValidDataLength map.
    let capacity = expected.unwrap_or(limits.max_chain_clusters as u64) as usize;
    let lease = resources.memory.reserve(
        (capacity as u64)
            .checked_mul(320)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| budget("exFAT map accounting overflow"))?,
    )?;
    let mut clusters = allocated(capacity)?;
    let mut visited = HashSet::new();
    visited
        .try_reserve(capacity)
        .map_err(|_| budget("exFAT chain allocation"))?;
    if expected != Some(0) {
        let mut cluster = first;
        loop {
            resources.cancellation.check()?;
            boot.cluster_offset(cluster)?;
            if clusters.len() >= limits.max_chain_clusters {
                return Err(budget("exFAT cluster-chain limit"));
            }
            if !visited.insert(cluster) {
                return Err(bad("exFAT FAT chain cycle"));
            }
            clusters.push(cluster);
            if contiguous {
                if clusters.len() as u64 == expected.unwrap() {
                    break;
                }
                cluster = cluster
                    .checked_add(1)
                    .ok_or_else(|| bad("exFAT contiguous cluster overflow"))?;
                continue;
            }
            let next = fat(source, boot, cluster, resources)?;
            if next == u32::MAX {
                break;
            }
            if expected.is_some_and(|n| clusters.len() as u64 >= n) {
                return Err(bad("exFAT chain exceeds data length"));
            }
            cluster = next;
        }
    } else if first != 0 {
        return Err(bad("exFAT empty allocation has first cluster"));
    }
    if expected.is_some_and(|n| n != clusters.len() as u64) {
        return Err(bad("exFAT chain shorter than data length"));
    }
    let length = length.unwrap_or(clusters.len() as u64 * u64::from(boot.cluster_bytes));
    let mut extents = allocated(clusters.len())?;
    for (i, cluster) in clusters.iter().enumerate() {
        let offset = i as u64 * u64::from(boot.cluster_bytes);
        extents.push(FileExtent {
            offset,
            length: (length - offset).min(u64::from(boot.cluster_bytes)),
            kind: ExtentKind::Data(boot.cluster_offset(*cluster)?),
        });
    }
    let file = ExtentMap::new(source.length, length, extents, limits.max_chain_clusters)
        .map_err(|e| Error::io("exFAT allocation map", e))?;
    Ok(Mapping {
        file,
        clusters,
        _lease: lease,
    })
}
fn verify_allocated(
    source: &CheckedSource<impl ExfatDecodeRead>,
    bitmap: &Mapping,
    clusters: &[u32],
    resources: &Resources,
) -> Result<()> {
    for cluster in clusters {
        resources.cancellation.check()?;
        let index = u64::from(*cluster - 2);
        let mut byte = [0];
        bitmap
            .file
            .read_at_with(index / 8, &mut byte, |at, out| {
                source.read_exact_at(at, out)
            })
            .map_err(|e| Error::io("exFAT allocation bitmap read", e))?;
        if byte[0] & (1 << (index % 8)) == 0 {
            return Err(bad("exFAT referenced cluster is free in allocation bitmap"));
        }
    }
    Ok(())
}
fn slot_at(
    source: &CheckedSource<impl ExfatDecodeRead>,
    map: &Mapping,
    index: usize,
    resources: &Resources,
) -> Result<[u8; 32]> {
    resources.cancellation.check()?;
    let mut slot = [0; 32];
    if map
        .file
        .read_at_with(index as u64 * 32, &mut slot, |at, out| {
            source.read_exact_at(at, out)
        })
        .map_err(|e| Error::io("exFAT directory read", e))?
        != 32
    {
        return Err(bad("exFAT short directory slot"));
    }
    Ok(slot)
}
fn scan(
    source: &CheckedSource<impl ExfatDecodeRead>,
    map: &Mapping,
    limits: ExfatReadLimits,
    resources: &Resources,
    mut visitor: impl FnMut(usize, [u8; 32]) -> Result<()>,
) -> Result<()> {
    let slots = usize::try_from(map.file.len() / 32)
        .map_err(|_| budget("exFAT root slot address space"))?;
    if slots > limits.max_directory_slots {
        return Err(budget("exFAT directory slot limit"));
    }
    let mut ended = false;
    for i in 0..slots {
        let slot = slot_at(source, map, i, resources)?;
        if slot[0] == 0 {
            ended = true;
            continue;
        }
        if ended {
            return Err(bad("exFAT non-end slot after directory terminator"));
        }
        if slot[0] < 0x80 {
            continue;
        }
        visitor(i, slot)?;
    }
    Ok(())
}
fn decode_upcase(bytes: &[u8]) -> Result<Vec<u16>> {
    let mut table = allocated(65536)?;
    let mut words = bytes.chunks_exact(2);
    while let Some(bytes) = words.next() {
        let value = word(bytes, 0);
        if value == 0xffff && table.len() != 65535 {
            let count = word(
                words
                    .next()
                    .ok_or_else(|| bad("truncated exFAT up-case identity run"))?,
                0,
            ) as usize;
            if count == 0 || table.len() + count > 65536 {
                return Err(bad("invalid exFAT up-case identity run"));
            }
            for _ in 0..count {
                table.push(table.len() as u16);
            }
        } else {
            if table.len() >= 65536 {
                return Err(bad("oversized exFAT up-case table"));
            }
            table.push(value);
        }
    }
    if table.len() != 65536 {
        return Err(bad("incomplete exFAT up-case table"));
    }
    for (unit, mapping) in table.iter().enumerate().take(128) {
        let expected = if (97..=122).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        if *mapping != expected as u16 {
            return Err(bad("invalid exFAT mandatory up-case mapping"));
        }
    }
    Ok(table)
}
fn names_equal(upcase: &[u16], left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| upcase[*a as usize] == upcase[*b as usize])
}
fn name_hash(upcase: &[u16], name: &[u16]) -> u16 {
    name.iter()
        .flat_map(|unit| upcase[*unit as usize].to_le_bytes())
        .fold(0_u16, |hash, b| {
            hash.rotate_right(1).wrapping_add(u16::from(b))
        })
}
fn set_checksum(raw: &[[u8; 32]]) -> u16 {
    raw.iter()
        .flatten()
        .enumerate()
        .filter(|(i, _)| *i != 2 && *i != 3)
        .fold(0_u16, |sum, (_, byte)| {
            sum.rotate_right(1).wrapping_add(u16::from(*byte))
        })
}
/// Reusable indexed immutable file; allocated-uninitialized ranges return zero bytes.
#[derive(Clone)]
pub struct ExfatFile {
    identity: Arc<ObjectId>,
    source: Arc<CheckedSource<Arc<dyn ReadAt>>>,
    map: Arc<Mapping>,
}
impl FileRead for ExfatFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.map.file.len()
    }
    fn read_at(&self, offset: u64, out: &mut [u8], resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        self.source.check()?;
        if offset >= self.len() {
            return Ok(0);
        }
        let count = self
            .map
            .file
            .read_at_with(offset, out, |at, buf| self.source.read_exact_at(at, buf))
            .map_err(|e| Error::io("exFAT file read", e))?;
        self.source.check()?;
        Ok(count)
    }
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.source.check()?;
        for e in self.map.file.extents() {
            resources.cancellation.check()?;
            visitor(LogicalExtent {
                offset: e.offset,
                length: e.length,
                kind: match e.kind {
                    ExtentKind::Data(_) => crate::fs_core::ExtentKind::Data,
                    ExtentKind::Unwritten => crate::fs_core::ExtentKind::Unwritten,
                    ExtentKind::Hole => crate::fs_core::ExtentKind::Hole,
                },
            })?;
        }
        self.source.check()
    }
}

/// Strict immutable single-FAT exFAT volume; caller guarantees stable source bytes.
pub struct ExfatVolume {
    decoder: ExfatDecoder<Arc<dyn ReadAt>>,
}
impl ExfatVolume {
    /// Validate boot, native root/system chains, bitmap and up-case table.
    pub fn open(source: Arc<dyn ReadAt>, limits: ExfatReadLimits, r: &Resources) -> Result<Self> {
        Ok(Self {
            decoder: ExfatDecoder::open(source, limits, r)?,
        })
    }
    /// Check cancellation and current backing length.
    pub fn check_stability(&self, r: &Resources) -> Result<()> {
        self.decoder.check_stability(r)
    }
    /// Validated geometry.
    pub fn boot(&self) -> &ExfatBoot {
        self.decoder.boot()
    }
    /// Native volume label.
    pub fn label(&self) -> Option<&[u16]> {
        self.decoder.label()
    }
    /// Scoped implicit root identity.
    pub fn root_identity(&self) -> ObjectId {
        self.decoder.root_identity()
    }
    /// Compare units through the on-volume up-case table.
    pub fn names_equal(&self, a: &[u16], b: &[u16]) -> bool {
        self.decoder.names_equal(a, b)
    }
    /// Complete root directory allocation.
    pub fn root_directory(&self, r: &Resources) -> Result<ExfatDirectory> {
        self.decoder.root_directory(r)
    }
    /// Complete native directory inventory.
    pub fn read_directory(&self, e: &ExfatEntry, r: &Resources) -> Result<ExfatDirectory> {
        self.decoder.read_directory(e, r)
    }
    /// Reusable immutable mapped file with initialized-prefix semantics.
    pub fn open_file(&self, e: &ExfatEntry, r: &Resources) -> Result<ExfatFile> {
        let map = self.decoder.file_map(e, r)?;
        let mut native = allocated(e.identity.native.len())?;
        native.extend_from_slice(&e.identity.native);
        Ok(ExfatFile {
            identity: Arc::new(ObjectId {
                source: e.identity.source,
                generation: e.identity.generation,
                native,
            }),
            source: self.decoder.source.clone(),
            map: Arc::new(map),
        })
    }
}
impl<'a> ExfatDecoder<&'a dyn crate::storage::Storage> {
    pub(crate) fn open_storage(
        source: &'a dyn crate::storage::Storage,
        scope: u128,
        limits: ExfatReadLimits,
        r: &Resources,
    ) -> Result<Self> {
        let mut value = Self::open(source, limits, r)?;
        value.scope = scope;
        Ok(value)
    }
    pub(crate) fn bitmap_position(&self, cluster: u32) -> Result<(u64, u8)> {
        self.boot.cluster_offset(cluster)?;
        let bit = u64::from(cluster - 2);
        Ok((self.bitmap.physical(bit / 8)?, 1 << (bit % 8)))
    }
}
impl Mapping {
    pub(crate) fn physical(&self, offset: u64) -> Result<u64> {
        self.file
            .extents()
            .iter()
            .find(|e| e.offset <= offset && offset - e.offset < e.length)
            .and_then(|e| match e.kind {
                ExtentKind::Data(at) => at.checked_add(offset - e.offset),
                _ => None,
            })
            .ok_or_else(|| bad("exFAT physical map position"))
    }
}
impl ExfatEntry {
    pub(crate) fn edit_locations(&self) -> &[u64] {
        &self.locations
    }
}
impl<R: ExfatDecodeRead> ExfatDecoder<R> {
    pub(crate) fn edit_allocation_map(&self, entry: &ExfatEntry, r: &Resources) -> Result<Mapping> {
        self.check_entry(entry)?;
        let map = mapping(
            &self.source,
            &self.boot,
            entry.first,
            Some(entry.length),
            entry.no_fat_chain(),
            self.limits,
            r,
        )?;
        verify_allocated(&self.source, &self.bitmap, &map.clusters, r)?;
        self.check_protected(&map)?;
        Ok(map)
    }
    pub(crate) fn edit_directory_map(
        &self,
        entry: Option<&ExfatEntry>,
        r: &Resources,
    ) -> Result<Mapping> {
        match entry {
            Some(entry) if entry.is_directory() => self.edit_allocation_map(entry, r),
            Some(_) => Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT object is not a directory",
            )),
            None => mapping(
                &self.source,
                &self.boot,
                self.boot.root_cluster,
                Some(self.root.file.len()),
                false,
                self.limits,
                r,
            ),
        }
    }
    pub(crate) fn edit_name_hash(&self, name: &[u16]) -> Result<u16> {
        validate_name(name)?;
        Ok(name_hash(&self.upcase.table, name))
    }
}
pub(crate) fn validate_name(name: &[u16]) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name
            .iter()
            .any(|c| *c < 32 || [34, 42, 47, 58, 60, 62, 63, 92, 124].contains(c))
        || name == [46]
        || name == [46, 46]
    {
        return Err(bad("invalid exFAT native filename"));
    }
    Ok(())
}
