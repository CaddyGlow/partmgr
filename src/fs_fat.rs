//! FAT12/16/32 geometry, bounded namespace inspection, and chain reads.
//!
//! This is not an ownership audit or writable FAT profile.
//! Inputs must remain immutable for all deferred reads. Files are opened from
//! caller-supplied cluster/size facts; callers must establish their provenance.
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
    fs_core::{NativeName, ObjectId, Reservation, Resources},
    fs_file::{ExtentFile, ExtentKind, FileExtent},
};
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
use crate::io::{DiskView, ReadAt};
use crate::storage::Storage;

/// FAT entry width selected solely from the data cluster count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatFamily {
    /// Twelve-bit packed entries.
    Fat12,
    /// Sixteen-bit entries.
    Fat16,
    /// Twenty-eight meaningful bits in thirty-two-bit entries.
    Fat32,
}
/// Validated geometry of the supported BPB profile, in volume-relative bytes.
#[derive(Clone, Debug)]
pub struct FatGeometry {
    family: FatFamily,
    media_descriptor: u8,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    cluster_count: u32,
    volume_bytes: u64,
    fat_offset: u64,
    fat_bytes: u64,
    fat_count: u8,
    data_offset: u64,
    root_offset: Option<u64>,
    root_bytes: u64,
    root_cluster: Option<u32>,
    active_fat: Option<u8>,
    fsinfo_sector: Option<u16>,
    backup_sector: Option<u16>,
}
impl FatGeometry {
    /// Decoded family; the label string is never used for this decision.
    pub fn family(&self) -> FatFamily {
        self.family
    }
    /// Validated BPB media descriptor used by reserved FAT entry zero.
    pub fn media_descriptor(&self) -> u8 {
        self.media_descriptor
    }
    /// Sector byte size recorded in the BPB, not backend physical geometry.
    pub fn bytes_per_sector(&self) -> u16 {
        self.bytes_per_sector
    }
    /// Cluster byte size, independent of container allocation size.
    pub fn cluster_bytes(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_cluster)
    }
    /// Count of addressable data clusters, starting at cluster 2.
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }
    /// Declared volume size; the supplied source may include trailing bytes.
    pub fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }
    /// First FAT byte position.
    pub fn fat_offset(&self) -> u64 {
        self.fat_offset
    }
    /// Length of each FAT copy.
    pub fn fat_bytes(&self) -> u64 {
        self.fat_bytes
    }
    /// Number of FAT copies.
    pub fn fat_count(&self) -> u8 {
        self.fat_count
    }
    /// First byte of cluster 2.
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }
    /// Fixed root directory position for FAT12/16; FAT32 uses a chain instead.
    pub fn root_offset(&self) -> Option<u64> {
        self.root_offset
    }
    /// Rounded fixed root region byte length, zero on FAT32.
    pub fn root_bytes(&self) -> u64 {
        self.root_bytes
    }
    /// FAT32 root cluster, not an allocation/chain validity claim.
    pub fn root_cluster(&self) -> Option<u32> {
        self.root_cluster
    }
    /// Selected FAT when mirroring is disabled; `None` means mirrored FATs.
    pub fn active_fat(&self) -> Option<u8> {
        self.active_fat
    }
    /// Declared FSInfo sector; content and free-space hints are not audited.
    pub fn fsinfo_sector(&self) -> Option<u16> {
        self.fsinfo_sector
    }
    /// Declared backup boot sector; content is not verified here.
    pub fn backup_sector(&self) -> Option<u16> {
        self.backup_sector
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn dword(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Immutable volume retained for deferred FAT and payload access.
pub(crate) trait FatDecodeRead {
    fn len(&self) -> io::Result<u64>;
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()>;
}
impl FatDecodeRead for Arc<dyn ReadAt> {
    fn len(&self) -> io::Result<u64> {
        Ok(ReadAt::len(self.as_ref()))
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.as_ref().read_exact_at(offset, out)
    }
}
impl FatDecodeRead for &dyn Storage {
    fn len(&self) -> io::Result<u64> {
        Storage::len(*self)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        Storage::read_exact_at(*self, offset, out)
    }
}
pub(crate) struct FatDecoder<R> {
    source: R,
    geometry: FatGeometry,
    identity: u128,
}
impl<R: FatDecodeRead> FatDecoder<R> {
    /// Inspect a bounded source without reading the entire FAT or any payload.
    ///
    /// Supports conventional 512/1024/2048/4096-byte sectors and clusters up to
    /// 32 KiB. FAT32 requires version 0:0 and in-reserved-area FSInfo/backup
    /// references. Other historical or vendor profiles are explicitly rejected.
    fn open(source: R, identity: u128) -> io::Result<Self> {
        let mut b = [0; 512];
        source.read_exact_at(0, &mut b)?;
        if b[510..512] != [0x55, 0xaa] {
            return Err(invalid("missing FAT boot signature"));
        }
        let bps = word(&b, 11);
        let spc = b[13];
        let reserved = u64::from(word(&b, 14));
        let fats = b[16];
        let roots = u64::from(word(&b, 17));
        if !matches!(bps, 512 | 1024 | 2048 | 4096)
            || !spc.is_power_of_two()
            || spc > 128
            || u64::from(bps) * u64::from(spc) > 32768
            || reserved == 0
            || fats == 0
        {
            return Err(invalid(
                "unsupported or invalid FAT sector/cluster/reserved geometry",
            ));
        }
        if b[21] != 0xf0 && !(0xf8..=0xff).contains(&b[21]) {
            return Err(invalid("invalid FAT media descriptor"));
        }
        let total16 = u64::from(word(&b, 19));
        let total32 = u64::from(dword(&b, 32));
        if (total16 == 0) == (total32 == 0) {
            return Err(invalid("ambiguous or empty FAT total sectors"));
        }
        let total = if total16 != 0 { total16 } else { total32 };
        let fatsz16 = u64::from(word(&b, 22));
        let fatsz = if fatsz16 != 0 {
            fatsz16
        } else {
            u64::from(dword(&b, 36))
        };
        if fatsz == 0 {
            return Err(invalid("zero FAT size"));
        }
        // All BPB factors are at most u32 and these calculations fit in u64.
        let root_sectors = (roots * 32).div_ceil(u64::from(bps));
        let root_sector = reserved + u64::from(fats) * fatsz;
        let data_sector = root_sector + root_sectors;
        if data_sector >= total {
            return Err(invalid("FAT/root areas leave no data region"));
        }
        let clusters = (total - data_sector) / u64::from(spc);
        let family = if clusters < 4085 {
            FatFamily::Fat12
        } else if clusters < 65525 {
            FatFamily::Fat16
        } else {
            FatFamily::Fat32
        };
        let max_cluster = match family {
            FatFamily::Fat12 => 0xfef,
            FatFamily::Fat16 => 0xffef,
            FatFamily::Fat32 => 0x0fff_ffef,
        };
        if clusters == 0 || clusters + 1 > max_cluster {
            return Err(invalid("cluster range overlaps reserved FAT markers"));
        }
        let required_fat_bytes = match family {
            FatFamily::Fat12 => ((clusters + 2) * 3).div_ceil(2),
            FatFamily::Fat16 => (clusters + 2) * 2,
            FatFamily::Fat32 => (clusters + 2) * 4,
        };
        let fat_bytes = fatsz * u64::from(bps);
        if required_fat_bytes > fat_bytes {
            return Err(invalid("FAT capacity cannot describe data clusters"));
        }
        let volume_bytes = total * u64::from(bps);
        if volume_bytes > source.len()? {
            return Err(invalid("FAT volume exceeds bounded source"));
        }
        let (root_cluster, active_fat, fsinfo_sector, backup_sector) = if family == FatFamily::Fat32
        {
            if fatsz16 != 0 || roots != 0 || total16 != 0 {
                return Err(invalid("FAT32 uses incompatible legacy BPB fields"));
            }
            if word(&b, 42) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported FAT32 version",
                ));
            }
            let flags = word(&b, 40);
            if flags & !0x008f != 0 {
                return Err(invalid("reserved FAT32 flags are set"));
            }
            let active = if flags & 0x80 != 0 {
                let index = (flags & 0xf) as u8;
                if index >= fats {
                    return Err(invalid("FAT32 active FAT is outside FAT copies"));
                }
                Some(index)
            } else {
                None
            };
            let root = dword(&b, 44);
            if root < 2 || u64::from(root) > clusters + 1 {
                return Err(invalid("FAT32 root cluster is outside data region"));
            }
            let fsinfo = word(&b, 48);
            let backup = word(&b, 50);
            if fsinfo == 0 || u64::from(fsinfo) >= reserved {
                return Err(invalid("FAT32 FSInfo is outside reserved area"));
            }
            if backup != 0 && (u64::from(backup) + 3 > reserved || backup == fsinfo) {
                return Err(invalid(
                    "FAT32 backup boot record is outside reserved area or overlaps FSInfo",
                ));
            }
            (
                Some(root),
                active,
                Some(fsinfo),
                if backup == 0 { None } else { Some(backup) },
            )
        } else {
            if fatsz16 == 0 || roots == 0 || (roots * 32) % u64::from(bps) != 0 {
                return Err(invalid(
                    "FAT12/16 requires integral fixed root and legacy FAT size",
                ));
            }
            (None, None, None, None)
        };
        let geometry = FatGeometry {
            family,
            media_descriptor: b[21],
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_count: clusters as u32,
            volume_bytes,
            fat_offset: reserved * u64::from(bps),
            fat_bytes,
            fat_count: fats,
            data_offset: data_sector * u64::from(bps),
            root_offset: if family == FatFamily::Fat32 {
                None
            } else {
                Some(root_sector * u64::from(bps))
            },
            root_bytes: root_sectors * u64::from(bps),
            root_cluster,
            active_fat,
            fsinfo_sector,
            backup_sector,
        };
        Ok(FatDecoder {
            source,
            geometry,
            identity,
        })
    }
    /// Validated BPB facts; this is not an allocation or namespace audit.
    pub fn geometry(&self) -> &FatGeometry {
        &self.geometry
    }
    /// Read one explicitly selected FAT copy, including reserved entries zero and one.
    /// FAT32 values retain only the twenty-eight defined bits. This validates bounds,
    /// not allocation ownership or agreement with other copies.
    pub fn read_fat_entry(&self, copy: u8, cluster: u32) -> io::Result<u32> {
        if copy >= self.geometry.fat_count || cluster > self.geometry.cluster_count + 1 {
            return Err(invalid("FAT copy or cluster index out of bounds"));
        }
        self.entry_from(copy, cluster)
    }
    fn entry_from(&self, copy: u8, cluster: u32) -> io::Result<u32> {
        let n = u64::from(cluster);
        let (offset, count) = match self.geometry.family {
            FatFamily::Fat12 => (n + n / 2, 2),
            FatFamily::Fat16 => (n * 2, 2),
            FatFamily::Fat32 => (n * 4, 4),
        };
        if offset + count > self.geometry.fat_bytes {
            return Err(invalid("FAT entry exceeds selected FAT"));
        }
        let mut bytes = [0; 4];
        self.source.read_exact_at(
            self.geometry.fat_offset + u64::from(copy) * self.geometry.fat_bytes + offset,
            &mut bytes[..count as usize],
        )?;
        Ok(match self.geometry.family {
            FatFamily::Fat12 => {
                let value = u32::from(word(&bytes, 0));
                if cluster & 1 != 0 {
                    value >> 4
                } else {
                    value & 0xfff
                }
            }
            FatFamily::Fat16 => u32::from(word(&bytes, 0)),
            FatFamily::Fat32 => dword(&bytes, 0) & 0x0fff_ffff,
        })
    }
    fn next(&self, cluster: u32) -> io::Result<u32> {
        let value = self.entry_from(self.geometry.active_fat.unwrap_or(0), cluster)?;
        if self.geometry.active_fat.is_none() {
            for copy in 1..self.geometry.fat_count {
                if self.entry_from(copy, cluster)? != value {
                    return Err(invalid("mirrored FAT entries disagree"));
                }
            }
        }
        Ok(value)
    }
    /// Build a bounded reusable direct file map from explicit directory facts.
    ///
    /// Requires exactly the clusters needed for `length` followed by EOC. This
    /// rejects cycles, short/excess chains, free/bad/reserved entries, and mirror
    /// disagreement. It does not establish cross-file ownership or decode names.
    /// Work is linear and limited by `max_clusters`; repeated reads use the map.
    pub fn open_file(
        &self,
        first_cluster: u32,
        length: u32,
        max_clusters: usize,
        resources: &Resources,
    ) -> io::Result<FatDecodedFileMap> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let length = u64::from(length);
        let count = length.div_ceil(self.geometry.cluster_bytes());
        if count > max_clusters as u64 || count > u64::from(self.geometry.cluster_count) {
            return Err(io::Error::other("FAT file chain budget exhausted"));
        }
        // Includes the input map, coalescing scratch, and final shared map.
        let bytes = count
            .checked_mul((3 * crate::platform::mem::size_of::<FileExtent>()) as u64)
            .ok_or_else(|| io::Error::other("FAT map budget overflow"))?;
        let reservation = resources.memory.reserve(bytes).map_err(io::Error::other)?;
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(count as usize)
            .map_err(io::Error::other)?;
        if count == 0 && first_cluster != 0 {
            return Err(invalid("empty FAT file has allocated first cluster"));
        }
        let mut cluster = first_cluster;
        let mut offset = 0;
        let reserved = match self.geometry.family {
            FatFamily::Fat12 => 0xff0,
            FatFamily::Fat16 => 0xfff0,
            FatFamily::Fat32 => 0x0fff_fff0,
        };
        let eoc = reserved + 8;
        for index in 0..count {
            resources.cancellation.check().map_err(io::Error::other)?;
            if cluster < 2 || cluster >= reserved || cluster > self.geometry.cluster_count + 1 {
                return Err(invalid("invalid cluster in FAT file chain"));
            }
            let size = (length - offset).min(self.geometry.cluster_bytes());
            extents.push(FileExtent {
                offset,
                length: size,
                kind: ExtentKind::Data(
                    self.geometry.data_offset
                        + u64::from(cluster - 2) * self.geometry.cluster_bytes(),
                ),
            });
            offset += size;
            let next = self.next(cluster)?;
            if index + 1 == count {
                if next < eoc {
                    return Err(invalid(
                        "FAT file chain exceeds declared length or contains a cycle",
                    ));
                }
            } else if next >= eoc {
                return Err(invalid("FAT file chain ends before declared length"));
            }
            cluster = next;
        }
        Ok(FatDecodedFileMap {
            extents,
            length,
            reservation,
        })
    }
}
/// A bounded indexed FAT chain retained with its memory reservation.
pub struct FatFile {
    file: ExtentFile,
    _reservation: Reservation,
}
impl FatFile {
    /// Logical file length.
    pub fn len(&self) -> u64 {
        self.file.len()
    }
    /// Whether the file has no bytes.
    pub fn is_empty(&self) -> bool {
        self.file.is_empty()
    }
    /// Direct positional read; errors may partially modify the caller buffer.
    pub fn read_at(&self, offset: u64, out: &mut [u8], resources: &Resources) -> io::Result<usize> {
        resources.cancellation.check().map_err(io::Error::other)?;
        self.file.read_at(offset, out)
    }
    /// Validated data mapping; adjacent storage ranges are coalesced.
    pub fn extents(&self) -> &[FileExtent] {
        self.file.extents()
    }
}

/// Namespace object validated from a directory slot, scoped to this volume open.
#[derive(Clone, Debug)]
pub struct FatEntry {
    name: NativeName,
    short_name: [u8; 11],
    raw: [u8; 32],
    identity: ObjectId,
    cluster: u32,
}
impl FatEntry {
    /// Exact UTF-16 LFN, or the exact eleven-byte short alias.
    pub fn name(&self) -> &NativeName {
        &self.name
    }
    /// Original short alias, including padding and the encoded 0x05 first byte.
    pub fn short_name(&self) -> &[u8; 11] {
        &self.short_name
    }
    /// Original metadata slot, retaining native timestamps and flags.
    pub fn raw_metadata(&self) -> &[u8; 32] {
        &self.raw
    }
    /// Source-scoped slot identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Whether this entry names a directory.
    pub fn is_directory(&self) -> bool {
        self.raw[11] & 0x10 != 0
    }
    /// Logical file length (zero for directories in this supported profile).
    pub fn len(&self) -> u32 {
        dword(&self.raw, 28)
    }
    /// Whether the declared length is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// Bounded directory inventory retaining all memory accounting.
pub struct FatDirectory {
    entries: Vec<FatEntry>,
    _reservation: Reservation,
}
impl FatDirectory {
    /// Rebind borrowed mutable-session inventory to the owning editor generation.
    pub(crate) fn set_generation(&mut self, generation: u64) {
        for entry in &mut self.entries {
            entry.identity.generation = generation;
        }
    }
    /// Native entries; deleted slots, dot entries, and volume labels are excluded.
    pub fn entries(&self) -> &[FatEntry] {
        &self.entries
    }
    /// Exact native-name lookup. OEM codepage and case folding are not guessed.
    pub fn lookup(&self, name: &NativeName) -> io::Result<Option<&FatEntry>> {
        let mut matches = self.entries.iter().filter(|entry| &entry.name == name);
        let first = matches.next();
        if matches.next().is_some() {
            return Err(invalid("ambiguous FAT name"));
        }
        Ok(first)
    }
}
impl<R: FatDecodeRead> FatDecoder<R> {
    /// Source-scoped root identity, distinct from all directory slots.
    pub fn root_identity(&self) -> ObjectId {
        ObjectId {
            source: self.identity,
            generation: 0,
            native: Vec::new(),
        }
    }
    /// Enumerate the root, bounding both chain traversal and scanned slots.
    pub fn root_directory(
        &self,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> io::Result<FatDirectory> {
        self.directory(None, max_clusters, max_slots, resources)
    }
    /// Enumerate a directory entry from this volume, without following dot links.
    pub fn read_directory(
        &self,
        entry: &FatEntry,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> io::Result<FatDirectory> {
        self.check_entry(entry)?;
        if !entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FAT object is not a directory",
            ));
        }
        self.directory(Some(entry.cluster), max_clusters, max_slots, resources)
    }
    fn check_entry(&self, entry: &FatEntry) -> io::Result<()> {
        if entry.identity.source != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FAT object belongs to another source",
            ));
        }
        Ok(())
    }
    pub(crate) fn file_map(
        &self,
        entry: &FatEntry,
        max_clusters: usize,
        resources: &Resources,
    ) -> io::Result<FatDecodedFileMap> {
        self.check_entry(entry)?;
        if entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FAT directory is not a file",
            ));
        }
        self.open_file(entry.cluster, entry.len(), max_clusters, resources)
    }
    fn directory(
        &self,
        cluster: Option<u32>,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> io::Result<FatDirectory> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let charge = (max_slots as u64)
            .checked_mul((crate::platform::mem::size_of::<FatEntry>() + 540) as u64)
            .and_then(|v| v.checked_add((max_clusters as u64).checked_mul(64)?))
            .and_then(|v| v.checked_add(1100))
            .ok_or_else(|| io::Error::other("FAT directory budget overflow"))?;
        let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(max_slots)
            .map_err(io::Error::other)?;
        let mut seen = HashSet::new();
        seen.try_reserve(max_clusters).map_err(io::Error::other)?;
        let mut current = cluster.or(self.geometry.root_cluster);
        let mut slots = 0usize;
        let mut lfn = Lfn::default();
        loop {
            let (base, bytes) = if let Some(c) = current {
                if c < 2 || c > self.geometry.cluster_count + 1 {
                    return Err(invalid("FAT directory cluster out of range"));
                }
                if seen.contains(&c) {
                    return Err(invalid("FAT directory chain cycle"));
                }
                if seen.len() == max_clusters {
                    return Err(io::Error::other("FAT directory chain budget exhausted"));
                }
                seen.insert(c);
                (
                    self.geometry.data_offset + u64::from(c - 2) * self.geometry.cluster_bytes(),
                    self.geometry.cluster_bytes(),
                )
            } else {
                (
                    self.geometry
                        .root_offset
                        .ok_or_else(|| invalid("missing FAT root"))?,
                    self.geometry.root_bytes,
                )
            };
            let mut ended = false;
            for offset in (0..bytes).step_by(32) {
                resources.cancellation.check().map_err(io::Error::other)?;
                if slots == max_slots {
                    return Err(io::Error::other("FAT directory slot budget exhausted"));
                }
                slots += 1;
                let mut raw = [0; 32];
                self.source.read_exact_at(base + offset, &mut raw)?;
                if raw[0] == 0 {
                    if lfn.total != 0 {
                        return Err(invalid("orphan FAT long name"));
                    }
                    ended = true;
                    break;
                }
                if raw[0] == 0xe5 {
                    lfn = Lfn::default();
                    continue;
                }
                if raw[11] == 0x0f {
                    lfn.push(&raw)?;
                    continue;
                }
                if raw[11] & 0xc0 != 0 || raw[11] & 0x18 == 0x18 {
                    return Err(invalid("invalid FAT entry attributes"));
                }
                let mut short_name = [0; 11];
                short_name.copy_from_slice(&raw[..11]);
                let name = lfn.finish(&short_name)?;
                if raw[11] & 8 != 0 {
                    continue;
                }
                if &short_name == b".          " || &short_name == b"..         " {
                    continue;
                }
                for range in [0..8, 8..11] {
                    let mut padded = false;
                    for index in range {
                        let byte = short_name[index];
                        if byte == b' ' {
                            padded = true;
                            continue;
                        }
                        if padded
                            || (byte < 0x20 && !(index == 0 && byte == 0x05))
                            || b"\"*+,/:;<=>?[\\]|".contains(&byte)
                        {
                            return Err(invalid("invalid FAT short name"));
                        }
                    }
                }
                if short_name[0] == b' ' {
                    return Err(invalid("empty FAT short name"));
                }
                let high = word(&raw, 20);
                if self.geometry.family != FatFamily::Fat32 && high != 0 {
                    return Err(invalid("legacy FAT entry has high cluster bits"));
                }
                let c = u32::from(word(&raw, 26)) | (u32::from(high) << 16);
                if c > self.geometry.cluster_count + 1
                    || (raw[11] & 0x10 == 0
                        && ((dword(&raw, 28) == 0 && c != 0) || (dword(&raw, 28) != 0 && c < 2)))
                {
                    return Err(invalid("invalid FAT namespace file cluster"));
                }
                if raw[11] & 0x10 != 0 && (c < 2 || dword(&raw, 28) != 0) {
                    return Err(invalid("invalid FAT directory entry"));
                }
                entries.push(FatEntry {
                    name,
                    short_name,
                    raw,
                    cluster: c,
                    identity: ObjectId {
                        source: self.identity,
                        generation: 0,
                        native: (base + offset).to_le_bytes().to_vec(),
                    },
                });
            }
            // A terminator bounds namespace reads; unused directory tail is not audited.
            if ended {
                break;
            }
            if let Some(c) = current {
                let next = self.next(c)?;
                let eoc = match self.geometry.family {
                    FatFamily::Fat12 => 0xff8,
                    FatFamily::Fat16 => 0xfff8,
                    FatFamily::Fat32 => 0x0fff_fff8,
                };
                if next >= eoc {
                    break;
                }
                current = Some(next);
            } else {
                break;
            }
        }
        if lfn.total != 0 {
            return Err(invalid("orphan FAT long name"));
        }
        Ok(FatDirectory {
            entries,
            _reservation: reservation,
        })
    }
}
#[derive(Default)]
struct Lfn {
    expected: u8,
    checksum: u8,
    total: usize,
    parts: Vec<[u16; 13]>,
}
impl Lfn {
    fn push(&mut self, raw: &[u8; 32]) -> io::Result<()> {
        let ordinal = raw[0] & 0x1f;
        if raw[0] & 0xa0 != 0 || ordinal == 0 || ordinal > 20 || raw[12] != 0 || word(raw, 26) != 0
        {
            return Err(invalid("invalid FAT long name slot"));
        }
        if raw[0] & 0x40 != 0 {
            if self.total != 0 {
                return Err(invalid("interrupted FAT long name"));
            }
            self.expected = ordinal;
            self.total = usize::from(ordinal);
            self.checksum = raw[13];
            self.parts = vec![[0; 13]; self.total];
        }
        if self.expected != ordinal || self.checksum != raw[13] {
            return Err(invalid("FAT long name ordinal/checksum mismatch"));
        }
        for (i, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            self.parts[usize::from(ordinal - 1)][i] = word(raw, at);
        }
        self.expected -= 1;
        Ok(())
    }
    fn finish(&mut self, short: &[u8; 11]) -> io::Result<NativeName> {
        if self.total == 0 {
            return Ok(NativeName::Bytes(short.to_vec()));
        }
        let sum = short
            .iter()
            .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte));
        if self.expected != 0 || sum != self.checksum {
            return Err(invalid("FAT long name lacks matching short alias"));
        }
        let mut units = Vec::new();
        let mut padding = false;
        for unit in self.parts.iter().flatten().copied() {
            if padding {
                if unit != 0xffff {
                    return Err(invalid("invalid FAT long name padding"));
                }
            } else if unit == 0 {
                padding = true;
            } else if unit == 0xffff {
                return Err(invalid("FAT long name padding before terminator"));
            } else {
                units.push(unit);
            }
        }
        if units.is_empty()
            || units.len() > 255
            || (padding && units.len() <= (self.total - 1) * 13)
        {
            return Err(invalid("invalid FAT long name length"));
        }
        *self = Self::default();
        Ok(NativeName::Utf16(units))
    }
}
/// Namespace-opened positional file handle.
pub struct FatNamespaceFile {
    identity: ObjectId,
    file: FatFile,
}
impl crate::fs_core::FileRead for FatNamespaceFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(
        &self,
        offset: u64,
        buffer: &mut [u8],
        resources: &Resources,
    ) -> crate::fs_core::Result<usize> {
        resources.cancellation.check()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        self.file
            .read_at(offset, buffer, resources)
            .map_err(|e| crate::fs_core::Error::io("FAT payload read", e))
    }
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(crate::fs_core::LogicalExtent) -> crate::fs_core::Result<()>,
    ) -> crate::fs_core::Result<()> {
        for extent in self.file.extents() {
            resources.cancellation.check()?;
            visitor(crate::fs_core::LogicalExtent {
                offset: extent.offset,
                length: extent.length,
                kind: crate::fs_core::ExtentKind::Data,
            })?;
        }
        Ok(())
    }
}

/// Immutable volume retained for deferred FAT and payload access.
pub struct FatVolume {
    pub(crate) decoder: FatDecoder<Arc<dyn ReadAt>>,
}
pub(crate) type FatStorageDecoder<'a> = FatDecoder<&'a dyn Storage>;
pub(crate) struct FatDecodedFileMap {
    pub(crate) extents: Vec<FileExtent>,
    pub(crate) length: u64,
    pub(crate) reservation: Reservation,
}
impl<'a> FatDecoder<&'a dyn Storage> {
    pub(crate) fn open_storage(source: &'a dyn Storage, scope: u128) -> io::Result<Self> {
        Self::open(source, scope)
    }
}
impl FatVolume {
    /// Inspect a bounded immutable source without reading payload or the whole FAT.
    /// Supports conventional sectors and clusters up to 32 KiB; unknown historical
    /// profiles and nonzero FAT32 versions are rejected.
    pub fn open(source: Arc<dyn ReadAt>) -> io::Result<Self> {
        let mut decoder = FatDecoder::open(
            source.clone(),
            u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                    .map_err(|_| io::Error::other("FAT source identity scope exhausted"))?,
            ),
        )?;
        decoder.source = Arc::new(DiskView::new(source, 0, decoder.geometry.volume_bytes)?);
        Ok(Self { decoder })
    }
    /// Validated BPB geometry.
    pub fn geometry(&self) -> &FatGeometry {
        self.decoder.geometry()
    }
    /// Read one selected FAT entry.
    pub fn read_fat_entry(&self, copy: u8, cluster: u32) -> io::Result<u32> {
        self.decoder.read_fat_entry(copy, cluster)
    }
    /// Source-scoped root identity.
    pub fn root_identity(&self) -> ObjectId {
        self.decoder.root_identity()
    }
    /// Enumerate bounded root entries.
    pub fn root_directory(
        &self,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> io::Result<FatDirectory> {
        self.decoder
            .root_directory(max_clusters, max_slots, resources)
    }
    /// Enumerate a bounded native directory.
    pub fn read_directory(
        &self,
        entry: &FatEntry,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> io::Result<FatDirectory> {
        self.decoder
            .read_directory(entry, max_clusters, max_slots, resources)
    }
    /// Build a reusable checked file map from directory facts.
    pub fn open_file(
        &self,
        first_cluster: u32,
        length: u32,
        max_clusters: usize,
        resources: &Resources,
    ) -> io::Result<FatFile> {
        let map = self
            .decoder
            .open_file(first_cluster, length, max_clusters, resources)?;
        let source = &self.decoder.source;
        Ok(FatFile {
            file: ExtentFile::new(source.clone(), map.length, map.extents, max_clusters)?,
            _reservation: map.reservation,
        })
    }
    /// Open a validated namespace file from this volume.
    pub fn open_entry(
        &self,
        entry: &FatEntry,
        max_clusters: usize,
        resources: &Resources,
    ) -> io::Result<FatNamespaceFile> {
        self.decoder.check_entry(entry)?;
        if entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FAT directory is not a file",
            ));
        }
        Ok(FatNamespaceFile {
            identity: entry.identity.clone(),
            file: self.open_file(entry.cluster, entry.len(), max_clusters, resources)?,
        })
    }
}
