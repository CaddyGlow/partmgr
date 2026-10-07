//! Initial FAT12/16/32 geometry and explicit chain reads.
//!
//! This is not a namespace engine, ownership audit, or writable FAT profile.
//! Inputs must remain immutable for all deferred reads. Files are opened from
//! caller-supplied cluster/size facts; callers must establish their provenance.
use crate::{
    fs_core::{Reservation, Resources},
    fs_file::{ExtentFile, ExtentKind, FileExtent},
};
use std::{io, sync::Arc};
use virtdisk::{DiskView, ReadAt};

/// FAT entry width selected solely from the data cluster count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatFamily {
    Fat12,
    Fat16,
    Fat32,
}
/// Validated geometry of the supported BPB profile, in volume-relative bytes.
#[derive(Clone, Debug)]
pub struct FatGeometry {
    family: FatFamily,
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
pub struct FatVolume {
    source: Arc<dyn ReadAt>,
    geometry: FatGeometry,
}
impl FatVolume {
    /// Inspect a bounded source without reading the entire FAT or any payload.
    ///
    /// Supports conventional 512/1024/2048/4096-byte sectors and clusters up to
    /// 32 KiB. FAT32 requires version 0:0 and in-reserved-area FSInfo/backup
    /// references. Other historical or vendor profiles are explicitly rejected.
    pub fn open(source: Arc<dyn ReadAt>) -> io::Result<Self> {
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
        if volume_bytes > source.len() {
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
        let source = Arc::new(DiskView::new(source, 0, volume_bytes)?);
        Ok(Self { source, geometry })
    }
    /// Validated BPB facts; this is not an allocation or namespace audit.
    pub fn geometry(&self) -> &FatGeometry {
        &self.geometry
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
    ) -> io::Result<FatFile> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let length = u64::from(length);
        let count = length.div_ceil(self.geometry.cluster_bytes());
        if count > max_clusters as u64 || count > u64::from(self.geometry.cluster_count) {
            return Err(io::Error::other("FAT file chain budget exhausted"));
        }
        // Includes the input map, coalescing scratch, and final shared map.
        let bytes = count
            .checked_mul((3 * std::mem::size_of::<FileExtent>()) as u64)
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
        Ok(FatFile {
            file: ExtentFile::new(self.source.clone(), length, extents, max_clusters)?,
            _reservation: reservation,
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
