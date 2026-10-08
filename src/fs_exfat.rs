//! exFAT revision 1.00 boot-region inspection and shared bounded positional decoding.
use crate::fs_core::{Error, ErrorKind, Resources, Result};
use crate::storage::Storage;
use std::{io, sync::Arc};
use virtdisk::ReadAt;
pub(crate) trait ExfatDecodeRead {
    fn len(&self) -> io::Result<u64>;
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()>;
}
impl ExfatDecodeRead for Arc<dyn ReadAt> {
    fn len(&self) -> io::Result<u64> {
        Ok(ReadAt::len(self.as_ref()))
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.as_ref().read_exact_at(at, out)
    }
}
impl ExfatDecodeRead for &dyn Storage {
    fn len(&self) -> io::Result<u64> {
        Storage::len(*self)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        Storage::read_exact_at(*self, at, out)
    }
}
struct ImmutableSource<'a, T: ReadAt + ?Sized>(&'a T);
impl<T: ReadAt + ?Sized> ExfatDecodeRead for ImmutableSource<'_, T> {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(at, out)
    }
}

fn invalid(context: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, context)
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn wide(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
/// Validated layout facts from both boot regions; this is not an allocation audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExfatBoot {
    /// Recorded media-relative partition offset; zero means unspecified.
    pub partition_offset: u64,
    /// Declared filesystem byte length, excluding any supplied region tail.
    pub volume_bytes: u64,
    /// Declared bytes per filesystem sector.
    pub sector_bytes: u32,
    /// Declared bytes per allocation cluster.
    pub cluster_bytes: u32,
    /// First FAT byte offset relative to this bounded filesystem source.
    pub fat_offset: u64,
    /// Byte length of each FAT.
    pub fat_bytes: u64,
    /// Cluster heap byte offset.
    pub heap_offset: u64,
    /// Number of addressable data clusters.
    pub clusters: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Volume serial number.
    pub serial: u32,
    /// Number of FATs: two denotes the separately unsupported TexFAT profile.
    pub fats: u8,
    /// Current main-region flags, including uninterpreted reserved bits.
    pub flags: u16,
    /// Main-region percentage in use; None represents the native unknown marker.
    pub percent_in_use: Option<u8>,
}
impl ExfatBoot {
    /// Inspect revision 1.00 geometry and both boot checksums with bounded scratch.
    ///
    /// Main/backup geometry must agree. Backup flags and usage are stale and are
    /// not compared. Dirty/media-failure flags are reported rather than cleared.
    /// No cluster contents or FAT entries are read, and no recovery is performed.
    pub fn inspect(source: &(impl ReadAt + ?Sized), resources: &Resources) -> Result<Self> {
        Self::inspect_decoder(&ImmutableSource(source), resources)
    }
    pub(crate) fn inspect_decoder(
        source: &(impl ExfatDecodeRead + ?Sized),
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        let _lease = resources.memory.reserve(8192)?;
        let observed_length = source
            .len()
            .map_err(|e| Error::io("exFAT source length", e))?;
        let mut main = [0u8; 4096];
        read(source, observed_length, 0, &mut main[..512], resources)?;
        let sector_shift = main[108];
        if !(9..=12).contains(&sector_shift) {
            return Err(invalid("exFAT sector shift"));
        }
        let sector = 1usize << sector_shift;
        read(source, observed_length, 0, &mut main[..sector], resources)?;
        let geometry = decode(&main, observed_length)?;
        let mut backup = [0u8; 4096];
        read(
            source,
            observed_length,
            12 * sector as u64,
            &mut backup[..sector],
            resources,
        )?;
        let backup_geometry = decode(&backup, observed_length)?;
        let mut normalized = backup_geometry;
        normalized.flags = geometry.flags;
        normalized.percent_in_use = geometry.percent_in_use;
        if normalized != geometry {
            return Err(invalid("exFAT main/backup layout disagreement"));
        }
        checksum_region(source, observed_length, 0, sector, &mut backup, resources)?;
        checksum_region(source, observed_length, 12, sector, &mut backup, resources)?;
        Ok(geometry)
    }
    /// Whether the current volume status declares incomplete metadata updates.
    pub fn is_dirty(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Whether the current volume status records backing-media failures.
    pub fn has_media_failure(&self) -> bool {
        self.flags & 4 != 0
    }
    /// Current FAT selection; an inactive FAT must not be treated as authoritative.
    pub fn active_fat(&self) -> u8 {
        (self.flags & 1) as u8
    }
    /// Checked cluster byte offset; reserved FAT entries are not data clusters.
    pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < 2 || u64::from(cluster) > u64::from(self.clusters) + 1 {
            return Err(invalid("exFAT cluster outside heap"));
        }
        u64::from(cluster - 2)
            .checked_mul(u64::from(self.cluster_bytes))
            .and_then(|relative| self.heap_offset.checked_add(relative))
            .filter(|offset| {
                offset
                    .checked_add(u64::from(self.cluster_bytes))
                    .is_some_and(|end| end <= self.volume_bytes)
            })
            .ok_or_else(|| invalid("exFAT cluster byte range overflow"))
    }
}
fn read(
    source: &(impl ExfatDecodeRead + ?Sized),
    length: u64,
    at: u64,
    out: &mut [u8],
    resources: &Resources,
) -> Result<()> {
    resources.cancellation.check()?;
    if source
        .len()
        .map_err(|e| Error::io("exFAT source length", e))?
        != length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "exFAT source length changed",
        ));
    }
    if at
        .checked_add(out.len() as u64)
        .is_none_or(|end| end > length)
    {
        return Err(invalid("exFAT boot read outside bounded source"));
    }
    source
        .read_exact_at(at, out)
        .map_err(|e| Error::io("exFAT boot read", e))?;
    resources.cancellation.check()?;
    if source
        .len()
        .map_err(|e| Error::io("exFAT source length", e))?
        != length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "exFAT source length changed during boot read",
        ));
    }
    Ok(())
}
fn decode(bytes: &[u8], source_length: u64) -> Result<ExfatBoot> {
    if bytes[..3] != [0xeb, 0x76, 0x90]
        || &bytes[3..11] != b"EXFAT   "
        || bytes[11..64].iter().any(|b| *b != 0)
        || bytes[510..512] != [0x55, 0xaa]
    {
        return Err(invalid("exFAT boot identifiers"));
    }
    if bytes[104..106] != [0, 1] {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "exFAT revision other than 1.00",
        ));
    }
    let shift = bytes[108];
    if !(9..=12).contains(&shift) || bytes[109] > 25 - shift {
        return Err(invalid("exFAT sector/cluster shifts"));
    }
    let sector_bytes = 1u32 << shift;
    let cluster_bytes = 1u32 << (shift + bytes[109]);
    let volume_sectors = wide(bytes, 72);
    let volume_bytes = volume_sectors
        .checked_mul(u64::from(sector_bytes))
        .filter(|v| *v >= 1 << 20 && *v <= source_length)
        .ok_or_else(|| invalid("exFAT declared volume length"))?;
    let fats = bytes[110];
    let flags = u16::from_le_bytes(bytes[106..108].try_into().unwrap());
    if !(1..=2).contains(&fats) || (flags & 1 != 0 && fats != 2) {
        return Err(invalid("exFAT FAT count/selection"));
    }
    let fat = u64::from(word(bytes, 80));
    let fat_sectors = u64::from(word(bytes, 84));
    let heap = u64::from(word(bytes, 88));
    let clusters = word(bytes, 92);
    let expected_clusters = volume_sectors
        .checked_sub(heap)
        .ok_or_else(|| invalid("exFAT heap beyond volume"))?
        / (1u64 << bytes[109]);
    if clusters == 0 || u64::from(clusters) != expected_clusters.min(u64::from(u32::MAX) - 10) {
        return Err(invalid("exFAT cluster count"));
    }
    let required_fat = ((u64::from(clusters) + 2) * 4).div_ceil(u64::from(sector_bytes));
    if fat < 24 || fat_sectors < required_fat || fat + fat_sectors * u64::from(fats) > heap {
        return Err(invalid("exFAT FAT/heap overlap or undersized FAT"));
    }
    let root_cluster = word(bytes, 96);
    if root_cluster < 2 || u64::from(root_cluster) > u64::from(clusters) + 1 {
        return Err(invalid("exFAT root cluster"));
    }
    let percent_in_use = match bytes[112] {
        0..=100 => Some(bytes[112]),
        255 => None,
        _ => return Err(invalid("exFAT percentage in use")),
    };
    Ok(ExfatBoot {
        partition_offset: wide(bytes, 64),
        volume_bytes,
        sector_bytes,
        cluster_bytes,
        fat_offset: fat * u64::from(sector_bytes),
        fat_bytes: fat_sectors * u64::from(sector_bytes),
        heap_offset: heap * u64::from(sector_bytes),
        clusters,
        root_cluster,
        serial: word(bytes, 100),
        fats,
        flags,
        percent_in_use,
    })
}
fn checksum_region(
    source: &(impl ExfatDecodeRead + ?Sized),
    length: u64,
    first: u64,
    sector: usize,
    scratch: &mut [u8; 4096],
    resources: &Resources,
) -> Result<()> {
    let mut checksum = 0u32;
    for number in 0..12 {
        read(
            source,
            length,
            (first + number) * sector as u64,
            &mut scratch[..sector],
            resources,
        )?;
        if number == 11 {
            if scratch[..sector]
                .chunks_exact(4)
                .any(|v| u32::from_le_bytes(v.try_into().unwrap()) != checksum)
            {
                return Err(invalid("exFAT boot checksum mismatch"));
            }
            break;
        }
        if (1..=8).contains(&number) && word(scratch, sector - 4) != 0xaa550000 {
            return Err(invalid("exFAT extended boot signature"));
        }
        for (i, byte) in scratch[..sector].iter().enumerate() {
            if number == 0 && matches!(i, 106 | 107 | 112) {
                continue;
            }
            checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
        }
    }
    Ok(())
}
