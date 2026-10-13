//! Explicit host source adapters. Opening read-only does not establish stability.
use crate::{
    forensics::{ByteRange, ForensicSource, SourceIdentity, StabilityProvider},
    io::{self, ReadAt},
};
use alloc::sync::Arc;
use std::path::Path;

/// Explicit host source selection; container authorization stays in virtdisk.
pub enum HostSource<'a> {
    /// Regular raw/dd artifact.
    Raw(&'a Path),
    /// Container with explicit format, recovery and parent authorization policy.
    Container {
        /// Container path.
        path: &'a Path,
        /// Explicit container family.
        format: virtdisk::ImageFormat,
        /// Explicit opening policy.
        options: &'a virtdisk::ReaderOpenOptions,
    },
    /// Offline physical disk held stable by the acquisition capability.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Physical(&'a Path),
}
/// Opened view plus sector geometry retained for partition interpretation.
pub struct OpenedSource {
    /// Stable bounded logical reader.
    pub source: ForensicSource,
    /// Logical sector size; explicitly supplied for artifact formats.
    pub logical_sector_size: u32,
}
/// Open a source only with a lifetime stability capability and explicit geometry.
/// A device's queried geometry must agree with any supplied geometry.
/// Selected regions must align to whole logical sectors. Acquisition gaps use
/// logical disk coordinates, including when a smaller volume is selected.
pub fn open(
    source: HostSource<'_>,
    identity: SourceIdentity,
    stability: Arc<dyn StabilityProvider>,
    logical_sector_size: Option<u32>,
    region: Option<ByteRange>,
    unavailable: alloc::vec::Vec<ByteRange>,
) -> io::Result<OpenedSource> {
    stability.check()?;
    let (reader, device_sector): (Arc<dyn ReadAt>, Option<u32>) = match source {
        HostSource::Raw(path) => (Arc::new(virtdisk::RawDisk::open(path)?), None),
        HostSource::Container {
            path,
            format,
            options,
        } => (
            Arc::new(virtdisk::Image::open_with_options(
                path,
                &options.clone().format(format),
            )?),
            None,
        ),
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        HostSource::Physical(path) => {
            let disk = virtdisk::PhysicalDisk::open(path)?;
            let sector = disk.logical_sector_size();
            (Arc::new(disk), Some(sector))
        }
    };
    if let (Some(explicit), Some(actual)) = (logical_sector_size, device_sector)
        && explicit != actual
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "logical sector geometry mismatch",
        ));
    }
    let sector = device_sector.or(logical_sector_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit logical sector geometry required",
        )
    })?;
    if sector < 512 || !sector.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid logical sector geometry",
        ));
    }
    let region = region.unwrap_or(ByteRange {
        offset: 0,
        length: reader.len(),
    });
    if !region.offset.is_multiple_of(u64::from(sector))
        || !region.length.is_multiple_of(u64::from(sector))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selected region is not sector aligned",
        ));
    }
    let source = ForensicSource::new(reader, identity, stability, region, unavailable)?;
    Ok(OpenedSource {
        source,
        logical_sector_size: sector,
    })
}

impl OpenedSource {
    /// Select an occupied partition by its one-based validated GPT/MBR slot.
    /// Table inspection uses the same stable reader and explicit sector geometry.
    pub fn select_partition(&self, index: u32) -> io::Result<Self> {
        let table = crate::partition::PartitionTable::read(
            Arc::new(self.source.clone()),
            self.logical_sector_size,
        )?;
        let partition = table
            .partitions()
            .iter()
            .find(|partition| partition.index == index)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "partition slot is absent")
            })?;
        let sector = u64::from(self.logical_sector_size);
        let offset = partition.first_lba.checked_mul(sector).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "partition offset overflow")
        })?;
        let length = partition.sectors.checked_mul(sector).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "partition length overflow")
        })?;
        Ok(Self {
            source: self.source.select_region(ByteRange { offset, length })?,
            logical_sector_size: self.logical_sector_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensics::AcquisitionLease;
    fn identity(source: &str) -> SourceIdentity {
        SourceIdentity {
            acquisition: "fixture".into(),
            source: source.into(),
            stability_provider: "closed test artifact".into(),
        }
    }
    #[test]
    fn raw_container_partition_equivalence_for_both_sector_geometries() {
        for sector in [512u32, 4096] {
            let dir = tempfile::tempdir().unwrap();
            let raw = dir.path().join("disk.dd");
            let container = dir.path().join("disk.vdi");
            let mut bytes = alloc::vec![0u8; 1024 * 1024];
            bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
            bytes[450] = 0x06;
            bytes[454..458].copy_from_slice(&2u32.to_le_bytes());
            bytes[458..462].copy_from_slice(&8u32.to_le_bytes());
            let start = 2 * sector as usize;
            for (index, byte) in bytes[start..start + 8 * sector as usize]
                .iter_mut()
                .enumerate()
            {
                *byte = index as u8;
            }
            std::fs::write(&raw, &bytes).unwrap();
            // Independent fixed VDI 1.1 fixture, one allocated 1 MiB block.
            let mut vdi = alloc::vec![0u8; 1024 + bytes.len()];
            for (at, value) in [
                (64, 0xbeda107fu32),
                (68, 0x10001),
                (72, 400),
                (76, 2),
                (340, 512),
                (344, 1024),
                (360, 512),
                (376, 1048576),
                (384, 1),
                (388, 1),
            ] {
                vdi[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            vdi[368..376].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            vdi[392..408].fill(1);
            vdi[408..424].fill(2);
            vdi[1024..].copy_from_slice(&bytes);
            std::fs::write(&container, vdi).unwrap();
            let lease = Arc::new(AcquisitionLease::default());
            let raw = open(
                HostSource::Raw(&raw),
                identity("raw"),
                lease.clone(),
                Some(sector),
                None,
                alloc::vec![],
            )
            .unwrap();
            let options = virtdisk::ReaderOpenOptions::default().format(virtdisk::ImageFormat::Vdi);
            let image = open(
                HostSource::Container {
                    path: &container,
                    format: virtdisk::ImageFormat::Vdi,
                    options: &options,
                },
                identity("vdi"),
                lease,
                Some(sector),
                None,
                alloc::vec![],
            )
            .unwrap();
            let raw_part = raw.select_partition(1).unwrap();
            let image_part = image.select_partition(1).unwrap();
            let mut a = alloc::vec![0; 8 * sector as usize];
            let mut b = a.clone();
            raw_part.source.read_exact_at(0, &mut a).unwrap();
            image_part.source.read_exact_at(0, &mut b).unwrap();
            assert_eq!(a, b);
            assert_ne!(raw_part.source.identity(), image_part.source.identity());
            assert_eq!(
                raw_part
                    .source
                    .translate_range(ByteRange {
                        offset: 0,
                        length: a.len() as u64
                    })
                    .unwrap()
                    .offset,
                2 * u64::from(sector)
            );
        }
    }
    #[test]
    fn explicit_geometry_region_bounds_and_alignment_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.dd");
        std::fs::write(&path, [0; 1024]).unwrap();
        let lease = Arc::new(AcquisitionLease::default());
        assert!(
            open(
                HostSource::Raw(&path),
                identity("raw"),
                lease.clone(),
                None,
                None,
                alloc::vec![]
            )
            .is_err()
        );
        assert!(
            open(
                HostSource::Raw(&path),
                identity("raw"),
                lease.clone(),
                Some(512),
                Some(ByteRange {
                    offset: 1,
                    length: 512
                }),
                alloc::vec![]
            )
            .is_err()
        );
        assert!(
            open(
                HostSource::Raw(&path),
                identity("raw"),
                lease.clone(),
                Some(512),
                Some(ByteRange {
                    offset: 512,
                    length: 1024
                }),
                alloc::vec![]
            )
            .is_err()
        );
        lease.invalidate();
        assert!(
            open(
                HostSource::Raw(&path),
                identity("raw"),
                lease,
                Some(512),
                None,
                alloc::vec![]
            )
            .is_err()
        );
    }
}
