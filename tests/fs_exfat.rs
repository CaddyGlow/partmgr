use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_exfat::ExfatBoot,
};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;

struct Source {
    bytes: Vec<u8>,
    length: u64,
    read_bytes: AtomicU64,
    fail_at: Option<u64>,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.read_bytes
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        if self.fail_at == Some(at) {
            return Err(io::Error::other("injected exFAT source failure"));
        }
        let data = self
            .bytes
            .get(at as usize..at as usize + out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(data);
        Ok(())
    }
}
fn resources(limit: u64) -> Resources {
    Resources {
        memory: Budget::new(limit),
        cancellation: Cancellation::default(),
    }
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn seal(bytes: &mut [u8], sector: usize) {
    for first in [0, 12 * sector] {
        let mut checksum = 0u32;
        for i in 0..11 * sector {
            if matches!(i, 106 | 107 | 112) {
                continue;
            }
            checksum = ((checksum >> 1) | ((checksum & 1) << 31))
                .wrapping_add(u32::from(bytes[first + i]));
        }
        for i in (first + 11 * sector..first + 12 * sector).step_by(4) {
            put(bytes, i, checksum);
        }
    }
}
fn fixture(shift: u8) -> Source {
    let sector = 1usize << shift;
    let mut bytes = vec![0; 24 * sector];
    bytes[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    bytes[3..11].copy_from_slice(b"EXFAT   ");
    let sectors = (2 * 1024 * 1024 / sector) as u64;
    bytes[72..80].copy_from_slice(&sectors.to_le_bytes());
    put(&mut bytes, 80, 24);
    put(&mut bytes, 84, 32);
    put(&mut bytes, 88, 56);
    put(&mut bytes, 92, sectors as u32 - 56);
    put(&mut bytes, 96, 2);
    put(&mut bytes, 100, 0x12345678);
    bytes[105] = 1;
    bytes[108] = shift;
    bytes[110] = 1;
    bytes[112] = 255;
    bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
    for n in 1..=8 {
        put(&mut bytes, (n + 1) * sector - 4, 0xaa550000);
    }
    bytes.copy_within(..12 * sector, 12 * sector);
    seal(&mut bytes, sector);
    Source {
        bytes,
        length: 2 << 20,
        read_bytes: AtomicU64::new(0),
        fail_at: None,
    }
}
#[test]
fn both_regions_and_all_sector_sizes_are_bounded_without_cluster_reads() {
    for shift in 9..=12 {
        let source = fixture(shift);
        let r = resources(8192);
        let boot = ExfatBoot::inspect(&source, &r).unwrap();
        assert_eq!(boot.sector_bytes, 1 << shift);
        assert_eq!(boot.volume_bytes, 2 << 20);
        assert_eq!(boot.percent_in_use, None);
        assert_eq!(
            boot.cluster_offset(2).unwrap(),
            56 * u64::from(boot.sector_bytes)
        );
        assert_eq!(
            boot.cluster_offset(boot.clusters + 1).unwrap() + u64::from(boot.cluster_bytes),
            boot.volume_bytes
        );
        assert!(boot.cluster_offset(1).is_err());
        assert!(boot.cluster_offset(boot.clusters + 2).is_err());
        assert_eq!(
            source.read_bytes.load(Ordering::Relaxed),
            512 + 26 * u64::from(boot.sector_bytes)
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn mutable_status_is_excluded_from_checksums_and_backup_status_is_stale() {
    let mut source = fixture(9);
    source.bytes[106] = 6;
    source.bytes[112] = 17;
    source.bytes[12 * 512 + 112] = 99;
    let boot = ExfatBoot::inspect(&source, &resources(8192)).unwrap();
    assert!(boot.is_dirty());
    assert!(boot.has_media_failure());
    assert_eq!(boot.percent_in_use, Some(17));
    assert_eq!(boot.active_fat(), 0);
    source.bytes[106] = 1;
    assert_eq!(
        ExfatBoot::inspect(&source, &resources(8192))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidData
    );
}
#[test]
fn checksums_signatures_geometry_and_revision_fail_closed() {
    for index in [120, 512 + 508, 11 * 512, 23 * 512 + 4] {
        let mut source = fixture(9);
        source.bytes[index] ^= 1;
        assert!(ExfatBoot::inspect(&source, &resources(8192)).is_err());
    }
    for index in [11, 80, 84, 88, 92, 96, 108, 109, 110, 112, 510] {
        let mut source = fixture(9);
        source.bytes[index] = if index == 112 { 101 } else { 255 };
        seal(&mut source.bytes, 512);
        assert!(
            ExfatBoot::inspect(&source, &resources(8192)).is_err(),
            "field {index}"
        );
    }
    let mut source = fixture(9);
    source.bytes[104] = 1;
    seal(&mut source.bytes, 512);
    assert_eq!(
        ExfatBoot::inspect(&source, &resources(8192))
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    let mut source = fixture(9);
    put(&mut source.bytes, 12 * 512 + 100, 999);
    seal(&mut source.bytes, 512);
    assert!(ExfatBoot::inspect(&source, &resources(8192)).is_err());
    let mut source = fixture(9);
    source.length -= 1;
    assert!(ExfatBoot::inspect(&source, &resources(8192)).is_err());
}
#[test]
fn cancellation_budget_and_underlying_io_are_explicit() {
    let source = fixture(9);
    assert_eq!(
        ExfatBoot::inspect(&source, &resources(8191))
            .unwrap_err()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(source.read_bytes.load(Ordering::Relaxed), 0);
    let r = resources(8192);
    r.cancellation.cancel();
    assert_eq!(
        ExfatBoot::inspect(&source, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    let mut source = fixture(9);
    source.fail_at = Some(512);
    let r = resources(8192);
    let error = ExfatBoot::inspect(&source, &r).unwrap_err();
    assert_eq!(
        error.source.unwrap().to_string(),
        "injected exFAT source failure"
    );
    assert_eq!(r.memory.used(), 0);
}
