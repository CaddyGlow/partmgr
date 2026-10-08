#![cfg(feature = "std")]

#[path = "common/reader_contract.rs"]
mod reader_contract;
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_fat::{FatFamily, FatVolume},
};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use virtdisk::{DiskView, ReadAt};
struct Image {
    len: u64,
    bytes: BTreeMap<u64, u8>,
    reads: AtomicUsize,
    fail: Option<u64>,
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let end = offset
            .checked_add(out.len() as u64)
            .filter(|end| *end <= self.len)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if self.fail.is_some_and(|fail| offset <= fail && fail < end) {
            return Err(io::Error::other("injected read"));
        }
        out.fill(0);
        for (&at, &value) in self.bytes.range(offset..end) {
            out[(at - offset) as usize] = value;
        }
        Ok(())
    }
}
fn put(image: &mut Image, offset: u64, bytes: &[u8]) {
    for (i, &byte) in bytes.iter().enumerate() {
        image.bytes.insert(offset + i as u64, byte);
    }
}
fn w(image: &mut Image, offset: u64, value: u16) {
    put(image, offset, &value.to_le_bytes());
}
fn d(image: &mut Image, offset: u64, value: u32) {
    put(image, offset, &value.to_le_bytes());
}
fn fixture(family: FatFamily) -> Image {
    // Independent literal BPBs, not generated through production code.
    let (total, reserved, fatsz, roots) = match family {
        FatFamily::Fat12 => (2880, 1, 9, 224),
        FatFamily::Fat16 => (10000, 1, 40, 512),
        FatFamily::Fat32 => (70000, 32, 600, 0),
    };
    let mut image = Image {
        len: total * 512,
        bytes: BTreeMap::new(),
        reads: AtomicUsize::new(0),
        fail: None,
    };
    put(&mut image, 0, &[0xeb, 0x3c, 0x90]);
    w(&mut image, 11, 512);
    put(&mut image, 13, &[1]);
    w(&mut image, 14, reserved);
    put(&mut image, 16, &[2]);
    w(&mut image, 17, roots);
    put(&mut image, 21, &[0xf8]);
    put(&mut image, 510, &[0x55, 0xaa]);
    if family == FatFamily::Fat32 {
        d(&mut image, 32, total as u32);
        d(&mut image, 36, fatsz);
        d(&mut image, 44, 2);
        w(&mut image, 48, 1);
        w(&mut image, 50, 6);
    } else {
        w(&mut image, 19, total as u16);
        w(&mut image, 22, fatsz as u16);
    }
    image
}
fn resources(limit: u64) -> Resources {
    Resources {
        memory: Budget::new(limit),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn hand_constructed_profiles_inspect_only_boot_and_ignore_type_labels() {
    for (family, count, data) in [
        (FatFamily::Fat12, 2847, 33),
        (FatFamily::Fat16, 9887, 113),
        (FatFamily::Fat32, 68768, 1232),
    ] {
        let mut image = fixture(family);
        put(&mut image, 82, b"NOTFAT!!");
        let source = Arc::new(image);
        let volume = FatVolume::open(source.clone()).unwrap();
        let geometry = volume.geometry();
        assert_eq!(geometry.family(), family);
        assert_eq!(geometry.cluster_count(), count);
        assert_eq!(geometry.data_offset(), data * 512);
        assert_eq!(source.reads.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn family_thresholds_use_cluster_count_and_reject_reserved_marker_overlap() {
    let mut image = fixture(FatFamily::Fat12);
    w(&mut image, 22, 12);
    w(&mut image, 19, 4078 + 1 + 24 + 14);
    image.len = (4078 + 1 + 24 + 14) * 512;
    assert_eq!(
        FatVolume::open(Arc::new(image))
            .unwrap()
            .geometry()
            .family(),
        FatFamily::Fat12
    );
    for clusters in [4079, 4084] {
        let mut image = fixture(FatFamily::Fat12);
        w(&mut image, 22, 12);
        w(&mut image, 19, clusters + 1 + 24 + 14);
        image.len = u64::from(clusters + 1 + 24 + 14) * 512;
        assert!(FatVolume::open(Arc::new(image)).is_err());
    }
    let mut image = fixture(FatFamily::Fat16);
    w(&mut image, 19, 4085 + 1 + 80 + 32);
    image.len = (4085 + 1 + 80 + 32) * 512;
    assert_eq!(
        FatVolume::open(Arc::new(image))
            .unwrap()
            .geometry()
            .family(),
        FatFamily::Fat16
    );
    let mut image = fixture(FatFamily::Fat32);
    d(&mut image, 32, 65525 + 1232);
    image.len = (65525 + 1232) * 512;
    assert_eq!(
        FatVolume::open(Arc::new(image))
            .unwrap()
            .geometry()
            .family(),
        FatFamily::Fat32
    );
}

#[test]
fn nonzero_bounded_region_and_truncated_sources() {
    let image = fixture(FatFamily::Fat12);
    let mut disk = Image {
        len: image.len + 4096,
        bytes: BTreeMap::new(),
        reads: AtomicUsize::new(0),
        fail: None,
    };
    for (offset, byte) in image.bytes {
        disk.bytes.insert(offset + 4096, byte);
    }
    let region = DiskView::new(Arc::new(disk), 4096, image.len).unwrap();
    assert!(FatVolume::open(Arc::new(region)).is_ok());
    let mut image = fixture(FatFamily::Fat12);
    image.len -= 512;
    assert!(FatVolume::open(Arc::new(image)).is_err());
}
#[test]
fn malformed_geometry_and_fat32_profile_are_rejected() {
    for mutation in 0..13 {
        let mut image = fixture(FatFamily::Fat32);
        match mutation {
            0 => w(&mut image, 11, 0),
            1 => put(&mut image, 13, &[3]),
            2 => w(&mut image, 14, 0),
            3 => put(&mut image, 16, &[0]),
            4 => w(&mut image, 19, 1),
            5 => d(&mut image, 36, 1),
            6 => w(&mut image, 17, 16),
            7 => w(&mut image, 40, 0x82),
            8 => w(&mut image, 40, 0x100),
            9 => w(&mut image, 42, 1),
            10 => d(&mut image, 44, 70000),
            11 => w(&mut image, 48, 32),
            12 => w(&mut image, 50, 31),
            _ => unreachable!(),
        }
        assert!(
            FatVolume::open(Arc::new(image)).is_err(),
            "mutation {mutation}"
        );
    }
    let mut image = fixture(FatFamily::Fat12);
    w(&mut image, 17, 1);
    assert!(FatVolume::open(Arc::new(image)).is_err());
    let mut image = fixture(FatFamily::Fat12);
    w(&mut image, 22, 1);
    assert!(FatVolume::open(Arc::new(image)).is_err());
    let mut image = fixture(FatFamily::Fat12);
    put(&mut image, 510, &[0, 0]);
    assert!(FatVolume::open(Arc::new(image)).is_err());
}
fn fat16_chain(first: u16, second: u16) -> Image {
    let mut image = fixture(FatFamily::Fat16);
    for copy in 0..2 {
        let fat = 512 + copy * 40 * 512;
        w(&mut image, fat + 4, first);
        w(&mut image, fat + 6, second);
    }
    put(&mut image, 113 * 512, &vec![0x41; 512]);
    put(&mut image, 114 * 512, &vec![0x42; 512]);
    image
}
#[test]
fn indexed_chain_reads_payload_only_on_demand_and_retains_budget() {
    let source = Arc::new(fat16_chain(3, 0xffff));
    let volume = FatVolume::open(source.clone()).unwrap();
    let resources = resources(4096);
    let file = volume.open_file(2, 700, 2, &resources).unwrap();
    assert!(resources.memory.used() > 0);
    assert_eq!(source.reads.load(Ordering::Relaxed), 5);
    let mut out = [0; 8];
    assert_eq!(file.read_at(508, &mut out, &resources).unwrap(), 8);
    assert_eq!(out, [0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42]);
    assert_eq!(file.read_at(699, &mut out, &resources).unwrap(), 1);
    assert_eq!(file.read_at(700, &mut out, &resources).unwrap(), 0);
    drop(file);
    assert_eq!(resources.memory.used(), 0);
}
#[test]
fn malformed_chains_cancellation_budgets_and_io_failures_propagate() {
    let resources = resources(4096);
    for (first, second) in [
        (2, 0xffff),
        (0, 0xffff),
        (0xfff7, 0xffff),
        (0xffff, 0xffff),
        (3, 2),
        (3, 4),
    ] {
        let volume = FatVolume::open(Arc::new(fat16_chain(first, second))).unwrap();
        assert!(
            volume.open_file(2, 700, 2, &resources).is_err(),
            "{first:x} {second:x}"
        );
    }
    let mut image = fat16_chain(3, 0xffff);
    w(&mut image, 512 + 40 * 512 + 4, 4);
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    assert!(volume.open_file(2, 700, 2, &resources).is_err());
    let volume = FatVolume::open(Arc::new(fat16_chain(3, 0xffff))).unwrap();
    assert!(volume.open_file(2, 700, 1, &resources).is_err());
    assert!(
        volume
            .open_file(2, 700, 2, &super_resources_zero())
            .is_err()
    );
    resources.cancellation.cancel();
    assert!(volume.open_file(2, 700, 2, &resources).is_err());
    let mut image = fat16_chain(3, 0xffff);
    image.fail = Some(516);
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    assert!(volume.open_file(2, 700, 2, &crate_resources()).is_err());
    let mut image = fixture(FatFamily::Fat12);
    image.fail = Some(11);
    assert!(FatVolume::open(Arc::new(image)).is_err());
}
fn super_resources_zero() -> Resources {
    resources(0)
}
fn crate_resources() -> Resources {
    resources(4096)
}
#[test]
fn fat12_packed_entries_and_fat32_active_fat_masking() {
    let mut image = fixture(FatFamily::Fat12);
    for copy in 0..2 {
        let fat = 512 + copy * 9 * 512;
        put(&mut image, fat + 3, &[3, 0xf0, 0xff]);
    }
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    assert!(volume.open_file(2, 700, 2, &resources(4096)).is_ok());
    let mut image = fixture(FatFamily::Fat32);
    w(&mut image, 40, 0x81);
    d(&mut image, (32 + 600) * 512 + 8, 0xffff_ffff);
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    assert_eq!(volume.geometry().active_fat(), Some(1));
    assert!(volume.open_file(2, 1, 1, &resources(4096)).is_ok());
}

#[test]
fn namespace_short_alias_identity_and_positional_content() {
    use partmgr::fs_core::{FileRead, NativeName};
    let mut image = fat16_chain(3, 0xffff);
    let mut slot = [0; 32];
    slot[..11].copy_from_slice(b"PAYLOAD BIN");
    slot[11] = 0x20;
    slot[26..28].copy_from_slice(&2u16.to_le_bytes());
    slot[28..32].copy_from_slice(&700u32.to_le_bytes());
    put(&mut image, 81 * 512, &slot);
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    let resources = resources(16384);
    let directory = volume.root_directory(2, 4, &resources).unwrap();
    let entry = directory
        .lookup(&NativeName::Bytes(b"PAYLOAD BIN".to_vec()))
        .unwrap()
        .unwrap();
    assert_eq!(entry.short_name(), b"PAYLOAD BIN");
    let file = volume.open_entry(entry, 2, &resources).unwrap();
    assert_eq!(file.identity(), entry.identity());
    reader_contract::assert_eof_contract(&file, &resources);
    let mut out = [0; 8];
    assert_eq!(file.read_at(508, &mut out, &resources).unwrap(), 8);
    assert_eq!(out, [0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42]);
    let other = FatVolume::open(Arc::new(fixture(FatFamily::Fat16))).unwrap();
    assert!(other.open_entry(entry, 2, &resources).is_err());
    drop(file);
    drop(directory);
    assert_eq!(resources.memory.used(), 0);
}
fn lfn_fixture() -> Image {
    let mut image = fixture(FatFamily::Fat16);
    let alias = b"LONGNA~1TXT";
    let checksum = alias
        .iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte));
    let mut long = [0xff; 32];
    long[0] = 0x41;
    long[11] = 0x0f;
    long[12] = 0;
    long[13] = checksum;
    long[26] = 0;
    long[27] = 0;
    let name = [b'N' as u16, 0xd800, b'x' as u16, 0];
    for (i, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
        .into_iter()
        .enumerate()
    {
        long[at..at + 2].copy_from_slice(&name.get(i).copied().unwrap_or(0xffff).to_le_bytes());
    }
    put(&mut image, 81 * 512, &long);
    let mut short = [0; 32];
    short[..11].copy_from_slice(alias);
    short[11] = 0x20;
    put(&mut image, 81 * 512 + 32, &short);
    image
}
#[test]
fn vfat_preserves_utf16_and_rejects_malformed_sequence() {
    use partmgr::fs_core::NativeName;
    let volume = FatVolume::open(Arc::new(lfn_fixture())).unwrap();
    let directory = volume.root_directory(2, 4, &resources(16384)).unwrap();
    assert_eq!(
        directory.entries()[0].name(),
        &NativeName::Utf16(vec![78, 0xd800, 120])
    );
    for (at, byte) in [(0, 0x42), (13, 0), (12, 1), (26, 1), (9, 0)] {
        let mut image = lfn_fixture();
        put(&mut image, 81 * 512 + at, &[byte]);
        assert!(
            FatVolume::open(Arc::new(image))
                .unwrap()
                .root_directory(2, 4, &resources(16384))
                .is_err(),
            "mutation {at}"
        );
    }
    assert!(volume.root_directory(2, 1, &resources(16384)).is_err());
    assert!(volume.root_directory(2, 4, &resources(0)).is_err());
    let cancelled = resources(16384);
    cancelled.cancellation.cancel();
    assert!(volume.root_directory(2, 4, &cancelled).is_err());
}

#[test]
fn directory_chain_cycles_limits_and_cross_source_entries() {
    let mut image = fat16_chain(2, 0xffff);
    let mut slot = [0; 32];
    slot[..11].copy_from_slice(b"SUBDIR     ");
    slot[11] = 0x10;
    slot[26..28].copy_from_slice(&2u16.to_le_bytes());
    put(&mut image, 81 * 512, &slot);
    // Deleted slots prevent an early directory terminator so the FAT cycle is read.
    for i in 0..16 {
        put(&mut image, 113 * 512 + i * 32, &[0xe5]);
    }
    let volume = FatVolume::open(Arc::new(image)).unwrap();
    let resources = resources(16384);
    let root = volume.root_directory(2, 4, &resources).unwrap();
    assert!(
        volume
            .read_directory(&root.entries()[0], 2, 32, &resources)
            .is_err()
    );
    assert!(
        volume
            .read_directory(&root.entries()[0], 0, 32, &resources)
            .is_err()
    );
    let other = FatVolume::open(Arc::new(fixture(FatFamily::Fat16))).unwrap();
    assert!(
        other
            .read_directory(&root.entries()[0], 2, 32, &resources)
            .is_err()
    );
}
