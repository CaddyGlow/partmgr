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
