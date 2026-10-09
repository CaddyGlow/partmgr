#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, FileRead, Resources},
    fs_fat::{FatFamily, FatVolume},
    fs_fat_builder::{FatBuildFile, FatBuildOptions, FatBuildPlan},
    storage::Storage,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;
struct Source {
    length: AtomicU64,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset + out.len() as u64 > self.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        for (index, b) in out.iter_mut().enumerate() {
            *b = ((offset + index as u64) % 251) as u8;
        }
        Ok(())
    }
}
struct Image {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail_write: bool,
    fail_flush: bool,
    corrupt: bool,
}
impl Image {
    fn new(length: usize) -> Self {
        Self {
            bytes: vec![0xab; length],
            writes: 0,
            flushes: 0,
            fail_write: false,
            fail_flush: false,
            corrupt: false,
        }
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[offset as usize..offset as usize + out.len()]);
        if self.corrupt && !out.is_empty() {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, offset: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_write {
            return Err(io::Error::other("injected write"));
        }
        let count = b.len().min(997);
        self.bytes[offset as usize..offset as usize + count].copy_from_slice(&b[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::other("injected flush"))
        } else {
            Ok(())
        }
    }
}
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.0[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(140000),
        cancellation: Cancellation::default(),
    }
}
fn options(family: FatFamily) -> FatBuildOptions {
    FatBuildOptions {
        family,
        sectors_per_cluster: 1,
        volume_id: 0x12345678,
    }
}
fn files() -> Vec<FatBuildFile> {
    vec![
        FatBuildFile {
            name: "Z.BIN".into(),
            source: Arc::new(Source {
                length: AtomicU64::new(200000),
            }),
        },
        FatBuildFile {
            name: "EMPTY".into(),
            source: Arc::new(Source {
                length: AtomicU64::new(0),
            }),
        },
    ]
}
#[test]
fn all_families_stream_deterministically_and_read_back_payloads() {
    for (family, length) in [
        (FatFamily::Fat12, 1440 * 1024),
        (FatFamily::Fat16, 32 * 1024 * 1024),
        (FatFamily::Fat32, 64 * 1024 * 1024),
    ] {
        let r = resources();
        let mut files = files();
        let plan = FatBuildPlan::new(length, options(family), &files, &r).unwrap();
        let mut image = Image::new(length as usize);
        let report = plan.emit(&mut image, &r).unwrap();
        assert_eq!(report.verified_bytes, length);
        assert_eq!(image.flushes, 1);
        assert!(r.memory.used() < 1000);
        let root = if family == FatFamily::Fat32 {
            let fat = u32::from_le_bytes(image.bytes[36..40].try_into().unwrap());
            (32 + 2 * fat) as usize * 512
        } else {
            let fat = u16::from_le_bytes(image.bytes[22..24].try_into().unwrap());
            (1 + 2 * usize::from(fat)) * 512
        };
        assert_eq!(&image.bytes[root..root + 11], b"EMPTY      ");
        let entry = &image.bytes[root + 32..root + 64];
        assert_eq!(&entry[..11], b"Z       BIN");
        let first = u32::from(u16::from_le_bytes(entry[26..28].try_into().unwrap()))
            | (u32::from(u16::from_le_bytes(entry[20..22].try_into().unwrap())) << 16);
        let volume = FatVolume::open(Arc::new(Bytes(image.bytes))).unwrap();
        assert_eq!(volume.geometry().family(), family);
        let file = volume
            .open_file(
                first,
                200000,
                400,
                &Resources {
                    memory: Budget::new(100000),
                    cancellation: Cancellation::default(),
                },
            )
            .unwrap();
        let mut out = [0; 17];
        file.read_at(199980, &mut out, &r).unwrap();
        assert_eq!(out, std::array::from_fn(|i| ((199980 + i) % 251) as u8));
        files.reverse();
        let other = FatBuildPlan::new(length, options(family), &files, &r).unwrap();
        let mut image = Image::new(length as usize);
        assert_eq!(other.emit(&mut image, &r).unwrap().sha256, report.sha256);
    }
}
#[test]
fn rejects_names_geometry_capacity_and_budget_before_mutation() {
    let r = resources();
    let source = Arc::new(Source {
        length: AtomicU64::new(1),
    });
    for name in ["lower.txt", "TOOLONGNAME", "A.B.C", "A.", "../X"] {
        assert!(
            FatBuildPlan::new(
                1440 * 1024,
                options(FatFamily::Fat12),
                &[FatBuildFile {
                    name: name.into(),
                    source: source.clone()
                }],
                &r
            )
            .is_err()
        );
    }
    let duplicates = [
        FatBuildFile {
            name: "A".into(),
            source: source.clone(),
        },
        FatBuildFile {
            name: "A".into(),
            source,
        },
    ];
    assert!(FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat12), &duplicates, &r).is_err());
    assert!(FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat32), &[], &r).is_err());
    let low = Resources {
        memory: Budget::new(100),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat12), &files(), &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
}
#[test]
fn distinguishes_preflight_staleness_write_flush_and_readback_failures() {
    let r = resources();
    let source = Arc::new(Source {
        length: AtomicU64::new(7),
    });
    let plan = FatBuildPlan::new(
        1440 * 1024,
        options(FatFamily::Fat12),
        &[FatBuildFile {
            name: "A".into(),
            source: source.clone(),
        }],
        &r,
    )
    .unwrap();
    source.length.store(8, Ordering::Release);
    let mut image = Image::new(1440 * 1024);
    assert_eq!(
        plan.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(image.writes, 0);
    source.length.store(7, Ordering::Release);
    image.fail_write = true;
    let error = plan.emit(&mut image, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert!(error.source.is_some());
    image.fail_write = false;
    image.fail_flush = true;
    let error = plan.emit(&mut image, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UncertainDurability);
    assert!(error.source.is_some());
    image.fail_flush = false;
    image.corrupt = true;
    assert_eq!(
        plan.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::InterruptedWrite
    );
}
#[test]
fn cancelled_before_emission_does_not_write() {
    let r = resources();
    let plan = FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat12), &[], &r).unwrap();
    r.cancellation.cancel();
    let mut image = Image::new(1440 * 1024);
    assert_eq!(
        plan.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(image.writes, 0);
    assert_eq!(image.flushes, 0);
}

struct ChangingSource(std::sync::atomic::AtomicU64);
impl ReadAt for ChangingSource {
    fn len(&self) -> u64 {
        7
    }
    fn read_exact_at(&self, _: u64, out: &mut [u8]) -> io::Result<()> {
        out.fill(self.0.fetch_add(1, Ordering::AcqRel) as u8);
        Ok(())
    }
}
#[test]
fn source_content_changes_abort_after_mutation_without_a_ready_report() {
    let r = resources();
    let files = [FatBuildFile {
        name: "CHANGES".into(),
        source: Arc::new(ChangingSource(AtomicU64::new(0))),
    }];
    let plan = FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat12), &files, &r).unwrap();
    let mut image = Image::new(1440 * 1024);
    let error = plan.emit(&mut image, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert!(error.context.contains("verification mismatch"));
    assert_eq!(image.flushes, 1);
}

struct CancellingStorage {
    image: Image,
    cancellation: Cancellation,
}
impl Storage for CancellingStorage {
    fn len(&self) -> io::Result<u64> {
        Storage::len(&self.image)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        Storage::read_exact_at(&self.image, offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let count = self.image.write_at(offset, bytes)?;
        self.cancellation.cancel();
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.image.flush()
    }
}
#[test]
fn cancellation_after_a_short_write_reports_modified_unpublished_staging() {
    let r = resources();
    let plan = FatBuildPlan::new(1440 * 1024, options(FatFamily::Fat12), &[], &r).unwrap();
    let mut storage = CancellingStorage {
        image: Image::new(1440 * 1024),
        cancellation: r.cancellation.clone(),
    };
    let error = plan.emit(&mut storage, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert!(error.context.contains("operation cancelled"));
    assert!(error.context.contains("unconfirmed"));
    assert_eq!(storage.image.writes, 1);
    assert_eq!(storage.image.flushes, 0);
}

fn tree_id(n: u8) -> partmgr::fs_core::ObjectId {
    partmgr::fs_core::ObjectId {
        source: 7,
        generation: 2,
        native: vec![n],
    }
}
fn tree_entry(
    n: u8,
    parent: Option<u8>,
    name: &[u16],
    file: bool,
) -> partmgr::fs_fat_builder::FatBuildTreeEntry {
    partmgr::fs_fat_builder::FatBuildTreeEntry {
        identity: tree_id(n),
        parent: parent.map(tree_id),
        name: name.to_vec(),
        source: file.then(|| {
            Arc::new(Source {
                length: AtomicU64::new(777),
            }) as Arc<dyn ReadAt>
        }),
    }
}
#[test]
fn nested_vfat_tree_preserves_native_units_and_canonical_dot_links() {
    use partmgr::{fs_core::NativeName, fs_fat_builder::FatTreeMetadataPolicy};
    let r = Resources {
        memory: Budget::new(2_000_000),
        cancellation: Cancellation::default(),
    };
    for family in [FatFamily::Fat12, FatFamily::Fat16, FatFamily::Fat32] {
        let length = match family {
            FatFamily::Fat12 => 1440 * 1024,
            FatFamily::Fat16 => 32 * 1024 * 1024,
            FatFamily::Fat32 => 64 * 1024 * 1024,
        };
        let native = vec![0xd800, 46, 116, 120, 116];
        let mut entries = vec![
            tree_entry(1, None, &"EFI".encode_utf16().collect::<Vec<_>>(), false),
            tree_entry(
                2,
                Some(1),
                &"BOOT".encode_utf16().collect::<Vec<_>>(),
                false,
            ),
            tree_entry(
                3,
                Some(2),
                &"BOOTX64.EFI".encode_utf16().collect::<Vec<_>>(),
                true,
            ),
            tree_entry(4, Some(2), &native, true),
            tree_entry(
                5,
                Some(2),
                &"long filename.txt".encode_utf16().collect::<Vec<_>>(),
                true,
            ),
            tree_entry(
                6,
                Some(2),
                &"long filename other.txt".encode_utf16().collect::<Vec<_>>(),
                true,
            ),
        ];
        let plan = FatBuildPlan::new_tree(
            length,
            options(family),
            &entries,
            FatTreeMetadataPolicy::DeterministicDefaults,
            &r,
        )
        .unwrap();
        let mut image = Image::new(length as usize);
        let report = plan.emit(&mut image, &r).unwrap();
        entries.reverse();
        let reversed = FatBuildPlan::new_tree(
            length,
            options(family),
            &entries,
            FatTreeMetadataPolicy::DeterministicDefaults,
            &r,
        )
        .unwrap();
        let mut other = Image::new(length as usize);
        assert_eq!(reversed.emit(&mut other, &r).unwrap().sha256, report.sha256);
        let fat_sectors = if family == FatFamily::Fat32 {
            u32::from_le_bytes(image.bytes[36..40].try_into().unwrap())
        } else {
            u32::from(u16::from_le_bytes(image.bytes[22..24].try_into().unwrap()))
        };
        let reserved = if family == FatFamily::Fat32 { 32 } else { 1 };
        let data = (reserved + 2 * fat_sectors + if family == FatFamily::Fat32 { 0 } else { 32 })
            as usize
            * 512;
        let root_offset = if family == FatFamily::Fat32 {
            data
        } else {
            (reserved + 2 * fat_sectors) as usize * 512
        };
        let cluster = |entry: &[u8]| {
            u32::from(u16::from_le_bytes(entry[26..28].try_into().unwrap()))
                | (u32::from(u16::from_le_bytes(entry[20..22].try_into().unwrap())) << 16)
        };
        let efi_cluster = cluster(&image.bytes[root_offset..root_offset + 32]);
        let efi_offset = data + (efi_cluster as usize - 2) * 512;
        assert_eq!(&image.bytes[efi_offset..efi_offset + 11], b".          ");
        assert_eq!(
            cluster(&image.bytes[efi_offset..efi_offset + 32]),
            efi_cluster
        );
        assert_eq!(
            &image.bytes[efi_offset + 32..efi_offset + 43],
            b"..         "
        );
        assert_eq!(cluster(&image.bytes[efi_offset + 32..efi_offset + 64]), 0);
        let boot_cluster = cluster(&image.bytes[efi_offset + 64..efi_offset + 96]);
        let boot_offset = data + (boot_cluster as usize - 2) * 512;
        assert_eq!(
            cluster(&image.bytes[boot_offset + 32..boot_offset + 64]),
            efi_cluster
        );
        let volume = FatVolume::open(Arc::new(Bytes(image.bytes))).unwrap();
        let root = volume.root_directory(100, 100, &r).unwrap();
        let efi = volume
            .read_directory(&root.entries()[0], 100, 100, &r)
            .unwrap();
        let boot = volume
            .read_directory(&efi.entries()[0], 100, 100, &r)
            .unwrap();
        assert_eq!(boot.entries().len(), 4);
        let file = boot
            .lookup(&NativeName::Utf16(native.clone()))
            .unwrap()
            .unwrap();
        let opened = volume.open_entry(file, 100, &r).unwrap();
        let mut bytes = [0; 11];
        opened.read_at(750, &mut bytes, &r).unwrap();
        assert_eq!(bytes, std::array::from_fn(|i| ((750 + i) % 251) as u8));
        let aliases: std::collections::HashSet<_> =
            boot.entries().iter().map(|e| e.short_name()).collect();
        assert_eq!(aliases.len(), 4);
    }
}
#[test]
fn fat32_tree_root_extends_and_tree_preflight_rejects_cycles_and_collisions() {
    use partmgr::fs_fat_builder::FatTreeMetadataPolicy;
    let r = Resources {
        memory: Budget::new(3_000_000),
        cancellation: Cancellation::default(),
    };
    let entries: Vec<_> = (1..=40)
        .map(|n| {
            tree_entry(
                n,
                None,
                &format!("FILE{n}.TXT").encode_utf16().collect::<Vec<_>>(),
                true,
            )
        })
        .collect();
    let plan = FatBuildPlan::new_tree(
        64 * 1024 * 1024,
        options(FatFamily::Fat32),
        &entries,
        FatTreeMetadataPolicy::DeterministicDefaults,
        &r,
    )
    .unwrap();
    let mut image = Image::new(64 * 1024 * 1024);
    plan.emit(&mut image, &r).unwrap();
    let volume = FatVolume::open(Arc::new(Bytes(image.bytes))).unwrap();
    assert_eq!(
        volume.root_directory(100, 200, &r).unwrap().entries().len(),
        40
    );
    for entries in [
        vec![
            tree_entry(1, Some(2), &[65], false),
            tree_entry(2, Some(1), &[66], false),
        ],
        vec![
            tree_entry(1, None, &[65], true),
            tree_entry(2, None, &[97], true),
        ],
        vec![tree_entry(1, Some(2), &[65], true)],
        vec![
            tree_entry(1, None, &[65], true),
            tree_entry(1, None, &[66], true),
        ],
        vec![
            tree_entry(1, None, &[65], true),
            tree_entry(2, Some(1), &[66], true),
        ],
        vec![tree_entry(1, None, &[46, 46], false)],
    ] {
        assert!(
            FatBuildPlan::new_tree(
                1440 * 1024,
                options(FatFamily::Fat12),
                &entries,
                FatTreeMetadataPolicy::DeterministicDefaults,
                &r
            )
            .is_err()
        );
    }
}

#[test]
fn flat_tree_planning_uses_linear_inventory_budget() {
    use partmgr::{
        fs_core::ObjectId,
        fs_fat_builder::{FatBuildTreeEntry, FatTreeMetadataPolicy},
    };
    let r = Resources {
        memory: Budget::new(24_000_000),
        cancellation: Cancellation::default(),
    };
    let source: Arc<dyn ReadAt> = Arc::new(Bytes(Vec::new()));
    let entries: Vec<_> = (0..10_000u32)
        .map(|n| FatBuildTreeEntry {
            identity: ObjectId {
                source: 1,
                generation: 0,
                native: n.to_le_bytes().to_vec(),
            },
            parent: None,
            name: format!("F{n:07}").encode_utf16().collect(),
            source: Some(source.clone()),
        })
        .collect();
    let plan = FatBuildPlan::new_tree(
        64 * 1024 * 1024,
        options(FatFamily::Fat32),
        &entries,
        FatTreeMetadataPolicy::DeterministicDefaults,
        &r,
    )
    .unwrap();
    assert!(r.memory.used() < 24_000_000);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
