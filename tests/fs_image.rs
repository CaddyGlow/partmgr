use partmgr::{
    fs_core::{
        Availability, Budget, Cancellation, ErrorKind, Family, Operation, Resources, StreamKind,
        TreeSource,
    },
    fs_fat_audit::FatAuditLimits,
    fs_image::{AllocationEvidence, AllocationPolicy, ReadFormat, ReadImage, ReadOptions, probe},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits},
    fs_ntfs_tree::NtfsTreePolicy,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean_fixture;
#[path = "fixtures/ntfs_index.rs"]
mod ntfs_fixture;
#[path = "fixtures/xfs_clean.rs"]
mod xfs_fixture;
struct Source {
    bytes: Vec<u8>,
    length: AtomicU64,
    reads: AtomicU64,
    fail: AtomicBool,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(false),
        }
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("facade source fault"));
        }
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if end as u64 > self.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        out.fill(0);
        if start < self.bytes.len() {
            let stored = out.len().min(self.bytes.len() - start);
            out[..stored].copy_from_slice(&self.bytes[start..start + stored]);
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    }
}
fn fat_fixture() -> Vec<u8> {
    // Independent FAT12 layout, one root file, one packed EOC cluster.
    let mut b = vec![0; 128 * 512];
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = 1;
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16] = 1;
    b[17..19].copy_from_slice(&16u16.to_le_bytes());
    b[19..21].copy_from_slice(&128u16.to_le_bytes());
    b[21] = 0xf8;
    b[22..24].copy_from_slice(&1u16.to_le_bytes());
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    b[512..518].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff, 0x0f, 0]);
    b[1024..1035].copy_from_slice(b"PAYLOAD BIN");
    b[1035] = 0x20;
    b[1050..1052].copy_from_slice(&2u16.to_le_bytes());
    b[1052..1056].copy_from_slice(&512u32.to_le_bytes());
    b[1536..2048].fill(0x76);
    b
}
fn fat_options() -> ReadOptions {
    ReadOptions::Fat {
        audit: FatAuditLimits {
            clusters: 512,
            entries: 16,
            directory_slots: 32,
            findings: 16,
        },
        objects: 16,
    }
}
fn ntfs_options() -> ReadOptions {
    ReadOptions::Ntfs {
        audit: partmgr::fs_ntfs_audit::NtfsAuditLimits {
            clusters: 2048,
            records: 128,
            attributes: 1024,
            ranges: 256,
            entries: 128,
            index_blocks: 32,
            depth: 8,
            work: 50000,
            findings: 64,
            free_ranges: 64,
        },
        read: NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        index: NtfsDirectoryLimits {
            blocks: 16,
            entries: 32,
            depth: 8,
        },
        occurrences: 32,
        depth: 8,
        namespace: NtfsTreePolicy::Complete,
    }
}
#[test]
fn bounded_probe_is_distinct_from_validation_and_returns_ambiguity() {
    let r = resources();
    let mut bytes = fat_fixture();
    bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
    let source = Source::new(bytes);
    let found = probe(&source, &r).unwrap();
    assert_eq!(found.get(), &[ReadFormat::Fat, ReadFormat::Ext]);
    assert_eq!(source.reads.load(Ordering::Acquire), 4);
    drop(found);
    assert_eq!(r.memory.used(), 0);
    let mut malformed = vec![0; 512];
    malformed[3..11].copy_from_slice(b"NTFS    ");
    let source = Arc::new(Source::new(malformed));
    assert_eq!(
        probe(source.as_ref(), &r).unwrap().get(),
        &[ReadFormat::Ntfs]
    );
    assert!(ReadImage::open(source, ntfs_options(), AllocationPolicy::MetadataOnly, &r).is_err());
    assert_eq!(r.memory.used(), 0);
    assert!(
        probe(&Source::new(vec![0; 64]), &r)
            .unwrap()
            .get()
            .is_empty()
    );
}
#[test]
fn clean_audit_precedes_inventory_and_capabilities_do_not_grant_mutation() {
    let r = resources();
    let image = ReadImage::open(
        Arc::new(Source::new(fat_fixture())),
        fat_options(),
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    assert_eq!(image.profile().family, Family::Fat12);
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    assert_eq!(
        image.profile().availability(Operation::Read),
        Availability::Supported
    );
    assert!(matches!(
        image.profile().availability(Operation::Replace),
        Availability::Unsupported { .. }
    ));
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries.len(), 1);
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(image);
    let mut out = [0; 13];
    assert_eq!(file.read_at(499, &mut out, &r).unwrap(), 13);
    assert_eq!(out, [0x76; 13]);
    drop(file);
    assert_eq!(r.memory.used(), 0);
    let mut lost = fat_fixture();
    lost[516] = 0xff;
    lost[517] = 0xff; // cluster3 now also allocated.
    assert!(
        ReadImage::open(
            Arc::new(Source::new(lost.clone())),
            fat_options(),
            AllocationPolicy::RequireClean,
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
    let image = ReadImage::open(
        Arc::new(Source::new(lost)),
        fat_options(),
        AllocationPolicy::MetadataOnly,
        &r,
    )
    .unwrap();
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::NotRequested
    );
    drop(image);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn retained_files_check_length_and_cancellation_even_at_eof() {
    let r = resources();
    let source = Arc::new(Source::new(fat_fixture()));
    let image = ReadImage::open(
        source.clone(),
        fat_options(),
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    let root = image.root();
    let page = image.directory_page(&root, None, 8, &r).unwrap();
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    source.length.fetch_add(1, Ordering::AcqRel);
    assert_eq!(
        image.revalidate(&root, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.length.fetch_sub(1, Ordering::AcqRel);
    let other = ReadImage::open(source, fat_options(), AllocationPolicy::RequireClean, &r).unwrap();
    assert!(other.metadata(&root, &r).is_err());
    drop(other);
    drop(image);
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(file.len(), &mut [], &resources())
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn ntfs_profile_never_fabricates_a_clean_global_audit() {
    let r = resources();
    let source = Arc::new(Source::new(ntfs_fixture::ntfs_index_seed()));
    assert!(
        ReadImage::open(
            source.clone(),
            ntfs_options(),
            AllocationPolicy::RequireClean,
            &r
        )
        .is_err()
    );
    assert!(source.reads.load(Ordering::Acquire) > 0);
    assert_eq!(r.memory.used(), 0);
    let image =
        ReadImage::open(source, ntfs_options(), AllocationPolicy::MetadataOnly, &r).unwrap();
    assert_eq!(image.profile().family, Family::Ntfs);
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::NotRequested
    );
    assert!(matches!(
        image.profile().availability(Operation::AuditAllocation),
        Availability::Requires { .. }
    ));
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].object, page.entries[1].object);
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(image);
    let mut out = [0; 5];
    assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 5);
    assert_eq!(&out, b"hello");
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn ntfs_clean_audit_and_user_namespace_are_separate_explicit_policies() {
    let r = resources();
    let source = Arc::new(Source::new(ntfs_clean_fixture::ntfs_audit_seed()));
    let mut options = ntfs_options();
    if let ReadOptions::Ntfs {
        namespace, read, ..
    } = &mut options
    {
        *namespace = NtfsTreePolicy::UserNamespace;
        read.attributes = 64;
        read.names = 16;
    }
    let image = ReadImage::open(source, options, AllocationPolicy::RequireClean, &r).unwrap();
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries.len(), 3);
    assert_eq!(page.entries[0].object, page.entries[1].object);
    assert_ne!(page.entries[0].object, page.entries[2].object);
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(image);
    let mut out = [0; 5];
    assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 5);
    assert_eq!(&out, b"hello");
    drop(file);
    assert_eq!(r.memory.used(), 0);
    assert!(matches!(ReadImage::open(
        Arc::new(Source::new(ntfs_clean_fixture::ntfs_audit_seed())),
        ntfs_options(), AllocationPolicy::RequireClean, &r
    ), Err(e) if e.kind == ErrorKind::Unsupported));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn xfs_dispatch_probes_audits_and_retains_sparse_hardlinked_native_bytes() {
    use partmgr::{
        fs_xfs::XfsReadLimits, fs_xfs_audit::XfsAuditLimits, fs_xfs_tree::XfsTreeLimits,
    };
    let r = resources();
    let source = Arc::new(Source::new(xfs_fixture::xfs_seed()));
    let candidates = probe(source.as_ref(), &r).unwrap();
    assert_eq!(candidates.get(), &[ReadFormat::Xfs]);
    drop(candidates);
    let options = ReadOptions::Xfs {
        read: XfsReadLimits {
            allocation_groups: 8,
            inodes: 256,
            metadata_records: 4096,
            extent_records: 256,
            work: 1_000_000,
            log_bytes: 128 << 20,
        },
        audit: XfsAuditLimits {
            blocks: 200000,
            entries: 1024,
            work: 1_000_000,
            findings: 512,
        },
        tree: XfsTreeLimits {
            objects: 16,
            entries: 16,
            depth: 8,
        },
    };
    let image = ReadImage::open(source, options, AllocationPolicy::RequireClean, &r).unwrap();
    assert_eq!(image.profile().family, Family::Xfs);
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let root = image.directory_page(&image.root(), None, 8, &r).unwrap();
    assert_eq!(root.entries.len(), 2);
    let nested = image
        .directory_page(&root.entries[1].object, None, 8, &r)
        .unwrap();
    assert_eq!(nested.entries.len(), 1);
    assert_eq!(
        nested.entries[0].name,
        partmgr::fs_core::NativeName::Bytes(vec![b'x', 0xff])
    );
    assert_eq!(root.entries[0].object, nested.entries[0].object);
    let file = image
        .open_stream(&nested.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(nested);
    drop(root);
    drop(image);
    let mut zero = [0xff; 16];
    assert_eq!(file.read_at(0, &mut zero, &r).unwrap(), 16);
    assert_eq!(zero, [0; 16]);
    assert_eq!(file.read_at(12288, &mut zero, &r).unwrap(), 16);
    assert_eq!(zero, [0; 16]);
    let mut payload = [0; 19];
    assert_eq!(file.read_at(4099, &mut payload, &r).unwrap(), 19);
    assert_eq!(
        payload,
        std::array::from_fn(|i| (((i + 3) * 73 + 11) % 256) as u8)
    );
    // Editor/read engines must not reuse a source domain even when their independent
    // opening counters reach the same value; source-only caches depend on this.
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("fat.raw");
    let journal = temporary.path().join("undo.raw");
    std::fs::write(&target, fat_fixture()).unwrap();
    std::fs::write(&journal, [0; 8192]).unwrap();
    use partmgr::{
        fs_fat_edit::{FatEditBinding, FatEditLimits, FatEditRegion, FatEditor},
        fs_undo::UndoLimits,
        storage::FileStorage,
    };
    let editor = FatEditor::open(
        FileStorage::open(target).unwrap(),
        FileStorage::open(journal).unwrap(),
        FatEditRegion {
            offset: 0,
            length: 65536,
        },
        FatEditBinding {
            volume: [1; 32],
            generation: 1,
        },
        FatEditLimits {
            audit: FatAuditLimits {
                clusters: 512,
                entries: 16,
                directory_slots: 32,
                findings: 16,
            },
            file_clusters: 32,
            affected_bytes: 512,
            replacements: 1,
            work: 1024,
            undo: UndoLimits {
                patches: 8,
                body_bytes: 8192,
            },
        },
        &r,
    )
    .unwrap();
    let edited = editor
        .open_file(
            &[partmgr::fs_core::NativeName::Bytes(b"PAYLOAD BIN".to_vec())],
            &r,
        )
        .unwrap();
    assert_eq!(edited.identity().source >> 64, 5);
    assert_eq!(file.identity().source >> 64, 9);
    assert_ne!(edited.identity().source >> 64, file.identity().source >> 64);
    drop(edited);
    drop(editor);
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn probe_and_open_budget_cancellation_and_io_failures_are_explicit() {
    let source = Arc::new(Source::new(fat_fixture()));
    let tiny = Resources {
        memory: Budget::new(1023),
        cancellation: Cancellation::default(),
    };
    assert!(matches!(probe(source.as_ref(),&tiny),Err(e) if e.kind==ErrorKind::BudgetExhausted));
    assert!(
        matches!(ReadImage::open(source.clone(),fat_options(),AllocationPolicy::RequireClean,&tiny),Err(e) if e.kind==ErrorKind::BudgetExhausted)
    );
    assert_eq!(source.reads.load(Ordering::Acquire), 0);
    assert_eq!(tiny.memory.used(), 0);
    let r = resources();
    source.fail.store(true, Ordering::Release);
    let e = match ReadImage::open(source, fat_options(), AllocationPolicy::RequireClean, &r) {
        Err(e) => e,
        Ok(_) => panic!("injected source fault"),
    };
    assert_eq!(e.kind, ErrorKind::Io);
    assert!(
        e.source
            .unwrap()
            .to_string()
            .contains("facade source fault")
    );
    assert_eq!(r.memory.used(), 0);
    r.cancellation.cancel();
    assert!(matches!(probe(&Source::new(vec![0;512]),&r),Err(e) if e.kind==ErrorKind::Cancelled));
}

#[path = "fixtures/ext2_clean.rs"]
mod ext_fixture;
#[test]
fn ext2_and_exfat_dispatch_retain_native_tree_content_and_clean_audit_evidence() {
    use partmgr::{
        fs_exfat_audit::ExfatAuditLimits, fs_exfat_tree::ExfatTreeLimits,
        fs_exfat_volume::ExfatReadLimits, fs_ext_audit::ExtAuditLimits,
    };
    let r = resources();
    let ext = ReadImage::open(
        Arc::new(Source::new(ext_fixture::fixture())),
        ReadOptions::Ext2 {
            audit: ExtAuditLimits {
                blocks: 128,
                inodes: 32,
                work: 65536,
                directory_blocks: 16,
                directory_entries: 32,
                findings: 16,
            },
            objects: 16,
            entries: 16,
            map_blocks: 32,
            directory_slots: 32,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    assert_eq!(ext.profile().family, Family::Ext2);
    assert_eq!(
        ext.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let page = ext.directory_page(&ext.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].object, page.entries[1].object);
    let file = ext
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(ext);
    let mut out = [0; 23];
    assert_eq!(file.read_at(1001, &mut out, &r).unwrap(), 23);
    assert_eq!(out, [73; 23]);
    drop(file);
    assert_eq!(r.memory.used(), 0);
    let prefix = include_bytes!("fixtures/exfat-basic-prefix.bin");
    let mut exfat = vec![0; 2 << 20];
    exfat[..prefix.len()].copy_from_slice(prefix);
    let exfat = ReadImage::open(
        Arc::new(Source::new(exfat)),
        ReadOptions::Exfat {
            read: ExfatReadLimits {
                max_chain_clusters: 512,
                max_directory_slots: 128,
                max_upcase_bytes: 131072,
            },
            audit: ExfatAuditLimits {
                clusters: 4096,
                entries: 32,
                directory_slots: 256,
                work: 16384,
                findings: 32,
            },
            tree: ExfatTreeLimits {
                objects: 32,
                directory_clusters: 16,
            },
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    assert_eq!(exfat.profile().family, Family::ExFat);
    assert_eq!(
        exfat.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let page = exfat.directory_page(&exfat.root(), None, 8, &r).unwrap();
    let name = partmgr::fs_core::NativeName::Utf16("prefixNoChain.bin".encode_utf16().collect());
    let entry = page.entries.iter().find(|e| e.name == name).unwrap();
    let file = exfat
        .open_stream(&entry.object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(exfat);
    let mut out = [0xff; 100];
    assert_eq!(file.read_at(600, &mut out, &r).unwrap(), 100);
    assert_eq!(out, [0; 100]);
    drop(file);
    assert_eq!(r.memory.used(), 0);
}

#[path = "fixtures/jffs2_clean.rs"]
#[allow(dead_code)] // Shared independent constructor also exports malformed-node helpers.
mod jffs2_fixture;
fn jffs2_options(big: bool) -> ReadOptions {
    use partmgr::{fs_flash::*, fs_jffs2::*, fs_jffs2_audit::Jffs2AuditLimits};
    ReadOptions::Jffs2 {
        geometry: FlashGeometry {
            erased_byte: 255,
            programming: FlashProgramming::ClearBitsOnly,
            erase_bytes: 4096,
            program_bytes: 4,
            layout: FlashLayout::LogicalNor,
        },
        endian: if big {
            Jffs2Endian::Big
        } else {
            Jffs2Endian::Little
        },
        read: Jffs2ReadLimits {
            scan_bytes: 1 << 20,
            nodes: 128,
            inodes: 32,
            fragments: 128,
            native_bytes: 4096,
            work: 100000,
        },
        audit: Jffs2AuditLimits {
            entries: 128,
            work: 128,
            findings: 16,
        },
    }
}
#[test]
fn jffs2_explicit_geometry_endian_native_history_and_retained_guards() {
    use partmgr::fs_core::{MetadataField, NativeName, ObjectKind, read_all};
    for big in [false, true] {
        for policy in [
            AllocationPolicy::RequireClean,
            AllocationPolicy::MetadataOnly,
        ] {
            let r = resources();
            let source = Arc::new(Source::new(jffs2_fixture::jffs2_seed(big)));
            let candidates = probe(source.as_ref(), &r).unwrap();
            assert_eq!(&**candidates, &[ReadFormat::Jffs2]);
            drop(candidates);
            let image = ReadImage::open(source.clone(), jffs2_options(big), policy, &r).unwrap();
            assert_eq!(image.profile().family, Family::Jffs2);
            // Inventory itself requires the complete audit even under MetadataOnly.
            assert_eq!(
                image.allocation_evidence(),
                AllocationEvidence::CleanProfileAudit
            );
            assert_eq!(image.root().source >> 64, 10);
            let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
            assert_eq!(page.entries.len(), 2);
            let file_object = page
                .entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(b"file".to_vec()))
                .unwrap()
                .object
                .clone();
            let nested = page
                .entries
                .iter()
                .find(|e| e.kind == ObjectKind::Directory)
                .unwrap()
                .object
                .clone();
            drop(page);
            let page = image.directory_page(&nested, None, 8, &r).unwrap();
            let alias = page
                .entries
                .iter()
                .find(|e| e.kind == ObjectKind::File)
                .unwrap();
            assert_eq!(alias.name, NativeName::Bytes(vec![b'x', 255]));
            assert_eq!(alias.object, file_object);
            let link = page
                .entries
                .iter()
                .find(|e| e.kind == ObjectKind::Symlink)
                .unwrap();
            assert_eq!(
                image.metadata(&link.object, &r).unwrap().symlink_target,
                MetadataField::Known(NativeName::Bytes(b"../file".to_vec()))
            );
            drop(page);
            let file = image
                .open_stream(&file_object, &StreamKind::Data, &r)
                .unwrap();
            drop(image);
            assert_eq!(
                read_all(file.as_ref(), 16, &r).unwrap().get().as_slice(),
                b"abXY\0\0"
            );
            source.length.store(4096, Ordering::Release);
            assert_eq!(
                file.read_at(6, &mut [], &r).unwrap_err().kind,
                ErrorKind::StalePlan
            );
            source.length.store(8192, Ordering::Release);
            r.cancellation.cancel();
            assert_eq!(
                file.read_at(6, &mut [], &resources()).unwrap_err().kind,
                ErrorKind::Cancelled
            );
            drop(file);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn jffs2_wrong_endian_layout_and_scan_limits_fail_without_fallback() {
    use partmgr::fs_flash::FlashLayout;
    let r = resources();
    let bytes = jffs2_fixture::jffs2_seed(false);
    for mode in 0..3 {
        let mut options = jffs2_options(mode == 0);
        if let ReadOptions::Jffs2 { geometry, read, .. } = &mut options {
            if mode == 1 {
                geometry.layout = FlashLayout::PhysicalNand {
                    page_bytes: 2048,
                    spare_bytes: 64,
                };
            }
            if mode == 2 {
                read.scan_bytes = 4096;
            }
        }
        assert!(
            ReadImage::open(
                Arc::new(Source::new(bytes.clone())),
                options,
                AllocationPolicy::RequireClean,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/hfsplus_clean.rs"]
mod hfsplus_fixture;

#[test]
fn hfsplus_facade_audits_both_catalog_profiles_and_preserves_resource_fork() {
    use partmgr::{
        fs_core::NativeName, fs_hfsplus::HfsPlusReadLimits, fs_hfsplus_audit::HfsPlusAuditLimits,
    };
    for binary in [false, true] {
        for policy in [
            AllocationPolicy::RequireClean,
            AllocationPolicy::MetadataOnly,
        ] {
            let r = resources();
            let source = Arc::new(Source::new(hfsplus_fixture::hfsplus_seed(binary)));
            let candidates = probe(source.as_ref(), &r).unwrap();
            assert_eq!(&**candidates, &[ReadFormat::HfsPlus]);
            drop(candidates);
            let image = ReadImage::open(
                source.clone(),
                ReadOptions::HfsPlus {
                    read: HfsPlusReadLimits {
                        blocks: 256,
                        nodes: 32,
                        records: 32,
                        extents: 64,
                        work: 1_000_000,
                    },
                    audit: HfsPlusAuditLimits {
                        blocks: 256,
                        objects: 32,
                        depth: 8,
                        work: 1_000_000,
                        findings: 16,
                    },
                },
                policy,
                &r,
            )
            .unwrap();
            assert_eq!(
                image.allocation_evidence(),
                AllocationEvidence::CleanProfileAudit
            );
            assert_eq!(image.root().source >> 64, 11);
            assert_eq!(
                image.profile().family,
                if binary {
                    Family::HfsX
                } else {
                    Family::HfsPlus
                }
            );
            let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
            let object = page
                .entries
                .iter()
                .find(|entry| entry.name == NativeName::Utf16(hfsplus_fixture::native_name(binary)))
                .unwrap()
                .object
                .clone();
            drop(page);
            let streams = image.streams(&object, &r).unwrap();
            assert_eq!(streams.len(), 2);
            drop(streams);
            let file = image
                .open_stream(&object, &StreamKind::ResourceFork, &r)
                .unwrap();
            let mut bytes = [0; 5];
            assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 5);
            assert_eq!(&bytes, b"RSRC!");
            source.length.fetch_sub(1, Ordering::AcqRel);
            assert!(
                matches!(file.read_at(5, &mut [], &r), Err(e) if e.kind == ErrorKind::StalePlan)
            );
            drop(file);
            drop(image);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn hfsplus_metadata_policy_cannot_bypass_lost_allocation_audit() {
    use partmgr::{fs_hfsplus::HfsPlusReadLimits, fs_hfsplus_audit::HfsPlusAuditLimits};
    for policy in [
        AllocationPolicy::RequireClean,
        AllocationPolicy::MetadataOnly,
    ] {
        let r = resources();
        let mut bytes = hfsplus_fixture::hfsplus_seed(false);
        // Mark otherwise unowned allocation block 40.
        bytes[4101] |= 0x80;
        let result = ReadImage::open(
            Arc::new(Source::new(bytes)),
            ReadOptions::HfsPlus {
                read: HfsPlusReadLimits {
                    blocks: 256,
                    nodes: 32,
                    records: 32,
                    extents: 64,
                    work: 1_000_000,
                },
                audit: HfsPlusAuditLimits {
                    blocks: 256,
                    objects: 32,
                    depth: 8,
                    work: 1_000_000,
                    findings: 16,
                },
            },
            policy,
            &r,
        );
        assert!(matches!(result, Err(e) if e.kind == ErrorKind::InvalidData));
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/hfs_clean.rs"]
#[allow(dead_code)] // Native fragmentation helper belongs to the separate formatter gate.
mod hfs_fixture;
#[test]
fn classic_hfs_facade_keeps_byte_names_and_resource_forks_with_clean_evidence() {
    use partmgr::{fs_core::NativeName, fs_hfs::HfsReadLimits, fs_hfs_audit::HfsAuditLimits};
    for policy in [
        AllocationPolicy::RequireClean,
        AllocationPolicy::MetadataOnly,
    ] {
        let r = resources();
        let source = Arc::new(Source::new(hfs_fixture::hfs_seed()));
        let candidates = probe(source.as_ref(), &r).unwrap();
        assert_eq!(&**candidates, &[ReadFormat::Hfs]);
        drop(candidates);
        let image = ReadImage::open(
            source.clone(),
            ReadOptions::Hfs {
                read: HfsReadLimits {
                    blocks: 256,
                    nodes: 64,
                    records: 128,
                    extents: 256,
                    work: 2_000_000,
                },
                audit: HfsAuditLimits {
                    blocks: 256,
                    objects: 128,
                    depth: 16,
                    work: 100_000,
                    findings: 32,
                },
            },
            policy,
            &r,
        )
        .unwrap();
        assert_eq!(image.profile().family, Family::Hfs);
        assert_eq!(image.root().source >> 64, 14);
        assert_eq!(
            image.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
        let object = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"Data".to_vec()))
            .unwrap()
            .object
            .clone();
        drop(page);
        let streams = image.streams(&object, &r).unwrap();
        assert_eq!(streams.len(), 2);
        drop(streams);
        let file = image
            .open_stream(&object, &StreamKind::ResourceFork, &r)
            .unwrap();
        let mut out = [0; 5];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 5);
        assert_eq!(&out, b"RSRC!");
        source.length.fetch_sub(1, Ordering::AcqRel);
        assert!(
            matches!(file.read_at(file.len(),&mut [],&r),Err(e) if e.kind==ErrorKind::StalePlan)
        );
        drop(file);
        drop(image);
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/jfs_clean.rs"]
#[allow(dead_code)]
mod jfs_fixture;
#[test]
fn jfs_facade_audits_preserves_sparse_native_stream_and_rejects_stale_eof() {
    use partmgr::{fs_core::NativeName, fs_jfs::JfsReadLimits, fs_jfs_audit::JfsAuditLimits};
    for policy in [
        AllocationPolicy::RequireClean,
        AllocationPolicy::MetadataOnly,
    ] {
        let r = Resources {
            memory: Budget::new(32 << 20),
            cancellation: Cancellation::default(),
        };
        let source = Arc::new(Source::new(jfs_fixture::jfs_seed()));
        let candidates = probe(source.as_ref(), &r).unwrap();
        assert_eq!(&**candidates, &[ReadFormat::Jfs]);
        drop(candidates);
        let image = ReadImage::open(
            source.clone(),
            ReadOptions::Jfs {
                read: JfsReadLimits {
                    blocks: 65536,
                    inodes: 512,
                    entries: 1024,
                    pages: 1024,
                    extents: 4096,
                    work: 64 * 1024 * 1024,
                },
                audit: JfsAuditLimits {
                    blocks: 65536,
                    objects: 1024,
                    depth: 32,
                    work: 1_000_000,
                    findings: 64,
                },
            },
            policy,
            &r,
        )
        .unwrap();
        assert_eq!(image.profile().family, Family::Jfs);
        assert_eq!(image.root().source >> 64, 15);
        assert_eq!(
            image.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
        let object = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Utf16(jfs_fixture::name()))
            .unwrap()
            .object
            .clone();
        drop(page);
        let file = image.open_stream(&object, &StreamKind::Data, &r).unwrap();
        let mut out = vec![0xaa; 4 * jfs_fixture::BLOCK + 7];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), out.len());
        assert!(
            out[jfs_fixture::BLOCK..2 * jfs_fixture::BLOCK]
                .iter()
                .all(|v| *v == 0)
        );
        assert!(out[3 * jfs_fixture::BLOCK..].iter().all(|v| *v == 0));
        source.length.fetch_sub(1, Ordering::AcqRel);
        assert!(
            matches!(file.read_at(file.len(),&mut [],&r),Err(e) if e.kind==ErrorKind::StalePlan)
        );
        drop(file);
        drop(image);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn jfs_metadata_policy_cannot_bypass_allocation_reference_audit() {
    use partmgr::{fs_jfs::JfsReadLimits, fs_jfs_audit::JfsAuditLimits};
    for policy in [
        AllocationPolicy::RequireClean,
        AllocationPolicy::MetadataOnly,
    ] {
        let r = Resources {
            memory: Budget::new(32 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = jfs_fixture::jfs_seed();
        let mut used: Vec<_> = (0..22).chain(23..35).collect();
        used.extend([90, 100, 102, 110, 112, 120]);
        jfs_fixture::rebuild_map(&mut bytes, &used);
        let result = ReadImage::open(
            Arc::new(Source::new(bytes)),
            ReadOptions::Jfs {
                read: JfsReadLimits {
                    blocks: 65536,
                    inodes: 512,
                    entries: 1024,
                    pages: 1024,
                    extents: 4096,
                    work: 64 * 1024 * 1024,
                },
                audit: JfsAuditLimits {
                    blocks: 65536,
                    objects: 1024,
                    depth: 32,
                    work: 1_000_000,
                    findings: 64,
                },
            },
            policy,
            &r,
        );
        assert!(result.is_err());
        drop(result);
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/apfs_clean.rs"]
#[allow(dead_code)]
mod apfs_fixture;
#[test]
fn apfs_facade_requires_explicit_volume_and_keeps_resource_forks() {
    use partmgr::{fs_apfs::ApfsReadLimits, fs_apfs_audit::ApfsAuditLimits, fs_core::NativeName};
    for policy in [
        AllocationPolicy::RequireClean,
        AllocationPolicy::MetadataOnly,
    ] {
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let source = Arc::new(Source::new(apfs_fixture::apfs_seed()));
        let candidates = probe(source.as_ref(), &r).unwrap();
        assert_eq!(&**candidates, &[ReadFormat::Apfs]);
        drop(candidates);
        let options = |volume_oid| ReadOptions::Apfs {
            read: ApfsReadLimits {
                blocks: 65536,
                checkpoint_blocks: 256,
                objects: 256,
                records: 256,
                work: 64 * 1024 * 1024,
            },
            audit: ApfsAuditLimits {
                blocks: 65536,
                objects: 512,
                depth: 32,
                work: 64 * 1024 * 1024,
                findings: 64,
            },
            volume_oid,
        };
        assert!(ReadImage::open(source.clone(), options(9999), policy, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        let image = ReadImage::open(source.clone(), options(1026), policy, &r).unwrap();
        assert_eq!(image.profile().family, Family::Apfs);
        assert_eq!(image.root().source >> 64, 16);
        assert_eq!(
            image.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
        let object = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
            .unwrap()
            .object
            .clone();
        drop(page);
        let file = image
            .open_stream(&object, &StreamKind::ResourceFork, &r)
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 8);
        assert_eq!(&bytes, b"resource");
        source.length.fetch_sub(1, Ordering::AcqRel);
        assert!(
            matches!(file.read_at(file.len(),&mut [],&r),Err(e) if e.kind==ErrorKind::StalePlan)
        );
        drop(file);
        drop(image);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn immutable_ext_extent_profile_requires_explicit_opt_in_and_reports_ext4() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = ext_fixture::fixture();
    bytes[1120..1124].copy_from_slice(&0x42u32.to_le_bytes());
    let inode = 6400;
    bytes[inode + 32..inode + 36].copy_from_slice(&0x80000u32.to_le_bytes());
    bytes[inode + 40..inode + 100].fill(0);
    for (offset, value) in [(0, 0xf30a), (2, 1), (4, 4), (6, 0)] {
        bytes[inode + 40 + offset..inode + 42 + offset]
            .copy_from_slice(&(value as u16).to_le_bytes());
    }
    bytes[inode + 56..inode + 58].copy_from_slice(&1u16.to_le_bytes());
    bytes[inode + 60..inode + 64].copy_from_slice(&8u32.to_le_bytes());
    let source = Arc::new(Source::new(bytes));
    let audit = partmgr::fs_ext_audit::ExtAuditLimits {
        blocks: 64,
        inodes: 16,
        work: 65536,
        directory_blocks: 8,
        directory_entries: 32,
        findings: 16,
    };
    let classic = ReadOptions::Ext2 {
        audit,
        objects: 16,
        entries: 16,
        map_blocks: 64,
        directory_slots: 32,
    };
    assert!(
        matches!(ReadImage::open(source.clone(),classic,AllocationPolicy::RequireClean,&r),Err(e) if e.kind==ErrorKind::Unsupported)
    );
    assert_eq!(r.memory.used(), 0);
    let image = ReadImage::open(
        source.clone(),
        ReadOptions::Ext {
            audit,
            objects: 16,
            entries: 16,
            map_blocks: 65536,
            directory_slots: 32,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    assert_eq!(image.profile().family, Family::Ext4);
    assert_eq!(
        image.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    let object = page.entries[0].object.clone();
    drop(page);
    let mut retained = Vec::new();
    for _ in 0..600 {
        retained.push(image.open_stream(&object, &StreamKind::Data, &r).unwrap());
    }
    drop(image);
    let baseline = r.memory.used();
    assert!(baseline < 1 << 20, "compact retained maps: {baseline}");
    let reads = source.reads.load(Ordering::Acquire);
    for file in &retained {
        let mut bytes = [0; 17];
        assert_eq!(file.read_at(7, &mut bytes, &r).unwrap(), bytes.len());
        assert_eq!(bytes, [73; 17]);
    }
    assert_eq!(source.reads.load(Ordering::Acquire) - reads, 600);
    assert_eq!(r.memory.used(), baseline);
    r.cancellation.cancel();
    for file in &retained {
        assert!(file.read_at(file.len(), &mut [], &r).is_err());
    }
    drop(retained);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn apfs_facade_explicit_selection_keeps_distinct_volumes_after_checkpoint_advance() {
    use partmgr::{fs_apfs::ApfsReadLimits, fs_apfs_audit::ApfsAuditLimits, fs_core::NativeName};
    let mut bytes = apfs_fixture::apfs_seed();
    apfs_fixture::second_volume(&mut bytes);
    apfs_fixture::next_checkpoint(&mut bytes);
    for oid in [1026, 1100] {
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let source = Source::new(bytes.clone());
        source
            .length
            .store(apfs_fixture::MULTIVOLUME_LENGTH, Ordering::Release);
        let source = Arc::new(source);
        let image = ReadImage::open(
            source,
            ReadOptions::Apfs {
                read: ApfsReadLimits {
                    blocks: 131073,
                    checkpoint_blocks: 256,
                    objects: 256,
                    records: 256,
                    work: 64 << 20,
                },
                audit: ApfsAuditLimits {
                    blocks: 131073,
                    objects: 512,
                    depth: 32,
                    work: 64 << 20,
                    findings: 64,
                },
                volume_oid: oid,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        assert_eq!(
            image.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        let page = image.directory_page(&image.root(), None, 16, &r).unwrap();
        if oid == 1026 {
            assert!(
                page.entries
                    .iter()
                    .any(|e| e.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
            );
        } else {
            assert!(page.entries.is_empty());
        }
        drop(page);
        drop(image);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn extended_ext_inode_stride_requires_broader_facade_selection() {
    use partmgr::{fs_core::NativeName, fs_ext_audit::ExtAuditLimits};
    let mut bytes = ext_fixture::fixture();
    let root = bytes[5 * 1024 + 128..5 * 1024 + 256].to_vec();
    let file = bytes[5 * 1024 + 10 * 128..5 * 1024 + 11 * 128].to_vec();
    let directory = bytes[7 * 1024..8 * 1024].to_vec();
    let payload = bytes[8 * 1024..9 * 1024].to_vec();
    bytes[5 * 1024..9 * 1024].fill(0);
    let root_at = 5 * 1024 + 256;
    let file_at = 5 * 1024 + 10 * 256;
    bytes[root_at..root_at + 128].copy_from_slice(&root);
    bytes[file_at..file_at + 128].copy_from_slice(&file);
    bytes[root_at + 40..root_at + 44].copy_from_slice(&9u32.to_le_bytes());
    bytes[file_at + 40..file_at + 44].copy_from_slice(&10u32.to_le_bytes());
    for at in [root_at, file_at] {
        bytes[at + 128..at + 130].copy_from_slice(&32u16.to_le_bytes());
    }
    bytes[9 * 1024..10 * 1024].copy_from_slice(&directory);
    bytes[10 * 1024..11 * 1024].copy_from_slice(&payload);
    bytes[1024 + 88..1024 + 90].copy_from_slice(&256u16.to_le_bytes());
    bytes[1024 + 12..1024 + 16].copy_from_slice(&53u32.to_le_bytes());
    bytes[2060..2062].copy_from_slice(&53u16.to_le_bytes());
    bytes[3073] |= 3;
    let source = Arc::new(Source::new(bytes));
    let r = Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    };
    let options = |classic| {
        let audit = ExtAuditLimits {
            blocks: 128,
            inodes: 64,
            work: 65536,
            directory_blocks: 64,
            directory_entries: 128,
            findings: 32,
        };
        if classic {
            ReadOptions::Ext2 {
                audit,
                objects: 16,
                entries: 32,
                map_blocks: 64,
                directory_slots: 64,
            }
        } else {
            ReadOptions::Ext {
                audit,
                objects: 16,
                entries: 32,
                map_blocks: 64,
                directory_slots: 64,
            }
        }
    };
    let error = ReadImage::open(
        source.clone(),
        options(true),
        AllocationPolicy::RequireClean,
        &r,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(r.memory.used(), 0);
    let image =
        ReadImage::open(source, options(false), AllocationPolicy::RequireClean, &r).unwrap();
    let page = image.directory_page(&image.root(), None, 16, &r).unwrap();
    let alias = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
        .unwrap();
    let file = image
        .open_stream(&alias.object, &StreamKind::Data, &r)
        .unwrap();
    let mut actual = [0; 1024];
    assert_eq!(file.read_at(0, &mut actual, &r).unwrap(), 1024);
    assert!(actual.iter().all(|b| *b == 73));
    drop((file, page, image));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn retained_facade_file_supports_concurrent_random_reads_without_metadata_rescans() {
    let r = resources();
    let source = Arc::new(Source::new(fat_fixture()));
    let image = ReadImage::open(
        source.clone(),
        fat_options(),
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    let identity = file.identity();
    drop(page);
    drop(image);
    let retained = r.memory.used();
    let before = source.reads.load(Ordering::Acquire);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|worker| {
                let file = &file;
                scope.spawn(move || {
                    let request_resources = resources();
                    for request in 0..64 {
                        let offset = (worker * 113 + request * 37) % 512;
                        let mut bytes = [0xa5; 17];
                        let expected = 17.min(512 - offset);
                        assert_eq!(
                            file.read_at(offset as u64, &mut bytes, &request_resources)
                                .unwrap(),
                            expected
                        );
                        assert_eq!(&bytes[..expected], vec![0x76; expected]);
                        assert!(bytes[expected..].iter().all(|byte| *byte == 0xa5));
                        assert_eq!(file.identity(), identity);
                    }
                    // Per-request cancellation cannot poison another worker or the source.
                    request_resources.cancellation.cancel();
                    assert_eq!(
                        file.read_at(0, &mut [0; 1], &request_resources)
                            .unwrap_err()
                            .kind,
                        ErrorKind::Cancelled
                    );
                    assert_eq!(request_resources.memory.used(), 0);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert_eq!(source.reads.load(Ordering::Acquire) - before, 256);
    assert_eq!(r.memory.used(), retained);
    let mut byte = [0];
    assert_eq!(file.read_at(0, &mut byte, &r).unwrap(), 1);
    assert_eq!(byte, [0x76]);
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(file.len(), &mut [], &resources())
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}

fn compressed_jffs2_options(big: bool, decoded_node_bytes: usize) -> ReadOptions {
    let ReadOptions::Jffs2 {
        geometry,
        endian,
        read,
        audit,
    } = jffs2_options(big)
    else {
        unreachable!()
    };
    ReadOptions::Jffs2Compressed {
        geometry,
        endian,
        read,
        audit,
        compression: partmgr::fs_jffs2::Jffs2CompressionLimits {
            compressed_node_bytes: 64,
            decoded_node_bytes,
            compressed_bytes: 1024,
            decoded_bytes: 4096,
            work: 8192,
        },
    }
}
fn compressed_jffs2_fixture(big: bool, decoded_size: u32) -> Vec<u8> {
    // Independent native RTIME pair: literal A followed by 255 overlapping copies.
    let mut bytes = jffs2_fixture::jffs2_seed(big);
    let mut header = bytes[68..136].to_vec();
    for (offset, value) in [
        (4, 70),
        (16, 4),
        (28, 256),
        (44, 0),
        (48, 2),
        (52, decoded_size),
    ] {
        jffs2_fixture::dword(&mut header, offset, value, big);
    }
    header[56] = 2;
    let checksum = jffs2_fixture::crc(&header[..8]);
    jffs2_fixture::dword(&mut header, 8, checksum, big);
    jffs2_fixture::dword(&mut header, 60, jffs2_fixture::crc(&[b'A', 255]), big);
    let checksum = jffs2_fixture::crc(&header[..60]);
    jffs2_fixture::dword(&mut header, 64, checksum, big);
    bytes[4096..4164].copy_from_slice(&header);
    bytes[4164..4166].copy_from_slice(&[b'A', 255]);
    bytes
}
#[test]
fn compressed_jffs2_facade_requires_opt_in_audits_both_policies_and_retains_guards() {
    use partmgr::fs_core::NativeName;
    for big in [false, true] {
        for policy in [
            AllocationPolicy::RequireClean,
            AllocationPolicy::MetadataOnly,
        ] {
            let r = resources();
            let source = Arc::new(Source::new(compressed_jffs2_fixture(big, 256)));
            assert!(ReadImage::open(source.clone(), jffs2_options(big), policy, &r).is_err());
            assert_eq!(r.memory.used(), 0);
            assert!(
                ReadImage::open(
                    source.clone(),
                    compressed_jffs2_options(big, 128),
                    policy,
                    &r
                )
                .is_err()
            );
            assert_eq!(r.memory.used(), 0);
            let image = ReadImage::open(
                source.clone(),
                compressed_jffs2_options(big, 1024),
                policy,
                &r,
            )
            .unwrap();
            assert_eq!(
                image.allocation_evidence(),
                AllocationEvidence::CleanProfileAudit
            );
            assert_eq!(image.profile().family, Family::Jffs2);
            let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
            let object = page
                .entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(b"file".to_vec()))
                .unwrap()
                .object
                .clone();
            let file = image.open_stream(&object, &StreamKind::Data, &r).unwrap();
            drop(page);
            drop(image);
            let retained = r.memory.used();
            let mut bytes = [0xa5; 19];
            assert_eq!(file.read_at(249, &mut bytes, &r).unwrap(), 7);
            assert_eq!(&bytes[..7], &[b'A'; 7]);
            assert_eq!(&bytes[7..], &[0xa5; 12]);
            assert_eq!(r.memory.used(), retained);
            source.length.fetch_sub(1, Ordering::AcqRel);
            assert_eq!(
                file.read_at(file.len(), &mut [], &r).unwrap_err().kind,
                ErrorKind::StalePlan
            );
            source.length.fetch_add(1, Ordering::AcqRel);
            r.cancellation.cancel();
            assert_eq!(
                file.read_at(0, &mut bytes, &resources()).unwrap_err().kind,
                ErrorKind::Cancelled
            );
            drop(file);
            assert_eq!(r.memory.used(), 0);
            let r = resources();
            assert!(
                ReadImage::open(
                    Arc::new(Source::new(compressed_jffs2_fixture(big, 255))),
                    compressed_jffs2_options(big, 1024),
                    policy,
                    &r
                )
                .is_err()
            );
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn apfs_facade_offline_reauthoring_preserves_sparse_data_fork_and_retained_guards() {
    use partmgr::{
        fs_apfs::ApfsReadLimits,
        fs_apfs_audit::ApfsAuditLimits,
        fs_apfs_builder::*,
        fs_core::{NativeName, read_all},
        storage::Storage,
    };
    struct Staging {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl Storage for Staging {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(61);
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let read = ApfsReadLimits {
        blocks: 65536,
        checkpoint_blocks: 256,
        objects: 256,
        records: 256,
        work: 64 << 20,
    };
    let audit = ApfsAuditLimits {
        blocks: 65536,
        objects: 512,
        depth: 32,
        work: 64 << 20,
        findings: 64,
    };
    let source = ReadImage::open(
        Arc::new(Source::new(apfs_fixture::apfs_seed())),
        ReadOptions::Apfs {
            read,
            audit,
            volume_oid: 1026,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    let plan = ApfsBuildPlan::plan(
        Arc::new(source),
        ApfsBuildOptions {
            image_bytes: 2 << 20,
            container_uuid: [0x71; 16],
            volume_uuid: [0x72; 16],
            volume_label: b"Facade authored".to_vec(),
            names: ApfsBuildNames::ExactBytes,
            metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
                uid: 501,
                gid: 20,
                file_permissions: 0o640,
                directory_permissions: 0o750,
                timestamp: 123456,
            }),
            limits: ApfsBuildLimits {
                objects: 32,
                occurrences: 64,
                name_bytes: 4096,
                depth: 16,
                blocks: 512,
                work: 64 << 20,
                page_entries: 2,
            },
        },
        &r,
    )
    .unwrap();
    assert!(
        plan.outcomes()
            .iter()
            .any(|o| o.inspection == ApfsMetadataInspection::Opaque)
    );
    let mut staging = Staging {
        bytes: vec![0xa7; 2 << 20],
        flushes: 0,
    };
    let report = plan.emit(&mut staging, &r).unwrap();
    assert!(staging.flushes > 0);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
    let output = Arc::new(Source::new(staging.bytes));
    let proof = report.audit(output.clone(), read, audit, &r).unwrap();
    assert!(proof.is_complete() && proof.is_clean());
    drop(proof);
    let image = ReadImage::open(
        output.clone(),
        ReadOptions::Apfs {
            read,
            audit,
            volume_oid: report.volume_oid,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    let page = image.directory_page(&image.root(), None, 16, &r).unwrap();
    let object = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
        .unwrap()
        .object
        .clone();
    let file = image.open_stream(&object, &StreamKind::Data, &r).unwrap();
    let fork = image
        .open_stream(&object, &StreamKind::ResourceFork, &r)
        .unwrap();
    drop(page);
    drop(image);
    let expected: Vec<u8> = (0..16397)
        .map(|i| {
            if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                0
            } else {
                (i % 4096 * 17 % 251) as u8
            }
        })
        .collect();
    assert_eq!(
        read_all(file.as_ref(), 16397, &r).unwrap().get().as_slice(),
        expected
    );
    assert_eq!(
        read_all(fork.as_ref(), 8, &r).unwrap().get().as_slice(),
        b"resource"
    );
    output.length.fetch_sub(1, Ordering::AcqRel);
    assert!(
        matches!(file.read_at(file.len(), &mut [], &r), Err(e) if e.kind == ErrorKind::StalePlan)
    );
    assert!(
        matches!(fork.read_at(fork.len(), &mut [], &r), Err(e) if e.kind == ErrorKind::StalePlan)
    );
    drop(file);
    drop(fork);
    assert_eq!(r.memory.used(), 0);
}
