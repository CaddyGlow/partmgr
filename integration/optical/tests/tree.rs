use partmgr::fs_core::{
    Budget, Cancellation, ErrorKind, MetadataField, NativeName, ObjectKind, Resources, StreamKind,
    TreeSource,
};
use partmgr_optical::{
    read::{OpticalReadIndex, OpticalReadLimits, SourceAdapter},
    tree::OpticalTreeSource,
};
use std::sync::Arc;
use virtdisk::RawDisk;
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> OpticalReadLimits {
    OpticalReadLimits {
        max_entries: 128,
        max_metadata_bytes: 1 << 20,
        max_extents: 1024,
        max_depth: 16,
    }
}
fn iso(
    path: &std::path::Path,
    namespace: libmkiso::IsoNamespace,
    r: &Resources,
) -> OpticalReadIndex {
    OpticalReadIndex::iso(
        SourceAdapter::new(Arc::new(RawDisk::open(path).unwrap()), r.clone(), u64::MAX),
        13,
        7,
        namespace,
        limits(),
        r,
    )
    .unwrap()
}
fn udf(path: &std::path::Path, r: &Resources) -> OpticalReadIndex {
    OpticalReadIndex::udf(
        SourceAdapter::new(Arc::new(RawDisk::open(path).unwrap()), r.clone(), u64::MAX),
        33,
        9,
        limits(),
        r,
    )
    .unwrap()
}
fn child(
    tree: &OpticalTreeSource,
    parent: &partmgr::fs_core::ObjectId,
    leaf: NativeName,
    r: &Resources,
) -> partmgr::fs_core::ObjectId {
    tree.directory_page(parent, None, 128, r)
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.name == leaf)
        .unwrap()
        .object
}
#[test]
fn iso_selected_primary_joliet_rockridge_leaf_topology_and_scoped_pages() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("tree");
    std::fs::create_dir_all(input.join("Mixed Parent/deep")).unwrap();
    std::fs::write(
        input.join("Mixed Parent/deep/Child file.bin"),
        b"actual optical bytes",
    )
    .unwrap();
    std::fs::write(input.join("first.bin"), b"first").unwrap();
    let path = dir.path().join("image.iso");
    libmkiso::write_iso9660_with_options(
        &input,
        &path,
        &libmkiso::IsoOptions {
            filename_policy: libmkiso::FilenamePolicy::Mangle,
            joliet: true,
            rock_ridge: true,
            ..Default::default()
        },
    )
    .unwrap();
    for namespace in [
        libmkiso::IsoNamespace::Primary,
        libmkiso::IsoNamespace::Joliet,
        libmkiso::IsoNamespace::RockRidge,
        libmkiso::IsoNamespace::PreferRockRidge,
    ] {
        let r = resources();
        let index = iso(&path, namespace, &r);
        let selected = index
            .entries()
            .iter()
            .find(|e| {
                e.kind == ObjectKind::File && e.display_path.contains("Child file")
                    || e.display_path.contains("CHILD_FI")
            })
            .map(|e| (e.native_name.clone(), e.leaf.clone()));
        let tree = OpticalTreeSource::new(index, &r).unwrap();
        let root = tree.root();
        let page = tree.directory_page(&root, None, 1, &r).unwrap();
        assert_eq!(page.entries.len(), 1);
        let token = page.next.clone().unwrap();
        let next = tree.directory_page(&root, Some(&token), 1, &r).unwrap();
        assert_eq!(next.entries.len(), 1);
        assert_ne!(page.entries[0].object, next.entries[0].object);
        let parent = tree
            .directory_page(&root, None, 16, &r)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.kind == ObjectKind::Directory)
            .unwrap()
            .object;
        assert!(tree.directory_page(&parent, Some(&token), 1, &r).is_err());
        let deep = tree
            .directory_page(&parent, None, 16, &r)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.kind == ObjectKind::Directory)
            .unwrap()
            .object;
        let leaf = tree
            .directory_page(&deep, None, 16, &r)
            .unwrap()
            .entries
            .remove(0);
        let file = tree
            .open_stream(&leaf.object, &StreamKind::Data, &r)
            .unwrap();
        let mut bytes = [0; 20];
        assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 20);
        assert_eq!(&bytes, b"actual optical bytes");
        assert_eq!(file.identity(), &leaf.object);
        match namespace {
            libmkiso::IsoNamespace::Primary => {
                assert!(matches!(&leaf.name,NativeName::Bytes(b) if b.ends_with(b";1")))
            }
            libmkiso::IsoNamespace::Joliet => assert!(
                matches!(&leaf.name,NativeName::Utf16(u) if String::from_utf16(u).unwrap()=="Child file.bin")
            ),
            _ => {
                assert_eq!(leaf.name, NativeName::Bytes(b"Child file.bin".to_vec()));
                if let Some((stored, semantic)) = selected {
                    assert_ne!(NativeName::Bytes(stored), semantic);
                }
            }
        }
        let metadata = tree.metadata(&root, &r).unwrap();
        assert!(matches!(
            metadata.get().created,
            MetadataField::Uninspectable { .. }
        ));
        drop(metadata);
        let mut stale = root.clone();
        stale.generation += 1;
        assert_eq!(
            tree.revalidate(&stale, &r).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        drop(page);
        drop(next);
        drop(tree);
        assert!(r.memory.used() > 0);
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn udf_hardlinks_named_root_system_streams_sparse_classes_and_lease_lifetime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.udf");
    let mut image = libmkiso::UdfImage::new();
    image
        .add_sparse_file(
            "nested/日本語.bin",
            vec![
                libmkiso::UdfFileExtent::Data(vec![7; 2048]),
                libmkiso::UdfFileExtent::Hole(2048),
                libmkiso::UdfFileExtent::AllocatedHole(2048),
                libmkiso::UdfFileExtent::Data(vec![9; 3]),
            ],
        )
        .unwrap();
    image
        .add_hard_link("alias.bin", "nested/日本語.bin")
        .unwrap();
    image
        .add_named_stream("nested/日本語.bin", "notes", b"named".to_vec())
        .unwrap();
    image
        .add_root_stream("root-note", b"root".to_vec())
        .unwrap();
    image
        .add_system_stream("sys-note", b"system".to_vec())
        .unwrap();
    image.add_symlink("link", "nested/日本語.bin").unwrap();
    image
        .write(
            &path,
            &libmkiso::UdfOptions {
                revision: libmkiso::UdfRevision::V201,
                ..Default::default()
            },
        )
        .unwrap();
    let r = resources();
    let index = udf(&path, &r);
    let expected_root = index.root_identity.clone();
    let tree = OpticalTreeSource::new(index, &r).unwrap();
    assert_eq!(tree.root(), expected_root);
    let root = tree.root();
    let nested = child(
        &tree,
        &root,
        NativeName::Utf16("nested".encode_utf16().collect()),
        &r,
    );
    let file = child(
        &tree,
        &nested,
        NativeName::Utf16("日本語.bin".encode_utf16().collect()),
        &r,
    );
    let alias = child(
        &tree,
        &root,
        NativeName::Utf16("alias.bin".encode_utf16().collect()),
        &r,
    );
    assert_eq!(file, alias);
    let inventory = tree.streams(&file, &r).unwrap();
    assert_eq!(inventory.get().len(), 2);
    let notes = StreamKind::Named(NativeName::Utf16("notes".encode_utf16().collect()));
    assert!(inventory.get().iter().any(|s| s.kind == notes));
    let data = tree.open_stream(&file, &StreamKind::Data, &r).unwrap();
    let named = tree.open_stream(&alias, &notes, &r).unwrap();
    assert_eq!(named.identity(), &alias);
    let mut b = [0; 5];
    named.read_at(0, &mut b, &r).unwrap();
    assert_eq!(&b, b"named");
    let mut classes = Vec::new();
    data.visit_extents(&r, &mut |e| {
        classes.push(e.kind);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        classes,
        vec![
            partmgr::fs_core::ExtentKind::Data,
            partmgr::fs_core::ExtentKind::Hole,
            partmgr::fs_core::ExtentKind::Unwritten,
            partmgr::fs_core::ExtentKind::Data
        ]
    );
    let roots = tree.streams(&root, &r).unwrap();
    assert_eq!(roots.get().len(), 2);
    for s in roots.get() {
        let handle = tree.open_stream(&root, &s.kind, &r).unwrap();
        assert_eq!(handle.identity(), &root);
    }
    assert!(tree.open_stream(&nested, &notes, &r).is_err());
    let link = child(
        &tree,
        &root,
        NativeName::Utf16("link".encode_utf16().collect()),
        &r,
    );
    assert!(tree.streams(&link, &r).unwrap().get().is_empty());
    assert!(tree.open_stream(&link, &StreamKind::Data, &r).is_err());
    assert!(matches!(
        tree.metadata(&link, &r).unwrap().get().symlink_target,
        MetadataField::Uninspectable { .. }
    ));
    drop(inventory);
    drop(roots);
    drop(tree);
    let mut zeros = [0xff; 16];
    data.read_at(3000, &mut zeros, &r).unwrap();
    assert_eq!(zeros, [0; 16]);
    drop(data);
    assert!(r.memory.used() > 0);
    drop(named);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn adapter_budget_cancellation_and_copy_preflight_reports_owned_streams() {
    use partmgr::{
        fs_copy::{CopyLimits, CopyNamePolicy, FatCopyOptions, FatCopyPlan},
        fs_fat::FatFamily,
        fs_fat_builder::{FatBuildOptions, FatTreeMetadataPolicy},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.udf");
    let mut image = libmkiso::UdfImage::new();
    image
        .add_bytes("nested/data.bin", b"payload".to_vec())
        .unwrap();
    image
        .add_named_stream("nested/data.bin", "notes", b"stream".to_vec())
        .unwrap();
    image
        .write(
            &path,
            &libmkiso::UdfOptions {
                revision: libmkiso::UdfRevision::V201,
                ..Default::default()
            },
        )
        .unwrap();
    let r = resources();
    let index = udf(&path, &r);
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        OpticalTreeSource::new(index, &tiny).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    let tree = Arc::new(OpticalTreeSource::new(udf(&path, &r), &r).unwrap());
    let options = FatCopyOptions {
        image_bytes: 1_440 * 1024,
        filesystem: FatBuildOptions {
            family: FatFamily::Fat12,
            sectors_per_cluster: 1,
            volume_id: 1,
        },
        names: CopyNamePolicy::StrictUtf8,
        metadata: FatTreeMetadataPolicy::DeterministicDefaults,
        limits: CopyLimits {
            objects: 128,
            pages: 128,
            page_entries: 8,
        },
    };
    assert_eq!(
        FatCopyPlan::new(tree.clone(), options, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    r.cancellation.cancel();
    assert_eq!(
        tree.directory_page(&tree.root(), None, 1, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "explicit native optical-to-FAT gate; requires PARTMGR_OPTICAL_TREE_EVIDENCE, fsck.fat and mcopy"]
fn native_iso_and_udf_to_fat_without_capture_host_extraction() {
    use partmgr::{
        fs_copy::{CopyLimits, CopyNamePolicy, FatCopyOptions, FatCopyPlan},
        fs_fat::{FatFamily, FatVolume},
        fs_fat_audit::{FatAuditLimits, audit_fat},
        fs_fat_builder::{FatBuildOptions, FatTreeMetadataPolicy},
        storage::FileStorage,
    };
    use std::process::Command;
    let directory = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_OPTICAL_TREE_EVIDENCE")
            .expect("set fresh native gate evidence path"),
    );
    std::fs::create_dir(&directory).unwrap();
    let mut receipt = String::new();
    receipt.push_str(&format!("libmkiso={}\nprofile=native-optical-topology-to-fat-v1\nmetadata=content-only deterministic-defaults\nsource_stability=caller-guaranteed\ncapture_host_extraction=false\n",libmkiso::VERSION));
    for (tool, flag) in [
        ("rustc", "--version"),
        ("cargo", "--version"),
        ("mcopy", "-V"),
        ("fsck.fat", "--help"),
    ] {
        let output = Command::new(tool).arg(flag).output().unwrap();
        receipt.push_str(&format!(
            "version_command={tool} {flag} exit={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let test_binary = std::env::current_exe().unwrap();
    let output = Command::new("sha256sum")
        .args([
            test_binary,
            package.join("Cargo.toml"),
            package.join("Cargo.lock"),
            package.join("src/read.rs"),
            package.join("src/tree.rs"),
            package.join("tests/tree.rs"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    receipt.push_str(&format!(
        "implementation_sha256sum={}\n",
        String::from_utf8_lossy(&output.stdout)
    ));
    let payload: Vec<u8> = (0..131089)
        .map(|i| ((i * 37 + i / 251 + 19) % 256) as u8)
        .collect();
    std::fs::write(directory.join("payload.bin"), &payload).unwrap();
    let mut source_tree = directory.join("fixture-input");
    std::fs::create_dir(&source_tree).unwrap();
    source_tree.push("nested/deep");
    std::fs::create_dir_all(&source_tree).unwrap();
    std::fs::write(source_tree.join("Long payload.bin"), &payload).unwrap();
    std::fs::write(source_tree.join("empty.bin"), []).unwrap();
    for format in ["iso", "udf"] {
        let source = directory.join(format!("source.{format}"));
        if format == "iso" {
            libmkiso::write_iso9660_with_options(
                &directory.join("fixture-input"),
                &source,
                &libmkiso::IsoOptions {
                    filename_policy: libmkiso::FilenamePolicy::Mangle,
                    rock_ridge: true,
                    ..Default::default()
                },
            )
            .unwrap();
        } else {
            let mut image = libmkiso::UdfImage::new();
            image
                .add_bytes("nested/deep/Long payload.bin", payload.clone())
                .unwrap();
            image.add_bytes("nested/deep/empty.bin", vec![]).unwrap();
            image.write(&source, &Default::default()).unwrap();
        }
        let r = resources();
        let source_before = std::fs::read(&source).unwrap();
        let index = if format == "iso" {
            iso(&source, libmkiso::IsoNamespace::RockRidge, &r)
        } else {
            udf(&source, &r)
        };
        let tree = Arc::new(OpticalTreeSource::new(index, &r).unwrap());
        let plan = FatCopyPlan::new(
            tree,
            FatCopyOptions {
                image_bytes: 32 << 20,
                filesystem: FatBuildOptions {
                    family: FatFamily::Fat16,
                    sectors_per_cluster: 1,
                    volume_id: 0x4f505446,
                },
                names: CopyNamePolicy::StrictUtf8,
                metadata: FatTreeMetadataPolicy::DeterministicDefaults,
                limits: CopyLimits {
                    objects: 128,
                    pages: 128,
                    page_entries: 8,
                },
            },
            &r,
        )
        .unwrap();
        let destination = directory.join(format!("{format}-fat16.img"));
        let image = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .unwrap();
        image.set_len(32 << 20).unwrap();
        drop(image);
        let mut storage = FileStorage::open(&destination).unwrap();
        let report = plan.emit(&mut storage, &r).unwrap();
        assert_eq!(report.files, 2);
        drop(storage);
        drop(plan);
        let audit = audit_fat(
            Arc::new(RawDisk::open(&destination).unwrap()),
            FatAuditLimits {
                clusters: 100000,
                entries: 128,
                directory_slots: 4096,
                findings: 100,
            },
            &r,
        )
        .unwrap();
        assert!(audit.namespace_complete());
        assert!(audit.findings().is_empty());
        drop(audit);
        let reader = FatVolume::open(Arc::new(RawDisk::open(&destination).unwrap())).unwrap();
        assert_eq!(reader.geometry().family(), FatFamily::Fat16);
        let before = std::fs::read(&destination).unwrap();
        for (label, argv) in [
            (
                "fsck",
                vec![
                    "fsck.fat".to_owned(),
                    "-n".into(),
                    "-v".into(),
                    destination.display().to_string(),
                ],
            ),
            (
                "extract",
                vec![
                    "mcopy".into(),
                    "-n".into(),
                    "-i".into(),
                    destination.display().to_string(),
                    "::/nested/deep/Long payload.bin".into(),
                    directory
                        .join(format!("{format}-extracted.bin"))
                        .display()
                        .to_string(),
                ],
            ),
            (
                "empty",
                vec![
                    "mcopy".into(),
                    "-n".into(),
                    "-i".into(),
                    destination.display().to_string(),
                    "::/nested/deep/empty.bin".into(),
                    directory
                        .join(format!("{format}-empty.bin"))
                        .display()
                        .to_string(),
                ],
            ),
        ] {
            let result = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
            receipt.push_str(&format!(
                "format={format} step={label} command={argv:?} exit={}\nstdout={}\nstderr={}\n",
                result.status,
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            ));
            std::fs::write(directory.join("receipt.txt"), &receipt).unwrap();
            assert!(result.status.success(), "{receipt}");
        }
        assert_eq!(
            std::fs::read(directory.join(format!("{format}-extracted.bin"))).unwrap(),
            payload
        );
        assert!(
            std::fs::read(directory.join(format!("{format}-empty.bin")))
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read(&source).unwrap(), source_before);
        assert_eq!(std::fs::read(&destination).unwrap(), before);
        let output = Command::new("sha256sum")
            .args([
                source.clone(),
                destination.clone(),
                directory.join("payload.bin"),
                directory.join(format!("{format}-extracted.bin")),
                directory.join(format!("{format}-empty.bin")),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        receipt.push_str(&format!(
            "format={format} artifact_sha256sum={}\n",
            String::from_utf8_lossy(&output.stdout)
        ));
        assert_eq!(r.memory.used(), 0);
        receipt.push_str(&format!("format={format} status=passed native_fsck=passed payload_bytes={} verified_image_bytes={} source_unchanged=true destination_unchanged=true reopened_audit=passed boot=unverified\n",payload.len(),report.verified_bytes));
    }
    receipt.push_str("status=passed\n");
    std::fs::write(directory.join("receipt.txt"), receipt).unwrap();
}
