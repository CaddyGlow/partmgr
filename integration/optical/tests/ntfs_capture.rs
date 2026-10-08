#![cfg(feature = "native-writer")]
use partmgr::{
    fs_core::{Budget, Cancellation, NativeName, Resources, StreamKind, TreeSource},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
    fs_ntfs_tree::{NtfsTreePolicy, NtfsTreeSource},
};
use partmgr_optical::write::{ByteNames, WriteLimits, WritePolicy, stage_iso, stage_udf};
use std::{ffi::OsStr, fs, path::Path, process::Command, sync::Arc};
use virtdisk::RawDisk;
fn run(tool: &str, args: &[&OsStr], directory: &Path, receipt: &mut String) -> Vec<u8> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("required {tool}: {e}"));
    let n = receipt.matches("command=").count();
    fs::write(
        directory.join(format!("{n:03}-{tool}.stdout")),
        &output.stdout,
    )
    .unwrap();
    fs::write(
        directory.join(format!("{n:03}-{tool}.stderr")),
        &output.stderr,
    )
    .unwrap();
    receipt.push_str(&format!(
        "command={tool} {args:?} status={}\n",
        output.status
    ));
    fs::write(directory.join("receipt.txt"), &*receipt).unwrap();
    assert!(
        output.status.success(),
        "{tool}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn hash(path: &Path, directory: &Path, receipt: &mut String) -> String {
    let output = run("sha256sum", &[path.as_os_str()], directory, receipt);
    let value = std::str::from_utf8(&output)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    receipt.push_str(&format!("file={} sha256={value}\n", path.display()));
    value
}
#[test]
#[ignore = "explicit NTFS optical capture gate requires native NTFS/TSK/7z and evidence directory"]
fn native_ntfs_user_namespace_to_iso_and_udf() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_OPTICAL_EVIDENCE")
            .expect("fresh evidence directory required"),
    );
    fs::create_dir(&directory).unwrap();
    let mut receipt = format!(
        "profile=NTFS3.1-clean-user-namespace-optical-content-only-v1\nlibmkiso={}\nnamespace_policy=explicit UserNamespace\nmetadata_policy=ContentOnly\ncapture_host_extraction=false\nsource_stability=caller-guaranteed-held-image\n",
        libmkiso::VERSION
    );
    let seven = if Command::new("7z").arg("i").output().is_ok() {
        "7z"
    } else {
        "7zz"
    };
    for (tool, version) in [
        ("mkntfs", "--version"),
        ("ntfscp", "--version"),
        ("fls", "-V"),
        ("icat", "-V"),
        ("sha256sum", "--version"),
        (seven, "i"),
        ("uname", "-a"),
    ] {
        run(tool, &[OsStr::new(version)], &directory, &mut receipt);
        let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("required binary");
        hash(&binary, &directory, &mut receipt);
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for path in [
        "src/fs_ntfs.rs",
        "src/fs_ntfs_tree.rs",
        "integration/optical/src/write.rs",
        "integration/optical/tests/ntfs_capture.rs",
        "integration/optical/Cargo.lock",
    ] {
        hash(&repository.join(path), &directory, &mut receipt);
    }
    hash(&std::env::current_exe().unwrap(), &directory, &mut receipt);
    let image = directory.join("source.ntfs");
    fs::File::create(&image).unwrap().set_len(64 << 20).unwrap();
    run(
        "mkntfs",
        &[OsStr::new("-F"), OsStr::new("-Q"), image.as_os_str()],
        &directory,
        &mut receipt,
    );
    let payload: Vec<_> = (0..131089)
        .map(|i| ((i * 43 + i / 17 + 11) % 251) as u8)
        .collect();
    let host = directory.join("expected-payload.bin");
    fs::write(&host, &payload).unwrap();
    for i in 0..32 {
        let name = format!("/file-{i:03}.bin");
        run(
            "ntfscp",
            &[image.as_os_str(), host.as_os_str(), OsStr::new(&name)],
            &directory,
            &mut receipt,
        );
    }
    let before = hash(&image, &directory, &mut receipt);
    let payload_hash = hash(&host, &directory, &mut receipt);
    let listing = String::from_utf8(run(
        "fls",
        &[OsStr::new("-f"), OsStr::new("ntfs"), image.as_os_str()],
        &directory,
        &mut receipt,
    ))
    .unwrap();
    let resources = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = NtfsReadLimits {
        attributes: 64,
        runs: 256,
        names: 16,
    };
    let indexes = NtfsDirectoryLimits {
        blocks: 64,
        entries: 128,
        depth: 16,
    };
    let disk = Arc::new(RawDisk::open(&image).unwrap());
    assert!(
        NtfsTreeSource::inventory(
            NtfsVolume::open(disk.clone(), limits, &resources).unwrap(),
            128,
            16,
            indexes,
            &resources
        )
        .is_err()
    );
    let tree = Arc::new(
        NtfsTreeSource::inventory_with_policy(
            NtfsVolume::open(disk, limits, &resources).unwrap(),
            128,
            16,
            indexes,
            NtfsTreePolicy::UserNamespace,
            &resources,
        )
        .unwrap(),
    );
    for e in tree.excluded_entries() {
        receipt.push_str(&format!(
            "excluded_name={:?} namespace={} identity={:?}\n",
            e.name, e.namespace, e.identity
        ));
    }
    assert!(!tree.excluded_entries().is_empty());
    let page = tree
        .directory_page(&tree.root(), None, 128, &resources)
        .unwrap();
    assert_eq!(page.entries.len(), 32);
    for entry in &page.entries {
        let NativeName::Utf16(units) = &entry.name else {
            panic!("native name")
        };
        let name = String::from_utf16(units).unwrap();
        let line = listing
            .lines()
            .find(|s| s.ends_with(&format!(":\t{name}")))
            .unwrap();
        let reference = line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        assert_eq!(
            u64::from_le_bytes(entry.object.native.as_slice().try_into().unwrap()),
            reference.split('-').next().unwrap().parse::<u64>().unwrap()
        );
        if name == "file-000.bin" {
            let oracle = run(
                "icat",
                &[image.as_os_str(), OsStr::new(reference)],
                &directory,
                &mut receipt,
            );
            assert_eq!(oracle, payload);
            let stream = tree
                .open_stream(&entry.object, &StreamKind::Data, &resources)
                .unwrap();
            let mut bytes = vec![0; payload.len()];
            assert_eq!(
                stream.read_at(0, &mut bytes, &resources).unwrap(),
                payload.len()
            );
            assert_eq!(bytes, payload);
        }
    }
    let write_limits = WriteLimits {
        maximum_entries: 128,
        maximum_bytes: 2 << 20,
        maximum_extents: 4096,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    };
    let iso_options = libmkiso::IsoOptions {
        rock_ridge: true,
        joliet: true,
        filename_policy: libmkiso::FilenamePolicy::Mangle,
        max_entries: 128,
        max_metadata_bytes: 2 << 20,
        ..Default::default()
    };
    let count = fs::read_dir(&directory).unwrap().count();
    assert!(
        stage_iso(
            tree.clone(),
            resources.clone(),
            write_limits.clone(),
            WritePolicy::RequireMetadata,
            &directory,
            &iso_options
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(&directory).unwrap().count(), count);
    receipt.push_str(
        "RequireMetadata=rejected_before_staging (uninspectable metadata and explicit omissions)\n",
    );
    let iso = stage_iso(
        tree.clone(),
        resources.clone(),
        write_limits.clone(),
        WritePolicy::ContentOnly,
        &directory,
        &iso_options,
    )
    .unwrap();
    assert_eq!(iso.report().files, 32);
    assert!(iso.report().opaque_metadata_fields >= 33);
    receipt.push_str(&format!("ISO_ContentOnly_report={:?}\n", iso.report()));
    let retained_iso = directory.join("captured.iso");
    fs::copy(iso.path(), &retained_iso).unwrap();
    drop(iso);
    let udf = stage_udf(
        tree,
        resources.clone(),
        write_limits,
        WritePolicy::ContentOnly,
        &directory,
        &libmkiso::UdfOptions {
            max_entries: 128,
            max_metadata_bytes: 2 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(udf.report().files, 32);
    assert!(udf.report().opaque_metadata_fields >= 33);
    receipt.push_str(&format!("UDF_ContentOnly_report={:?}\n", udf.report()));
    let retained_udf = directory.join("captured.udf");
    fs::copy(udf.path(), &retained_udf).unwrap();
    drop(udf);
    for (image, label) in [(&retained_iso, "iso"), (&retained_udf, "udf")] {
        let before = hash(image, &directory, &mut receipt);
        let extracted = directory.join(format!("validation-{label}"));
        let target = format!("-o{}", extracted.display());
        run(
            seven,
            &[
                OsStr::new("x"),
                OsStr::new("-y"),
                OsStr::new(&target),
                image.as_os_str(),
            ],
            &directory,
            &mut receipt,
        );
        for i in 0..32 {
            let file = extracted.join(format!("file-{i:03}.bin"));
            assert_eq!(fs::read(&file).unwrap(), payload);
            assert_eq!(hash(&file, &directory, &mut receipt), payload_hash);
        }
        assert_eq!(hash(image, &directory, &mut receipt), before);
    }
    assert_eq!(hash(&image, &directory, &mut receipt), before);
    drop(page);
    assert_eq!(resources.memory.used(), 0);
    receipt.push_str("native_hardlink_authoring=not_available; independent index fixtures cover shared identity\nstatus=passed\n");
    fs::write(directory.join("receipt.txt"), receipt).unwrap();
}
