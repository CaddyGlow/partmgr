#![cfg(feature = "native-writer")]
use partmgr::{
    fs_core::{Budget, Cancellation, MetadataField, NativeName, Resources, TreeSource},
    fs_ext::ExtVolume,
    fs_ext_tree::ExtTreeSource,
};
use partmgr_optical::write::{ByteNames, WriteLimits, WritePolicy, stage_iso, stage_udf};
use std::{ffi::OsStr, io, path::Path, process::Command, sync::Arc};
use virtdisk::RawDisk;
fn available(program: &str) -> bool {
    match Command::new(program).arg("-V").output() {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => panic!("cannot inspect {program}: {error}"),
    }
}
fn run(program: &str, args: &[&OsStr], receipt: &mut String) -> std::process::Output {
    let mut command = Command::new(program);
    command.args(args);
    receipt.push_str(&format!("command={command:?}\n"));
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"));
    receipt.push_str(&format!(
        "exit={}\nstdout={}\nstderr={}\n",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(output.status.success(), "{receipt}");
    output
}
fn limits() -> WriteLimits {
    WriteLimits {
        maximum_entries: 64,
        maximum_bytes: 256 * 1024,
        maximum_extents: 1024,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    }
}
fn oracle(
    seven: &str,
    image: &Path,
    directory: &Path,
    payload: &[u8],
    expected_sha256: &str,
    receipt: &mut String,
) {
    let target = format!("-o{}", directory.display());
    run(
        seven,
        &[
            OsStr::new("x"),
            OsStr::new("-y"),
            OsStr::new(&target),
            image.as_os_str(),
        ],
        receipt,
    );
    for path in ["nested/payload.bin", "alias.bin"] {
        let extracted = directory.join(path);
        assert_eq!(std::fs::read(&extracted).unwrap(), payload);
        assert_eq!(sha256(&extracted, receipt), expected_sha256);
    }
    receipt.push_str("independent_payload_oracle=passed both hard-linked namespace paths\n");
}
#[test]
#[ignore = "explicit native gate requires e2fsprogs, sha256sum and 7z/7zz"]
fn native_ext2_tree_to_staged_iso_and_udf_without_host_tree_extraction() {
    for tool in ["mke2fs", "debugfs", "e2fsck", "sha256sum"] {
        assert!(
            available(tool),
            "enabled ext2 optical native gate requires {tool}"
        );
    }
    let evidence = std::env::var_os("PARTMGR_EXT_OPTICAL_EVIDENCE").map(std::path::PathBuf::from);
    let temp = if let Some(directory) = &evidence {
        std::fs::create_dir_all(directory).unwrap();
        tempfile::Builder::new()
            .prefix("ext-optical-")
            .tempdir_in(directory)
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let mut receipt = format!(
        "profile=ext2-optical-content-only-v1\nlibmkiso_version={}\nsource=classic ext2 direct RawDisk/ExtVolume/ExtTreeSource\nmetadata_policy=ContentOnly\npayload_bytes=262161\nstatus=running\n",
        libmkiso::VERSION
    );
    // e2fsprogs version commands use stderr and may exit nonzero; retain exact outputs.
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        let output = Command::new(tool).arg("-V").output().unwrap();
        receipt.push_str(&format!(
            "version_command={tool} -V exit={} stdout={} stderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let seven = if available("7z") {
        Some("7z")
    } else if available("7zz") {
        Some("7zz")
    } else {
        panic!("enabled ext2 optical native gate requires 7z or 7zz")
    };
    if let Some(seven) = seven {
        run(seven, &[OsStr::new("i")], &mut receipt);
    } else {
        receipt.push_str("native_optical_oracle=skipped 7z/7zz executable missing\n");
    }
    run("sha256sum", &[OsStr::new("--version")], &mut receipt);
    for tool in ["mke2fs", "debugfs", "e2fsck", "sha256sum", seven.unwrap()] {
        let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join(tool))
            .find(|path| path.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        receipt.push_str(&format!("tool_path={tool}: {}\n", executable.display()));
        sha256(&executable, &mut receipt);
    }
    let image = temp.path().join("source.ext2");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    run(
        "mke2fs",
        &[
            OsStr::new("-q"),
            OsStr::new("-F"),
            OsStr::new("-t"),
            OsStr::new("ext2"),
            OsStr::new("-O"),
            OsStr::new("none"),
            OsStr::new("-I"),
            OsStr::new("128"),
            image.as_os_str(),
        ],
        &mut receipt,
    );
    let payload: Vec<_> = (0..262161)
        .map(|i| ((i * 43 + i / 17 + 11) % 251) as u8)
        .collect();
    let payload_path = temp.path().join("independent-payload.bin");
    std::fs::write(&payload_path, &payload).unwrap();
    let commands = temp.path().join("debugfs.commands");
    std::fs::write(&commands,format!("mkdir /nested\nwrite {} /nested/payload.bin\nlink /nested/payload.bin /alias.bin\nset_inode_field /nested/payload.bin links_count 2\nset_inode_field /nested/payload.bin mode 0100640\nset_inode_field /nested/payload.bin uid 123\nset_inode_field /nested/payload.bin gid 456\nset_inode_field /nested/payload.bin mtime 1000000000\n",payload_path.display())).unwrap();
    run(
        "debugfs",
        &[
            OsStr::new("-w"),
            OsStr::new("-f"),
            commands.as_os_str(),
            image.as_os_str(),
        ],
        &mut receipt,
    );
    run(
        "e2fsck",
        &[OsStr::new("-fn"), image.as_os_str()],
        &mut receipt,
    );
    let stat = run(
        "debugfs",
        &[
            OsStr::new("-R"),
            OsStr::new("stat /nested/payload.bin"),
            image.as_os_str(),
        ],
        &mut receipt,
    );
    let stat = std::str::from_utf8(&stat.stdout).unwrap();
    let words: Vec<_> = stat.split_whitespace().collect();
    for (field, expected) in [("User:", "123"), ("Group:", "456"), ("Links:", "2")] {
        let index = words.iter().position(|word| *word == field).unwrap();
        assert_eq!(words[index + 1], expected);
    }
    let before = sha256(&image, &mut receipt);
    let expected_sha256 = sha256(&payload_path, &mut receipt);
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "Cargo.toml",
        "src/lib.rs",
        "src/read.rs",
        "src/write.rs",
        "tests/ext_capture.rs",
    ] {
        sha256(&manifest.join(path), &mut receipt);
    }
    let repository = manifest.parent().unwrap().parent().unwrap();
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "src/lib.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/fs_ext.rs",
        "src/fs_ext_tree.rs",
    ] {
        sha256(&repository.join(path), &mut receipt);
    }
    sha256(&std::env::current_exe().unwrap(), &mut receipt);
    let resources = Resources {
        memory: Budget::new(8 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let volume = ExtVolume::open(Arc::new(RawDisk::open(&image).unwrap()), &resources).unwrap();
    let tree = Arc::new(ExtTreeSource::inventory(volume, 64, 64, 1024, 256, &resources).unwrap());
    let root = tree
        .directory_page(&tree.root(), None, 64, &resources)
        .unwrap();
    let original_parent = root
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
        .unwrap();
    let alias = root
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias.bin".to_vec()))
        .unwrap();
    let nested = tree
        .directory_page(&original_parent.object, None, 64, &resources)
        .unwrap();
    let original = nested
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload.bin".to_vec()))
        .unwrap();
    assert_eq!(original.object, alias.object);
    let metadata = tree.metadata(&original.object, &resources).unwrap();
    assert_eq!(metadata.mode, MetadataField::Known(0o100640));
    assert_eq!(
        metadata.owner,
        MetadataField::Known([123u32.to_le_bytes(), 456u32.to_le_bytes()].concat())
    );
    assert!(matches!(metadata.modified, MetadataField::Opaque { .. }));
    drop(metadata);
    drop(nested);
    drop(root);
    let baseline = resources.memory.used();
    let iso_options = libmkiso::IsoOptions {
        rock_ridge: true,
        joliet: true,
        filename_policy: libmkiso::FilenamePolicy::Mangle,
        max_entries: 64,
        max_metadata_bytes: 512 * 1024,
        ..Default::default()
    };
    // Metadata fidelity is refused before authoring any staged output.
    let count_before = std::fs::read_dir(temp.path()).unwrap().count();
    assert!(
        stage_iso(
            tree.clone(),
            resources.clone(),
            limits(),
            WritePolicy::RequireMetadata,
            temp.path(),
            &iso_options
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read_dir(temp.path()).unwrap().count(),
        count_before
    );
    assert_eq!(resources.memory.used(), baseline);
    let staged = stage_iso(
        tree.clone(),
        resources.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &iso_options,
    )
    .unwrap();
    assert_eq!(staged.report().files, 1);
    assert_eq!(staged.report().metadata_objects, 5);
    assert!(staged.report().known_metadata_fields >= 15);
    assert_eq!(staged.report().uninspectable_metadata_fields, 0);
    assert!(staged.report().opaque_metadata_fields >= 20);
    let iso_sha256 = sha256(staged.path(), &mut receipt);
    let reader = libmkiso::IsoReader::open_with_options(
        std::fs::File::open(staged.path()).unwrap(),
        libmkiso::IsoReadOptions {
            namespace: libmkiso::IsoNamespace::RockRidge,
            ..Default::default()
        },
    )
    .unwrap();
    let original = reader
        .entries()
        .iter()
        .position(|e| e.name == "nested/payload.bin")
        .unwrap();
    let alias = reader
        .entries()
        .iter()
        .position(|e| e.name == "alias.bin")
        .unwrap();
    assert_eq!(
        reader.index().extents[original],
        reader.index().extents[alias]
    );
    let unix = reader.entries()[original].unix.as_ref().unwrap();
    assert_eq!(unix.mode, 0o100644);
    assert_eq!((unix.uid, unix.gid), (0, 0));
    assert_eq!(unix.links, 2);
    receipt.push_str(&format!("iso_report={:?}\niso_hardlink_extents_shared=true input_mode=0100640 output_mode=0100644 output_uid=0 output_gid=0\n",staged.report()));
    if let Some(seven) = seven {
        oracle(
            seven,
            staged.path(),
            &temp.path().join("oracle-iso"),
            &payload,
            &expected_sha256,
            &mut receipt,
        );
    }
    assert_eq!(sha256(staged.path(), &mut receipt), iso_sha256);
    if evidence.is_some() {
        std::fs::copy(staged.path(), temp.path().join("artifact.iso")).unwrap();
    }
    let path = staged.path().to_path_buf();
    drop(reader);
    drop(staged);
    assert!(!path.exists());
    assert_eq!(resources.memory.used(), baseline);
    let udf_options = libmkiso::UdfOptions {
        max_entries: 64,
        max_metadata_bytes: 512 * 1024,
        ..Default::default()
    };
    let staged = stage_udf(
        tree.clone(),
        resources.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &udf_options,
    )
    .unwrap();
    assert_eq!(staged.report().files, 1);
    assert_eq!(staged.report().metadata_objects, 5);
    assert!(staged.report().known_metadata_fields >= 15);
    assert_eq!(staged.report().uninspectable_metadata_fields, 0);
    assert!(staged.report().opaque_metadata_fields >= 20);
    let udf_sha256 = sha256(staged.path(), &mut receipt);
    let source = partmgr_optical::read::SourceAdapter::new(
        Arc::new(RawDisk::open(staged.path()).unwrap()),
        resources.clone(),
        16 * 1024 * 1024,
    );
    let reader = libmkiso::UdfReader::open_source(source, libmkiso::UdfLimits::default()).unwrap();
    let original = reader
        .entries()
        .iter()
        .position(|e| e.name == "nested/payload.bin")
        .unwrap();
    let alias = reader
        .entries()
        .iter()
        .position(|e| e.name == "alias.bin")
        .unwrap();
    assert_eq!(reader.entries()[original].icb, reader.entries()[alias].icb);
    let metadata = reader.metadata(original).unwrap();
    assert_eq!(
        metadata.ownership,
        libmkiso::preservation::Field::Present((u32::MAX, u32::MAX))
    );
    assert_eq!(
        metadata.permissions,
        libmkiso::preservation::Field::Present(0x14a5)
    );
    for entry in [original, alias] {
        let mut out = [0; 4096];
        let count = reader.read_at(entry, 260000, &mut out).unwrap();
        assert_eq!(&out[..count], &payload[260000..]);
    }
    receipt.push_str(&format!("udf_report={:?}\nudf_hardlink_icb_shared=true output_uid=4294967295 output_gid=4294967295 output_permissions=0x14a5\n",staged.report()));
    if let Some(seven) = seven {
        oracle(
            seven,
            staged.path(),
            &temp.path().join("oracle-udf"),
            &payload,
            &expected_sha256,
            &mut receipt,
        );
    }
    assert_eq!(sha256(staged.path(), &mut receipt), udf_sha256);
    if evidence.is_some() {
        std::fs::copy(staged.path(), temp.path().join("artifact.udf")).unwrap();
    }
    let path = staged.path().to_path_buf();
    drop(reader);
    drop(staged);
    assert!(!path.exists());
    assert_eq!(resources.memory.used(), baseline);
    drop(tree);
    assert_eq!(resources.memory.used(), 0);
    run(
        "e2fsck",
        &[OsStr::new("-fn"), image.as_os_str()],
        &mut receipt,
    );
    assert_eq!(sha256(&image, &mut receipt), before);
    receipt.push_str("source_sha256_unchanged=true\n");
    receipt.push_str("status=passed\n");
    if let Some(directory) = evidence {
        let retained = temp.keep();
        std::fs::write(
            directory.join("ext2-optical-content-only-v1.txt"),
            format!("artifact_directory={}\n{receipt}", retained.display()),
        )
        .unwrap();
    }
    eprintln!(
        "PASSED ext2-optical-content-only-v1: direct ext2 tree -> staged ISO/UDF, hard links and explicit metadata transformation, independent oracle available={}",
        seven.is_some()
    );
}

fn sha256(path: &Path, receipt: &mut String) -> String {
    let output = run("sha256sum", &[path.as_os_str()], receipt);
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let digest = text.split_whitespace().next().unwrap();
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    digest.to_owned()
}
