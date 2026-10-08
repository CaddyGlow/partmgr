#![cfg(feature = "native-writer")]
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_jfs::{JfsReadLimits, JfsVolume},
    fs_jfs_audit::JfsAuditLimits,
    fs_jfs_tree::JfsTreeSource,
};
use partmgr_optical::write::{ByteNames, WriteLimits, WritePolicy, stage_iso, stage_udf};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[path = "../../../tests/fixtures/jfs_clean.rs"]
#[allow(dead_code)]
mod fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}

fn fixture_bytes(valid_name: bool) -> Vec<u8> {
    let mut bytes = fixture::jfs_seed();
    if valid_name {
        let old = [0xa9, 0x03, 0x00, 0xd8, 0x78, 0];
        for at in 0..bytes.len() - 5 {
            if bytes[at..at + 6] == old {
                bytes[at] = b'z';
                bytes[at + 1] = 0;
                bytes[at + 2] = b'b';
                bytes[at + 3] = 0;
            }
        }
    }
    bytes
}
fn tree(valid_name: bool, r: &Resources) -> Arc<JfsTreeSource> {
    inventory(Arc::new(Bytes(fixture_bytes(valid_name))), r)
}
fn inventory(source: Arc<dyn ReadAt>, r: &Resources) -> Arc<JfsTreeSource> {
    let volume = JfsVolume::open(
        source,
        JfsReadLimits {
            blocks: 65536,
            inodes: 512,
            entries: 1024,
            pages: 1024,
            extents: 4096,
            work: 64 * 1024 * 1024,
        },
        r,
    )
    .unwrap();
    Arc::new(
        JfsTreeSource::inventory(
            volume,
            JfsAuditLimits {
                blocks: 65536,
                objects: 1024,
                depth: 32,
                work: 1_000_000,
                findings: 64,
            },
            r,
        )
        .unwrap(),
    )
}
#[test]
fn jfs_optical_capture_rejects_unrepresentable_names_then_streams_sparse_data() {
    capture(None);
}
fn capture(evidence: Option<&std::path::Path>) {
    use partmgr::fs_core::{NativeName, StreamKind, TreeSource};
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let directory = tempfile::tempdir().unwrap();
    let limits = WriteLimits {
        maximum_entries: 32,
        maximum_bytes: 1 << 20,
        maximum_extents: 64,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    };
    let invalid = tree(false, &r);
    for udf in [false, true] {
        let result = if udf {
            stage_udf(
                invalid.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::UdfOptions::default(),
            )
        } else {
            stage_iso(
                invalid.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::IsoOptions::default(),
            )
        };
        assert!(result.is_err());
        drop(result);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    drop(invalid);
    assert_eq!(r.memory.used(), 0);
    let source = tree(true, &r);
    let page = source.directory_page(&source.root(), None, 16, &r).unwrap();
    let name = "zbx";
    let object = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Utf16(name.encode_utf16().collect()))
        .unwrap()
        .object
        .clone();
    drop(page);
    let file = source.open_stream(&object, &StreamKind::Data, &r).unwrap();
    let mut expected = vec![0; 4 * fixture::BLOCK + 7];
    for block in [0, 2] {
        for byte in 0..fixture::BLOCK {
            expected[block * fixture::BLOCK + byte] = (byte * 17 % 251) as u8;
        }
    }
    assert_eq!(file.len(), expected.len() as u64);
    let mut observed = vec![0xaa; expected.len()];
    assert_eq!(file.read_at(0, &mut observed, &r).unwrap(), observed.len());
    assert_eq!(observed, expected);
    drop(file);
    assert!(
        expected[fixture::BLOCK..2 * fixture::BLOCK]
            .iter()
            .all(|v| *v == 0)
    );
    for udf in [false, true] {
        let staged = if udf {
            stage_udf(
                source.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::UdfOptions::default(),
            )
        } else {
            stage_iso(
                source.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::IsoOptions {
                    rock_ridge: true,
                    ..Default::default()
                },
            )
        }
        .unwrap();
        if udf {
            let bytes = std::fs::read(staged.path()).unwrap();
            let reader = libmkiso::UdfReader::open(&bytes, libmkiso::UdfLimits::default()).unwrap();
            let index = reader
                .entries()
                .iter()
                .position(|e| e.name == name)
                .unwrap();
            assert_eq!(reader.read_entry(index, 100_000).unwrap(), expected);
        } else {
            let mut reader = libmkiso::IsoReader::open_with_options(
                std::fs::File::open(staged.path()).unwrap(),
                libmkiso::IsoReadOptions {
                    namespace: libmkiso::IsoNamespace::RockRidge,
                    ..Default::default()
                },
            )
            .unwrap();
            let index = reader
                .index()
                .entries
                .iter()
                .position(|e| e.name == name)
                .unwrap();
            assert_eq!(reader.read_entry(index, 100_000).unwrap(), expected);
        }
        if let Some(evidence) = evidence {
            let label = if udf { "udf" } else { "iso" };
            let image = evidence.join(format!("capture.{label}"));
            std::fs::copy(staged.path(), &image).unwrap();
            for (index, (name, wanted)) in [
                (name, expected.as_slice()),
                ("Alias", expected.as_slice()),
                ("Box/Child", b"nested!".as_slice()),
            ]
            .into_iter()
            .enumerate()
            {
                let extraction_name = if udf {
                    name.to_owned()
                } else {
                    name.to_ascii_uppercase()
                };
                let mut command = if udf {
                    let library = std::env::var_os("PARTMGR_JFS_UDF_LIBRARY")
                        .expect("explicit libudfread library required");
                    let mut c = std::process::Command::new("python3");
                    c.arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../../scripts/udf-native-extract.py"),
                    )
                    .arg(library)
                    .arg(&image)
                    .arg(format!("/{name}"));
                    c
                } else {
                    let mut c = std::process::Command::new(
                        std::env::var_os("PARTMGR_JFS_OPTICAL_EXTRACTOR")
                            .unwrap_or_else(|| "7z".into()),
                    );
                    c.args(["e", "-so"]).arg(&image).arg(&extraction_name);
                    c
                };
                let command_description = format!("{command:?}");
                let image_before = std::fs::read(&image).unwrap();
                let output = command
                    .output()
                    .expect("enabled gate requires independent extractor");
                assert_eq!(std::fs::read(&image).unwrap(), image_before);
                std::fs::write(
                    evidence.join(format!("{label}-{index}.stdout")),
                    &output.stdout,
                )
                .unwrap();
                std::fs::write(
                    evidence.join(format!("{label}-{index}.stderr")),
                    &output.stderr,
                )
                .unwrap();
                std::fs::write(
                    evidence.join(format!("{label}-{index}.command.txt")),
                    format!("command={command_description} status={}\n", output.status),
                )
                .unwrap();
                assert!(
                    output.status.success(),
                    "7z: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    output.stdout == wanted,
                    "independent payload mismatch: observed {} expected {} bytes",
                    output.stdout.len(),
                    wanted.len()
                );
            }
        }
        drop(staged);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    drop(source);
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "explicit 7z/libudfread extraction requires fresh PARTMGR_JFS_OPTICAL_EVIDENCE"]
fn native_jfs_iso_udf_independent_payload_extraction() {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_JFS_OPTICAL_EVIDENCE")
            .expect("fresh evidence directory required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let extractor =
        std::env::var_os("PARTMGR_JFS_OPTICAL_EXTRACTOR").unwrap_or_else(|| "7z".into());
    let tool = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join(&extractor))
        .find(|p| p.is_file())
        .expect("7z required");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        std::fs::read(manifest.join("tests/jfs_capture.rs")).unwrap(),
        include_bytes!("jfs_capture.rs")
    );
    let hash = |p: &std::path::Path| {
        let out = Command::new("sha256sum")
            .arg(p)
            .output()
            .expect("sha256sum required");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let mut paths = vec![
        tool,
        std::env::current_exe().unwrap(),
        manifest.join("tests/jfs_capture.rs"),
        manifest.join("Cargo.lock"),
    ];
    for name in [
        "src/fs_jfs.rs",
        "src/fs_jfs_audit.rs",
        "src/fs_jfs_tree.rs",
        "tests/fixtures/jfs_clean.rs",
    ] {
        paths.push(manifest.join("../..").join(name));
    }
    paths.push(PathBuf::from(
        std::env::var_os("PARTMGR_JFS_UDF_LIBRARY").expect("explicit libudfread library required"),
    ));
    paths.push(manifest.join("../../scripts/udf-native-extract.py"));
    assert_eq!(
        std::fs::read(manifest.join("../../scripts/udf-native-extract.py")).unwrap(),
        include_bytes!("../../../scripts/udf-native-extract.py")
    );
    paths.push(
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("python3"))
            .find(|p| p.is_file())
            .expect("python3 required"),
    );
    let before: Vec<_> = paths.iter().map(|p| hash(p)).collect();
    let version = Command::new(&extractor)
        .arg("i")
        .output()
        .expect("7z required");
    assert!(version.status.success());
    std::fs::write(root.join("7z-version.stdout"), version.stdout).unwrap();
    capture(Some(&root));
    for (path, h) in paths.iter().zip(&before) {
        assert_eq!(&hash(path), h);
    }
    let mut receipt = String::from(
        "profile=JFS-independent-fixture-to-ISO-UDF-content-only\nscope=independent optical payload extraction; not native JFS extraction, metadata preservation or firmware\n",
    );
    for h in before {
        receipt.push_str(&h);
    }
    for name in ["capture.iso", "capture.udf"] {
        receipt.push_str(&hash(&root.join(name)));
    }
    receipt.push_str("status=passed\nindependent_payloads=match\nsource_tool_executable_end_revalidation=passed\n");
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}

struct PayloadFault(Vec<u8>);
impl ReadAt for PayloadFault {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if at < (101 * fixture::BLOCK) as u64 && end > (100 * fixture::BLOCK) as u64 {
            return Err(io::Error::other("injected deferred JFS payload failure"));
        }
        let start = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.0
                .get(start..usize::try_from(end).map_err(io::Error::other)?)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
#[test]
fn deferred_jfs_payload_failure_cleans_both_optical_stages_and_refunds() {
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let source = inventory(Arc::new(PayloadFault(fixture_bytes(true))), &r);
    let baseline = r.memory.used();
    let directory = tempfile::tempdir().unwrap();
    let limits = WriteLimits {
        maximum_entries: 32,
        maximum_bytes: 1 << 20,
        maximum_extents: 64,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    };
    for udf in [false, true] {
        let result = if udf {
            stage_udf(
                source.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::UdfOptions::default(),
            )
        } else {
            stage_iso(
                source.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::IsoOptions {
                    rock_ridge: true,
                    ..Default::default()
                },
            )
        };
        let error = match result {
            Ok(_) => panic!("deferred source failure must abort staging"),
            Err(e) => e,
        };
        assert!(
            format!("{error:#}").contains("injected deferred JFS payload failure"),
            "{error:#}"
        );
        drop(error);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_eq!(r.memory.used(), baseline);
    }
    drop(source);
    assert_eq!(r.memory.used(), 0);
}
