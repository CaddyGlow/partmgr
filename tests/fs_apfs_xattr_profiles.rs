//! Independent candidate graphs distinguish unsupported profiles from allocation corruption.
use partmgr::{fs_apfs::*, fs_core::*};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[path = "fixtures/apfs_resource.rs"]
mod resource_fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.0
                .get(start..start + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}

fn raw(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn candidate_records(
    shared_id: bool,
    reference_record: bool,
) -> (fixture::Records, fixture::Records) {
    let (mut catalog, mut extents) = resource_fixture::records(true, 0);
    if shared_id {
        for (key, value) in &mut catalog {
            if raw(key, 0) == (4u64 << 60 | 21) {
                fixture::p64(value, 4, 24);
            }
        }
        catalog.retain(|record| raw(&record.0, 0) != (8u64 << 60 | 25));
        fixture::p32(&mut extents.last_mut().unwrap().1, 16, 1);
        if reference_record {
            catalog.push((
                (6u64 << 60 | 24).to_le_bytes().to_vec(),
                2u32.to_le_bytes().to_vec(),
            ));
        }
    } else {
        for (key, value) in &mut catalog {
            if raw(key, 0) == (4u64 << 60 | 16) {
                fixture::p64(value, 20, 0);
            }
            if raw(key, 0) == (8u64 << 60 | 24) {
                fixture::p64(value, 8, 0);
            }
        }
        let value = &mut extents.last_mut().unwrap().1;
        fixture::p64(value, 8, 21);
        fixture::p32(value, 16, 1);
    }
    catalog.sort_by(|a, b| {
        let x = raw(&a.0, 0);
        let y = raw(&b.0, 0);
        (x & 0x0fff_ffff_ffff_ffff)
            .cmp(&(y & 0x0fff_ffff_ffff_ffff))
            .then((x >> 60).cmp(&(y >> 60)))
            .then_with(|| match x >> 60 {
                4 | 9 => a.0[10..].cmp(&b.0[10..]),
                5 | 8 => raw(&a.0, 8).cmp(&raw(&b.0, 8)),
                _ => a.0[8..].cmp(&b.0[8..]),
            })
    });
    (catalog, extents)
}
fn candidate(shared_id: bool, reference_record: bool) -> Vec<u8> {
    let mut image = resource_fixture::generic_seed(true, 0);
    let (catalog, extents) = candidate_records(shared_id, reference_record);
    // Both aliases/resources are exact native ResourceFork names here.
    // Retain independently authored inode flags from that graph too.
    image[22 * 4096..23 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &catalog, false));
    image[23 * 4096..24 * 4096]
        .copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &extents, false));
    image
}
#[test]
fn sparse_and_shared_id_candidates_are_explicitly_gated_without_free_proof() {
    for (shared_id, refs) in [(false, false), (true, false), (true, true)] {
        let r = Resources {
            memory: Budget::new(64 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let c = ApfsContainer::open(
            Arc::new(Bytes(candidate(shared_id, refs))),
            ApfsReadLimits {
                blocks: 512,
                checkpoint_blocks: 256,
                objects: 256,
                records: 256,
                work: 8 * 1024 * 1024,
            },
            &r,
        )
        .unwrap();
        let error = match ApfsVolume::open(c, 1026, &r) {
            Ok(_) => panic!("unsupported candidate published"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported, "{error:?}");
        assert!(
            error.context.contains("resource") || error.context.contains("xattr"),
            "{error:?}"
        );
        assert_eq!(r.memory.used(), 0);
    }
}

const PROFILE_SOURCES: &[(&str, &[u8])] = &[
    (
        "src/fs_apfs_tree.rs",
        include_bytes!("../src/fs_apfs_tree.rs"),
    ),
    (
        "tests/fixtures/apfs_resource.rs",
        include_bytes!("../tests/fixtures/apfs_resource.rs"),
    ),
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
    ("src/lib.rs", include_bytes!("../src/lib.rs")),
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
    ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
    (
        "src/fs_apfs_retention.rs",
        include_bytes!("../src/fs_apfs_retention.rs"),
    ),
    (
        "src/fs_apfs_edit_retention.rs",
        include_bytes!("../src/fs_apfs_edit_retention.rs"),
    ),
    (
        "src/fs_apfs_edit_reclaim.rs",
        include_bytes!("../src/fs_apfs_edit_reclaim.rs"),
    ),
    (
        "src/fs_apfs_edit_tree.rs",
        include_bytes!("../src/fs_apfs_edit_tree.rs"),
    ),
    ("src/storage.rs", include_bytes!("../src/storage.rs")),
    ("src/fs_apfs.rs", include_bytes!("../src/fs_apfs.rs")),
    (
        "src/fs_apfs_index.rs",
        include_bytes!("../src/fs_apfs_index.rs"),
    ),
    (
        "src/fs_apfs_audit.rs",
        include_bytes!("../src/fs_apfs_audit.rs"),
    ),
    (
        "src/fs_apfs_edit.rs",
        include_bytes!("../src/fs_apfs_edit.rs"),
    ),
    (
        "src/fs_apfs_edit_cow.rs",
        include_bytes!("../src/fs_apfs_edit_cow.rs"),
    ),
    (
        "src/fs_apfs_edit_disk.rs",
        include_bytes!("../src/fs_apfs_edit_disk.rs"),
    ),
    (
        "src/fs_apfs_edit_namespace.rs",
        include_bytes!("../src/fs_apfs_edit_namespace.rs"),
    ),
    (
        "tests/fixtures/apfs_clean.rs",
        include_bytes!("../tests/fixtures/apfs_clean.rs"),
    ),
    (
        "tests/fs_apfs_edit_namespace.rs",
        include_bytes!("../tests/fs_apfs_edit_namespace.rs"),
    ),
    (
        "tests/fs_apfs_xattr_profiles.rs",
        include_bytes!("../tests/fs_apfs_xattr_profiles.rs"),
    ),
];

fn digest(bytes: &[u8]) -> String {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut command = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    command.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = command.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}
#[test]
#[ignore = "requires explicit checked native resource source and fresh profile-oracle evidence directory"]
fn native_sparse_shared_id_checker_limits_are_not_native_legality_claims() {
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_XATTR_PROFILE_EVIDENCE")
            .expect("enabled gate requires evidence directory"),
    );
    fs::create_dir(&out).unwrap();
    let source = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_XATTR_PROFILE_SOURCE")
            .expect("enabled gate requires independently checked native resource source"),
    );
    let checker =
        PathBuf::from("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck");
    let tool = fs::read(&checker).unwrap();
    let baseline = fs::read(&source).unwrap();
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("compiled-test"), &executable).unwrap();
    fs::write(out.join("binary.sha256"), digest(&executable)).unwrap();
    fs::write(
        out.join("tool-start.sha256"),
        format!("{} {}\n", checker.display(), digest(&tool)),
    )
    .unwrap();
    fs::write(out.join("input-provenance.txt"), format!("{} {}\nconstruction=independent raw ResourceFork records with complete native formatter geometry; candidates do not prove macOS legality\n",source.display(),digest(&baseline))).unwrap();
    let mut hashes = String::new();
    for (name, bytes) in PROFILE_SOURCES {
        let actual = fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap();
        assert_eq!(actual, *bytes);
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        hashes.push_str(&format!("{name} {}\n", digest(bytes)));
    }
    fs::write(out.join("source-start.sha256"), &hashes).unwrap();
    let mut commands = format!(
        "{} [\"-c\",\"-u\",\"-w\",{:?}]\n",
        checker.display(),
        source
    );
    let initial = Command::new(&checker)
        .args(["-c", "-u", "-w"])
        .arg(&source)
        .output()
        .unwrap();
    fs::write(out.join("baseline.stdout"), &initial.stdout).unwrap();
    fs::write(out.join("baseline.stderr"), &initial.stderr).unwrap();
    fs::write(
        out.join("baseline.status"),
        format!("{:?}\n", initial.status.code()),
    )
    .unwrap();
    assert!(initial.status.success() && initial.stdout.is_empty());
    for (index, (shared_id, refs)) in [(false, false), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let (mut catalog, mut extents) = candidate_records(shared_id, refs);
        for (key, value) in &mut catalog {
            if raw(key, 0) >> 60 == 8 && raw(value, 8) != 0 {
                let physical = raw(value, 8);
                fixture::p64(value, 8, physical + 200);
            }
        }
        for (key, _) in &mut extents {
            let physical = raw(key, 0) & 0x0fff_ffff_ffff_ffff;
            fixture::p64(key, 0, 2u64 << 60 | (physical + 200));
        }
        let mut image = baseline.clone();
        image[174 * 4096..175 * 4096]
            .copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &catalog, false));
        image[175 * 4096..176 * 4096]
            .copy_from_slice(&fixture::leaf(175, 1, 0x40000000, 15, &extents, false));
        let path = out.join(format!("candidate-{index}.img"));
        fs::write(&path, &image).unwrap();
        commands.push_str(&format!(
            "{} [\"-c\",\"-u\",\"-w\",{:?}]\n",
            checker.display(),
            path
        ));
        let result = Command::new(&checker)
            .args(["-c", "-u", "-w"])
            .arg(&path)
            .output()
            .unwrap();
        fs::write(
            out.join(format!("candidate-{index}.stdout")),
            &result.stdout,
        )
        .unwrap();
        fs::write(
            out.join(format!("candidate-{index}.stderr")),
            &result.stderr,
        )
        .unwrap();
        fs::write(
            out.join(format!("candidate-{index}.status")),
            format!("{:?}\n", result.status.code()),
        )
        .unwrap();
        assert!(!result.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            text.contains(if shared_id {
                "xattrs can't be cloned"
            } else {
                "xattrs can't have holes"
            }),
            "{text}"
        );
        assert_eq!(fs::read(path).unwrap(), image);
        let r = Resources {
            memory: Budget::new(128 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let c = ApfsContainer::open(
            Arc::new(Bytes(image)),
            ApfsReadLimits {
                blocks: 16384,
                checkpoint_blocks: 256,
                objects: 256,
                records: 256,
                work: 64 * 1024 * 1024,
            },
            &r,
        )
        .unwrap();
        let error = match ApfsVolume::open(c, 1026, &r) {
            Ok(_) => panic!("native candidate published"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported, "{error:?}");
        assert_eq!(r.memory.used(), 0);
    }
    for (name, bytes) in PROFILE_SOURCES {
        assert_eq!(
            fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap(),
            *bytes
        );
    }
    assert_eq!(fs::read(source).unwrap(), baseline);
    assert_eq!(fs::read(&checker).unwrap(), tool);
    assert_eq!(
        fs::read(std::env::current_exe().unwrap()).unwrap(),
        executable
    );
    fs::write(out.join("source-end.sha256"), hashes).unwrap();
    fs::write(out.join("commands.txt"), commands).unwrap();
    fs::write(
        out.join("tool-end.sha256"),
        format!("{} {}\n", checker.display(), digest(&tool)),
    )
    .unwrap();
    fs::write(out.join("receipt.txt"),"status=passed\ncandidates=3\nprofile=independent unsupported sparse/shared-ID resource candidates\nchecker=experimental apfsck rejects all three\nmacos_legality=unestablished\n").unwrap();
}

struct Disk {
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
}
impl partmgr::storage::Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let bytes = self.bytes.lock().unwrap();
        out.copy_from_slice(
            bytes
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let count = input.len().min(61);
        self.bytes.lock().unwrap()[at as usize..at as usize + count]
            .copy_from_slice(&input[..count]);
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Input {
    id: ObjectId,
    reads: std::sync::atomic::AtomicUsize,
    length: u64,
}
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let count = out
            .len()
            .min(13)
            .min(self.length.saturating_sub(at) as usize);
        for (i, byte) in out[..count].iter_mut().enumerate() {
            *byte = ((at + i as u64) * 31 + 7) as u8;
        }
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: self.length,
            kind: ExtentKind::Data,
        })
    }
}
fn edit_limits() -> partmgr::fs_apfs_edit::ApfsEditLimits {
    partmgr::fs_apfs_edit::ApfsEditLimits {
        metadata_blocks: 64,
        attempts: 65,
        work: 16 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: 512,
            checkpoint_blocks: 8,
            objects: 256,
            records: 256,
            work: 64 * 1024 * 1024,
        },
        audit: partmgr::fs_apfs_audit::ApfsAuditLimits {
            blocks: 512,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    }
}
#[test]
fn external_xattr_birth_on_files_and_directories_is_deferred_and_complete() {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    for directory in [false, true] {
        let r = Resources {
            memory: Budget::new(384 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let bytes = Arc::new(Mutex::new(resource_fixture::seed(true, 0)));
        let writes = Arc::new(AtomicUsize::new(0));
        let mut editor = partmgr::fs_apfs_edit::ApfsEditor::open(
            Disk {
                bytes: bytes.clone(),
                writes: writes.clone(),
            },
            1026,
            edit_limits(),
            &r,
        )
        .unwrap();
        let id = if directory {
            editor.directory_identity(17, &r)
        } else {
            editor.file_identity(21, &r)
        }
        .unwrap();
        let input = Arc::new(Input {
            id: ObjectId {
                source: 999,
                generation: 3,
                native: b"independent xattr".to_vec(),
            },
            reads: AtomicUsize::new(0),
            length: 16397,
        });
        let plan = editor
            .plan_replace_xattr_stream(&id, "user/new.é".as_bytes(), input.clone(), &r)
            .unwrap();
        assert_eq!(input.reads.load(Ordering::SeqCst), 0);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, &r).unwrap();
        drop(editor);
        assert!(input.reads.load(Ordering::SeqCst) > 16397 / 13);
        let c = ApfsContainer::open(
            Arc::new(Bytes(bytes.lock().unwrap().clone())),
            edit_limits().read,
            &r,
        )
        .unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let tree =
            partmgr::fs_apfs_tree::ApfsTreeSource::inventory(v, edit_limits().audit, &r).unwrap();
        let id = tree
            .volume()
            .lookup(
                &[NativeName::Bytes(if directory {
                    b"Box".to_vec()
                } else {
                    b"Clone".to_vec()
                })],
                &r,
            )
            .unwrap();
        let kind = StreamKind::Named(NativeName::Bytes("user/new.é".as_bytes().to_vec()));
        assert!(
            tree.streams(&id, &r)
                .unwrap()
                .get()
                .iter()
                .any(|s| s.kind == kind && s.length == 16397)
        );
        let stream = tree.open_stream(&id, &kind, &r).unwrap();
        assert_eq!(
            read_all(stream.as_ref(), 16397, &r)
                .unwrap()
                .get()
                .as_slice(),
            (0u64..16397)
                .map(|at| (at * 31 + 7) as u8)
                .collect::<Vec<_>>()
        );
        drop((stream, tree));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn external_xattr_caps_cancel_names_and_memory_refuse_before_io() {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    let r = Resources {
        memory: Budget::new(384 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let original = resource_fixture::generic_seed(true, 0);
    let bytes = Arc::new(Mutex::new(original.clone()));
    let writes = Arc::new(AtomicUsize::new(0));
    let editor = partmgr::fs_apfs_edit::ApfsEditor::open(
        Disk {
            bytes: bytes.clone(),
            writes: writes.clone(),
        },
        1026,
        edit_limits(),
        &r,
    )
    .unwrap();
    let id = editor.file_identity(21, &r).unwrap();
    let input = Arc::new(Input {
        id: ObjectId {
            source: 999,
            generation: 3,
            native: b"independent xattr".to_vec(),
        },
        reads: AtomicUsize::new(0),
        length: 512 * 4096 + 1,
    });
    assert!(
        editor
            .plan_replace_xattr_stream(&id, b"user/new", input.clone(), &r)
            .is_err()
    );
    for name in [
        b"".as_slice(),
        b"bad\0name",
        b"\xff",
        b"com.apple.ResourceFork",
        b"com.apple.system.Security",
    ] {
        assert!(
            editor
                .plan_replace_xattr_stream(&id, name, input.clone(), &r)
                .is_err()
        );
    }
    let foreign = ObjectId {
        source: id.source + 1,
        ..id.clone()
    };
    assert!(
        editor
            .plan_replace_xattr_stream(&foreign, b"user/new", input.clone(), &r)
            .is_err()
    );
    let hold = r
        .memory
        .reserve(384 * 1024 * 1024 - r.memory.used())
        .unwrap();
    assert!(
        editor
            .plan_replace_xattr_stream(&id, b"user/new", input.clone(), &r)
            .is_err()
    );
    drop(hold);
    r.cancellation.cancel();
    assert!(
        editor
            .plan_replace_xattr_stream(&id, b"user/new", input.clone(), &r)
            .is_err()
    );
    assert_eq!(input.reads.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(*bytes.lock().unwrap(), original);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
