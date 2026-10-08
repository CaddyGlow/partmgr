use partmgr::{
    fs_core::{
        Budget, Cancellation, FileRead, LogicalExtent, NativeName, ObjectId, Resources, StreamKind,
        TreeSource,
    },
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{
        ExtCreateMetadata, ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditor, ExtReplacement,
    },
    fs_image::{AllocationEvidence, AllocationPolicy, ReadImage, ReadOptions},
    fs_storage::SectorGeometry,
    fs_undo::UndoLimits,
    storage::{FileStorage, Storage},
};
use partmgr_storage_integration::WriterSession;
use std::sync::Arc;
use virtdisk::{DiskView, Image, ImageFormat, ImageWriter, ReadAt};
#[path = "../../../tests/fixtures/ext2_clean.rs"]
mod fixture;
fn round_trip(format: ImageFormat, dir: tempfile::TempDir) -> (tempfile::TempDir, Vec<u8>) {
    const BASE: usize = 8192;
    const VOLUME: usize = 65536;
    const DISK: usize = 4 << 20;
    let path = dir.path().join("disk.img");
    let journal = dir.path().join("undo.raw");
    std::fs::write(&journal, vec![0; 131072]).unwrap();
    let mut expected = vec![0x5a; DISK];
    expected[..BASE].fill(0xa5);
    expected[BASE..BASE + VOLUME].copy_from_slice(&fixture::fixture());
    let mut initial = WriterSession::new(
        ImageWriter::create(&path, format, DISK as u64).unwrap(),
        0,
        DISK as u64,
        SectorGeometry::default(),
    )
    .unwrap();
    assert_eq!(initial.write_at(0, &expected).unwrap(), DISK);
    initial.flush().unwrap();
    drop(initial);
    let session = WriterSession::new(
        ImageWriter::open(&path, format).unwrap(),
        BASE as u64,
        VOLUME as u64,
        SectorGeometry::default(),
    )
    .unwrap();
    let r = Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    };
    let mut editor = ExtEditor::open(
        FailedBarrier {
            inner: session,
            fail: true,
        },
        FileStorage::open(&journal).unwrap(),
        ExtEditRegion {
            offset: 0,
            length: VOLUME as u64,
        },
        ExtEditBinding {
            volume: [0x62; 32],
            generation: 3,
        },
        ExtEditLimits {
            audit: ExtAuditLimits {
                blocks: 64,
                inodes: 16,
                work: 65536,
                directory_blocks: 4,
                directory_entries: 32,
                findings: 32,
            },
            file_blocks: 32,
            directory_entries: 32,
            affected_bytes: 32768,
            work: 65536,
            undo: UndoLimits {
                patches: 64,
                body_bytes: 65536,
            },
        },
        &r,
    )
    .unwrap();
    assert!(ImageWriter::open(&path, format).is_err());
    assert!(FileStorage::open(&journal).is_err());
    let before_failure = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let failed = editor
        .plan_replace(
            &[ExtReplacement {
                file: &before_failure,
                offset: 0,
                bytes: b"rejected commit",
            }],
            &r,
        )
        .unwrap();
    let failure = editor.commit(failed, [0x71; 16], &r).unwrap_err();
    assert!(failure.source.source.is_some());
    assert_eq!(
        editor.state(),
        partmgr::fs_ext_edit::ExtEditState::NeedsRecovery
    );
    assert!(editor.read_at(&before_failure, 0, &mut [0], &r).is_err());
    editor.recover(&r).unwrap();
    assert_eq!(editor.state(), partmgr::fs_ext_edit::ExtEditState::Ready);
    let restored = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let mut original = [0; 1024];
    assert_eq!(
        editor.read_at(&restored, 0, &mut original, &r).unwrap(),
        1024
    );
    assert_eq!(original, [73; 1024]);
    drop((before_failure, restored));
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let batch = editor
        .plan_replace(
            &[ExtReplacement {
                file: &file,
                offset: 17,
                bytes: b"container edit",
            }],
            &r,
        )
        .unwrap();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
        expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    editor.commit(batch, [1; 16], &r).unwrap();
    assert!(editor.read_at(&file, 0, &mut [0], &r).is_err());
    drop(file);
    let current = editor
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    let mut bytes = [0; 14];
    assert_eq!(editor.read_at(&current, 17, &mut bytes, &r).unwrap(), 14);
    assert_eq!(&bytes, b"container edit");
    drop(current);
    let append = Append {
        identity: ObjectId {
            source: 999,
            generation: 1,
            native: vec![1],
        },
        bytes: (0..13 * 1024 + 7).map(|i| (i * 17) as u8).collect(),
    };
    for operation in 0..2 {
        let old = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let batch = if operation == 0 {
            editor.plan_extend(&old, &append, &r).unwrap()
        } else {
            editor.plan_truncate(&old, 513, &r).unwrap()
        };
        let report = batch.resize_report().unwrap();
        if operation == 0 {
            assert_eq!(report.allocated_indirect_blocks, 1);
        } else {
            assert_eq!(report.freed_indirect_blocks, 1);
        }
        for patch in batch.patches() {
            let at = BASE + patch.offset() as usize;
            assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
            expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
        }
        editor.commit(batch, [operation + 2; 16], &r).unwrap();
        assert!(editor.read_at(&old, 0, &mut [0], &r).is_err());
        drop(old);
        let current = editor
            .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
            .unwrap();
        if operation == 0 {
            let mut actual = vec![0; append.bytes.len()];
            assert_eq!(
                editor.read_at(&current, 1024, &mut actual, &r).unwrap(),
                actual.len()
            );
            assert_eq!(actual, append.bytes);
        } else {
            assert_eq!(current.len(), 513);
        }
        drop(current);
    }
    let root = editor.open_directory(&[], &r).unwrap();
    let metadata = ExtCreateMetadata::zeroed(0o100640);
    let name = [b'n', 255];
    let batch = editor
        .plan_create_file(&root, &name, &metadata, &[0x42; 700], &r)
        .unwrap();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
        expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    editor.commit(batch, [4; 16], &r).unwrap();
    assert!(
        editor
            .plan_create_file(&root, b"stale", &metadata, &[], &r)
            .is_err()
    );
    drop(root);
    let created = editor
        .open_file(&[NativeName::Bytes(name.to_vec())], &r)
        .unwrap();
    let mut bytes = [0; 700];
    assert_eq!(editor.read_at(&created, 0, &mut bytes, &r).unwrap(), 700);
    assert_eq!(bytes, [0x42; 700]);
    drop(created);
    let root = editor.open_directory(&[], &r).unwrap();
    let batch = editor
        .plan_create_directory(&root, b"parent", &ExtCreateMetadata::zeroed(0o40750), &r)
        .unwrap();
    review(&mut expected, BASE, &batch);
    editor.commit(batch, [5; 16], &r).unwrap();
    drop(root);
    let root = editor.open_directory(&[], &r).unwrap();
    let parent = editor
        .open_directory(&[NativeName::Bytes(b"parent".to_vec())], &r)
        .unwrap();
    let batch = editor
        .plan_rename(&root, &name, &parent, b"moved", &r)
        .unwrap();
    review(&mut expected, BASE, &batch);
    editor.commit(batch, [6; 16], &r).unwrap();
    drop((root, parent));
    assert!(
        editor
            .open_file(&[NativeName::Bytes(name.to_vec())], &r)
            .is_err()
    );
    let moved = editor
        .open_file(
            &[
                NativeName::Bytes(b"parent".to_vec()),
                NativeName::Bytes(b"moved".to_vec()),
            ],
            &r,
        )
        .unwrap();
    let mut payload = [0; 700];
    assert_eq!(editor.read_at(&moved, 0, &mut payload, &r).unwrap(), 700);
    assert_eq!(payload, [0x42; 700]);
    drop(moved);
    let root = editor.open_directory(&[], &r).unwrap();
    let batch = editor
        .plan_delete(&root, b"alias", 1_700_000_001, &r)
        .unwrap();
    assert!(!batch.namespace_report().unwrap().released_inode);
    review(&mut expected, BASE, &batch);
    editor.commit(batch, [7; 16], &r).unwrap();
    drop(root);
    assert!(
        editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .is_err()
    );
    let retained = editor
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    let mut bytes = [0; 14];
    assert_eq!(editor.read_at(&retained, 17, &mut bytes, &r).unwrap(), 14);
    assert_eq!(&bytes, b"container edit");
    drop(retained);
    let parent_path = [NativeName::Bytes(b"parent".to_vec())];
    let root = editor.open_directory(&[], &r).unwrap();
    assert!(
        editor
            .plan_delete(&root, b"parent", 1_700_000_002, &r)
            .is_err()
    );
    drop(root);
    let parent = editor.open_directory(&parent_path, &r).unwrap();
    let batch = editor
        .plan_delete(&parent, b"moved", 1_700_000_002, &r)
        .unwrap();
    assert!(batch.namespace_report().unwrap().released_inode);
    review(&mut expected, BASE, &batch);
    editor.commit(batch, [8; 16], &r).unwrap();
    drop(parent);
    assert!(
        editor
            .open_file(
                &[
                    NativeName::Bytes(b"parent".to_vec()),
                    NativeName::Bytes(b"moved".to_vec())
                ],
                &r
            )
            .is_err()
    );
    let root = editor.open_directory(&[], &r).unwrap();
    let batch = editor
        .plan_delete(&root, b"parent", 1_700_000_003, &r)
        .unwrap();
    assert!(batch.namespace_report().unwrap().released_inode);
    review(&mut expected, BASE, &batch);
    editor.commit(batch, [9; 16], &r).unwrap();
    drop(root);
    assert!(editor.open_directory(&parent_path, &r).is_err());
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let image = Image::open(&path, Some(format)).unwrap();
    let mut actual = vec![0; DISK];
    image.read_exact_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let source: Arc<dyn ReadAt> =
        Arc::new(DiskView::new(Arc::new(image), BASE as u64, VOLUME as u64).unwrap());
    let read = ReadImage::open(
        source,
        ReadOptions::Ext2 {
            audit: ExtAuditLimits {
                blocks: 64,
                inodes: 16,
                work: 65536,
                directory_blocks: 4,
                directory_entries: 32,
                findings: 32,
            },
            objects: 16,
            entries: 32,
            map_blocks: 32,
            directory_slots: 32,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    assert_eq!(
        read.allocation_evidence(),
        AllocationEvidence::CleanProfileAudit
    );
    let page = read.directory_page(&read.root(), None, 32, &r).unwrap();
    assert!(
        !page
            .entries
            .iter()
            .any(|entry| entry.name == NativeName::Bytes(b"alias".to_vec())
                || entry.name == NativeName::Bytes(b"parent".to_vec()))
    );
    let object = page
        .entries
        .iter()
        .find(|entry| entry.name == NativeName::Bytes(vec![b'x', 255]))
        .unwrap()
        .object
        .clone();
    drop(page);
    let file = read.open_stream(&object, &StreamKind::Data, &r).unwrap();
    assert_eq!(file.len(), 513);
    let mut bytes = [0; 513];
    assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 513);
    let mut wanted = [73; 513];
    wanted[17..31].copy_from_slice(b"container edit");
    assert_eq!(bytes, wanted);
    drop(file);
    drop(read);
    assert_eq!(r.memory.used(), 0);
    (dir, expected)
}
#[test]
fn raw_ext2_owned_edit_preserves_full_framing_and_hardlinks() {
    round_trip(ImageFormat::Raw, tempfile::tempdir().unwrap());
}
#[test]
#[cfg(target_os = "linux")]
fn qcow2_ext2_owned_edit_preserves_full_framing_and_hardlinks() {
    round_trip(ImageFormat::Qcow2, tempfile::tempdir().unwrap());
}

struct Append {
    identity: ObjectId,
    bytes: Vec<u8>,
}
impl FileRead for Append {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let start = usize::try_from(at).unwrap_or(usize::MAX);
        let n = out
            .len()
            .min(13)
            .min(self.bytes.len().saturating_sub(start));
        if n > 0 {
            out[..n].copy_from_slice(&self.bytes[start..start + n]);
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        r.cancellation.check()?;
        visitor(LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: partmgr::fs_core::ExtentKind::Data,
        })
    }
}

fn review(expected: &mut [u8], base: usize, batch: &partmgr::fs_ext_edit::ExtEditBatch) {
    for patch in batch.patches() {
        let at = base + patch.offset() as usize;
        assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
        expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
}

struct FailedBarrier {
    inner: WriterSession,
    fail: bool,
}
impl Storage for FailedBarrier {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write_at(at, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        if std::mem::take(&mut self.fail) {
            return Err(std::io::Error::other(
                "injected failure after actual container barrier",
            ));
        }
        Ok(())
    }
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "explicit qemu-img oracle requires fresh PARTMGR_EXT_CONTAINER_EVIDENCE"]
fn independent_qcow2_conversion_after_ext2_recovery_and_namespace_lifecycle() {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_EXT_CONTAINER_EVIDENCE")
            .expect("explicit evidence path required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let mut receipt = String::from(
        "profile=ext2-qcow2-owned-recovery-and-nine-commit-lifecycle\nscope=independent container oracle; not native filesystem, firmware or hardware power-loss evidence\n",
    );
    let tool = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("qemu-img"))
        .find(|p| p.is_file())
        .expect("qemu-img required");
    let run = |label: &str, args: &[&std::ffi::OsStr]| {
        let out = Command::new(&tool)
            .args(args)
            .output()
            .expect("enabled gate requires qemu-img");
        std::fs::write(root.join(format!("{label}.stdout")), &out.stdout).unwrap();
        std::fs::write(root.join(format!("{label}.stderr")), &out.stderr).unwrap();
        std::fs::write(
            root.join(format!("{label}.command.txt")),
            format!("program={tool:?}\nargs={args:?}\nstatus={}\n", out.status),
        )
        .unwrap();
        assert!(
            out.status.success(),
            "qemu-img {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let binary = std::env::current_exe().unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let test = manifest.join("tests/ext_edit.rs");
    assert_eq!(std::fs::read(&test).unwrap(), include_bytes!("ext_edit.rs"));
    let hash = |p: &std::path::Path| {
        let out = Command::new("sha256sum")
            .arg(p)
            .output()
            .expect("sha256sum required");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let mut paths = vec![tool.clone(), binary, test, manifest.join("Cargo.lock")];
    for name in [
        "src/fs_ext.rs",
        "src/fs_ext_audit.rs",
        "src/fs_ext_edit.rs",
        "src/fs_ext_edit_allocation.rs",
        "src/fs_ext_edit_namespace.rs",
        "src/fs_ext_edit_transaction.rs",
        "src/fs_undo.rs",
    ] {
        paths.push(manifest.join("../..").join(name));
    }
    let before: Vec<_> = paths.iter().map(|p| hash(p)).collect();
    let version = run("version", &[std::ffi::OsStr::new("--version")]);
    receipt.push_str(&String::from_utf8(version.stdout).unwrap());
    for h in &before {
        receipt.push_str(h);
    }
    let dir = tempfile::Builder::new()
        .prefix("ext-qcow2-")
        .tempdir_in(&root)
        .unwrap();
    let (dir, expected) = round_trip(ImageFormat::Qcow2, dir);
    let disk = dir.path().join("disk.img");
    let raw = dir.path().join("converted.raw");
    let disk_hash = hash(&disk);
    let check = run(
        "check",
        &[
            std::ffi::OsStr::new("check"),
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new("qcow2"),
            disk.as_os_str(),
        ],
    );
    receipt.push_str(&format!(
        "qemu_check={}\n",
        String::from_utf8_lossy(&check.stdout)
    ));
    run(
        "convert",
        &[
            std::ffi::OsStr::new("convert"),
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new("qcow2"),
            std::ffi::OsStr::new("-O"),
            std::ffi::OsStr::new("raw"),
            disk.as_os_str(),
            raw.as_os_str(),
        ],
    );
    assert_eq!(std::fs::read(&raw).unwrap(), expected);
    assert_eq!(hash(&disk), disk_hash);
    for (p, h) in paths.iter().zip(&before) {
        assert_eq!(&hash(p), h);
    }
    receipt.push_str(&format!("converted={}status=passed\nwhole_logical_image=match\ncontainer_unchanged_by_oracle=passed\nsource_tool_binary_revalidation=passed\n",hash(&raw)));
    let kept = dir.keep();
    receipt.push_str(&format!("artifacts={}\n", kept.display()));
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}
