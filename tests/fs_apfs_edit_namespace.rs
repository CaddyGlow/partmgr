#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_apfs_edit::*, fs_core::*, storage::Storage};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use virtdisk::ReadAt;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
struct Disk {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let b = self.bytes.lock().unwrap();
        out.copy_from_slice(
            b.get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let n = input.len().min(61);
        let mut b = self.bytes.lock().unwrap();
        b.get_mut(at as usize..at as usize + n)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&input[..n]);
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.0
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
struct Input {
    id: ObjectId,
    length: u64,
    reads: AtomicUsize,
}
impl Input {
    fn new(length: u64) -> Arc<Self> {
        Arc::new(Self {
            id: ObjectId {
                source: 999,
                generation: 5,
                native: b"independent deferred sparse input".to_vec(),
            },
            length,
            reads: AtomicUsize::new(0),
        })
    }
    fn model(&self) -> Vec<u8> {
        (0..self.length)
            .map(|at| {
                if (4096..8192).contains(&at) {
                    0
                } else {
                    (at * 31 + 7) as u8
                }
            })
            .collect()
    }
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
        self.reads.fetch_add(1, Ordering::SeqCst);
        let n = out
            .len()
            .min(13)
            .min(self.length.saturating_sub(at) as usize);
        for (i, v) in out[..n].iter_mut().enumerate() {
            let at = at + i as u64;
            *v = if (4096..8192).contains(&at) {
                0
            } else {
                (at * 31 + 7) as u8
            };
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        let mut at = 0;
        for (stop, kind) in [
            (4096, ExtentKind::Data),
            (8192, ExtentKind::Hole),
            (self.length, ExtentKind::Data),
        ] {
            let stop = stop.min(self.length);
            if stop > at {
                v(LogicalExtent {
                    offset: at,
                    length: stop - at,
                    kind,
                })?;
                at = stop;
            }
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(384 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
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
        audit: ApfsAuditLimits {
            blocks: 512,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn setup(r: &Resources) -> (ApfsEditor<Disk>, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
    let bytes = Arc::new(Mutex::new(fixture::apfs_seed()));
    let writes = Arc::new(AtomicUsize::new(0));
    let editor = ApfsEditor::open(
        Disk {
            bytes: bytes.clone(),
            writes: writes.clone(),
        },
        1026,
        limits(),
        r,
    )
    .unwrap();
    (editor, bytes, writes)
}
fn reopen(bytes: Vec<u8>, r: &Resources) -> ApfsVolume {
    let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits().read, r).unwrap();
    let v = ApfsVolume::open(c, 1026, r).unwrap();
    let proof = audit_apfs(&v, limits().audit, r).unwrap();
    assert!(
        proof.is_complete() && proof.is_clean(),
        "{:?}",
        proof.findings()
    );
    v
}
fn child(v: &ApfsVolume, parent: &ObjectId, name: &[u8], r: &Resources) -> ObjectId {
    v.directory(parent, r)
        .unwrap()
        .iter()
        .find(|e| e.name == NativeName::Bytes(name.to_vec()))
        .unwrap()
        .object
        .clone()
}
fn data(v: &ApfsVolume, id: &ObjectId, r: &Resources) -> Vec<u8> {
    read_all(&v.open_stream(id, &StreamKind::Data, r).unwrap(), 65536, r)
        .unwrap()
        .get()
        .clone()
}
#[test]
fn actual_native_create_replace_truncate_links_rename_move_unlink_project_and_reopen() {
    for operation in 0..10 {
        let r = resources();
        let (mut editor, bytes, writes) = setup(&r);
        let original = bytes.lock().unwrap().clone();
        let root = editor.directory_identity(2, &r).unwrap();
        let box_id = editor.directory_identity(17, &r).unwrap();
        let file = editor.file_identity(16, &r).unwrap();
        let input = Input::new(8192 + 29);
        let plan = match operation {
            0 => editor.plan_create(
                &root,
                "新-é".as_bytes(),
                input.clone(),
                ApfsCreateMetadata {
                    permissions: 0o640,
                    uid: 42,
                    gid: 43,
                    timestamp: 123456789,
                },
                &r,
            ),
            1 => editor.plan_create_directory(
                &root,
                b"Empty",
                ApfsCreateMetadata {
                    permissions: 0o750,
                    uid: 42,
                    gid: 43,
                    timestamp: 123456789,
                },
                &r,
            ),
            2 => editor.plan_replace(&file, input.clone(), &r),
            3 => editor.plan_truncate(&file, 8192 + 7, &r),
            4 => editor.plan_truncate(&file, 24576 + 3, &r),
            5 => editor.plan_hardlink(&file, &box_id, b"Alias", 123456, &r),
            6 => editor.plan_rename(
                &root,
                "Aé-file".as_bytes(),
                &root,
                "Ré-named".as_bytes(),
                &r,
            ),
            7 => editor.plan_rename(&root, "Aé-file".as_bytes(), &box_id, b"Moved", &r),
            8 => editor.plan_unlink(&box_id, b"Child", &r),
            _ => editor.plan_unlink(&root, "Aé-file".as_bytes(), &r),
        }
        .unwrap_or_else(|e| panic!("operation {operation}: {e:?}"));
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert_eq!(input.reads.load(Ordering::SeqCst), 0);
        let anchor = editor.recovery_anchor();
        let receipt = editor
            .commit_mutation(plan, &anchor, &r)
            .unwrap_or_else(|e| panic!("commit {operation}: {e:?}"));
        assert_eq!(receipt.xid, 2);
        assert!(receipt.retained_history);
        let after = bytes.lock().unwrap().clone();
        for block in [100, 102, 110, 112] {
            assert_eq!(
                &after[block * 4096..(block + 1) * 4096],
                &original[block * 4096..(block + 1) * 4096]
            );
        }
        let v = reopen(after, &r);
        let root = v.root_identity();
        let b = child(&v, &root, b"Box", &r);
        match operation {
            0 => {
                let id = child(&v, &root, "新-é".as_bytes(), &r);
                assert_eq!(data(&v, &id, &r), input.model());
                let m = v.metadata(&id, &r).unwrap();
                assert_eq!(
                    m.owner,
                    MetadataField::Known([42u32.to_le_bytes(), 43u32.to_le_bytes()].concat())
                );
            }
            1 => {
                let id = child(&v, &root, b"Empty", &r);
                assert!(v.directory(&id, &r).unwrap().is_empty());
            }
            2 => {
                let id = child(&v, &root, "Aé-file".as_bytes(), &r);
                assert_eq!(data(&v, &id, &r), input.model());
                assert_eq!(
                    read_all(
                        &v.open_stream(&id, &StreamKind::ResourceFork, &r).unwrap(),
                        8,
                        &r
                    )
                    .unwrap()
                    .get()
                    .as_slice(),
                    b"resource"
                );
            }
            3 | 4 => {
                let id = child(&v, &root, "Aé-file".as_bytes(), &r);
                let got = data(&v, &id, &r);
                let old = reopen(original.clone(), &r);
                let old_id = child(&old, &old.root_identity(), "Aé-file".as_bytes(), &r);
                let mut model = data(&old, &old_id, &r);
                model.resize(if operation == 3 { 8199 } else { 24579 }, 0);
                assert_eq!(got, model);
            }
            5 => {
                let a = child(&v, &root, "Aé-file".as_bytes(), &r);
                let alias = child(&v, &b, b"Alias", &r);
                assert_eq!(a, alias);
                let m = v.metadata(&a, &r).unwrap();
                let (_, raw) = m
                    .attributes
                    .iter()
                    .find(|(n, _)| *n == NativeName::Bytes(b"apfs.inode".to_vec()))
                    .unwrap();
                if let MetadataField::Opaque { bytes, .. } = raw {
                    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 2);
                } else {
                    panic!("native inode unavailable");
                }
            }
            6 => {
                child(&v, &root, "Ré-named".as_bytes(), &r);
                assert!(
                    v.directory(&root, &r)
                        .unwrap()
                        .iter()
                        .all(|e| e.name != NativeName::Bytes("Aé-file".as_bytes().to_vec()))
                );
            }
            7 => {
                child(&v, &b, b"Moved", &r);
                assert_eq!(v.directory(&root, &r).unwrap().len(), 1);
            }
            8 => assert!(v.directory(&b, &r).unwrap().is_empty()),
            _ => assert_eq!(v.directory(&root, &r).unwrap().len(), 1),
        }
        drop(v);
        drop(editor);
        assert_eq!(r.memory.used(), 0, "operation {operation}");
    }
}
fn operation_plan(
    editor: &ApfsEditor<impl Storage>,
    operation: usize,
    input: Arc<dyn FileRead>,
    r: &Resources,
) -> ApfsMutationPlan {
    let root = editor.directory_identity(2, r).unwrap();
    let box_id = editor.directory_identity(17, r).unwrap();
    let file = editor.file_identity(16, r).unwrap();
    let metadata = ApfsCreateMetadata {
        permissions: 0o640,
        uid: 42,
        gid: 43,
        timestamp: 123456789,
    };
    match operation {
        0 => editor.plan_create(&root, "新-é".as_bytes(), input, metadata, r),
        1 => editor.plan_create_directory(&root, b"Empty", metadata, r),
        2 => editor.plan_replace(&file, input, r),
        3 => editor.plan_truncate(&file, 8199, r),
        4 => editor.plan_truncate(&file, 24579, r),
        5 => editor.plan_hardlink(&file, &box_id, b"Alias", 123456, r),
        6 => editor.plan_rename(&root, "Aé-file".as_bytes(), &root, "Ré-named".as_bytes(), r),
        7 => editor.plan_rename(&root, "Aé-file".as_bytes(), &box_id, b"Moved", r),
        8 => editor.plan_unlink(&box_id, b"Child", r),
        9 => editor.plan_unlink(&root, "Aé-file".as_bytes(), r),
        10 => editor.plan_rename(&root, b"Box", &root, b"ChangedBox", r),
        _ => editor.plan_unlink(&root, b"Box", r),
    }
    .unwrap()
}
#[derive(Debug, PartialEq, Eq)]
struct Occurrence {
    path: Vec<Vec<u8>>,
    inode: u64,
    kind: ObjectKind,
    raw_inode: Vec<u8>,
    attributes: Vec<(NativeName, Vec<u8>)>,
    data: Vec<u8>,
    resource: Vec<u8>,
    named: Vec<(StreamKind, Vec<u8>)>,
}
fn signature(bytes: Vec<u8>, r: &Resources) -> Vec<Occurrence> {
    let v = reopen(bytes, r);
    let tree =
        partmgr::fs_apfs_tree::ApfsTreeSource::inventory(v.clone(), limits().audit, r).unwrap();
    let mut queue = vec![(v.root_identity(), Vec::<Vec<u8>>::new())];
    let mut out = Vec::new();
    while let Some((id, path)) = queue.pop() {
        for entry in v.directory(&id, r).unwrap().iter() {
            let NativeName::Bytes(name) = &entry.name else {
                panic!("not native bytes")
            };
            let mut p = path.clone();
            p.push(name.clone());
            let m = v.metadata(&entry.object, r).unwrap();
            let (_, raw) = m
                .attributes
                .iter()
                .find(|(n, _)| *n == NativeName::Bytes(b"apfs.inode".to_vec()))
                .unwrap();
            let MetadataField::Opaque {
                bytes: raw_inode, ..
            } = raw
            else {
                panic!("native inode missing")
            };
            let (data, resource) = if entry.kind == ObjectKind::File {
                let data = data(&v, &entry.object, r);
                let resource = match v.open_stream(&entry.object, &StreamKind::ResourceFork, r) {
                    Ok(f) => read_all(&f, 65536, r).unwrap().get().clone(),
                    Err(e)
                        if e.kind == ErrorKind::Unsupported
                            && e.context == "APFS unavailable stream" =>
                    {
                        Vec::new()
                    }
                    Err(e) => panic!("fork {e:?}"),
                };
                (data, resource)
            } else {
                queue.push((entry.object.clone(), p.clone()));
                (Vec::new(), Vec::new())
            };
            out.push(Occurrence {
                path: p,
                inode: u64::from_be_bytes(entry.object.native[8..].try_into().unwrap()),
                kind: entry.kind.clone(),
                raw_inode: raw_inode.clone(),
                attributes: m
                    .attributes
                    .iter()
                    .filter_map(|(name, field)| match field {
                        MetadataField::Opaque { bytes, .. } => Some((name.clone(), bytes.clone())),
                        _ => None,
                    })
                    .collect(),
                data,
                resource,
                named: tree
                    .streams(&entry.object, r)
                    .unwrap()
                    .get()
                    .iter()
                    .filter(|stream| matches!(stream.kind, StreamKind::Named(_)))
                    .map(|stream| {
                        (
                            stream.kind.clone(),
                            read_all(
                                tree.open_stream(&entry.object, &stream.kind, r)
                                    .unwrap()
                                    .as_ref(),
                                65536,
                                r,
                            )
                            .unwrap()
                            .get()
                            .clone(),
                        )
                    })
                    .collect(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}
struct CutState {
    visible: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    flushes: usize,
    cut_write: Option<usize>,
    cut_flush: Option<usize>,
    write_durable: bool,
    failed_flush_durable: bool,
}
struct CutDisk(Arc<Mutex<CutState>>);
impl Storage for CutDisk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let s = self.0.lock().unwrap();
        out.copy_from_slice(
            s.visible
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        let fail = s.cut_write == Some(s.writes);
        s.writes += 1;
        let n = input.len().min(61);
        let n = if fail { n / 2 } else { n };
        s.visible[at as usize..at as usize + n].copy_from_slice(&input[..n]);
        if s.write_durable {
            s.durable[at as usize..at as usize + n].copy_from_slice(&input[..n]);
        }
        if fail {
            Err(io::Error::other("independent torn namespace mutation"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        let fail = s.cut_flush == Some(s.flushes);
        s.flushes += 1;
        if !fail || s.failed_flush_durable {
            s.durable = s.visible.clone();
        }
        if fail {
            Err(io::Error::other("independent namespace barrier"))
        } else {
            Ok(())
        }
    }
}
fn cut_state(
    operation: usize,
    write_durable: bool,
    failed_flush_durable: bool,
) -> Arc<Mutex<CutState>> {
    let visible = if operation == 11 {
        empty_box_seed()
    } else {
        fixture::apfs_seed()
    };
    Arc::new(Mutex::new(CutState {
        durable: visible.clone(),
        visible,
        writes: 0,
        flushes: 0,
        cut_write: None,
        cut_flush: None,
        write_durable,
        failed_flush_durable,
    }))
}
const CUT_SOURCES: &[(&str, &[u8])] = &[
    (
        "src/fs_apfs_tree.rs",
        include_bytes!("../src/fs_apfs_tree.rs"),
    ),
    (
        "tests/fixtures/apfs_resource.rs",
        include_bytes!("fixtures/apfs_resource.rs"),
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
        include_bytes!("fixtures/apfs_clean.rs"),
    ),
    (
        "tests/fs_apfs_edit_namespace.rs",
        include_bytes!("fs_apfs_edit_namespace.rs"),
    ),
];
fn cut_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
struct CutEvidence {
    directory: std::path::PathBuf,
    binary: Vec<u8>,
    source_hashes: String,
    operations: String,
}
impl CutEvidence {
    fn start() -> Option<Self> {
        let directory = std::path::PathBuf::from(std::env::var_os("PARTMGR_APFS_CUT_EVIDENCE")?);
        std::fs::create_dir(&directory).expect("fresh portable cut evidence directory");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut source_hashes = String::new();
        for (name, compiled) in CUT_SOURCES {
            assert_eq!(
                std::fs::read(root.join(name)).unwrap(),
                *compiled,
                "compiled cut source {name}"
            );
            let target = directory.join("compiled-source").join(name);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, compiled).unwrap();
            source_hashes.push_str(&format!("{name} {}\n", cut_digest(compiled)));
        }
        std::fs::write(directory.join("source-start.sha256"), &source_hashes).unwrap();
        let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(directory.join("compiled-test"), &binary).unwrap();
        std::fs::write(directory.join("binary.sha256"), cut_digest(&binary)).unwrap();
        std::fs::write(directory.join("command.txt"),"PARTMGR_APFS_CUT_EVIDENCE=<fresh-dir> cargo test --locked --test fs_apfs_edit_namespace each_operation_native_block -- --nocapture\n").unwrap();
        Some(Self {
            directory,
            binary,
            source_hashes,
            operations: String::new(),
        })
    }
    fn finish(self) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for (name, compiled) in CUT_SOURCES {
            assert_eq!(
                std::fs::read(root.join(name)).unwrap(),
                *compiled,
                "cut source changed {name}"
            );
            assert_eq!(
                std::fs::read(self.directory.join("compiled-source").join(name)).unwrap(),
                *compiled
            );
        }
        assert_eq!(
            std::fs::read(std::env::current_exe().unwrap()).unwrap(),
            self.binary
        );
        assert_eq!(
            std::fs::read(self.directory.join("compiled-test")).unwrap(),
            self.binary
        );
        std::fs::write(self.directory.join("source-end.sha256"), self.source_hashes).unwrap();
        std::fs::write(self.directory.join("operations.txt"), self.operations).unwrap();
        std::fs::write(self.directory.join("receipt.txt"),"status=passed\nprofile=twelve operation native-block/torn-publication/boot/barrier cuts\npersistence_models=write durable/volatile x failed flush durable/volatile\noracle=complete old or new exact occurrences/native inodes/DATA/resource forks with clean full historical audit\nmacos_native_evidence=unavailable\n").unwrap();
    }
}
#[test]
fn each_operation_native_block_torn_publication_and_barrier_cuts_recover_all_four_persistence_models()
 {
    let mut evidence = CutEvidence::start();
    for operation in 0..12 {
        let r = resources();
        let state = cut_state(operation, true, true);
        let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
        let old = signature(state.lock().unwrap().visible.clone(), &r);
        let plan = operation_plan(&editor, operation, Input::new(8221), &r);
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, &r).unwrap();
        let s = state.lock().unwrap();
        let count = s.writes;
        let expected = signature(s.visible.clone(), &r);
        drop(s);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        let calls_per_block = 4096usize.div_ceil(61);
        assert!(count.is_multiple_of(calls_per_block));
        let mut cuts: Vec<_> = (0..count / calls_per_block)
            .map(|i| (Some(i * calls_per_block), None))
            .collect();
        for interior in [1, 7, 31, 65, 66] {
            cuts.push((Some(count - calls_per_block + interior), None));
            cuts.push((Some(count - 2 * calls_per_block + interior), None));
        }
        cuts.extend((0..5).map(|flush| (None, Some(flush))));
        if let Some(evidence) = &mut evidence {
            evidence.operations.push_str(&format!("operation={operation} baseline_short_writes={count} cuts={} persistence_models=4 scenarios={} old_signature_sha256={} new_signature_sha256={} cut_list={cuts:?}\n",cuts.len(),cuts.len()*4,cut_digest(format!("{old:?}").as_bytes()),cut_digest(format!("{expected:?}").as_bytes())));
        }
        for write_durable in [false, true] {
            for failed_flush_durable in [false, true] {
                for &(cut_write, cut_flush) in &cuts {
                    let r = resources();
                    let state = cut_state(operation, write_durable, failed_flush_durable);
                    let mut editor =
                        ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                    let plan = operation_plan(&editor, operation, Input::new(8221), &r);
                    let anchor = editor.recovery_anchor();
                    {
                        let mut s = state.lock().unwrap();
                        s.cut_write = cut_write;
                        s.cut_flush = cut_flush;
                    }
                    assert!(
                        editor.commit_mutation(plan, &anchor, &r).is_err(),
                        "op{operation} {cut_write:?}/{cut_flush:?}"
                    );
                    assert_eq!(
                        editor.directory_identity(2, &r).unwrap_err().kind,
                        ErrorKind::InterruptedWrite
                    );
                    drop(editor);
                    assert_eq!(r.memory.used(), 0);
                    {
                        let mut s = state.lock().unwrap();
                        s.visible = s.durable.clone();
                        s.cut_write = None;
                        s.cut_flush = None;
                    }
                    let recovered=ApfsEditor::recover_with_anchor(CutDisk(state.clone()),&anchor,limits(),&r).unwrap_or_else(|e|panic!("recover op{operation} {cut_write:?}/{cut_flush:?} {write_durable}/{failed_flush_durable}: {e:?}"));
                    let xid = recovered.checkpoint_xid();
                    assert!(xid == 1 || xid == 2);
                    let got = signature(state.lock().unwrap().visible.clone(), &r);
                    assert_eq!(
                        &got,
                        if xid == 1 { &old } else { &expected },
                        "op{operation} {cut_write:?}/{cut_flush:?}"
                    );
                    drop(recovered);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
    }
    if let Some(evidence) = evidence {
        evidence.finish();
    }
}

#[test]
fn exact_name_collision_cycle_nonempty_special_permissions_foreign_caps_and_cancel_are_prewrite() {
    let r = resources();
    let (editor, bytes, writes) = setup(&r);
    let before = bytes.lock().unwrap().clone();
    let root = editor.directory_identity(2, &r).unwrap();
    let b = editor.directory_identity(17, &r).unwrap();
    let file = editor.file_identity(16, &r).unwrap();
    let m = ApfsCreateMetadata {
        permissions: 0o640,
        uid: 1,
        gid: 2,
        timestamp: 1,
    };
    for name in [
        b"".as_slice(),
        b".",
        b"..",
        b"a/b",
        b"a\0b",
        b"\xff",
        "Aé-file".as_bytes(),
    ] {
        assert!(
            editor
                .plan_create(&root, name, Input::new(10), m, &r)
                .is_err()
        );
    }
    assert!(
        editor
            .plan_create_directory(
                &root,
                b"x",
                ApfsCreateMetadata {
                    permissions: 0o7777,
                    ..m
                },
                &r
            )
            .is_err()
    );
    assert!(editor.plan_rename(&root, b"Box", &b, b"Cycle", &r).is_err());
    assert!(editor.plan_unlink(&root, b"Box", &r).is_err());
    assert!(
        editor
            .plan_rename(&root, "Aé-file".as_bytes(), &root, b"Box", &r)
            .is_err()
    );
    assert!(
        editor
            .plan_replace(&file, Input::new(u64::MAX), &r)
            .is_err()
    );
    let mut foreign = file.clone();
    foreign.generation += 1;
    assert!(
        editor
            .plan_hardlink(&foreign, &root, b"stale", 1, &r)
            .is_err()
    );
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        editor
            .plan_truncate(&file, 0, &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(*bytes.lock().unwrap(), before);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
struct ChangingInput {
    inner: Arc<Input>,
    ids: [ObjectId; 2],
    changed: std::sync::atomic::AtomicBool,
    reads: AtomicUsize,
    fail_at: Option<usize>,
}
impl ChangingInput {
    fn new(fail_at: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            inner: Input::new(8221),
            ids: [
                ObjectId {
                    source: 900,
                    generation: 1,
                    native: b"changing".to_vec(),
                },
                ObjectId {
                    source: 900,
                    generation: 2,
                    native: b"changing".to_vec(),
                },
            ],
            changed: std::sync::atomic::AtomicBool::new(false),
            reads: AtomicUsize::new(0),
            fail_at,
        })
    }
}
impl FileRead for ChangingInput {
    fn identity(&self) -> &ObjectId {
        &self.ids[usize::from(self.changed.load(Ordering::SeqCst))]
    }
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail_at == Some(n) {
            return Err(Error::io(
                "independent deferred source failure",
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "source denied after first COW block",
                ),
            ));
        }
        self.inner.read_at(at, out, r)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.inner.visit_extents(r, v)
    }
}
#[test]
fn retained_source_plan_staleness_owner_cancellation_memory_caps_and_deferred_io_refund() {
    for operation in [0, 2] {
        for failure in 0..5 {
            let r = resources();
            let (mut editor, bytes, writes) = setup(&r);
            let before = bytes.lock().unwrap().clone();
            let input = ChangingInput::new(if failure == 4 { Some(317) } else { None });
            let anchor = editor.recovery_anchor();
            let plan = operation_plan(&editor, operation, input.clone(), &r);
            let baseline = r.memory.used();
            let held = if failure == 2 {
                Some(r.memory.reserve(384 * 1024 * 1024 - baseline).unwrap())
            } else {
                None
            };
            match failure {
                0 => input.changed.store(true, Ordering::SeqCst),
                1 => r.cancellation.cancel(),
                2 => {}
                3 => {
                    bytes.lock().unwrap()[32] ^= 1;
                }
                _ => {}
            }
            let error = editor
                .commit_mutation(plan, &anchor, &resources())
                .unwrap_err();
            if failure == 4 {
                assert_eq!(error.kind, ErrorKind::InterruptedWrite);
                assert_eq!(
                    error.source.unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert!(writes.load(Ordering::SeqCst) > 0);
                let recovered = editor.recover(&resources()).unwrap();
                assert_eq!(recovered.checkpoint_xid(), 1);
                drop(recovered);
            } else if failure == 2 {
                assert_eq!(error.kind, ErrorKind::InterruptedWrite);
                drop(held);
                let recovered = editor.recover(&resources()).unwrap();
                assert_eq!(recovered.checkpoint_xid(), 2);
                drop(recovered);
            } else {
                assert_eq!(writes.load(Ordering::SeqCst), 0);
                if failure != 3 {
                    assert_eq!(*bytes.lock().unwrap(), before);
                }
                drop(editor);
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
}
// Independent raw catalog/extent/bitmap construction: one fewer file, Box has no children.
fn empty_box_seed() -> Vec<u8> {
    let mut bytes = fixture::apfs_seed();
    let mut catalog = fixture::fs_records();
    catalog.retain(|r| {
        !(u64::from_le_bytes(r.0[..8].try_into().unwrap()) & 0x0fffffffffffffff == 18
            || u64::from_le_bytes(r.0[..8].try_into().unwrap()) >> 60 == 9
                && u64::from_le_bytes(r.1[..8].try_into().unwrap()) == 18)
    });
    let raw = &mut catalog
        .iter_mut()
        .find(|r| r.0 == fixture::key(17, 3))
        .unwrap()
        .1;
    fixture::p32(raw, 56, 0);
    bytes[22 * 4096..23 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &catalog, false));
    let mut extents = fixture::extent_records();
    extents.retain(|r| r.0 != fixture::key(112, 2));
    bytes[23 * 4096..24 * 4096]
        .copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &extents, false));
    bytes[41 * 4096 + 112 / 8] &= !(1 << (112 % 8));
    let sm = &mut bytes[10 * 4096..11 * 4096];
    fixture::p64(sm, 72, 462);
    fixture::seal(sm);
    let cib = &mut bytes[42 * 4096..43 * 4096];
    fixture::p32(cib, 60, 462);
    fixture::seal(cib);
    let vol = &mut bytes[19 * 4096..20 * 4096];
    fixture::p64(vol, 88, 8);
    fixture::p64(vol, 184, 1);
    fixture::seal(vol);
    bytes
}
#[test]
fn empty_data_creation_replacement_truncate_and_empty_directory_removal_are_real_native_mutations()
{
    for operation in 0..5 {
        let r = resources();
        let seed = if operation == 4 {
            empty_box_seed()
        } else {
            fixture::apfs_seed()
        };
        let bytes = Arc::new(Mutex::new(seed));
        let mut editor = ApfsEditor::open(
            Disk {
                bytes: bytes.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
            },
            1026,
            limits(),
            &r,
        )
        .unwrap();
        let root = editor.directory_identity(2, &r).unwrap();
        let file = editor.file_identity(16, &r).unwrap();
        let plan = match operation {
            0 => editor.plan_create(
                &root,
                b"Zero",
                Input::new(0),
                ApfsCreateMetadata {
                    permissions: 0o600,
                    uid: 1,
                    gid: 2,
                    timestamp: 3,
                },
                &r,
            ),
            1 => editor.plan_replace(&file, Input::new(0), &r),
            2 => editor.plan_truncate(&file, 0, &r),
            3 => editor.plan_rename(&root, b"Box", &root, "箱".as_bytes(), &r),
            _ => editor.plan_unlink(&root, b"Box", &r),
        }
        .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, &r).unwrap();
        let v = reopen(bytes.lock().unwrap().clone(), &r);
        let root = v.root_identity();
        match operation {
            0 => assert!(data(&v, &child(&v, &root, b"Zero", &r), &r).is_empty()),
            1 | 2 => {
                let id = child(&v, &root, "Aé-file".as_bytes(), &r);
                assert!(data(&v, &id, &r).is_empty());
                assert_eq!(
                    read_all(
                        &v.open_stream(&id, &StreamKind::ResourceFork, &r).unwrap(),
                        8,
                        &r
                    )
                    .unwrap()
                    .get()
                    .as_slice(),
                    b"resource"
                );
            }
            3 => {
                let b = child(&v, &root, "箱".as_bytes(), &r);
                child(&v, &b, b"Child", &r);
            }
            _ => assert_eq!(v.directory(&root, &r).unwrap().len(), 1),
        };
        drop(v);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn shared_pool_exhaustion_blocks_new_mutation_planning_and_refunds() {
    let r = resources();
    let (editor, bytes, writes) = setup(&r);
    let original = bytes.lock().unwrap().clone();
    let held = r
        .memory
        .reserve(384 * 1024 * 1024 - r.memory.used())
        .unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    assert_eq!(
        editor
            .plan_replace(&id, Input::new(8221), &resources())
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(*bytes.lock().unwrap(), original);
    drop(held);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn cloned_stream_mutations_preserve_other_inode_bytes_and_historical_owners() {
    for distinct in [false, true] {
        for operation in 0..5 {
            let r = resources();
            let seed = fixture::shared_seed(distinct);
            let baseline = reopen(seed.clone(), &r);
            let original = data(
                &baseline,
                &child(
                    &baseline,
                    &baseline.root_identity(),
                    "Aé-file".as_bytes(),
                    &r,
                ),
                &r,
            );
            drop(baseline);
            let bytes = Arc::new(Mutex::new(seed));
            let mut editor = ApfsEditor::open(
                Disk {
                    bytes: bytes.clone(),
                    writes: Arc::new(AtomicUsize::new(0)),
                },
                1026,
                limits(),
                &r,
            )
            .unwrap();
            let anchor = editor.recovery_anchor();
            let file = editor.file_identity(16, &r).unwrap();
            let root = editor.directory_identity(2, &r).unwrap();
            let input = Input::new(if operation == 0 { 29 } else { 8199 });
            let plan = match operation {
                0 => editor.plan_range(&file, 8190, input.clone(), &r),
                1 => editor.plan_replace(&file, input.clone(), &r),
                2 => editor.plan_truncate(&file, 8199, &r),
                3 => editor.plan_hardlink(&file, &root, b"Additional", 1234, &r),
                _ => editor.plan_unlink(&root, b"Clone", &r),
            }
            .unwrap();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            drop(editor);
            let volume = reopen(bytes.lock().unwrap().clone(), &r);
            if operation != 4 {
                assert_eq!(
                    data(
                        &volume,
                        &child(&volume, &volume.root_identity(), b"Clone", &r),
                        &r
                    ),
                    original
                );
            }
            let expected = match operation {
                0 => {
                    let mut expected = original.clone();
                    expected[8190..8219].copy_from_slice(&input.model());
                    expected
                }
                1 => input.model(),
                2 => original[..8199].to_vec(),
                _ => original.clone(),
            };
            assert_eq!(
                data(
                    &volume,
                    &child(&volume, &volume.root_identity(), "Aé-file".as_bytes(), &r),
                    &r
                ),
                expected
            );
            drop(volume);
            drop(input);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

fn cloned_plan(editor: &ApfsEditor<CutDisk>, operation: usize, r: &Resources) -> ApfsMutationPlan {
    cloned_plan_inode(editor, operation, 16, r)
}
fn cloned_plan_inode(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    inode: u64,
    r: &Resources,
) -> ApfsMutationPlan {
    let file = editor.file_identity(inode, r).unwrap();
    let root = editor.directory_identity(2, r).unwrap();
    match operation {
        0 => editor.plan_range(&file, 8190, Input::new(29), r),
        1 => editor.plan_replace(&file, Input::new(8199), r),
        2 => editor.plan_truncate(&file, 8199, r),
        3 => editor.plan_hardlink(&file, &root, b"Additional", 1234, r),
        4 => editor.plan_unlink(&root, b"Clone", r),
        _ => editor.plan_rename(&root, b"Clone", &root, "Renamé".as_bytes(), r),
    }
    .unwrap()
}

#[test]
fn cloned_mutations_cold_torn_writes_and_all_barriers_preserve_complete_old_or_new_state() {
    for distinct in [false, true] {
        for operation in 0..6 {
            let make = |write_durable, failed_flush_durable| {
                let visible = fixture::shared_seed(distinct);
                Arc::new(Mutex::new(CutState {
                    durable: visible.clone(),
                    visible,
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable,
                    failed_flush_durable,
                }))
            };
            let r = resources();
            let state = make(true, true);
            let old = signature(state.lock().unwrap().visible.clone(), &r);
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
            let plan = cloned_plan(&editor, operation, &r);
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            let new = signature(state.lock().unwrap().visible.clone(), &r);
            let writes = state.lock().unwrap().writes;
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let mut cuts = vec![(Some(0), None), (Some(writes - 1), None)];
            cuts.extend((0..5).map(|barrier| (None, Some(barrier))));
            for write_durable in [false, true] {
                for failed_flush_durable in [false, true] {
                    for &(cut_write, cut_flush) in &cuts {
                        let r = resources();
                        let state = make(write_durable, failed_flush_durable);
                        let mut editor =
                            ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                        let plan = cloned_plan(&editor, operation, &r);
                        let anchor = editor.recovery_anchor();
                        {
                            let mut s = state.lock().unwrap();
                            s.cut_write = cut_write;
                            s.cut_flush = cut_flush;
                        }
                        assert_eq!(
                            editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
                            ErrorKind::InterruptedWrite
                        );
                        drop(editor);
                        assert_eq!(r.memory.used(), 0);
                        {
                            let mut s = state.lock().unwrap();
                            s.visible = s.durable.clone();
                            s.cut_write = None;
                            s.cut_flush = None;
                        }
                        let recovered = ApfsEditor::recover_with_anchor(
                            CutDisk(state.clone()),
                            &anchor,
                            limits(),
                            &r,
                        )
                        .unwrap();
                        let xid = recovered.checkpoint_xid();
                        assert!(xid == 1 || xid == 2);
                        assert_eq!(
                            &signature(state.lock().unwrap().visible.clone(), &r),
                            if xid == 1 { &old } else { &new }
                        );
                        drop(recovered);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "requires explicit checked native populated source and fresh retained evidence directory"]
fn native_cloned_mutations_checker_and_complete_forks() {
    native_mutation_gate(false, false, false, false);
}
#[test]
#[ignore = "requires explicit native populated source and fresh resource evidence directory"]
fn native_resource_fork_mutations_checker_and_complete_streams() {
    native_mutation_gate(true, false, false, false);
}
fn native_mutation_gate(resource_mutation: bool, external: bool, xattr: bool, generic: bool) {
    use std::{fs, path::PathBuf, process::Command};
    let directory = PathBuf::from(
        std::env::var_os(if generic {
            "PARTMGR_APFS_EXTERNAL_XATTR_EVIDENCE"
        } else if xattr {
            "PARTMGR_APFS_XATTR_EVIDENCE"
        } else if external {
            "PARTMGR_APFS_EXTERNAL_RESOURCE_EVIDENCE"
        } else if resource_mutation {
            "PARTMGR_APFS_RESOURCE_EVIDENCE"
        } else {
            "PARTMGR_APFS_CLONE_EVIDENCE"
        })
        .expect("enabled gate requires evidence directory"),
    );
    fs::create_dir(&directory).unwrap();
    let source = PathBuf::from(
        std::env::var_os(if generic {
            "PARTMGR_APFS_EXTERNAL_XATTR_SOURCE"
        } else if xattr {
            "PARTMGR_APFS_XATTR_SOURCE"
        } else if external {
            "PARTMGR_APFS_EXTERNAL_RESOURCE_SOURCE"
        } else if resource_mutation {
            "PARTMGR_APFS_RESOURCE_SOURCE"
        } else {
            "PARTMGR_APFS_CLONE_SOURCE"
        })
        .expect("enabled gate requires independently checked populated native image"),
    );
    let apfsck =
        PathBuf::from("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck");
    let icat =
        PathBuf::from("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat");
    let mut source_hashes = String::new();
    for (name, compiled) in CUT_SOURCES {
        assert_eq!(
            fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap(),
            *compiled
        );
        let path = directory.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, compiled).unwrap();
        source_hashes.push_str(&format!("{name} {}\n", cut_digest(compiled)));
    }
    fs::write(directory.join("source-start.sha256"), &source_hashes).unwrap();
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(directory.join("compiled-test"), &binary).unwrap();
    fs::write(directory.join("binary.sha256"), cut_digest(&binary)).unwrap();
    let tools: Vec<_> = [&apfsck, &icat]
        .into_iter()
        .map(|path| (path.clone(), fs::read(path).unwrap()))
        .collect();
    fs::write(
        directory.join("tools-start.sha256"),
        tools
            .iter()
            .map(|(path, bytes)| format!("{} {}\n", path.display(), cut_digest(bytes)))
            .collect::<String>(),
    )
    .unwrap();
    let baseline = fs::read(&source).unwrap();
    fs::write(directory.join("input-provenance.txt"), format!("{} {}\nconstruction=independent raw shared-record insertion into pinned formatter image\n",source.display(),cut_digest(&baseline))).unwrap();
    let mut commands = String::new();
    let run = |commands: &mut String, label: &str, tool: &PathBuf, args: &[&str]| {
        commands.push_str(&format!("{} {args:?}\n", tool.display()));
        let output = Command::new(tool).args(args).output().unwrap();
        fs::write(directory.join(format!("{label}.stdout")), &output.stdout).unwrap();
        fs::write(directory.join(format!("{label}.stderr")), &output.stderr).unwrap();
        fs::write(
            directory.join(format!("{label}.status")),
            format!("{:?}\n", output.status.code()),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        output.stdout
    };
    let forms: &[bool] = if xattr { &[false] } else { &[false, true] };
    for &distinct in forms {
        let mut seed = baseline.clone();
        if xattr {
            native_embedded_xattr_seed(&mut seed, if distinct { 10 } else { 2 });
        } else if external {
            native_external_resource_seed(&mut seed, distinct);
            if generic {
                native_generic_xattr_seed(&mut seed, distinct);
            }
        } else {
            fixture::insert_native_shared(&mut seed, distinct);
        }
        let seed_path = directory.join(format!("seed-{distinct}.img"));
        fs::write(&seed_path, &seed).unwrap();
        run(
            &mut commands,
            &format!("seed-{distinct}-checker"),
            &apfsck,
            &["-c", "-u", "-w", seed_path.to_str().unwrap()],
        );
        let original = run(
            &mut commands,
            &format!("seed-{distinct}-data"),
            &icat,
            &[
                "-P",
                "apfs",
                "-B",
                "171",
                "-f",
                "apfs",
                seed_path.to_str().unwrap(),
                "16",
            ],
        );
        let resource = run(
            &mut commands,
            &format!("seed-{distinct}-resource"),
            &icat,
            &[
                "-P",
                "apfs",
                "-B",
                "171",
                "-f",
                "apfs",
                seed_path.to_str().unwrap(),
                "16-4353-1",
            ],
        );
        let child_data = if resource_mutation {
            run(
                &mut commands,
                &format!("seed-{distinct}-child-data"),
                &icat,
                &[
                    "-P",
                    "apfs",
                    "-B",
                    "171",
                    "-f",
                    "apfs",
                    seed_path.to_str().unwrap(),
                    "18",
                ],
            )
        } else {
            Vec::new()
        };
        for operation in 0..if xattr {
            6
        } else if external {
            7
        } else if resource_mutation {
            8
        } else {
            6
        } {
            let r = Resources {
                memory: Budget::new(512 * 1024 * 1024),
                cancellation: Cancellation::default(),
            };
            let mut l = limits();
            l.metadata_blocks = 256;
            l.attempts = 257;
            l.read.blocks = seed.len() as u64 / 4096;
            l.audit.blocks = l.read.blocks;
            let state = Arc::new(Mutex::new(CutState {
                visible: seed.clone(),
                durable: seed.clone(),
                writes: 0,
                flushes: 0,
                cut_write: None,
                cut_flush: None,
                write_durable: true,
                failed_flush_durable: true,
            }));
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, l, &r).unwrap();
            let plan = if generic {
                native_generic_xattr_plan(&editor, operation, &r)
            } else if xattr {
                embedded_xattr_plan(&editor, operation, &r)
            } else if external {
                external_resource_plan(&editor, operation, &r)
            } else if resource_mutation {
                inline_resource_plan(&editor, operation, &r)
            } else {
                cloned_plan_inode(&editor, operation, 21, &r)
            };
            let volume = plan.planned_volume_block().to_string();
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let path = directory.join(format!("case-{distinct}-{operation}.img"));
            let image = state.lock().unwrap().durable.clone();
            if external || xattr {
                let writes = state.lock().unwrap().writes;
                let cold = Arc::new(Mutex::new(CutState {
                    visible: seed.clone(),
                    durable: seed.clone(),
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable: true,
                    failed_flush_durable: true,
                }));
                let mut owned = ApfsEditor::open(CutDisk(cold.clone()), 1026, l, &r).unwrap();
                let plan = if generic {
                    native_generic_xattr_plan(&owned, operation, &r)
                } else if xattr {
                    embedded_xattr_plan(&owned, operation, &r)
                } else {
                    external_resource_plan(&owned, operation, &r)
                };
                let recovery = owned.recovery_anchor();
                cold.lock().unwrap().cut_write = Some(writes - 4096usize.div_ceil(61));
                assert_eq!(
                    owned.commit_mutation(plan, &recovery, &r).unwrap_err().kind,
                    ErrorKind::InterruptedWrite
                );
                drop(owned);
                let bad = cold.lock().unwrap().durable.clone();
                let mut expected = bad[..4096].to_vec();
                fixture::seal(&mut expected);
                assert_ne!(
                    &bad[..8],
                    &expected[..8],
                    "independent Fletcher-invalid boot"
                );
                let bad_path = directory.join(format!("case-{distinct}-{operation}-badboot.img"));
                fs::write(&bad_path, &bad).unwrap();
                let label = format!("case-{distinct}-{operation}-badboot-checker");
                let args = ["-c", "-u", "-w", bad_path.to_str().unwrap()];
                commands.push_str(&format!("{} {args:?}\n", apfsck.display()));
                let output = Command::new(&apfsck).args(args).output().unwrap();
                fs::write(directory.join(format!("{label}.stdout")), &output.stdout).unwrap();
                fs::write(directory.join(format!("{label}.stderr")), &output.stderr).unwrap();
                fs::write(
                    directory.join(format!("{label}.status")),
                    format!("{:?}\n", output.status.code()),
                )
                .unwrap();
                assert!(!output.status.success());
                assert_eq!(fs::read(&bad_path).unwrap(), bad);
                {
                    let mut s = cold.lock().unwrap();
                    s.visible = s.durable.clone();
                    s.cut_write = None;
                }
                let recovered =
                    ApfsEditor::recover_with_anchor(CutDisk(cold.clone()), &recovery, l, &r)
                        .unwrap();
                assert_eq!(recovered.checkpoint_xid(), 2);
                drop(recovered);
                assert_eq!(
                    cold.lock().unwrap().durable,
                    image,
                    "cold recovery exact native publication"
                );
                assert_eq!(r.memory.used(), 0);
            }
            fs::write(&path, &image).unwrap();
            let checker = run(
                &mut commands,
                &format!("case-{distinct}-{operation}-checker"),
                &apfsck,
                &["-c", "-u", "-w", path.to_str().unwrap()],
            );
            assert!(checker.is_empty());
            let mut expected = original.clone();
            match if resource_mutation {
                usize::MAX
            } else {
                operation
            } {
                0 => expected[8190..8219].copy_from_slice(&Input::new(29).model()),
                1 => expected = Input::new(8199).model(),
                2 => expected.truncate(8199),
                _ => {}
            }
            let mut data_models = vec![(16, &original), (21, &expected)];
            if resource_mutation && operation == 6 {
                data_models.push((18, &child_data));
            }
            for (inode, model) in data_models {
                if !resource_mutation && inode == 21 && operation == 4 {
                    continue;
                }
                let got = run(
                    &mut commands,
                    &format!("case-{distinct}-{operation}-inode-{inode}"),
                    &icat,
                    &[
                        "-P",
                        "apfs",
                        "-B",
                        &volume,
                        "-f",
                        "apfs",
                        path.to_str().unwrap(),
                        &inode.to_string(),
                    ],
                );
                assert!(
                    got == *model,
                    "complete fork mismatch {distinct}/{operation}/{inode}"
                );
                fs::write(
                    directory.join(format!(
                        "case-{distinct}-{operation}-inode-{inode}.expected"
                    )),
                    model,
                )
                .unwrap();
            }
            let got = run(
                &mut commands,
                &format!("case-{distinct}-{operation}-resource"),
                &icat,
                &[
                    "-P",
                    "apfs",
                    "-B",
                    &volume,
                    "-f",
                    "apfs",
                    path.to_str().unwrap(),
                    "16-4353-1",
                ],
            );
            assert_eq!(got, resource);
            if resource_mutation && !xattr {
                let expected_resource = if external {
                    match operation {
                        0 => Input::new(16397).model(),
                        1 => {
                            let mut b = resource.clone();
                            b[2..5].copy_from_slice(&Input::new(3).model());
                            b
                        }
                        2 => {
                            let mut b = resource.clone();
                            b.resize(16397, 0);
                            b
                        }
                        3 => resource[..3].to_vec(),
                        5 => Input::new(29).model(),
                        _ => Vec::new(),
                    }
                } else {
                    match operation {
                        0 | 5 | 6 => Input::new(if operation == 5 { 3804 } else { 29 }).model(),
                        1 => {
                            let mut bytes = resource.clone();
                            bytes[2..5].copy_from_slice(&Input::new(3).model());
                            bytes
                        }
                        2 => resource[..3].to_vec(),
                        3 => {
                            let mut bytes = resource.clone();
                            bytes.resize(29, 0);
                            bytes
                        }
                        _ => Vec::new(),
                    }
                };
                let native = if generic {
                    "21-4354-1"
                } else if !external && operation == 6 {
                    "18-4353-1"
                } else {
                    "21-4353-1"
                };
                let label = format!("case-{distinct}-{operation}-changed-resource");
                let args = [
                    "-P",
                    "apfs",
                    "-B",
                    &volume,
                    "-f",
                    "apfs",
                    path.to_str().unwrap(),
                    native,
                ];
                if operation == if external { 6 } else { 7 } || external && operation == 4 {
                    commands.push_str(&format!("{} {args:?}\n", icat.display()));
                    let output = Command::new(&icat).args(args).output().unwrap();
                    fs::write(directory.join(format!("{label}.stdout")), &output.stdout).unwrap();
                    fs::write(directory.join(format!("{label}.stderr")), &output.stderr).unwrap();
                    fs::write(
                        directory.join(format!("{label}.status")),
                        format!("{:?}\n", output.status.code()),
                    )
                    .unwrap();
                    assert!(!output.status.success() && output.stdout.is_empty());
                    if external && operation == 4 {
                        assert_eq!(output.status.code(), Some(1));
                        let expected = if generic {
                            b"Attribute not found in file (tsk_fs_attrlist_get_id: Attribute 4354-1 not found)\n".as_slice()
                        } else {
                            b"Attribute not found in file (tsk_fs_attrlist_get_id: Attribute 4353-1 not found)\n".as_slice()
                        };
                        assert_eq!(output.stderr, expected);
                        fs::write(directory.join(format!("{label}.oracle-gap")),"present zero-length external fork: native checker accepted; pinned TSK omits empty stream attribute; no successful TSK empty-fork extraction claimed\n").unwrap();
                    }
                } else {
                    let actual = run(&mut commands, &label, &icat, &args);
                    assert_eq!(actual, expected_resource);
                    fs::write(
                        directory.join(format!("{label}.expected")),
                        expected_resource,
                    )
                    .unwrap();
                }
            }
            if xattr {
                let inode = if operation == 5 { 17 } else { 16 };
                let attribute_id = if operation == 0 {
                    3
                } else if operation == 5 {
                    1
                } else {
                    2
                };
                let native = format!("{inode}-4354-{attribute_id}");
                let args = [
                    "-P",
                    "apfs",
                    "-B",
                    &volume,
                    "-f",
                    "apfs",
                    path.to_str().unwrap(),
                    &native,
                ];
                let label = format!("case-{distinct}-{operation}-xattr");
                if operation == 4 {
                    commands.push_str(&format!("{} {args:?}\n", icat.display()));
                    let output = Command::new(&icat).args(args).output().unwrap();
                    fs::write(directory.join(format!("{label}.stdout")), &output.stdout).unwrap();
                    fs::write(directory.join(format!("{label}.stderr")), &output.stderr).unwrap();
                    fs::write(
                        directory.join(format!("{label}.status")),
                        format!("{:?}\n", output.status.code()),
                    )
                    .unwrap();
                    assert!(!output.status.success() && output.stdout.is_empty());
                } else {
                    let actual = run(&mut commands, &label, &icat, &args);
                    let expected = match operation {
                        2 => vec![0x91; 3804],
                        3 => Vec::new(),
                        _ => b"new exact bytes\0".to_vec(),
                    };
                    assert_eq!(actual, expected);
                    fs::write(directory.join(format!("{label}.expected")), expected).unwrap();
                }
            }
            assert_eq!(fs::read(&path).unwrap(), image);
        }
    }
    for (name, compiled) in CUT_SOURCES {
        assert_eq!(
            fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap(),
            *compiled
        );
    }
    for (path, bytes) in &tools {
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
    assert_eq!(fs::read(&source).unwrap(), baseline);
    assert_eq!(fs::read(std::env::current_exe().unwrap()).unwrap(), binary);
    fs::write(directory.join("source-end.sha256"), source_hashes).unwrap();
    fs::write(directory.join("commands.txt"), commands).unwrap();
    fs::write(
        directory.join("receipt.txt"),
        format!("status=passed\ncases={}\nprofile={}\nchecker=experimental apfsck\nmacos_clone_oracle=unavailable\n",if xattr {6} else if external {14} else if resource_mutation {16} else {12},if generic {"external generic xattr mutation"} else if xattr {"embedded xattr mutation"} else if external {"external resource mutation"} else if resource_mutation {"inline resource mutation"} else {"clone mutation"}),
    )
    .unwrap();
}

#[test]
fn final_original_inode_unlink_keeps_clones_stream_and_canonical_physical_owner() {
    for distinct in [false, true] {
        let r = resources();
        let mut seed = fixture::shared_seed(distinct);
        // Independently enlarge the checkpoint data ring for both removals.
        for old in 9..13 {
            let bytes = seed[old * 4096..(old + 1) * 4096].to_vec();
            seed[(128 + old - 9) * 4096..(129 + old - 9) * 4096].copy_from_slice(&bytes);
        }
        for at in [0, 2] {
            let nx = &mut seed[at * 4096..(at + 1) * 4096];
            fixture::p32(nx, 108, 16);
            fixture::p64(nx, 120, 128);
            fixture::seal(nx);
        }
        let map = &mut seed[4096..8192];
        for i in 0..4 {
            fixture::p64(map, 40 + i * 40 + 32, 128 + i as u64);
        }
        fixture::seal(map);
        for bit in 9..17 {
            seed[41 * 4096 + bit / 8] &= !(1 << (bit % 8));
        }
        for bit in 128..144 {
            seed[41 * 4096 + bit / 8] |= 1 << (bit % 8);
        }
        let spaceman = &mut seed[129 * 4096..130 * 4096];
        fixture::p64(spaceman, 72, 453);
        fixture::seal(spaceman);
        let cib = &mut seed[42 * 4096..43 * 4096];
        fixture::p32(cib, 60, 453);
        fixture::seal(cib);
        let baseline = reopen(seed.clone(), &r);
        let original = data(
            &baseline,
            &child(&baseline, &baseline.root_identity(), b"Clone", &r),
            &r,
        );
        drop(baseline);
        let bytes = Arc::new(Mutex::new(seed));
        let mut editor = ApfsEditor::open(
            Disk {
                bytes: bytes.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
            },
            1026,
            limits(),
            &r,
        )
        .unwrap();
        let anchor = editor.recovery_anchor();
        for (parent, name) in [(17, b"Alias".as_slice()), (2, "Aé-file".as_bytes())] {
            let directory = editor.directory_identity(parent, &r).unwrap();
            let plan = editor.plan_unlink(&directory, name, &r).unwrap();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
        }
        drop(editor);
        let volume = reopen(bytes.lock().unwrap().clone(), &r);
        assert_eq!(
            data(
                &volume,
                &child(&volume, &volume.root_identity(), b"Clone", &r),
                &r
            ),
            original
        );
        assert!(
            volume
                .lookup(&[NativeName::Bytes("Aé-file".as_bytes().to_vec())], &r)
                .is_err()
        );
        drop(volume);
        assert_eq!(r.memory.used(), 0);
    }
}

fn resource_bytes(v: &ApfsVolume, id: &ObjectId, r: &Resources) -> Vec<u8> {
    read_all(
        &v.open_stream(id, &StreamKind::ResourceFork, r).unwrap(),
        3804,
        r,
    )
    .unwrap()
    .get()
    .clone()
}
#[test]
fn inline_resource_replace_range_truncate_create_and_clones_keep_data_and_other_forks() {
    for distinct in [false, true] {
        for operation in 0..8 {
            let r = resources();
            let seed = fixture::shared_seed(distinct);
            let old = reopen(seed.clone(), &r);
            let data_model = data(&old, &child(&old, &old.root_identity(), b"Clone", &r), &r);
            drop(old);
            let bytes = Arc::new(Mutex::new(seed));
            let mut editor = ApfsEditor::open(
                Disk {
                    bytes: bytes.clone(),
                    writes: Arc::new(AtomicUsize::new(0)),
                },
                1026,
                limits(),
                &r,
            )
            .unwrap();
            let id = editor
                .file_identity(if operation == 6 { 18 } else { 21 }, &r)
                .unwrap();
            let anchor = editor.recovery_anchor();
            let input = Input::new(if operation == 1 {
                3
            } else if operation == 5 {
                3804
            } else {
                29
            });
            let plan = match operation {
                0 | 5 | 6 => editor.plan_replace_resource_fork(&id, input.clone(), &r),
                1 => editor.plan_range_resource_fork(&id, 2, input.clone(), &r),
                2 => editor.plan_truncate_resource_fork(&id, 3, &r),
                3 => editor.plan_truncate_resource_fork(&id, 29, &r),
                4 => editor.plan_truncate_resource_fork(&id, 0, &r),
                _ => editor.plan_remove_resource_fork(&id, &r),
            }
            .unwrap();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            drop(editor);
            let volume = reopen(bytes.lock().unwrap().clone(), &r);
            let original = child(&volume, &volume.root_identity(), "Aé-file".as_bytes(), &r);
            let clone = child(&volume, &volume.root_identity(), b"Clone", &r);
            assert_eq!(data(&volume, &original, &r), data_model);
            assert_eq!(data(&volume, &clone, &r), data_model);
            assert_eq!(resource_bytes(&volume, &original, &r), b"resource");
            let target = if operation == 6 {
                volume
                    .lookup(
                        &[
                            NativeName::Bytes(b"Box".to_vec()),
                            NativeName::Bytes(b"Child".to_vec()),
                        ],
                        &r,
                    )
                    .unwrap()
            } else {
                clone.clone()
            };
            let expected = match operation {
                0 | 5 | 6 => input.model(),
                1 => {
                    let mut m = b"resource".to_vec();
                    m[2..5].copy_from_slice(&input.model());
                    m
                }
                2 => b"res".to_vec(),
                3 => {
                    let mut m = b"resource".to_vec();
                    m.resize(29, 0);
                    m
                }
                _ => Vec::new(),
            };
            if operation == 7 {
                assert!(
                    volume
                        .open_stream(&target, &StreamKind::ResourceFork, &r)
                        .is_err()
                );
            } else {
                assert_eq!(resource_bytes(&volume, &target, &r), expected);
            }
            if operation == 6 {
                assert_eq!(resource_bytes(&volume, &clone, &r), b"resource");
            }
            drop(volume);
            drop(input);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn inline_resource_caps_cancellation_input_io_and_changed_identity_are_prewrite_and_refund() {
    let r = resources();
    let (mut editor, bytes, writes) = setup(&r);
    let original = bytes.lock().unwrap().clone();
    let id = editor.file_identity(16, &r).unwrap();
    let child_id = editor.file_identity(18, &r).unwrap();
    let large = Input::new(512 * 4096 + 1);
    assert!(
        editor
            .plan_replace_resource_fork(&id, large.clone(), &r)
            .is_err()
    );
    assert!(
        editor
            .plan_truncate_resource_fork(&id, 512 * 4096 + 1, &r)
            .is_err()
    );
    assert_eq!(large.reads.load(Ordering::SeqCst), 0);
    let input = Input::new(3);
    assert!(
        editor
            .plan_range_resource_fork(&id, u64::MAX, input.clone(), &r)
            .is_err()
    );
    assert!(
        editor
            .plan_range_resource_fork(&child_id, 0, input.clone(), &r)
            .is_err()
    );
    assert_eq!(input.reads.load(Ordering::SeqCst), 0);
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        editor
            .plan_truncate_resource_fork(&id, 0, &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    let mut failed = ChangingInput::new(Some(0));
    Arc::get_mut(&mut failed).unwrap().inner = Input::new(29);
    let error = editor
        .plan_replace_resource_fork(&id, failed, &r)
        .err()
        .unwrap();
    assert_eq!(
        error.source.unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    let held = r
        .memory
        .reserve(384 * 1024 * 1024 - r.memory.used())
        .unwrap();
    assert_eq!(
        editor
            .plan_replace_resource_fork(&id, input.clone(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    drop(held);
    let mut changed = ChangingInput::new(None);
    Arc::get_mut(&mut changed).unwrap().inner = Input::new(29);
    let plan = editor
        .plan_replace_resource_fork(&id, changed.clone(), &r)
        .unwrap();
    let anchor = editor.recovery_anchor();
    changed.changed.store(true, Ordering::SeqCst);
    assert_eq!(
        editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(*bytes.lock().unwrap(), original);
    drop(editor);
    drop(changed);
    drop(input);
    drop(large);
    assert_eq!(r.memory.used(), 0);
}
fn inline_resource_plan(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    r: &Resources,
) -> ApfsMutationPlan {
    let id = editor
        .file_identity(if operation == 6 { 18 } else { 21 }, r)
        .unwrap();
    match operation {
        0 | 5 | 6 => editor.plan_replace_resource_fork(
            &id,
            Input::new(if operation == 5 { 3804 } else { 29 }),
            r,
        ),
        1 => editor.plan_range_resource_fork(&id, 2, Input::new(3), r),
        2 => editor.plan_truncate_resource_fork(&id, 3, r),
        3 => editor.plan_truncate_resource_fork(&id, 29, r),
        4 => editor.plan_truncate_resource_fork(&id, 0, r),
        _ => editor.plan_remove_resource_fork(&id, r),
    }
    .unwrap()
}
#[test]
fn inline_resource_all_metadata_block_writes_and_barriers_cold_recover_four_models() {
    for distinct in [false, true] {
        for operation in 0..8 {
            let make = |write_durable, failed_flush_durable| {
                let visible = fixture::shared_seed(distinct);
                Arc::new(Mutex::new(CutState {
                    durable: visible.clone(),
                    visible,
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable,
                    failed_flush_durable,
                }))
            };
            let r = resources();
            let state = make(true, true);
            let old = signature(state.lock().unwrap().visible.clone(), &r);
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
            let plan = inline_resource_plan(&editor, operation, &r);
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            let new = signature(state.lock().unwrap().visible.clone(), &r);
            let writes = state.lock().unwrap().writes;
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let per_block = 4096usize.div_ceil(61);
            assert!(writes.is_multiple_of(per_block));
            let mut cuts: Vec<_> = (0..writes / per_block)
                .map(|block| (Some(block * per_block), None))
                .collect();
            cuts.push((Some(writes - 1), None));
            cuts.extend((0..5).map(|barrier| (None, Some(barrier))));
            println!(
                "resource_operation={operation} distinct_data_stream={distinct} native_block_writes={} cuts={} models=4 scenarios={}",
                writes / per_block,
                cuts.len(),
                cuts.len() * 4
            );
            for write_durable in [false, true] {
                for failed_flush_durable in [false, true] {
                    for &(cut_write, cut_flush) in &cuts {
                        let r = resources();
                        let state = make(write_durable, failed_flush_durable);
                        let mut editor =
                            ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                        let plan = inline_resource_plan(&editor, operation, &r);
                        let anchor = editor.recovery_anchor();
                        {
                            let mut s = state.lock().unwrap();
                            s.cut_write = cut_write;
                            s.cut_flush = cut_flush;
                        }
                        assert_eq!(
                            editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
                            ErrorKind::InterruptedWrite
                        );
                        drop(editor);
                        assert_eq!(r.memory.used(), 0);
                        {
                            let mut s = state.lock().unwrap();
                            s.visible = s.durable.clone();
                            s.cut_write = None;
                            s.cut_flush = None;
                        }
                        let recovered = ApfsEditor::recover_with_anchor(
                            CutDisk(state.clone()),
                            &anchor,
                            limits(),
                            &r,
                        )
                        .unwrap();
                        let xid = recovered.checkpoint_xid();
                        assert!(xid == 1 || xid == 2);
                        assert_eq!(
                            &signature(state.lock().unwrap().visible.clone(), &r),
                            if xid == 1 { &old } else { &new }
                        );
                        drop(recovered);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[path = "fixtures/apfs_resource.rs"]
mod resource_fixture;
#[test]
fn external_resource_removal_keeps_other_physical_owner_and_both_data_streams() {
    for shared in [false, true] {
        let r = resources();
        let bytes = Arc::new(Mutex::new(resource_fixture::seed(shared, 0)));
        let mut editor = ApfsEditor::open(
            Disk {
                bytes: bytes.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
            },
            1026,
            limits(),
            &r,
        )
        .unwrap();
        let id = editor.file_identity(21, &r).unwrap();
        let plan = editor.plan_remove_resource_fork(&id, &r).unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, &r).unwrap();
        drop(editor);
        let c = ApfsContainer::open(
            Arc::new(Bytes(bytes.lock().unwrap().clone())),
            limits().read,
            &r,
        )
        .unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let audit = audit_apfs(&v, limits().audit, &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        for name in [b"A\xc3\xa9-file".as_slice(), b"Clone".as_slice()] {
            let object = v.lookup(&[NativeName::Bytes(name.to_vec())], &r).unwrap();
            let file = v.open_file(&object, &r).unwrap();
            let actual = read_all(&file, 65536, &r).unwrap().get().clone();
            let expected: Vec<u8> = (0..16397)
                .map(|i| {
                    if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                        0
                    } else {
                        (i % 4096 * 17 % 251) as u8
                    }
                })
                .collect();
            assert_eq!(actual, expected);
            let fork = v.open_stream(&object, &StreamKind::ResourceFork, &r);
            if name == b"Clone" {
                assert!(fork.is_err());
            } else {
                assert_eq!(
                    read_all(&fork.unwrap(), 8, &r).unwrap().get().clone(),
                    b"resource"
                );
            }
        }
        drop((audit, v));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn external_resource_replace_range_truncate_and_inline_growth_preserve_both_forks() {
    for shared in [false, true] {
        for operation in 0..6 {
            let r = resources();
            let seed = if operation == 5 {
                fixture::shared_seed(true)
            } else {
                resource_fixture::seed(shared, 0)
            };
            let bytes = Arc::new(Mutex::new(seed));
            let mut editor = ApfsEditor::open(
                Disk {
                    bytes: bytes.clone(),
                    writes: Arc::new(AtomicUsize::new(0)),
                },
                1026,
                limits(),
                &r,
            )
            .unwrap();
            let id = editor.file_identity(21, &r).unwrap();
            let input = Input::new(if operation == 1 { 3 } else { 16397 });
            let plan = match operation {
                0 => editor.plan_replace_resource_fork(&id, input.clone(), &r),
                1 => editor.plan_range_resource_fork(&id, 2, input.clone(), &r),
                2 | 5 => editor.plan_truncate_resource_fork(&id, 16397, &r),
                3 => editor.plan_truncate_resource_fork(&id, 3, &r),
                _ => editor.plan_truncate_resource_fork(&id, 0, &r),
            }
            .unwrap();
            assert_eq!(input.reads.load(Ordering::SeqCst), 0, "deferred input");
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            drop(editor);
            let v = reopen(bytes.lock().unwrap().clone(), &r);
            let original = v
                .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
                .unwrap();
            let changed = v
                .lookup(&[NativeName::Bytes(b"Clone".to_vec())], &r)
                .unwrap();
            assert_eq!(data(&v, &original, &r), data(&v, &changed, &r));
            assert_eq!(resource_bytes(&v, &original, &r), b"resource");
            let expected = match operation {
                0 => input.model(),
                1 => {
                    let mut v = b"resource".to_vec();
                    v[2..5].copy_from_slice(&input.model());
                    v
                }
                2 | 5 => {
                    let mut v = b"resource".to_vec();
                    v.resize(16397, 0);
                    v
                }
                3 => b"res".to_vec(),
                _ => Vec::new(),
            };
            let stream = v
                .open_stream(&changed, &StreamKind::ResourceFork, &r)
                .unwrap();
            assert_eq!(
                read_all(&stream, 65536, &r).unwrap().get().as_slice(),
                expected
            );
            drop((stream, v));
            assert_eq!(r.memory.used(), 0);
        }
    }
}

fn external_resource_plan(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    r: &Resources,
) -> ApfsMutationPlan {
    let id = editor.file_identity(21, r).unwrap();
    match operation {
        0 => editor.plan_replace_resource_fork(&id, Input::new(16397), r),
        1 => editor.plan_range_resource_fork(&id, 2, Input::new(3), r),
        2 => editor.plan_truncate_resource_fork(&id, 16397, r),
        3 => editor.plan_truncate_resource_fork(&id, 3, r),
        4 => editor.plan_truncate_resource_fork(&id, 0, r),
        5 => editor.plan_replace_resource_fork(&id, Input::new(29), r),
        _ => editor.plan_remove_resource_fork(&id, r),
    }
    .unwrap()
}
#[test]
fn external_resource_all_blocks_and_barriers_cold_recover_four_models() {
    for distinct in [false, true] {
        for operation in 0..7 {
            let make = |write_durable, failed_flush_durable| {
                let visible = resource_fixture::seed(distinct, 0);
                Arc::new(Mutex::new(CutState {
                    durable: visible.clone(),
                    visible,
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable,
                    failed_flush_durable,
                }))
            };
            let r = resources();
            let state = make(true, true);
            let old = signature(state.lock().unwrap().visible.clone(), &r);
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
            let plan = external_resource_plan(&editor, operation, &r);
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            let new = signature(state.lock().unwrap().visible.clone(), &r);
            let writes = state.lock().unwrap().writes;
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let per_block = 4096usize.div_ceil(61);
            assert!(writes.is_multiple_of(per_block));
            let mut cuts: Vec<_> = (0..writes / per_block)
                .map(|block| (Some(block * per_block), None))
                .collect();
            cuts.push((Some(writes - 1), None));
            cuts.extend((0..5).map(|barrier| (None, Some(barrier))));
            println!(
                "external_resource_operation={operation} distinct_data_stream={distinct} native_block_writes={} cuts={} models=4 scenarios={}",
                writes / per_block,
                cuts.len(),
                cuts.len() * 4
            );
            for write_durable in [false, true] {
                for failed_flush_durable in [false, true] {
                    for &(cut_write, cut_flush) in &cuts {
                        let r = resources();
                        let state = make(write_durable, failed_flush_durable);
                        let mut editor =
                            ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                        let plan = external_resource_plan(&editor, operation, &r);
                        let anchor = editor.recovery_anchor();
                        {
                            let mut s = state.lock().unwrap();
                            s.cut_write = cut_write;
                            s.cut_flush = cut_flush;
                        }
                        assert_eq!(
                            editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
                            ErrorKind::InterruptedWrite
                        );
                        drop(editor);
                        assert_eq!(r.memory.used(), 0);
                        {
                            let mut s = state.lock().unwrap();
                            s.visible = s.durable.clone();
                            s.cut_write = None;
                            s.cut_flush = None;
                        }
                        let recovered = ApfsEditor::recover_with_anchor(
                            CutDisk(state.clone()),
                            &anchor,
                            limits(),
                            &r,
                        )
                        .unwrap();
                        let xid = recovered.checkpoint_xid();
                        assert!(xid == 1 || xid == 2);
                        assert_eq!(
                            &signature(state.lock().unwrap().visible.clone(), &r),
                            if xid == 1 { &old } else { &new }
                        );
                        drop(recovered);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn native_external_resource_seed(image: &mut [u8], shared: bool) {
    fixture::insert_native_shared(image, true);
    let (mut fs, mut ext) = resource_fixture::records(shared, 0);
    let raw = |b: &[u8], at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    for (key, value) in &mut fs {
        if raw(key, 0) >> 60 == 8 {
            let physical = raw(value, 8);
            if physical != 0 {
                fixture::p64(value, 8, physical + 200);
            }
        }
    }
    for (key, _) in &mut ext {
        let physical = raw(key, 0) & 0x0fffffffffffffff;
        fixture::p64(key, 0, 2u64 << 60 | (physical + 200));
    }
    image[174 * 4096..175 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &fs, false));
    image[175 * 4096..176 * 4096]
        .copy_from_slice(&fixture::leaf(175, 1, 0x40000000, 15, &ext, false));
    let count = if shared { 1 } else { 2 };
    for block in 313..313 + count {
        assert_eq!(image[195 * 4096 + block / 8] & (1 << (block % 8)), 0);
        image[195 * 4096 + block / 8] |= 1 << (block % 8);
        image[block * 4096..block * 4096 + 8].copy_from_slice(b"resource");
    }
    let free = raw(image, 10 * 4096 + 72);
    fixture::p64(image, 10 * 4096 + 72, free - count as u64);
    fixture::seal(&mut image[10 * 4096..11 * 4096]);
    let free = u32::from_le_bytes(image[196 * 4096 + 60..196 * 4096 + 64].try_into().unwrap());
    fixture::p32(image, 196 * 4096 + 60, free - count as u32);
    fixture::seal(&mut image[196 * 4096..197 * 4096]);
    let allocated = raw(image, 171 * 4096 + 88);
    fixture::p64(image, 171 * 4096 + 88, allocated + count as u64);
    fixture::p64(image, 171 * 4096 + 176, 26);
    fixture::seal(&mut image[171 * 4096..172 * 4096]);
}

#[test]
#[ignore = "requires checked native source and explicit fresh external-resource evidence directory"]
fn native_external_resource_mutations_checker_and_complete_streams() {
    native_mutation_gate(true, true, false, false);
}

fn embedded_xattr_records(flags: u16) -> fixture::Records {
    let (mut records, _) = fixture::shared_records(true);
    let name = b"user.\xc3\xa9";
    let mut key = (4u64 << 60 | 16).to_le_bytes().to_vec();
    key.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    key.extend_from_slice(name);
    key.push(0);
    let mut value = flags.to_le_bytes().to_vec();
    value.extend_from_slice(&3u16.to_le_bytes());
    value.extend_from_slice(b"old");
    records.push((key, value));
    records.sort_by(|a, b| {
        let raw = |b: &[u8], at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let x = raw(&a.0, 0);
        let y = raw(&b.0, 0);
        (x & 0x0fffffffffffffff)
            .cmp(&(y & 0x0fffffffffffffff))
            .then((x >> 60).cmp(&(y >> 60)))
            .then_with(|| match x >> 60 {
                4 | 9 => a.0[10..].cmp(&b.0[10..]),
                8 => raw(&a.0, 8).cmp(&raw(&b.0, 8)),
                _ => a.0[8..].cmp(&b.0[8..]),
            })
    });
    records
}
fn embedded_xattr_seed(flags: u16) -> Vec<u8> {
    let mut bytes = fixture::shared_seed(true);
    let records = embedded_xattr_records(flags);
    bytes[22 * 4096..23 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
    bytes
}
fn attribute(v: &ApfsVolume, id: &ObjectId, name: &[u8], r: &Resources) -> Option<Vec<u8>> {
    v.metadata(id, r)
        .unwrap()
        .attributes
        .iter()
        .find_map(|(n, field)| {
            if n == &NativeName::Bytes(name.to_vec()) {
                match field {
                    MetadataField::Opaque { bytes, .. } => Some(bytes.clone()),
                    _ => panic!("native xattr interpretation"),
                }
            } else {
                None
            }
        })
}
#[test]
fn native_embedded_xattr_create_replace_remove_preserve_reserved_flags_forks_and_history() {
    for flags in [2, 10] {
        for operation in 0..5 {
            let r = resources();
            let bytes = Arc::new(Mutex::new(embedded_xattr_seed(flags)));
            let mut editor = ApfsEditor::open(
                Disk {
                    bytes: bytes.clone(),
                    writes: Arc::new(AtomicUsize::new(0)),
                },
                1026,
                limits(),
                &r,
            )
            .unwrap();
            let id = editor.file_identity(16, &r).unwrap();
            let name = if operation == 0 {
                b"user/new".as_slice()
            } else {
                b"user.\xc3\xa9".as_slice()
            };
            let value = if operation == 2 {
                vec![0x91; 3804]
            } else if operation == 3 {
                Vec::new()
            } else {
                b"new exact bytes\0".to_vec()
            };
            let plan = if operation == 4 {
                editor.plan_remove_xattr(&id, name, &r)
            } else {
                editor.plan_set_xattr(&id, name, &value, &r)
            }
            .unwrap();
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            drop(editor);
            let v = reopen(bytes.lock().unwrap().clone(), &r);
            let id = v
                .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
                .unwrap();
            assert_eq!(resource_bytes(&v, &id, &r), b"resource");
            let expected: Vec<u8> = (0..16397)
                .map(|i| {
                    if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                        0
                    } else {
                        (i % 4096 * 17 % 251) as u8
                    }
                })
                .collect();
            assert_eq!(data(&v, &id, &r), expected);
            assert_eq!(
                attribute(&v, &id, name, &r),
                if operation == 4 { None } else { Some(value) }
            );
            if flags == 10 && operation != 0 && operation != 4 {
                let metadata = v.metadata(&id, &r).unwrap();
                let raw = metadata
                    .attributes
                    .iter()
                    .find_map(|(name, field)| {
                        if name == &NativeName::Bytes(b"apfs.xattr-record".to_vec()) {
                            match field {
                                MetadataField::Opaque { bytes, .. } => Some(bytes),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    })
                    .unwrap();
                let key_len = 10 + usize::from(u16::from_le_bytes(raw[8..10].try_into().unwrap()));
                assert_eq!(
                    u16::from_le_bytes(raw[key_len..key_len + 2].try_into().unwrap()),
                    10
                );
            }
            drop(v);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

fn embedded_xattr_plan(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    r: &Resources,
) -> ApfsMutationPlan {
    let id = if operation == 5 {
        editor.directory_identity(17, r)
    } else {
        editor.file_identity(16, r)
    }
    .unwrap();
    let name = if operation == 0 {
        b"user/new".as_slice()
    } else if operation == 5 {
        b"user.directory".as_slice()
    } else {
        b"user.\xc3\xa9".as_slice()
    };
    match operation {
        4 => editor.plan_remove_xattr(&id, name, r),
        2 => editor.plan_set_xattr(&id, name, &vec![0x91; 3804], r),
        3 => editor.plan_set_xattr(&id, name, &[], r),
        _ => editor.plan_set_xattr(&id, name, b"new exact bytes\0", r),
    }
    .unwrap()
}
#[test]
fn embedded_xattr_all_blocks_and_barriers_cold_recover_four_models() {
    for distinct in [false, true] {
        for operation in 0..6 {
            let make = |write_durable, failed_flush_durable| {
                let visible = embedded_xattr_seed(if distinct { 10 } else { 2 });
                Arc::new(Mutex::new(CutState {
                    durable: visible.clone(),
                    visible,
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable,
                    failed_flush_durable,
                }))
            };
            let r = resources();
            let state = make(true, true);
            let old = signature(state.lock().unwrap().visible.clone(), &r);
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
            let plan = embedded_xattr_plan(&editor, operation, &r);
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            let new = signature(state.lock().unwrap().visible.clone(), &r);
            let writes = state.lock().unwrap().writes;
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let per_block = 4096usize.div_ceil(61);
            assert!(writes.is_multiple_of(per_block));
            let mut cuts: Vec<_> = (0..writes / per_block)
                .map(|block| (Some(block * per_block), None))
                .collect();
            cuts.push((Some(writes - 1), None));
            cuts.extend((0..5).map(|barrier| (None, Some(barrier))));
            println!(
                "embedded_xattr_operation={operation} distinct_data_stream={distinct} native_block_writes={} cuts={} models=4 scenarios={}",
                writes / per_block,
                cuts.len(),
                cuts.len() * 4
            );
            for write_durable in [false, true] {
                for failed_flush_durable in [false, true] {
                    for &(cut_write, cut_flush) in &cuts {
                        let r = resources();
                        let state = make(write_durable, failed_flush_durable);
                        let mut editor =
                            ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                        let plan = embedded_xattr_plan(&editor, operation, &r);
                        let anchor = editor.recovery_anchor();
                        {
                            let mut s = state.lock().unwrap();
                            s.cut_write = cut_write;
                            s.cut_flush = cut_flush;
                        }
                        assert_eq!(
                            editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
                            ErrorKind::InterruptedWrite
                        );
                        drop(editor);
                        assert_eq!(r.memory.used(), 0);
                        {
                            let mut s = state.lock().unwrap();
                            s.visible = s.durable.clone();
                            s.cut_write = None;
                            s.cut_flush = None;
                        }
                        let recovered = ApfsEditor::recover_with_anchor(
                            CutDisk(state.clone()),
                            &anchor,
                            limits(),
                            &r,
                        )
                        .unwrap();
                        let xid = recovered.checkpoint_xid();
                        assert!(xid == 1 || xid == 2);
                        assert_eq!(
                            &signature(state.lock().unwrap().visible.clone(), &r),
                            if xid == 1 { &old } else { &new }
                        );
                        drop(recovered);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn native_embedded_xattr_seed(image: &mut [u8], flags: u16) {
    fixture::insert_native_shared(image, true);
    let mut records = embedded_xattr_records(flags);
    for (key, value) in &mut records {
        if u64::from_le_bytes(key[..8].try_into().unwrap()) >> 60 == 8 {
            let physical = u64::from_le_bytes(value[8..16].try_into().unwrap());
            if physical != 0 {
                fixture::p64(value, 8, physical + 200);
            }
        }
    }
    image[174 * 4096..175 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
}
#[test]
#[ignore = "requires checked native source and explicit fresh embedded-xattr evidence directory"]
fn native_embedded_xattr_mutations_checker_cold_and_complete_streams() {
    native_mutation_gate(true, false, true, false);
}

#[test]
fn embedded_xattr_caps_names_special_semantics_foreign_cancel_and_budget_are_prewrite() {
    let r = resources();
    let (editor, bytes, writes) = setup(&r);
    let original = bytes.lock().unwrap().clone();
    let id = editor.file_identity(16, &r).unwrap();
    for name in [
        b"".as_slice(),
        b"a\0b",
        b"com.apple.ResourceFork",
        b"com.apple.system.Security",
        b"com.apple.decmpfs",
        b"com.apple.FinderInfo",
        b"com.apple.fs.cow-exempt-file-count",
        &[0xff],
    ] {
        assert!(editor.plan_set_xattr(&id, name, b"bytes", &r).is_err());
    }
    assert!(
        editor
            .plan_set_xattr(&id, &vec![b'a'; 822], b"bytes", &r)
            .is_err()
    );
    assert!(
        editor
            .plan_set_xattr(&id, b"user.test", &vec![0; 3805], &r)
            .is_err()
    );
    assert!(editor.plan_remove_xattr(&id, b"user.absent", &r).is_err());
    let mut foreign = id.clone();
    foreign.source += 1;
    assert_eq!(
        editor
            .plan_set_xattr(&foreign, b"user.test", b"bytes", &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        editor
            .plan_set_xattr(&id, b"user.test", b"bytes", &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    let held = r
        .memory
        .reserve(384 * 1024 * 1024 - r.memory.used())
        .unwrap();
    assert_eq!(
        editor
            .plan_set_xattr(&id, b"user.test", b"bytes", &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    drop(held);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(*bytes.lock().unwrap(), original);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn external_generic_xattr_cow_operations_preserve_other_inode_and_data() {
    let name = "user/external.é".as_bytes();
    let kind = StreamKind::Named(NativeName::Bytes(name.to_vec()));
    for shared in [false, true] {
        for operation in 0..6 {
            let r = resources();
            let bytes = Arc::new(Mutex::new(resource_fixture::generic_seed(shared, 0)));
            let writes = Arc::new(AtomicUsize::new(0));
            let mut editor = ApfsEditor::open(
                Disk {
                    bytes: bytes.clone(),
                    writes,
                },
                1026,
                limits(),
                &r,
            )
            .unwrap();
            let id = editor.file_identity(21, &r).unwrap();
            let plan = match operation {
                0 => editor.plan_replace_xattr_stream(&id, name, Input::new(16397), &r),
                1 => editor.plan_range_xattr_stream(&id, name, 2, Input::new(3), &r),
                2 => editor.plan_truncate_xattr_stream(&id, name, 16397, &r),
                3 => editor.plan_truncate_xattr_stream(&id, name, 3, &r),
                4 => editor.plan_set_xattr(&id, name, b"embedded", &r),
                _ => editor.plan_remove_xattr(&id, name, &r),
            }
            .unwrap();
            let anchor = editor.recovery_anchor();
            editor.commit_range(plan, &anchor, &r).unwrap();
            drop(editor);
            let v = reopen(bytes.lock().unwrap().clone(), &r);
            let original = v
                .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
                .unwrap();
            let changed = v
                .lookup(&[NativeName::Bytes(b"Clone".to_vec())], &r)
                .unwrap();
            assert_eq!(data(&v, &original, &r), data(&v, &changed, &r));
            assert_eq!(
                read_all(&v.open_stream(&original, &kind, &r).unwrap(), 65536, &r)
                    .unwrap()
                    .get()
                    .as_slice(),
                b"resource"
            );
            if operation < 4 {
                let actual =
                    read_all(&v.open_stream(&changed, &kind, &r).unwrap(), 65536, &r).unwrap();
                let expected = match operation {
                    0 => Input::new(16397).model(),
                    1 => {
                        let mut b = b"resource".to_vec();
                        b[2..5].copy_from_slice(&Input::new(3).model());
                        b
                    }
                    2 => {
                        let mut b = b"resource".to_vec();
                        b.resize(16397, 0);
                        b
                    }
                    _ => b"res".to_vec(),
                };
                assert_eq!(actual.get().as_slice(), expected);
            } else {
                assert!(v.open_stream(&changed, &kind, &r).is_err());
                if operation == 4 {
                    assert_eq!(
                        attribute(&v, &changed, name, &r),
                        Some(b"embedded".to_vec())
                    );
                }
            }
            drop(v);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn external_generic_xattr_all_blocks_and_barriers_cold_recover_four_models() {
    for distinct in [false, true] {
        for operation in 0..7 {
            let make = |write_durable, failed_flush_durable| {
                let visible = resource_fixture::generic_seed(distinct, 0);
                Arc::new(Mutex::new(CutState {
                    durable: visible.clone(),
                    visible,
                    writes: 0,
                    flushes: 0,
                    cut_write: None,
                    cut_flush: None,
                    write_durable,
                    failed_flush_durable,
                }))
            };
            let r = resources();
            let state = make(true, true);
            let old = signature(state.lock().unwrap().visible.clone(), &r);
            let mut editor = ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
            let plan = external_generic_plan(&editor, operation, &r);
            let anchor = editor.recovery_anchor();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            let new = signature(state.lock().unwrap().visible.clone(), &r);
            let writes = state.lock().unwrap().writes;
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            let per_block = 4096usize.div_ceil(61);
            assert!(writes.is_multiple_of(per_block));
            let mut cuts: Vec<_> = (0..writes / per_block)
                .map(|block| (Some(block * per_block), None))
                .collect();
            cuts.push((Some(writes - 1), None));
            cuts.extend((0..5).map(|barrier| (None, Some(barrier))));
            println!(
                "external_generic_operation={operation} distinct_data_stream={distinct} native_block_writes={} cuts={} models=4 scenarios={}",
                writes / per_block,
                cuts.len(),
                cuts.len() * 4
            );
            for write_durable in [false, true] {
                for failed_flush_durable in [false, true] {
                    for &(cut_write, cut_flush) in &cuts {
                        let r = resources();
                        let state = make(write_durable, failed_flush_durable);
                        let mut editor =
                            ApfsEditor::open(CutDisk(state.clone()), 1026, limits(), &r).unwrap();
                        let plan = external_generic_plan(&editor, operation, &r);
                        let anchor = editor.recovery_anchor();
                        {
                            let mut s = state.lock().unwrap();
                            s.cut_write = cut_write;
                            s.cut_flush = cut_flush;
                        }
                        assert_eq!(
                            editor.commit_mutation(plan, &anchor, &r).unwrap_err().kind,
                            ErrorKind::InterruptedWrite
                        );
                        drop(editor);
                        assert_eq!(r.memory.used(), 0);
                        {
                            let mut s = state.lock().unwrap();
                            s.visible = s.durable.clone();
                            s.cut_write = None;
                            s.cut_flush = None;
                        }
                        let recovered = ApfsEditor::recover_with_anchor(
                            CutDisk(state.clone()),
                            &anchor,
                            limits(),
                            &r,
                        )
                        .unwrap();
                        let xid = recovered.checkpoint_xid();
                        assert!(xid == 1 || xid == 2);
                        assert_eq!(
                            &signature(state.lock().unwrap().visible.clone(), &r),
                            if xid == 1 { &old } else { &new }
                        );
                        drop(recovered);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn external_generic_plan(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    r: &Resources,
) -> ApfsMutationPlan {
    let id = editor.file_identity(21, r).unwrap();
    let name = "user/external.é".as_bytes();
    match operation {
        0 => editor.plan_replace_xattr_stream(&id, name, Input::new(16397), r),
        1 => editor.plan_range_xattr_stream(&id, name, 2, Input::new(3), r),
        2 => editor.plan_truncate_xattr_stream(&id, name, 16397, r),
        3 => editor.plan_truncate_xattr_stream(&id, name, 3, r),
        4 => editor.plan_truncate_xattr_stream(&id, name, 0, r),
        5 => editor.plan_set_xattr(&id, name, b"embedded", r),
        _ => editor.plan_remove_xattr(&id, name, r),
    }
    .unwrap()
}

fn native_generic_xattr_seed(image: &mut [u8], shared: bool) {
    let (mut fs, _) = resource_fixture::records(shared, 0);
    for (key, value) in &mut fs {
        let tag = u64::from_le_bytes(key[..8].try_into().unwrap());
        if tag == (4u64 << 60 | 21) {
            key.truncate(8);
            let name = "user/external.é\0".as_bytes();
            key.extend_from_slice(&(name.len() as u16).to_le_bytes());
            key.extend_from_slice(name);
        }
        if tag == (3u64 << 60 | 21) {
            let flags = u64::from_le_bytes(value[48..56].try_into().unwrap());
            fixture::p64(value, 48, (flags & !0x4000) | 0x8000);
        }
        if tag >> 60 == 8 {
            let physical = u64::from_le_bytes(value[8..16].try_into().unwrap());
            if physical != 0 {
                fixture::p64(value, 8, physical + 200);
            }
        }
    }
    image[174 * 4096..175 * 4096].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &fs, false));
}
fn native_generic_xattr_plan(
    editor: &ApfsEditor<CutDisk>,
    operation: usize,
    r: &Resources,
) -> ApfsMutationPlan {
    if operation == 5 {
        let id = editor.file_identity(21, r).unwrap();
        editor
            .plan_set_xattr(
                &id,
                "user/external.é".as_bytes(),
                &Input::new(29).model(),
                r,
            )
            .unwrap()
    } else {
        external_generic_plan(editor, operation, r)
    }
}
#[test]
#[ignore = "requires explicit checked native source and fresh external-xattr evidence directory"]
fn native_external_xattr_mutations_checker_cold_and_complete_streams() {
    native_mutation_gate(true, true, false, true);
}
