use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_apfs_edit::*, fs_core::*, storage::Storage};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
        .bytes
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
                    .bytes,
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
    data: Vec<u8>,
    resource: Vec<u8>,
}
fn signature(bytes: Vec<u8>, r: &Resources) -> Vec<Occurrence> {
    let v = reopen(bytes, r);
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
                    Ok(f) => read_all(&f, 65536, r).unwrap().bytes.clone(),
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
                data,
                resource,
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
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
    ("src/lib.rs", include_bytes!("../src/lib.rs")),
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
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
                    .bytes,
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
