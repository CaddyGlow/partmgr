#![cfg(feature = "std")]

use partmgr::{
    fs_core::{
        Budget, Cancellation, Error, ErrorKind, FileRead, LogicalExtent, NativeName, ObjectId,
        Resources, Result, StreamKind, TreeSource, read_all,
    },
    fs_flash::{FlashGeometry, FlashImage, FlashLayout, FlashLimits, FlashProgramming},
    fs_jffs2::{Jffs2Endian, Jffs2ReadLimits, Jffs2Volume},
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
    fs_jffs2_edit::{Jffs2CreateMetadata, Jffs2EditLimits, Jffs2Editor, recover},
    fs_storage::{BoundedSession, SectorGeometry},
    storage::{FileStorage, Storage},
};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use virtdisk::{DiskView, RawDisk};
struct NativeRangeSource {
    file: fs::File,
    id: ObjectId,
    length: u64,
}
impl FileRead for NativeRangeSource {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, p: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        use std::os::unix::fs::FileExt;
        r.cancellation.check()?;
        if self
            .file
            .metadata()
            .map_err(|e| Error::io("native range source metadata", e))?
            .len()
            != self.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "native range source length changed",
            ));
        }
        self.file
            .read_at(out, p)
            .map_err(|e| Error::io("native range source read", e))
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "native range source has no allocation profile",
        ))
    }
}
const SOURCES: &[(&str, &[u8])] = &[
    ("src/lib.rs", include_bytes!("../src/lib.rs")),
    ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
    (
        "src/fs_jffs2_tree.rs",
        include_bytes!("../src/fs_jffs2_tree.rs"),
    ),
    ("src/fs_jffs2.rs", include_bytes!("../src/fs_jffs2.rs")),
    (
        "src/fs_jffs2_audit.rs",
        include_bytes!("../src/fs_jffs2_audit.rs"),
    ),
    (
        "src/fs_jffs2_edit.rs",
        include_bytes!("../src/fs_jffs2_edit.rs"),
    ),
    (
        "src/fs_jffs2_edit_journal.rs",
        include_bytes!("../src/fs_jffs2_edit_journal.rs"),
    ),
    (
        "src/fs_jffs2_edit_namespace.rs",
        include_bytes!("../src/fs_jffs2_edit_namespace.rs"),
    ),
    (
        "src/fs_jffs2_edit_file.rs",
        include_bytes!("../src/fs_jffs2_edit_file.rs"),
    ),
    (
        "src/fs_jffs2_edit_gc.rs",
        include_bytes!("../src/fs_jffs2_edit_gc.rs"),
    ),
    ("src/fs_flash.rs", include_bytes!("../src/fs_flash.rs")),
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
    ("src/fs_storage.rs", include_bytes!("../src/fs_storage.rs")),
    ("src/storage.rs", include_bytes!("../src/storage.rs")),
    (
        "tests/fs_jffs2_edit.rs",
        include_bytes!("../tests/fs_jffs2_edit.rs"),
    ),
    (
        "tests/fs_jffs2_edit_native.rs",
        include_bytes!("../tests/fs_jffs2_edit_native.rs"),
    ),
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
];
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(tool: &Path, args: &[String], receipt: &mut String) -> std::process::Output {
    receipt.push_str(&format!(
        "argv={:?}\n",
        std::iter::once(tool.display().to_string())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
    ));
    let output = Command::new(tool).args(args).output().unwrap();
    receipt.push_str(&format!(
        "status={} stdout_bytes={} stdout_sha256={} stderr={}\n",
        output.status,
        output.stdout.len(),
        hash(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        output.status.success(),
        "{}: {}",
        tool.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn geometry() -> FlashGeometry {
    FlashGeometry {
        erased_byte: 255,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 65536,
        program_bytes: 4,
        layout: FlashLayout::LogicalNor,
    }
}
fn limits() -> Jffs2EditLimits {
    Jffs2EditLimits {
        read: Jffs2ReadLimits {
            scan_bytes: 1 << 20,
            nodes: 1024,
            inodes: 256,
            fragments: 4096,
            native_bytes: 65536,
            work: 1_000_000,
        },
        audit: Jffs2AuditLimits {
            entries: 1024,
            work: 4096,
            findings: 64,
        },
        journal_bytes: 262144,
        slots: 64,
        file_bytes: 32768,
        scratch_bytes: 4096,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    Program,
    Erase,
}
struct Backend {
    storage: BoundedSession<FileStorage>,
    fault: Fault,
    cut: bool,
}
impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        self.storage.len()
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        self.storage.read_exact_at(p, b)
    }
    fn write_at(&mut self, p: u64, b: &[u8]) -> io::Result<usize> {
        if !self.cut
            && matches!(self.fault, Fault::Program | Fault::Erase)
            && (matches!(self.fault, Fault::Program) || b.iter().all(|v| *v == 255))
        {
            self.cut = true;
            let n = b.len().min(4);
            assert_eq!(self.storage.write_at(p, &b[..n])?, n);
            self.storage.flush()?;
            return Err(io::Error::other(
                "modeled partial native NOR write after actual flush",
            ));
        }
        self.storage.write_at(p, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.storage.flush()
    }
}
fn flash(path: &Path, length: u64, fault: Fault, r: &Resources) -> FlashImage<Backend> {
    FlashImage::new(
        Backend {
            storage: BoundedSession::new(
                FileStorage::open(path).unwrap(),
                8192,
                length,
                SectorGeometry::new(Some(512), Some(512)).unwrap(),
            )
            .unwrap(),
            fault,
            cut: false,
        },
        geometry(),
        &[],
        FlashLimits {
            bad_blocks: 0,
            operation_bytes: 65536,
            scratch_bytes: 512,
        },
        r,
    )
    .unwrap()
}
fn journal(path: &Path, n: u64) -> FileStorage {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.set_len(n).unwrap();
    file.sync_all().unwrap();
    drop(file);
    FileStorage::open(path).unwrap()
}
fn capture(image: &Path, raw: &Path, length: usize, original: &[u8]) -> Vec<u8> {
    let bytes = fs::read(image).unwrap();
    assert_eq!(&bytes[..8192], &original[..8192]);
    assert_eq!(&bytes[8192 + length..], &original[8192 + length..]);
    let body = bytes[8192..8192 + length].to_vec();
    fs::write(raw, &body).unwrap();
    body
}
fn reopen(image: &Path, length: u64, expected: &[u8], r: &Resources) {
    let disk = RawDisk::open(image).unwrap();
    let source = Arc::new(DiskView::new(Arc::new(disk), 8192, length).unwrap());
    let volume =
        Jffs2Volume::open(source, geometry(), Jffs2Endian::Little, limits().read, r).unwrap();
    assert!(audit(&volume, limits().audit, r).unwrap().is_clean());
    let tree =
        partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(volume, limits().audit, r).unwrap();
    let page = tree.directory_page(&tree.root(), None, 64, r).unwrap();
    let entry = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
        .unwrap();
    let f = tree
        .open_stream(&entry.object, &StreamKind::Data, r)
        .unwrap();
    assert_eq!(
        read_all(f.as_ref(), 32768, r).unwrap().get().as_slice(),
        expected
    );
    assert!(
        page.entries
            .iter()
            .any(|e| e.name == NativeName::Bytes(b"added".to_vec()))
    );
}
fn oracle(tools: &Path, raw: &Path, payload: &[u8], receipt: &mut String, output: &Path) {
    let dump = run(
        &tools.join("jffs2dump"),
        &["-l".into(), "-c".into(), raw.display().to_string()],
        receipt,
    );
    let text = String::from_utf8_lossy(&dump.stdout).to_lowercase();
    assert!(
        !text.contains("wrong") && !text.contains("invalid"),
        "{}",
        text
    );
    fs::write(output.with_extension("dump.txt"), &dump.stdout).unwrap();
    let native = run(
        &tools.join("jffs2reader"),
        &[raw.display().to_string(), "-f".into(), "/payload".into()],
        receipt,
    );
    assert_eq!(native.stdout, payload);
    fs::write(output, &native.stdout).unwrap();
    receipt.push_str(&format!("oracle=completed-CRC-validated-single-node-only payload_sha256={} bytes={} raw_sha256={}\n",hash(payload),payload.len(),hash(&fs::read(raw).unwrap())));
}
#[test]
#[ignore = "requires JFFS2_EDIT_EVIDENCE, JFFS2_TOOLS and JFFS2_EXTRACTOR; enabled missing prerequisites fail"]
fn native_independent_incremental_history_append_shrink_restart_and_gc() {
    let evidence = PathBuf::from(
        std::env::var_os("JFFS2_EDIT_EVIDENCE").expect("enabled gate requires evidence directory"),
    );
    fs::create_dir_all(&evidence).unwrap();
    let receipt_path = evidence.join("jffs2-owned-nor-append-gc-v1.txt");
    fs::write(&receipt_path, "result=running\n").unwrap();
    let tools =
        PathBuf::from(std::env::var_os("JFFS2_TOOLS").expect("enabled gate requires mtd-utils"));
    let mut receipt = String::from(
        "profile=jffs2-owned-logical-nor-packed-pristine-gc-v5\ngeometry=LE erase65536 program4 FF 1048576-byte region (327680-byte mtd-utils history plus declared FF capacity) at offset8192 framed raw image\nmodeled_faults=partialprogram+partialerase actual backend sync_all; no physical power-loss claim\noracle=jffs2dump CRC+native nodes; legacy jffs2reader completed single-node /payload only, no torn-namespace/kernel-mount claim\ntest=cargo test --all-features --locked --test fs_jffs2_edit_native -- --ignored --nocapture\n",
    );
    for name in ["mkfs.jffs2", "jffs2dump", "jffs2reader"] {
        let p = tools.join(name);
        assert!(p.is_file(), "missing {}", p.display());
        receipt.push_str(&format!(
            "tool={} sha256={}\n",
            p.display(),
            hash(&fs::read(&p).unwrap())
        ));
        if name != "jffs2reader" {
            let version = run(&p, &["--version".into()], &mut receipt);
            receipt.push_str(&format!(
                "version={}\n",
                String::from_utf8_lossy(&version.stdout)
            ));
        } else {
            receipt.push_str("jffs2reader_version=legacy binary from same mtd-utils package; no reliable --version option\n");
        }
    }
    for &(path, baked) in SOURCES {
        let live = fs::read(path).unwrap();
        assert!(live == baked, "stale compiled source {path}");
        receipt.push_str(&format!(
            "source={} sha256={} baked_live_match=true\n",
            path,
            hash(baked)
        ));
    }
    let executable = std::env::current_exe().unwrap();
    let executable_hash = hash(&fs::read(&executable).unwrap());
    let mut tool_hashes = ["mkfs.jffs2", "jffs2dump", "jffs2reader"]
        .into_iter()
        .map(|name| {
            let path = tools.join(name);
            let digest = hash(&fs::read(&path).unwrap());
            (path, digest)
        })
        .collect::<Vec<_>>();
    let extractor = PathBuf::from(
        std::env::var_os("JFFS2_EXTRACTOR")
            .expect("enabled range gate requires independent Jefferson"),
    );
    let version = run(&extractor, &["--help".into()], &mut receipt);
    receipt.push_str(&format!(
        "extractor_help={}\n",
        String::from_utf8_lossy(&version.stdout)
    ));
    let extractor_bytes = fs::read(&extractor).unwrap();
    let python = PathBuf::from(
        String::from_utf8_lossy(&extractor_bytes)
            .lines()
            .next()
            .unwrap()
            .strip_prefix("#!")
            .unwrap(),
    );
    for path in [&extractor, &python] {
        let digest = hash(&fs::read(path).unwrap());
        receipt.push_str(&format!("tool={:?} sha256={digest}\n", path));
        tool_hashes.push((path.clone(), digest));
    }
    let sources=run(&python,&["-c".into(),"import jefferson.jffs2,importlib.metadata;print(jefferson.jffs2.__file__);print('versions='+','.join(n+'='+importlib.metadata.version(n) for n in ['jefferson','dissect.cstruct','lzallright','click']))".into()],&mut receipt);
    let paths = String::from_utf8(sources.stdout).unwrap();
    let parser = PathBuf::from(paths.lines().next().unwrap());
    let digest = hash(&fs::read(&parser).unwrap());
    tool_hashes.push((parser.clone(), digest.clone()));
    receipt.push_str(&format!(
        "extractor_parser={:?} sha256={digest} {}\n",
        parser,
        paths.lines().nth(1).unwrap()
    ));
    receipt.push_str(&format!("test_executable_sha256={}\n", executable_hash));
    if let Some(archive) = std::env::var_os("JFFS2_SPEC_ARCHIVE") {
        let dir = evidence.join("primary-spec");
        fs::create_dir_all(&dir).unwrap();
        for entry in fs::read_dir(archive).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let b = fs::read(entry.path()).unwrap();
                fs::write(dir.join(entry.file_name()), &b).unwrap();
                receipt.push_str(&format!(
                    "primary_source={:?} sha256={}\n",
                    entry.file_name(),
                    hash(&b)
                ));
            }
        }
    }
    let tree = evidence.join("source-tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("a_dummy"), b"dummy").unwrap();
    let old = (0..2048)
        .map(|n| ((n * 29 + 3) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(tree.join("payload"), &old).unwrap();
    let addition = evidence.join("source-addition");
    fs::create_dir(&addition).unwrap();
    fs::write(
        addition.join("added"),
        b"independently incremented disjoint native history\n",
    )
    .unwrap();
    let base = evidence.join("base.jffs2");
    let increment = evidence.join("increment.jffs2");
    run(
        &tools.join("mkfs.jffs2"),
        &[
            "-r".into(),
            tree.display().to_string(),
            "-o".into(),
            base.display().to_string(),
            "-l".into(),
            "-m".into(),
            "none".into(),
            "-s".into(),
            "32768".into(),
            "-e".into(),
            "65536".into(),
            "--pad=262144".into(),
            "-f".into(),
            "-U".into(),
        ],
        &mut receipt,
    );
    run(
        &tools.join("mkfs.jffs2"),
        &[
            "-r".into(),
            addition.display().to_string(),
            "-o".into(),
            increment.display().to_string(),
            "-i".into(),
            base.display().to_string(),
            "-l".into(),
            "-m".into(),
            "none".into(),
            "-s".into(),
            "32768".into(),
            "-e".into(),
            "65536".into(),
            "--pad=65536".into(),
            "-f".into(),
            "-U".into(),
        ],
        &mut receipt,
    );
    let mut source = fs::read(&base).unwrap();
    source.extend_from_slice(&fs::read(&increment).unwrap());
    assert_eq!(source.len(), 327680);
    source.resize(16 * 65536, 255);
    let source_path = evidence.join("independent-history.jffs2");
    fs::write(&source_path, &source).unwrap();
    oracle(
        &tools,
        &source_path,
        &old,
        &mut receipt,
        &evidence.join("original-native-payload.bin"),
    );
    let source_hash = hash(&source);
    let binding: [u8; 32] = Sha256::digest(&source).into();
    let mut framed = vec![0xa5; 8192];
    framed.extend_from_slice(&source);
    framed.extend_from_slice(&[0x5a; 8192]);
    let image = evidence.join("framed-owned.img");
    fs::write(&image, &framed).unwrap();
    let r = resources();
    let large = (0..5013)
        .map(|n| ((n * 73 + 11) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(evidence.join("expected-replacement.bin"), &large).unwrap();
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::None, &r),
        binding,
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    let plan = editor
        .replace(&editor.identity(1).unwrap(), b"payload", &large, 1234, &r)
        .unwrap();
    let mut j = journal(&evidence.join("append.journal"), plan.journal_length());
    let report = editor.commit(plan, &mut j, &r).unwrap();
    drop(j);
    drop(editor);
    let raw = evidence.join("after-append.jffs2");
    let body = capture(&image, &raw, source.len(), &framed);
    assert_eq!(report.sha256, <[u8; 32]>::from(Sha256::digest(&body)));
    reopen(&image, source.len() as u64, &large, &r);
    oracle(
        &tools,
        &raw,
        &large,
        &mut receipt,
        &evidence.join("append-native-payload.bin"),
    );
    let small = (0..333)
        .map(|n| ((n * 41 + 19) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(evidence.join("expected-shrink.bin"), &small).unwrap();
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::Program, &r),
        binding,
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    let plan = editor
        .replace(&editor.identity(1).unwrap(), b"payload", &small, 2345, &r)
        .unwrap();
    let shrink_journal = evidence.join("shrink.journal");
    let mut j = journal(&shrink_journal, plan.journal_length());
    let failure = editor.commit(plan, &mut j, &r).unwrap_err();
    assert!(failure.mutation_attempted && failure.mutation_uncertain);
    receipt.push_str(&format!("modeled_program_failure={failure:?}\n"));
    drop(j);
    drop(editor.into_flash());
    let mut f = flash(&image, source.len() as u64, Fault::None, &r);
    let mut j = FileStorage::open(&shrink_journal).unwrap();
    let report = recover(&mut f, &mut j, binding, Jffs2Endian::Little, limits(), &r).unwrap();
    let repeated = recover(&mut f, &mut j, binding, Jffs2Endian::Little, limits(), &r).unwrap();
    assert_eq!(repeated.accepted_bytes, 0);
    drop(j);
    drop(f);
    let raw = evidence.join("after-shrink-recovery.jffs2");
    let body = capture(&image, &raw, source.len(), &framed);
    assert_eq!(report.sha256, <[u8; 32]>::from(Sha256::digest(&body)));
    reopen(&image, source.len() as u64, &small, &r);
    oracle(
        &tools,
        &raw,
        &small,
        &mut receipt,
        &evidence.join("shrink-native-payload.bin"),
    );
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::Erase, &r),
        binding,
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    let plan = editor.collect(0, &r).unwrap();
    let gc_journal = evidence.join("gc.journal");
    let mut j = journal(&gc_journal, plan.journal_length());
    let failure = editor.commit(plan, &mut j, &r).unwrap_err();
    assert!(failure.mutation_attempted && failure.mutation_uncertain);
    receipt.push_str(&format!("modeled_erase_failure={failure:?}\n"));
    drop(j);
    drop(editor.into_flash());
    let mut f = flash(&image, source.len() as u64, Fault::None, &r);
    let mut j = FileStorage::open(&gc_journal).unwrap();
    let report = recover(&mut f, &mut j, binding, Jffs2Endian::Little, limits(), &r).unwrap();
    drop(j);
    drop(f);
    let raw = evidence.join("after-gc-recovery.jffs2");
    let body = capture(&image, &raw, source.len(), &framed);
    assert!(body[..65536].iter().all(|v| *v == 255));
    assert_eq!(report.sha256, <[u8; 32]>::from(Sha256::digest(&body)));
    reopen(&image, source.len() as u64, &small, &r);
    oracle(
        &tools,
        &raw,
        &small,
        &mut receipt,
        &evidence.join("gc-native-payload.bin"),
    );
    let relocated = run(
        &tools.join("jffs2reader"),
        &[raw.display().to_string(), "-f".into(), "/a_dummy".into()],
        &mut receipt,
    );
    assert_eq!(relocated.stdout, b"dummy");
    fs::write(
        evidence.join("gc-native-relocated-dummy.bin"),
        &relocated.stdout,
    )
    .unwrap();
    receipt.push_str(&format!(
        "gc_relocated_inode_oracle=passed bytes=5 sha256={}\n",
        hash(&relocated.stdout)
    ));
    assert_eq!(&body[4 * 65536..], &source[4 * 65536..]);
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::None, &r),
        binding,
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    let metadata = Jffs2CreateMetadata {
        permissions: 0o750,
        uid: 17,
        gid: 23,
        accessed: 10,
        modified: 40,
        changed: 50,
    };
    let operations = [
        "create-directory",
        "create-file",
        "move",
        "hardlink",
        "unlink",
        "create-symlink",
    ];
    let created = b"native namespace payload";
    for operation in operations {
        let root = editor.identity(1).unwrap();
        let plan = match operation {
            "create-directory" => editor.create_directory(&root, b"nested", metadata, &r),
            "create-file" => editor.create_file(&root, b"created", created, metadata, &r),
            "move" => editor.rename(
                &root,
                b"created",
                &editor.identity(7).unwrap(),
                b"moved",
                60,
                &r,
            ),
            "hardlink" => editor.link(&editor.identity(8).unwrap(), &root, b"alias", 61, &r),
            "unlink" => editor.unlink(&editor.identity(7).unwrap(), b"moved", 62, &r),
            "create-symlink" => editor.create_symlink(&root, b"link", b"alias", metadata, &r),
            _ => unreachable!(),
        }
        .unwrap();
        let mut j = journal(
            &evidence.join(format!("namespace-{operation}.journal")),
            plan.journal_length(),
        );
        let report = editor.commit(plan, &mut j, &r).unwrap();
        receipt.push_str(&format!(
            "namespace_operation={operation} whole_sha256={:x}\n",
            Sha256::digest(fs::read(&image).unwrap())
        ));
        assert!(!report.mutation_uncertain);
    }
    // The created symlink is allocated in pristine block nine under this exact fixture.
    let plan = editor.collect(9 * 65536, &r).unwrap();
    let mut j = journal(
        &evidence.join("namespace-symlink-gc.journal"),
        plan.journal_length(),
    );
    editor.commit(plan, &mut j, &r).unwrap();
    drop(j);
    drop(editor.into_flash());
    let namespace_raw = evidence.join("after-namespace-symlink-gc.jffs2");
    let namespace_body = capture(&image, &namespace_raw, source.len(), &framed);
    let dump = run(
        &tools.join("jffs2dump"),
        &["-l".into(), namespace_raw.display().to_string()],
        &mut receipt,
    );
    let text = String::from_utf8_lossy(&dump.stdout).to_lowercase();
    assert!(!text.contains("wrong") && !text.contains("bad crc"));
    fs::write(evidence.join("namespace-native.dump.txt"), dump.stdout).unwrap();
    let extracted = run(
        &tools.join("jffs2reader"),
        &[
            namespace_raw.display().to_string(),
            "-f".into(),
            "/alias".into(),
        ],
        &mut receipt,
    );
    assert_eq!(extracted.stdout, created);
    fs::write(
        evidence.join("namespace-native-alias.bin"),
        &extracted.stdout,
    )
    .unwrap();
    let source_view = Arc::new(
        DiskView::new(
            Arc::new(RawDisk::open(&image).unwrap()),
            8192,
            source.len() as u64,
        )
        .unwrap(),
    );
    let v = Jffs2Volume::open(
        source_view,
        geometry(),
        Jffs2Endian::Little,
        limits().read,
        &r,
    )
    .unwrap();
    assert!(audit(&v, limits().audit, &r).unwrap().is_clean());
    assert_eq!(
        read_all(&v.open_file(9, &r).unwrap(), 254, &r)
            .unwrap()
            .get()
            .as_slice(),
        b"alias"
    );
    drop(v);
    assert_eq!(
        &namespace_body[4 * 65536..5 * 65536],
        &source[4 * 65536..5 * 65536]
    );
    receipt.push_str(&format!("namespace_completed_oracle=CRC+legacy_single-node_alias_payload sha256={} symlink_target=framework-exact-no-follow gc_live_symlink=passed final_sha256={}\n", hash(created), hash(&namespace_body)));
    let mut range_limits = limits();
    range_limits.file_bytes = 256;
    let patch = (0..5000)
        .map(|n| ((n * 19 + 7) % 251) as u8)
        .collect::<Vec<_>>();
    let payload_path = evidence.join("range-input.bin");
    fs::write(&payload_path, &patch).unwrap();
    let payload = NativeRangeSource {
        file: fs::File::open(&payload_path).unwrap(),
        id: ObjectId {
            source: 99,
            generation: 1,
            native: b"range-input".to_vec(),
        },
        length: patch.len() as u64,
    };
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::None, &r),
        binding,
        Jffs2Endian::Little,
        range_limits,
        &r,
    )
    .unwrap();
    let plan = editor
        .link(
            &editor.identity(8).unwrap(),
            &editor.identity(1).unwrap(),
            b"alias2",
            70,
            &r,
        )
        .unwrap();
    let mut j = journal(
        &evidence.join("range-hardlink.journal"),
        plan.journal_length(),
    );
    editor.commit(plan, &mut j, &r).unwrap();
    drop(j);
    let plan = editor
        .write_range(&editor.identity(8).unwrap(), 13, &payload, 5013, 71, &r)
        .unwrap();
    let mut j = journal(&evidence.join("range-edit.journal"), plan.journal_length());
    editor.commit(plan, &mut j, &r).unwrap();
    drop(j);
    drop(editor.into_flash());
    drop(payload);
    let mut expected = created[..13].to_vec();
    expected.extend_from_slice(&patch);
    let range_raw = evidence.join("after-multi-node-range.jffs2");
    let range_body = capture(&image, &range_raw, source.len(), &framed);
    let dump = run(
        &tools.join("jffs2dump"),
        &["-l".into(), range_raw.display().to_string()],
        &mut receipt,
    );
    let text = String::from_utf8_lossy(&dump.stdout).to_lowercase();
    assert!(!text.contains("wrong") && !text.contains("bad crc"));
    fs::write(evidence.join("range-native.dump.txt"), dump.stdout).unwrap();
    let destination = evidence.join("range-extracted");
    // Jefferson's CLI guesses endian from byte zero, which is erased after GC.
    // Invoke its unchanged independent core with the declared LE geometry on exact raw bytes.
    let extraction = run(&python, &[
        "-c".into(),
        "import sys;from pathlib import Path;from jefferson.jffs2 import set_endianness,scan_fs,dump_fs;set_endianness('<');p=Path(sys.argv[2]);p.mkdir();dump_fs(scan_fs(Path(sys.argv[1]).read_bytes(),'<'),p)".into(),
        range_raw.display().to_string(), destination.display().to_string()
    ], &mut receipt);
    fs::write(
        evidence.join("range-extractor.stdout.txt"),
        &extraction.stdout,
    )
    .unwrap();
    receipt.push_str("extractor_profile=unchanged-Jefferson-core-explicit-LE exact-full-raw-input; CLI-bytezero-endian-guess-cannot-handle-erased-prefix\n");
    let extracted = fs::read(destination.join("alias2")).unwrap();
    assert_eq!(extracted, expected);
    fs::write(evidence.join("range-expected.bin"), &expected).unwrap();
    let source_view = Arc::new(
        DiskView::new(
            Arc::new(RawDisk::open(&image).unwrap()),
            8192,
            source.len() as u64,
        )
        .unwrap(),
    );
    let v = Jffs2Volume::open(
        source_view,
        geometry(),
        Jffs2Endian::Little,
        limits().read,
        &r,
    )
    .unwrap();
    assert!(audit(&v, limits().audit, &r).unwrap().is_clean());
    assert_eq!(
        read_all(&v.open_file(8, &r).unwrap(), 5013, &r)
            .unwrap()
            .get()
            .as_slice(),
        expected
    );
    let victim = v.inode(8).unwrap().latest_header_offset().unwrap() / 65536 * 65536;
    drop(v);
    let mut editor = Jffs2Editor::open(
        flash(&image, source.len() as u64, Fault::None, &r),
        binding,
        Jffs2Endian::Little,
        range_limits,
        &r,
    )
    .unwrap();
    let plan = editor.collect(victim, &r).unwrap();
    let mut j = journal(
        &evidence.join("multi-node-gc.journal"),
        plan.journal_length(),
    );
    editor.commit(plan, &mut j, &r).unwrap();
    drop(j);
    drop(editor.into_flash());
    let packed = fs::read(evidence.join("multi-node-gc.journal")).unwrap();
    let count = u32::from_le_bytes(packed[180..184].try_into().unwrap()) as usize;
    assert!(count >= 20);
    let mut cursor = 1024;
    let mut next_offset = None;
    let mut destination_block = None;
    let mut node_bytes = 0u64;
    for _ in 0..count {
        let offset = u64::from_le_bytes(packed[cursor..cursor + 8].try_into().unwrap());
        let length = u64::from_le_bytes(packed[cursor + 8..cursor + 16].try_into().unwrap());
        if let Some(next) = next_offset {
            assert_eq!(offset, next);
        }
        if let Some(block) = destination_block {
            assert_eq!(offset / 65536, block);
        }
        assert!(offset % 65536 >= 12 && offset % 65536 + length <= 65536);
        destination_block = Some(offset / 65536);
        next_offset = Some(offset + length);
        node_bytes += length;
        cursor += 16 + length as usize;
    }
    receipt.push_str(&format!("packed_pristine_gc=passed nodes={count} node_bytes={node_bytes} destination_blocks=1 reserved_prefix=12 aligned_records=4 journal_sha256={}\n", hash(&packed)));
    let gc_raw = evidence.join("after-multi-node-gc.jffs2");
    let gc_body = capture(&image, &gc_raw, source.len(), &framed);
    let dump = run(
        &tools.join("jffs2dump"),
        &["-l".into(), gc_raw.display().to_string()],
        &mut receipt,
    );
    let text = String::from_utf8_lossy(&dump.stdout).to_lowercase();
    assert!(!text.contains("wrong") && !text.contains("bad crc"));
    fs::write(evidence.join("multi-node-gc.dump.txt"), dump.stdout).unwrap();
    let destination = evidence.join("multi-node-gc-extracted");
    let extraction = run(&python, &["-c".into(), "import sys;from pathlib import Path;from jefferson.jffs2 import set_endianness,scan_fs,dump_fs;set_endianness('<');p=Path(sys.argv[2]);p.mkdir();dump_fs(scan_fs(Path(sys.argv[1]).read_bytes(),'<'),p)".into(), gc_raw.display().to_string(), destination.display().to_string()], &mut receipt);
    fs::write(
        evidence.join("multi-node-gc-extractor.stdout.txt"),
        extraction.stdout,
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("alias2")).unwrap(), expected);
    receipt.push_str(&format!("multi_node_gc_native=CRC+Jefferson-overlay victim={victim} original_inode=8 payload_bytes=5013 raw_sha256={} payload_sha256={} no-native-isize-zero-tail-oracle\n", hash(&gc_body), hash(&expected)));

    receipt.push_str(&format!("multi_node_range_native=CRC+Jefferson-version-overlay bytes=5013 patch_bytes=5000 preserved_prefix=13 inode=8 hardlinks=framework-identity raw_sha256={} payload_sha256={} no-native-truncate-isize-oracle\n",hash(&range_body),hash(&expected)));
    assert_eq!(hash(&fs::read(&source_path).unwrap()), source_hash);
    assert_eq!(r.memory.used(), 0);
    receipt.push_str(&format!("result=passed source_sha256={source_hash} framed_prefix_suffix=unchanged disjoint_increment_block=unchanged append_bytes=5013 shrink_bytes=333 final_gc_sha256={} leases=refunded\n",hash(&body)));
    for &(path, baked) in SOURCES {
        assert!(
            fs::read(path).unwrap() == baked,
            "source changed during native gate {path}"
        );
    }
    for (tool, expected) in tool_hashes {
        assert_eq!(
            hash(&fs::read(&tool).unwrap()),
            expected,
            "tool changed during gate {}",
            tool.display()
        );
    }
    assert_eq!(
        hash(&fs::read(executable).unwrap()),
        executable_hash,
        "test executable changed during gate"
    );
    receipt.push_str("source_tool_executable_end_revalidation=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}
