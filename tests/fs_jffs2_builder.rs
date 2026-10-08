use partmgr::{
    fs_core::*, fs_flash::*, fs_jffs2::*, fs_jffs2_audit::*, fs_jffs2_builder::*, fs_jffs2_tree::*,
    storage::Storage,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use virtdisk::ReadAt;
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 0x4242,
        generation: 1,
        native: vec![n],
    }
}
struct Payload {
    bytes: Vec<u8>,
    id: ObjectId,
    len: AtomicU64,
    fail: AtomicBool,
    max_read: AtomicUsize,
}
impl FileRead for Payload {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.len.load(Ordering::Relaxed)
    }
    fn read_at(&self, p: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        self.max_read.fetch_max(b.len(), Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::io(
                "builder causal source",
                io::Error::other("modeled source failure"),
            ));
        }
        let n = (self.len().saturating_sub(p)).min(b.len() as u64) as usize;
        b[..n].copy_from_slice(&self.bytes[p as usize..p as usize + n]);
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: ExtentKind::Data,
        })
    }
}
struct Tree {
    file: Arc<Payload>,
    reverse: bool,
    collision: bool,
    utf16_root: bool,
    nonutf8: bool,
    special: bool,
    extra: bool,
    stale: AtomicBool,
}
impl Tree {
    fn new(reverse: bool) -> Self {
        let mut bytes: Vec<u8> = (0..90013).map(|n| ((n * 73 + 11) % 256) as u8).collect();
        bytes[..4096].fill(0);
        let len = bytes.len() as u64;
        Self {
            file: Arc::new(Payload {
                bytes,
                id: id(3),
                len: AtomicU64::new(len),
                fail: AtomicBool::new(false),
                max_read: AtomicUsize::new(0),
            }),
            reverse,
            collision: false,
            utf16_root: false,
            nonutf8: false,
            special: false,
            extra: false,
            stale: AtomicBool::new(false),
        }
    }
}
impl TreeSource for Tree {
    fn root(&self) -> ObjectId {
        id(1)
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn revalidate(&self, o: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.stale.load(Ordering::Relaxed)
            || o.source != 0x4242
            || !(1..=4).contains(&o.native[0])
        {
            return Err(Error::new(ErrorKind::StalePlan, "modeled tree changed"));
        }
        Ok(())
    }
    fn metadata(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(o, r)?;
        Budgeted::try_new(&r.memory, 1024, || {
            Ok(Metadata {
                created: MetadataField::Absent,
                modified: MetadataField::Absent,
                accessed: MetadataField::Absent,
                owner: MetadataField::Absent,
                mode: MetadataField::Absent,
                security: MetadataField::Absent,
                attributes: vec![],
                native_flags: MetadataField::Absent,
                symlink_target: if o.native == [4] {
                    MetadataField::Known(NativeName::Bytes(b"payload".to_vec()))
                } else {
                    MetadataField::Absent
                },
                reparse_data: MetadataField::Absent,
            })
        })
    }
    fn directory_page(
        &self,
        o: &ObjectId,
        c: Option<&[u8]>,
        _: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.revalidate(o, r)?;
        assert!(c.is_none());
        let reservation = r.memory.reserve(4096)?;
        let mut entries = if o.native == [1] {
            vec![DirectoryEntry {
                name: if self.utf16_root {
                    NativeName::Utf16(b"nested".iter().map(|b| u16::from(*b)).collect())
                } else {
                    NativeName::Bytes(b"nested".to_vec())
                },
                object: id(2),
                kind: ObjectKind::Directory,
            }]
        } else if o.native == [2] {
            vec![
                DirectoryEntry {
                    name: NativeName::Bytes(if self.nonutf8 {
                        vec![b'p', 255]
                    } else {
                        b"payload".to_vec()
                    }),
                    object: id(3),
                    kind: if self.special {
                        ObjectKind::Special
                    } else {
                        ObjectKind::File
                    },
                },
                DirectoryEntry {
                    name: NativeName::Bytes(b"alias".to_vec()),
                    object: id(3),
                    kind: ObjectKind::File,
                },
                DirectoryEntry {
                    name: NativeName::Bytes(b"link".to_vec()),
                    object: id(4),
                    kind: ObjectKind::Symlink,
                },
            ]
        } else {
            return Err(Error::new(ErrorKind::InvalidOperation, "not a directory"));
        };
        if self.collision && o.native == [2] {
            entries[0].name = NativeName::Utf16(vec![0xe9]);
            entries[1].name = NativeName::Bytes(vec![0xc3, 0xa9]);
        }
        if self.reverse {
            entries.reverse();
        }
        Ok(DirectoryPage {
            entries,
            next: None,
            reservation,
        })
    }
    fn streams(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.revalidate(o, r)?;
        Budgeted::try_new(&r.memory, 128, || {
            let mut out = vec![];
            if o.native == [3] {
                out.push(StreamInfo {
                    kind: StreamKind::Data,
                    length: self.file.len(),
                });
                if self.extra {
                    out.push(StreamInfo {
                        kind: StreamKind::Named(NativeName::Bytes(b"ads".to_vec())),
                        length: 0,
                    });
                }
            }
            Ok(out)
        })
    }
    fn open_stream(
        &self,
        o: &ObjectId,
        s: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(o, r)?;
        assert_eq!(o, &id(3));
        assert_eq!(s, &StreamKind::Data);
        Ok(self.file.clone())
    }
}
struct Image {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    partial_error: bool,
    flush_error: bool,
    corrupt: bool,
}
impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0xa5; 262144],
            writes: 0,
            flushes: 0,
            partial_error: false,
            flush_error: false,
            corrupt: false,
        }
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.bytes[p as usize..p as usize + b.len()]);
        if self.corrupt {
            b[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, p: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.partial_error {
            let n = b.len().min(13);
            self.bytes[p as usize..p as usize + n].copy_from_slice(&b[..n]);
            return Err(io::Error::other("hidden partial write"));
        }
        let n = b.len().min(997);
        self.bytes[p as usize..p as usize + n].copy_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flush_error {
            Err(io::Error::other("modeled flush error"))
        } else {
            Ok(())
        }
    }
}
struct ReadImage(Vec<u8>);
impl ReadAt for ReadImage {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.0[p as usize..p as usize + b.len()]);
        Ok(())
    }
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn options(endian: Jffs2Endian, zero: bool) -> Jffs2BuildOptions {
    Jffs2BuildOptions {
        geometry: FlashGeometry {
            layout: FlashLayout::LogicalNor,
            erased_byte: 255,
            programming: FlashProgramming::ClearBitsOnly,
            erase_bytes: 65536,
            program_bytes: 4,
        },
        endian,
        names: Jffs2BuildNamePolicy::NativeBytesOnly,
        metadata: Jffs2BuildMetadataPolicy::ReplaceWithDefaults(Jffs2BuildMetadata {
            uid: 123,
            gid: 456,
            file_permissions: 0o640,
            directory_permissions: 0o750,
            symlink_permissions: 0o777,
            timestamp: 123456,
        }),
        zero_nodes: zero,
    }
}
fn limits() -> Jffs2BuildLimits {
    Jffs2BuildLimits {
        objects: 16,
        entries: 32,
        native_bytes: 4096,
        records: 128,
        image_bytes: 1 << 20,
        depth: 8,
        work: 4096,
        node_data_bytes: 4096,
        scratch_bytes: 4096,
    }
}
fn read_limits() -> Jffs2ReadLimits {
    Jffs2ReadLimits {
        scan_bytes: 1 << 20,
        nodes: 512,
        inodes: 64,
        fragments: 512,
        native_bytes: 4096,
        work: 1000000,
    }
}
fn al() -> Jffs2AuditLimits {
    Jffs2AuditLimits {
        entries: 128,
        work: 128,
        findings: 16,
    }
}
#[test]
fn deterministic_both_endian_none_zero_streams_hardlinks_and_metadata() {
    for endian in [Jffs2Endian::Little, Jffs2Endian::Big] {
        for zero in [false, true] {
            let r = r();
            let mut previous = None;
            for reverse in [false, true] {
                let tree = Arc::new(Tree::new(reverse));
                let plan = Jffs2BuildPlan::from_tree(
                    tree.clone(),
                    262144,
                    options(endian, zero),
                    limits(),
                    &r,
                )
                .unwrap();
                let mut image = Image::new();
                let report = plan.emit(&mut image, &r).unwrap();
                assert_eq!(image.flushes, 1);
                assert_eq!(report.verified_bytes, 262144);
                assert_eq!(report.hardlink_names, 1);
                assert_eq!(report.transformed_objects, 4);
                assert!(tree.file.max_read.load(Ordering::Relaxed) <= 4096);
                if let Some(previous) = &previous {
                    assert_eq!(previous, &image.bytes);
                } else {
                    previous = Some(image.bytes.clone());
                }
                let volume = Jffs2Volume::open(
                    Arc::new(ReadImage(image.bytes)),
                    options(endian, zero).geometry,
                    endian,
                    read_limits(),
                    &r,
                )
                .unwrap();
                assert!(audit(&volume, al(), &r).unwrap().is_clean());
                let source = Jffs2TreeSource::inventory(volume, al(), &r).unwrap();
                let root = source.root();
                let p = source.directory_page(&root, None, 16, &r).unwrap();
                let nested = p.entries[0].object.clone();
                drop(p);
                let p = source.directory_page(&nested, None, 16, &r).unwrap();
                let file = p
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
                    .unwrap()
                    .object
                    .clone();
                let alias = p
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
                    .unwrap()
                    .object
                    .clone();
                assert_eq!(file, alias);
                let meta = source.metadata(&file, &r).unwrap();
                assert_eq!(meta.mode, MetadataField::Known(0x81a0));
                assert_eq!(meta.modified.as_known_ticks(), Some(123456));
                drop(meta);
                assert_eq!(
                    read_all(
                        source
                            .open_stream(&file, &StreamKind::Data, &r)
                            .unwrap()
                            .as_ref(),
                        100000,
                        &r
                    )
                    .unwrap()
                    .get()
                    .as_slice(),
                    tree.file.bytes
                );
                drop(p);
                drop(source);
                drop(plan);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}
trait Ticks {
    fn as_known_ticks(&self) -> Option<i128>;
}
impl Ticks for MetadataField<NativeTimestamp> {
    fn as_known_ticks(&self) -> Option<i128> {
        match self {
            MetadataField::Known(t) => Some(t.ticks),
            _ => None,
        }
    }
}
#[test]
fn all_preflight_rejections_leave_target_unwritten() {
    let r = r();
    let mut l = limits();
    l.records = 1;
    assert!(
        Jffs2BuildPlan::from_tree(
            Arc::new(Tree::new(false)),
            262144,
            options(Jffs2Endian::Little, false),
            l,
            &r
        )
        .is_err()
    );
    let mut o = options(Jffs2Endian::Little, false);
    o.metadata = Jffs2BuildMetadataPolicy::RequirePreservation;
    assert!(
        Jffs2BuildPlan::from_tree(Arc::new(Tree::new(false)), 262144, o, limits(), &r).is_err()
    );
    let mut t = Tree::new(false);
    t.collision = true;
    let mut o = options(Jffs2Endian::Little, false);
    o.names = Jffs2BuildNamePolicy::Utf16ToUtf8;
    assert!(Jffs2BuildPlan::from_tree(Arc::new(t), 262144, o, limits(), &r).is_err());
    let mut t = Tree::new(false);
    t.extra = true;
    assert!(
        Jffs2BuildPlan::from_tree(
            Arc::new(t),
            262144,
            options(Jffs2Endian::Little, false),
            limits(),
            &r
        )
        .is_err()
    );
    assert!(
        Jffs2BuildPlan::from_tree(
            Arc::new(Tree::new(false)),
            65536,
            options(Jffs2Endian::Little, false),
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn causal_failures_stale_cancel_partial_write_flush_and_readback() {
    let r = r();
    let tree = Arc::new(Tree::new(false));
    let plan = Jffs2BuildPlan::from_tree(
        tree.clone(),
        262144,
        options(Jffs2Endian::Little, false),
        limits(),
        &r,
    )
    .unwrap();
    tree.file.fail.store(true, Ordering::Relaxed);
    let mut image = Image::new();
    let error = plan.emit(&mut image, &r).unwrap_err();
    assert!(std::error::Error::source(&error.source).is_some());
    tree.file.fail.store(false, Ordering::Relaxed);
    tree.file.len.store(90012, Ordering::Relaxed);
    let mut image = Image::new();
    let e = plan.emit(&mut image, &r).unwrap_err();
    assert!(!e.mutation_attempted);
    assert_eq!(image.writes, 0);
    tree.file.len.store(90013, Ordering::Relaxed);
    let mut image = Image::new();
    image.partial_error = true;
    let e = plan.emit(&mut image, &r).unwrap_err();
    assert!(e.mutation_attempted);
    assert_eq!(e.accepted_bytes, 0);
    assert_ne!(image.bytes[..13], [0xa5; 13]);
    let mut image = Image::new();
    image.flush_error = true;
    let e = plan.emit(&mut image, &r).unwrap_err();
    assert_eq!(e.source.kind, ErrorKind::UncertainDurability);
    assert!(e.mutation_attempted && !e.flush_completed);
    let mut image = Image::new();
    image.corrupt = true;
    let e = plan.emit(&mut image, &r).unwrap_err();
    assert!(e.flush_completed);
    assert_eq!(e.verified_bytes, 0);
    r.cancellation.cancel();
    let e = plan.emit(&mut Image::new(), &r).unwrap_err();
    assert!(!e.mutation_attempted);
    let alternate = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    assert!(
        !plan
            .emit(&mut Image::new(), &alternate)
            .unwrap_err()
            .mutation_attempted
    );
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}

struct SourceOrder {
    inner: Arc<dyn TreeSource>,
    reverse: bool,
    maximum: Arc<AtomicUsize>,
}
struct ObservedFile {
    inner: Arc<dyn FileRead>,
    maximum: Arc<AtomicUsize>,
}
impl FileRead for ObservedFile {
    fn identity(&self) -> &ObjectId {
        self.inner.identity()
    }
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&self, p: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        self.maximum.fetch_max(b.len(), Ordering::Relaxed);
        let count = b.len().min(37);
        self.inner.read_at(p, &mut b[..count], r)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.inner.visit_extents(r, v)
    }
}
impl TreeSource for SourceOrder {
    fn root(&self) -> ObjectId {
        self.inner.root()
    }
    fn stability(&self) -> SourceStability {
        self.inner.stability()
    }
    fn metadata(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.inner.metadata(o, r)
    }
    fn directory_page(
        &self,
        o: &ObjectId,
        c: Option<&[u8]>,
        n: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        let mut p = self.inner.directory_page(o, c, n, r)?;
        if self.reverse {
            p.entries.reverse();
        }
        Ok(p)
    }
    fn streams(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.inner.streams(o, r)
    }
    fn open_stream(
        &self,
        o: &ObjectId,
        s: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        Ok(Arc::new(ObservedFile {
            inner: self.inner.open_stream(o, s, r)?,
            maximum: self.maximum.clone(),
        }))
    }
    fn revalidate(&self, o: &ObjectId, r: &Resources) -> Result<()> {
        self.inner.revalidate(o, r)
    }
}
struct FileTarget {
    inner: partmgr::storage::FileStorage,
    flushes: usize,
}
impl Storage for FileTarget {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(p, b)
    }
    fn write_at(&mut self, p: u64, b: &[u8]) -> io::Result<usize> {
        self.inner.write_at(p, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        self.inner.flush()
    }
}
const BUILD_SOURCES: &[(&str, &[u8])] = &[
    (
        "src/fs_jffs2_builder.rs",
        include_bytes!("../src/fs_jffs2_builder.rs"),
    ),
    (
        "src/fs_jffs2_builder_compression.rs",
        include_bytes!("../src/fs_jffs2_builder_compression.rs"),
    ),
    ("src/fs_jffs2.rs", include_bytes!("../src/fs_jffs2.rs")),
    (
        "src/fs_jffs2_compression.rs",
        include_bytes!("../src/fs_jffs2_compression.rs"),
    ),
    (
        "src/fs_jffs2_audit.rs",
        include_bytes!("../src/fs_jffs2_audit.rs"),
    ),
    (
        "src/fs_jffs2_tree.rs",
        include_bytes!("../src/fs_jffs2_tree.rs"),
    ),
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
    ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
    ("src/fs_flash.rs", include_bytes!("../src/fs_flash.rs")),
    ("src/storage.rs", include_bytes!("../src/storage.rs")),
    (
        "tests/fs_jffs2_builder.rs",
        include_bytes!("fs_jffs2_builder.rs"),
    ),
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
];
#[test]
#[ignore = "requires JFFS2_BUILD_EVIDENCE, JFFS2_TOOLS and JFFS2_EXTRACTOR; missing enabled prerequisites fail"]
fn native_mtd_utils_and_independent_extraction_direct_builder() {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };
    fn hash(p: &Path) -> String {
        format!("{:x}", Sha256::digest(fs::read(p).unwrap()))
    }
    fn run(p: &Path, args: &[&str], receipt: &mut String) -> std::process::Output {
        receipt.push_str(&format!("argv={:?} {:?}\n", p, args));
        let out = Command::new(p)
            .args(args)
            .output()
            .expect("enabled native gate requires executable");
        receipt.push_str(&format!(
            "status={} stdout={} stderr={}\n",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
    let evidence = PathBuf::from(
        std::env::var_os("JFFS2_BUILD_EVIDENCE")
            .expect("enabled gate requires durable evidence directory"),
    );
    fs::create_dir_all(&evidence).unwrap();
    let receipt_path = evidence.join("jffs2-direct-tree-builder-v1.txt");
    assert!(!receipt_path.exists(), "fresh evidence directory required");
    fs::write(&receipt_path, "result=running\n").unwrap();
    let compression = match std::env::var("JFFS2_BUILD_COMPRESSION").ok().as_deref() {
        None => None,
        Some("rtime") => Some(Jffs2BuildCompression::Rtime),
        Some("zlib") => Some(Jffs2BuildCompression::Zlib),
        _ => panic!("unsupported explicit build codec"),
    };
    for &(name, baked) in BUILD_SOURCES {
        assert_eq!(fs::read(name).unwrap(), baked, "baked/live mismatch {name}");
    }

    let tools =
        PathBuf::from(std::env::var_os("JFFS2_TOOLS").expect("enabled gate requires mtd-utils"));
    let extractor = PathBuf::from(
        std::env::var_os("JFFS2_EXTRACTOR").expect("enabled gate requires independent extractor"),
    );
    let mut receipt = String::from(
        "profile=jffs2-direct-logical-nor-tree-none-zero-v1\ngeometry=262144 bytes erase65536 program4 FF LE/BE\nsource=deferred common TreeSource 90013 byte regular file + hardlink + nested dir + exact symlink target; first4096 bytes zero\nmetadata=explicit replacement uid123 gid456 modes0640/0750/0777 seconds123456\ntest=cargo test --all-features --locked --test fs_jffs2_builder -- --ignored --nocapture\n",
    );
    if compression.is_some() {
        receipt = receipt.replace("tree-none-zero-v1", "tree-rtime-zlib-v2");
    }
    for &(name, baked) in BUILD_SOURCES {
        receipt.push_str(&format!(
            "bound_source={name} sha256={:x}\n",
            Sha256::digest(baked)
        ));
    }
    receipt.push_str(&format!("selected_compression={compression:?} layout=NONE-worst-case codec_workspace_zlib2097152 rtime2048 encoded_buffer=node_data_bytes4096 no payload cache\n"));
    for name in ["mkfs.jffs2", "jffs2dump"] {
        let tool = tools.join(name);
        assert!(tool.is_file());
        receipt.push_str(&format!("tool={} sha256={}\n", tool.display(), hash(&tool)));
        run(&tool, &["--version"], &mut receipt);
    }
    assert!(extractor.is_file());
    receipt.push_str(&format!(
        "extractor={} executable_sha256={}\n",
        extractor.display(),
        hash(&extractor)
    ));
    let python = std::env::var_os("JFFS2_EXTRACTOR_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let script = fs::read_to_string(&extractor)
                .expect("set JFFS2_EXTRACTOR_PYTHON for non-script extractor launchers");
            let first = script.lines().next().unwrap_or("");
            let p = PathBuf::from(
                first
                    .strip_prefix("#!")
                    .expect("extractor needs interpreter shebang")
                    .trim(),
            );
            assert!(
                p.is_absolute() && p.is_file(),
                "set JFFS2_EXTRACTOR_PYTHON for env/argument shebang launchers"
            );
            p
        });
    run(
        &python,
        &[
            "-c",
            "import importlib.metadata,jefferson.jffs2,pathlib,hashlib;print('jefferson='+importlib.metadata.version('jefferson'));print('dissect-cstruct='+importlib.metadata.version('dissect-cstruct'));print('lzallright='+importlib.metadata.version('lzallright'));p=pathlib.Path(jefferson.jffs2.__file__);print('extractor_source='+str(p));print('extractor_source_sha256='+hashlib.sha256(p.read_bytes()).hexdigest())",
        ],
        &mut receipt,
    );
    let executable = std::env::current_exe().unwrap();
    receipt.push_str(&format!("test_executable_sha256={}\n", hash(&executable)));
    let parser = run(
        &python,
        &[
            "-c",
            "import jefferson.jffs2;print(jefferson.jffs2.__file__)",
        ],
        &mut receipt,
    );
    let parser = PathBuf::from(String::from_utf8(parser.stdout).unwrap().trim());
    let proof_tools = [
        tools.join("mkfs.jffs2"),
        tools.join("jffs2dump"),
        extractor.clone(),
        python.clone(),
        parser,
        executable,
    ];
    let proof_hashes = proof_tools.iter().map(|p| hash(p)).collect::<Vec<_>>();
    for (p, h) in proof_tools.iter().zip(&proof_hashes) {
        receipt.push_str(&format!("tool_or_binary={p:?} sha256={h}\n"));
    }
    if let Some(archive) = std::env::var_os("JFFS2_SPEC_ARCHIVE") {
        let archive = PathBuf::from(archive);
        for name in ["jffs2.h", "scan.c", "readinode.c", "nodelist.c", "build.c"] {
            let path = evidence.join(format!("primary-{name}"));
            fs::copy(archive.join(name), &path).unwrap();
            receipt.push_str(&format!(
                "primary_reference={name} sha256={} retained={}\n",
                hash(&path),
                path.display()
            ));
        }
    }
    let expected = Tree::new(false).file.bytes.clone();
    let author_root = evidence.join("independent-source-tree");
    fs::create_dir_all(author_root.join("nested")).unwrap();
    fs::write(author_root.join("nested/payload"), &expected).unwrap();
    fs::hard_link(
        author_root.join("nested/payload"),
        author_root.join("nested/alias"),
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("payload", author_root.join("nested/link")).unwrap();
    let input = evidence.join("independent-input.img");
    run(
        &tools.join("mkfs.jffs2"),
        &[
            "-r",
            author_root.to_str().unwrap(),
            "-o",
            input.to_str().unwrap(),
            "-l",
            "-m",
            "none",
            "-e",
            "65536",
            "--pad=262144",
            "-f",
            "-U",
        ],
        &mut receipt,
    );
    let input_hash = hash(&input);
    receipt.push_str(&format!("independent_input_sha256={input_hash} capture=RawDisk->Jffs2Volume->Jffs2TreeSource no host extraction used by authoring\n"));
    for (label, endian) in [("le", Jffs2Endian::Little), ("be", Jffs2Endian::Big)] {
        for zero in [false, true] {
            let mut previous = None;
            for reverse in [false, true] {
                let resources = r();
                let input_volume = Jffs2Volume::open(
                    Arc::new(virtdisk::RawDisk::open(&input).unwrap()),
                    options(Jffs2Endian::Little, false).geometry,
                    Jffs2Endian::Little,
                    read_limits(),
                    &resources,
                )
                .unwrap();
                let source: Arc<dyn TreeSource> =
                    Arc::new(Jffs2TreeSource::inventory(input_volume, al(), &resources).unwrap());
                let maximum = Arc::new(AtomicUsize::new(0));
                let source: Arc<dyn TreeSource> = Arc::new(SourceOrder {
                    inner: source,
                    reverse,
                    maximum: maximum.clone(),
                });
                let plan = match compression {
                    Some(codec) => Jffs2BuildPlan::from_tree_compressed(
                        source,
                        262144,
                        options(endian, zero),
                        limits(),
                        codec,
                        &resources,
                    ),
                    None => Jffs2BuildPlan::from_tree(
                        source,
                        262144,
                        options(endian, zero),
                        limits(),
                        &resources,
                    ),
                }
                .unwrap();
                let name = format!("{label}-zero{zero}-reverse{reverse}");
                let path = evidence.join(format!("{name}.img"));
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                f.set_len(262144).unwrap();
                drop(f);
                let mut target = FileTarget {
                    inner: partmgr::storage::FileStorage::open(&path).unwrap(),
                    flushes: 0,
                };
                let report = plan.emit(&mut target, &resources).unwrap();
                assert_eq!(target.flushes, 1);
                drop(target);
                let before = hash(&path);
                assert_eq!(
                    <[u8; 32]>::from(Sha256::digest(fs::read(&path).unwrap())),
                    report.sha256
                );
                if let Some(previous) = &previous {
                    assert_eq!(previous, &before);
                } else {
                    previous = Some(before.clone());
                }
                let out = run(
                    &tools.join("jffs2dump"),
                    &[
                        if endian == Jffs2Endian::Little {
                            "-l"
                        } else {
                            "-b"
                        },
                        "-c",
                        path.to_str().unwrap(),
                    ],
                    &mut receipt,
                );
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
                .to_ascii_lowercase();
                assert!(!combined.contains("wrong") && !combined.contains("invalid"));
                let dump = String::from_utf8_lossy(&out.stdout);
                let target = |name: &str| {
                    let line = dump
                        .lines()
                        .find(|line| {
                            line.contains("Dirent") && line.ends_with(&format!("name {name}"))
                        })
                        .unwrap();
                    let tokens: Vec<_> = line.split_whitespace().collect();
                    let at = tokens.iter().position(|t| *t == "#ino").unwrap();
                    tokens[at + 1].trim_end_matches(',').parse::<u32>().unwrap()
                };
                assert_eq!(target("alias"), target("payload"));
                assert_eq!(report.hardlink_names, 1);
                assert_eq!(report.verified_bytes, 262144);

                let extraction = evidence.join(format!("{name}-independent-extraction"));
                assert!(!extraction.exists(), "use fresh native evidence directory");
                run(
                    &extractor,
                    &[path.to_str().unwrap(), "-d", extraction.to_str().unwrap()],
                    &mut receipt,
                );
                // Jefferson retains the last dirent per inode; deterministic sort emits payload after alias.
                assert_eq!(
                    fs::read(extraction.join("nested/payload")).unwrap(),
                    expected
                );
                assert_eq!(
                    fs::read_link(extraction.join("nested/link")).unwrap(),
                    Path::new("payload")
                );
                assert_eq!(hash(&path), before);
                let volume = match compression {
                    Some(_) => Jffs2Volume::open_compressed(
                        Arc::new(virtdisk::RawDisk::open(&path).unwrap()),
                        options(endian, zero).geometry,
                        endian,
                        read_limits(),
                        Jffs2CompressionLimits {
                            compressed_node_bytes: 4096,
                            decoded_node_bytes: 4096,
                            compressed_bytes: 262144,
                            decoded_bytes: 262144,
                            work: 524288,
                        },
                        &resources,
                    ),
                    None => Jffs2Volume::open(
                        Arc::new(virtdisk::RawDisk::open(&path).unwrap()),
                        options(endian, zero).geometry,
                        endian,
                        read_limits(),
                        &resources,
                    ),
                }
                .unwrap();
                if compression.is_some() {
                    let bytes = fs::read(&path).unwrap();
                    let mut at = 0;
                    let mut compressed = 0;
                    while at + 12 <= bytes.len() {
                        let word = |p| {
                            if endian == Jffs2Endian::Big {
                                u16::from_be_bytes(bytes[p..p + 2].try_into().unwrap())
                            } else {
                                u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap())
                            }
                        };
                        if word(at) != 0x1985 {
                            at += 4;
                            continue;
                        }
                        let len = if endian == Jffs2Endian::Big {
                            u32::from_be_bytes(bytes[at + 4..at + 8].try_into().unwrap())
                        } else {
                            u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap())
                        } as usize;
                        if word(at + 2) == 0xe002 && [2, 6].contains(&bytes[at + 56]) {
                            compressed += 1;
                        }
                        at += len.next_multiple_of(4);
                    }
                    assert!(compressed >= 20);
                    receipt.push_str(&format!("actual_compressed_nodes={compressed}\n"));
                }
                assert!(audit(&volume, al(), &resources).unwrap().is_clean());
                drop(volume);
                drop(plan);
                assert_eq!(resources.memory.used(), 0);
                assert_eq!(hash(&input), input_hash);
                assert!(maximum.load(Ordering::Relaxed) <= 4096);
                receipt.push_str(&format!("image={name} sha256={before} payload_sha256={} native_crc=passed independent_extraction=passed reader_complete_audit=passed max_source_read={} flushes=1 actual_FileStorage_flush=passed sourceorder_determinism=passed\n",hash(&extraction.join("nested/payload")),maximum.load(Ordering::Relaxed)));
            }
        }
    }
    for source in [
        "src/fs_jffs2_builder.rs",
        "tests/fs_jffs2_builder.rs",
        "docs/filesystem-jffs2-builder.md",
        "src/fs_jffs2.rs",
        "src/fs_jffs2_audit.rs",
        "src/fs_jffs2_tree.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/fs_flash.rs",
        "src/storage.rs",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        receipt.push_str(&format!(
            "source={source} sha256={}\n",
            hash(Path::new(source))
        ));
    }
    for &(name, baked) in BUILD_SOURCES {
        assert_eq!(fs::read(name).unwrap(), baked, "source changed {name}");
    }
    for (p, h) in proof_tools.iter().zip(proof_hashes) {
        assert_eq!(hash(p), h, "tool/binary changed {p:?}");
    }
    receipt.push_str("baked_live_source_tool_binary_end_revalidation=passed\n");
    receipt.push_str("result=passed; direct offline unpublished logical NOR authoring only, no append/GC/hardware or physical power-loss claim\n");
    fs::write(receipt_path, receipt).unwrap();
}

#[test]
fn exact_erase_boundary_native_names_conversion_and_low_memory() {
    let resources = r();
    let tree = Arc::new(Tree::new(false));
    tree.file.len.store(65000, Ordering::Relaxed);
    let mut l = limits();
    l.node_data_bytes = 32268;
    let plan = Jffs2BuildPlan::from_tree(
        tree,
        262144,
        options(Jffs2Endian::Little, false),
        l,
        &resources,
    )
    .unwrap();
    let mut image = Image::new();
    plan.emit(&mut image, &resources).unwrap();
    assert_eq!(&image.bytes[65536..65538], &0x1985u16.to_le_bytes());
    let v = Jffs2Volume::open(
        Arc::new(ReadImage(image.bytes)),
        options(Jffs2Endian::Little, false).geometry,
        Jffs2Endian::Little,
        read_limits(),
        &resources,
    )
    .unwrap();
    assert!(audit(&v, al(), &resources).unwrap().is_clean());
    drop(v);
    drop(plan);
    assert_eq!(resources.memory.used(), 0);
    let mut t = Tree::new(false);
    t.utf16_root = true;
    t.nonutf8 = true;
    let mut o = options(Jffs2Endian::Little, false);
    o.names = Jffs2BuildNamePolicy::Utf16ToUtf8;
    let plan = Jffs2BuildPlan::from_tree(Arc::new(t), 262144, o, limits(), &resources).unwrap();
    let mut image = Image::new();
    assert_eq!(
        plan.emit(&mut image, &resources).unwrap().converted_names,
        1
    );
    let v = Jffs2Volume::open(
        Arc::new(ReadImage(image.bytes)),
        o.geometry,
        o.endian,
        read_limits(),
        &resources,
    )
    .unwrap();
    let tree = Jffs2TreeSource::inventory(v, al(), &resources).unwrap();
    let p = tree
        .directory_page(&tree.root(), None, 16, &resources)
        .unwrap();
    let p2 = tree
        .directory_page(&p.entries[0].object, None, 16, &resources)
        .unwrap();
    assert!(
        p2.entries
            .iter()
            .any(|e| e.name == NativeName::Bytes(vec![b'p', 255]))
    );
    drop(p2);
    drop(p);
    drop(tree);
    drop(plan);
    assert_eq!(resources.memory.used(), 0);
    let tiny = Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    };
    let t = Arc::new(Tree::new(false));
    assert!(Jffs2BuildPlan::from_tree(t.clone(), 262144, o, limits(), &tiny).is_err());
    assert_eq!(t.file.max_read.load(Ordering::Relaxed), 0);
    assert_eq!(tiny.memory.used(), 0);
}
#[test]
fn compressed_profiles_deterministic_short_read_hardlinks_zero_symlinks_both_endian() {
    for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
        for endian in [Jffs2Endian::Little, Jffs2Endian::Big] {
            let mut previous = None;
            for reverse in [false, true] {
                let resources = r();
                let mut tree = Tree::new(reverse);
                tree.nonutf8 = true;
                let tree = Arc::new(tree);
                let expected = tree.file.bytes.clone();
                let maximum = Arc::new(AtomicUsize::new(0));
                let source = Arc::new(SourceOrder {
                    inner: tree,
                    reverse,
                    maximum: maximum.clone(),
                });
                let plan = Jffs2BuildPlan::from_tree_compressed(
                    source,
                    262144,
                    options(endian, true),
                    limits(),
                    codec,
                    &resources,
                )
                .unwrap();
                let mut image = Image::new();
                let report = plan.emit(&mut image, &resources).unwrap();
                assert_eq!(image.flushes, 1);
                assert_eq!(report.hardlink_names, 1);
                assert!(maximum.load(Ordering::Relaxed) <= 4096);
                if let Some(previous) = &previous {
                    assert_eq!(previous, &image.bytes);
                } else {
                    previous = Some(image.bytes.clone());
                }
                let volume = Jffs2Volume::open_compressed(
                    Arc::new(ReadImage(image.bytes)),
                    options(endian, true).geometry,
                    endian,
                    read_limits(),
                    Jffs2CompressionLimits {
                        compressed_node_bytes: 4096,
                        decoded_node_bytes: 4096,
                        compressed_bytes: 262144,
                        decoded_bytes: 262144,
                        work: 524288,
                    },
                    &resources,
                )
                .unwrap();
                assert!(audit(&volume, al(), &resources).unwrap().is_clean());
                let tree = Jffs2TreeSource::inventory(volume, al(), &resources).unwrap();
                let root = tree
                    .directory_page(&tree.root(), None, 16, &resources)
                    .unwrap();
                let nested = root
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
                    .unwrap();
                let page = tree
                    .directory_page(&nested.object, None, 16, &resources)
                    .unwrap();
                let payload = page
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(vec![b'p', 255]))
                    .unwrap();
                let alias = page
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
                    .unwrap();
                assert_eq!(payload.object, alias.object);
                let metadata = tree.metadata(&payload.object, &resources).unwrap();
                assert_eq!(metadata.mode, MetadataField::Known(0x81a0));
                assert_eq!(metadata.modified.as_known_ticks(), Some(123456));
                drop(metadata);
                let link = page
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"link".to_vec()))
                    .unwrap();
                let metadata = tree.metadata(&link.object, &resources).unwrap();
                assert_eq!(
                    metadata.symlink_target,
                    MetadataField::Known(NativeName::Bytes(b"payload".to_vec()))
                );
                drop(metadata);
                let file = tree
                    .open_stream(&payload.object, &StreamKind::Data, &resources)
                    .unwrap();
                let mut first = None;
                file.visit_extents(&resources, &mut |e| {
                    if first.is_none() {
                        first = Some(e);
                    }
                    Ok(())
                })
                .unwrap();
                assert_eq!(
                    first,
                    Some(LogicalExtent {
                        offset: 0,
                        length: 4096,
                        kind: ExtentKind::Hole
                    })
                );
                let mut actual = vec![0; expected.len()];
                file.read_at(0, &mut actual, &resources).unwrap();
                assert_eq!(actual, expected);
                drop(file);
                drop(page);
                drop(root);
                drop(tree);
                drop(plan);
                assert_eq!(resources.memory.used(), 0);
            }
        }
    }
}
#[test]
fn compressed_workspace_and_source_failures_are_bounded_and_causal() {
    for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
        let resources = r();
        let tree = Arc::new(Tree::new(false));
        let plan = Jffs2BuildPlan::from_tree_compressed(
            tree.clone(),
            262144,
            options(Jffs2Endian::Little, true),
            limits(),
            codec,
            &resources,
        )
        .unwrap();
        let tiny = Resources {
            memory: Budget::new(1),
            cancellation: Cancellation::default(),
        };
        let mut image = Image::new();
        assert_eq!(
            plan.emit(&mut image, &tiny).unwrap_err().source.kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(image.writes, 0);
        tree.file.fail.store(true, Ordering::Relaxed);
        let error = plan.emit(&mut image, &resources).unwrap_err();
        assert_eq!(error.source.kind, ErrorKind::Io);
        assert!(error.source.source.is_some());
        drop(plan);
        assert_eq!(resources.memory.used(), 0);
    }
}
#[test]
fn compressed_target_partial_flush_and_readback_failures_report_uncertainty() {
    for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
        for mode in 0..3 {
            let resources = r();
            let plan = Jffs2BuildPlan::from_tree_compressed(
                Arc::new(Tree::new(false)),
                262144,
                options(Jffs2Endian::Little, true),
                limits(),
                codec,
                &resources,
            )
            .unwrap();
            let mut image = Image::new();
            match mode {
                0 => image.partial_error = true,
                1 => image.flush_error = true,
                _ => image.corrupt = true,
            }
            let error = plan.emit(&mut image, &resources).unwrap_err();
            assert!(error.mutation_attempted);
            assert_eq!(error.flush_completed, mode == 2);
            if mode < 2 {
                assert_eq!(
                    error.source.kind,
                    if mode == 1 {
                        ErrorKind::UncertainDurability
                    } else {
                        ErrorKind::Io
                    }
                );
                assert!(error.source.source.is_some());
            }
            drop(plan);
            assert_eq!(resources.memory.used(), 0);
        }
        let resources = r();
        assert!(
            Jffs2BuildPlan::from_tree_compressed(
                Arc::new(Tree::new(false)),
                65536,
                options(Jffs2Endian::Little, true),
                limits(),
                codec,
                &resources
            )
            .is_err()
        );
        assert_eq!(resources.memory.used(), 0);
    }
}
#[test]
fn compressed_profile_incompressible_data_falls_back_to_none_without_expansion() {
    for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
        let resources = r();
        let mut tree = Tree::new(false);
        let file = Arc::get_mut(&mut tree.file).unwrap();
        let mut x = 0x974ab581u32;
        for b in &mut file.bytes {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let expected = file.bytes.clone();
        let plan = Jffs2BuildPlan::from_tree_compressed(
            Arc::new(tree),
            262144,
            options(Jffs2Endian::Little, true),
            limits(),
            codec,
            &resources,
        )
        .unwrap();
        let mut image = Image::new();
        plan.emit(&mut image, &resources).unwrap();
        let v = Jffs2Volume::open(
            Arc::new(ReadImage(image.bytes)),
            options(Jffs2Endian::Little, true).geometry,
            Jffs2Endian::Little,
            read_limits(),
            &resources,
        )
        .unwrap();
        let tree = Jffs2TreeSource::inventory(v, al(), &resources).unwrap();
        let root = tree
            .directory_page(&tree.root(), None, 16, &resources)
            .unwrap();
        let nested = root
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
            .unwrap();
        let page = tree
            .directory_page(&nested.object, None, 16, &resources)
            .unwrap();
        let id = &page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
            .unwrap()
            .object;
        let file = tree.open_stream(id, &StreamKind::Data, &resources).unwrap();
        let mut actual = vec![0; expected.len()];
        file.read_at(0, &mut actual, &resources).unwrap();
        assert_eq!(actual, expected);
        drop(file);
        drop(page);
        drop(root);
        drop(tree);
        drop(plan);
        assert_eq!(resources.memory.used(), 0);
    }
}
