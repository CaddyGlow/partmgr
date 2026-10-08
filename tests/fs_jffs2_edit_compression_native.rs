use partmgr::fs_jffs2_builder::Jffs2BuildCompression;
use partmgr::{
    fs_core::{
        Budget, Cancellation, Error, ErrorKind, FileRead, LogicalExtent, NativeName, ObjectId,
        Resources, Result, TreeSource, read_all,
    },
    fs_flash::{FlashGeometry, FlashImage, FlashLayout, FlashLimits, FlashProgramming},
    fs_jffs2::{Jffs2CompressionLimits, Jffs2Endian, Jffs2ReadLimits, Jffs2Volume},
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
    fs_jffs2_edit::{Jffs2EditCompression, Jffs2EditLimits, Jffs2Editor, recover_compressed},
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
use virtdisk::RawDisk;
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
        let count = out.len().min(37);
        self.file
            .read_at(&mut out[..count], p)
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
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
    ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
    ("src/fs_flash.rs", include_bytes!("../src/fs_flash.rs")),
    ("src/storage.rs", include_bytes!("../src/storage.rs")),
    ("src/fs_storage.rs", include_bytes!("../src/fs_storage.rs")),
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
    (
        "src/fs_jffs2_edit_compression.rs",
        include_bytes!("../src/fs_jffs2_edit_compression.rs"),
    ),
    (
        "src/fs_jffs2_builder.rs",
        include_bytes!("../src/fs_jffs2_builder.rs"),
    ),
    (
        "src/fs_jffs2_builder_compression.rs",
        include_bytes!("../src/fs_jffs2_builder_compression.rs"),
    ),
    ("tests/fs_jffs2_edit.rs", include_bytes!("fs_jffs2_edit.rs")),
    (
        "src/fs_jffs2_edit_compression_tests.rs",
        include_bytes!("../src/fs_jffs2_edit_compression_tests.rs"),
    ),
    (
        "tests/fs_jffs2_edit_compression_native.rs",
        include_bytes!("fs_jffs2_edit_compression_native.rs"),
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
        journal_bytes: 524288,
        slots: 128,
        file_bytes: 4096,
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

fn profile(codec: Jffs2BuildCompression) -> Jffs2EditCompression {
    Jffs2EditCompression {
        codec,
        read: Jffs2CompressionLimits {
            compressed_node_bytes: 4096,
            decoded_node_bytes: 4096,
            compressed_bytes: 1 << 20,
            decoded_bytes: 1 << 20,
            work: 4 << 20,
        },
    }
}
fn sources(receipt: &mut String) {
    for &(path, baked) in SOURCES {
        assert_eq!(fs::read(path).unwrap(), baked, "baked/live source {path}");
        receipt.push_str(&format!("source={path} sha256={}\n", hash(baked)));
    }
}
fn oracle(raw: &Path, output: &Path, big: bool, python: &Path, receipt: &mut String) {
    let query = r#"from pathlib import Path
import sys,struct
from jefferson.jffs2 import set_endianness,scan_fs,dump_fs,parse_unknown_node,parse_dirent,JFFS2_NODETYPE_DIRENT,JFFS2_MAGIC_BITMASK
p=Path(sys.argv[2]);p.mkdir();e=sys.argv[3];set_endianness(e)
raw=Path(sys.argv[1]).read_bytes();f=scan_fs(raw,e);names={};pos=0
magic=struct.pack(e+'H',JFFS2_MAGIC_BITMASK)
while True:
    at=raw.find(magic,pos)
    if at<0:break
    pos=at+1
    if len(raw)-at<12:continue
    h=parse_unknown_node(raw[at:at+12])
    if not h.hdr_crc_match or h.totlen<12 or at+h.totlen>len(raw):continue
    pos=at+((h.totlen+3)&~3)
    if h.nodetype!=JFFS2_NODETYPE_DIRENT:continue
    d=parse_dirent(raw[at:at+h.totlen],at)
    assert d.node_crc_match and d.name_crc_match
    key=(d.pino,d.name)
    if key not in names or d.version>names[key].version:names[key]=d
f[JFFS2_NODETYPE_DIRENT]={k:d for k,d in names.items() if d.ino and d.name.isascii()}
dump_fs(f,p)
"#;
    receipt.push_str(&format!(
        "oracle_query_sha256={} oracle_query={query:?}\n",
        hash(query.as_bytes())
    ));
    run(
        python,
        &[
            "-c".into(),
            query.into(),
            raw.display().to_string(),
            output.display().to_string(),
            if big { ">".into() } else { "<".into() },
        ],
        receipt,
    );
}
#[test]
#[ignore = "enabled native compressed edit gate requires JFFS2_EDIT_CODEC_EVIDENCE/JFFS2_TOOLS/JFFS2_EXTRACTOR"]
fn native_compressed_owned_range_gc_recovery_crc_complete_payload_both_endians() {
    use std::os::unix::ffi::OsStringExt;
    let evidence = PathBuf::from(
        std::env::var_os("JFFS2_EDIT_CODEC_EVIDENCE").expect("fresh evidence directory required"),
    );
    assert!(evidence.is_dir());
    let receipt_path = evidence.join("jffs2-compressed-edit-v1.txt");
    assert!(!receipt_path.exists());
    fs::write(&receipt_path, "result=running\n").unwrap();
    let tools =
        PathBuf::from(std::env::var_os("JFFS2_TOOLS").expect("mtd-utils directory required"));
    let extractor =
        PathBuf::from(std::env::var_os("JFFS2_EXTRACTOR").expect("Jefferson executable required"));
    let script = fs::read_to_string(&extractor).unwrap();
    let python = PathBuf::from(script.lines().next().unwrap().strip_prefix("#!").unwrap());
    let mut receipt = String::from(
        "profile=jffs2-owned-compressed-range-gc-v1\ngeometry=explicit NOR FF erase65536 program4 LE/BE; region8192 length262144; source=independent mkfs forced RTIME/ZLIB\nmetadata=inode/hardlinks preserved range mtimectime4000; GC semantic metadata preserved\noracle=unchanged Jefferson codec/history implementation; explicit endian; directory query retains latest (parent,native-name) entries through Jefferson CRC parser (avoids its inode-keyed hardlink collapse), restricted to ASCII names because tool UTF8 decode rejects raw FF; raw node/data/version/CRC unchanged; nonUTF8 names independently jffs2dump exact\nmodel=normal plus one partial program/error and partial erase/error on real FileStorage; actual sync_all flush; no physical power-loss claim\nlimits=scan1048576 nodes1024 inodes256 fragments4096 names65536 work1000000 audit1024/4096/64 journal524288 slots128 file4096 scratch4096 codec4096/4096 totals1048576/1048576 work4194304 memory67108864 cache0\n",
    );
    receipt.push_str(&format!(
        "start_unix_seconds={}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    sources(&mut receipt);
    let parser = run(
        &python,
        &[
            "-c".into(),
            "import jefferson.jffs2;print(jefferson.jffs2.__file__)".into(),
        ],
        &mut receipt,
    );
    let parser = PathBuf::from(String::from_utf8(parser.stdout).unwrap().trim());
    let paths = [
        tools.join("mkfs.jffs2"),
        tools.join("jffs2dump"),
        extractor,
        python.clone(),
        parser,
        std::env::current_exe().unwrap(),
    ];
    let hashes: Vec<String> = paths.iter().map(|p| hash(&fs::read(p).unwrap())).collect();
    for (path, digest) in paths.iter().zip(&hashes) {
        receipt.push_str(&format!("tool_or_binary={path:?} sha256={digest}\n"));
    }
    let version = run(
        &tools.join("mkfs.jffs2"),
        &["--version".into()],
        &mut receipt,
    );
    receipt.push_str(&String::from_utf8_lossy(&version.stdout));
    let version = run(&python, &["-c".into(),"import importlib.metadata as m;print('jefferson='+m.version('jefferson'));print('dissect.cstruct='+m.version('dissect.cstruct'));print('lzallright='+m.version('lzallright'))".into()], &mut receipt);
    receipt.push_str(&String::from_utf8_lossy(&version.stdout));
    fs::write(&receipt_path, &receipt).unwrap();
    let host = evidence.join("producer-tree");
    fs::create_dir(&host).unwrap();
    fs::create_dir(host.join("nested")).unwrap();
    let pattern = b"native compressed history repeats robustly.";
    let payload: Vec<u8> = (0..90013).map(|n| pattern[n % pattern.len()]).collect();
    fs::write(host.join("nested/payload"), &payload).unwrap();
    fs::hard_link(host.join("nested/payload"), host.join("alias")).unwrap();
    fs::hard_link(
        host.join("nested/payload"),
        host.join(std::ffi::OsString::from_vec(b"native-\xff".to_vec())),
    )
    .unwrap();
    std::os::unix::fs::symlink("nested/payload", host.join("link")).unwrap();
    let pattern = b"deferred compressed patch pattern";
    let patch: Vec<u8> = (0..8193).map(|n| pattern[n % pattern.len()]).collect();
    let patch_path = evidence.join("range-input.bin");
    fs::write(&patch_path, &patch).unwrap();
    let mut expected = payload.clone();
    expected[4093..4093 + patch.len()].copy_from_slice(&patch);
    expected.resize(payload.len() + 333, 0);
    fs::write(evidence.join("expected.bin"), &expected).unwrap();
    let expected_hash = hash(&expected);
    for big in [false, true] {
        for (codec_name, codec) in [
            ("rtime", Jffs2BuildCompression::Rtime),
            ("zlib", Jffs2BuildCompression::Zlib),
        ] {
            let name = format!("{}-{codec_name}", if big { "BE" } else { "LE" });
            let raw = evidence.join(format!("{name}-source.jffs2"));
            run(
                &tools.join("mkfs.jffs2"),
                &[
                    if big { "-b".into() } else { "-l".into() },
                    "-f".into(),
                    "-q".into(),
                    "-e".into(),
                    "65536".into(),
                    "-s".into(),
                    "4096".into(),
                    "--pad=262144".into(),
                    "-x".into(),
                    "lzo".into(),
                    "-x".into(),
                    if codec_name == "rtime" {
                        "zlib".into()
                    } else {
                        "rtime".into()
                    },
                    "-X".into(),
                    codec_name.into(),
                    "-r".into(),
                    host.display().to_string(),
                    "-o".into(),
                    raw.display().to_string(),
                ],
                &mut receipt,
            );
            assert_eq!(fs::metadata(&raw).unwrap().len(), 262144);
            fs::write(&receipt_path, &receipt).unwrap();
            let endian = if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            };
            let r = resources();
            let compression = profile(codec);
            let source = Jffs2Volume::open_compressed(
                Arc::new(RawDisk::open(&raw).unwrap()),
                geometry(),
                endian,
                limits().read,
                compression.read,
                &r,
            )
            .unwrap();
            let tree =
                partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(source, limits().audit, &r)
                    .unwrap();
            let root = tree.directory_page(&tree.root(), None, 16, &r).unwrap();
            let id = root
                .entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
                .unwrap()
                .object
                .clone();
            let number = u32::from_le_bytes(id.native.as_slice().try_into().unwrap());
            assert!(root.entries.iter().any(|e| e.name == NativeName::Bytes(b"native-\xff".to_vec()) && e.object == id));
            drop(root);
            drop(tree);
            assert_eq!(r.memory.used(), 0);
            let source_bytes = fs::read(&raw).unwrap();
            let mut normal_digest = None;
            for (fault_name, fault) in [
                ("normal", Fault::None),
                ("program-error", Fault::Program),
                ("erase-error", Fault::Erase),
            ] {
                let case = format!("{name}-{fault_name}");
                receipt.push_str(&format!(
                    "case_start={case} source_sha256={}\n",
                    hash(&source_bytes)
                ));
                fs::write(&receipt_path, &receipt).unwrap();
                let target = evidence.join(format!("{case}.region"));
                let mut framed = vec![0x36; 8192];
                framed.extend(&source_bytes);
                framed.extend([0x93; 8192]);
                fs::write(&target, &framed).unwrap();
                let mut editor = Jffs2Editor::open_compressed(
                    flash(&target, 262144, fault, &r),
                    [23; 32],
                    endian,
                    limits(),
                    compression,
                    &r,
                )
                .unwrap();
                let input = NativeRangeSource {
                    file: fs::File::open(&patch_path).unwrap(),
                    id: ObjectId {
                        source: 333,
                        generation: 1,
                        native: b"range-input".to_vec(),
                    },
                    length: patch.len() as u64,
                };
                let plan = editor
                    .write_range(
                        &editor.identity(number).unwrap(),
                        4093,
                        &input,
                        expected.len() as u64,
                        4000,
                        &r,
                    )
                    .unwrap();
                let journal_path = evidence.join(format!("{case}-range.journal"));
                let mut j = journal(&journal_path, plan.journal_length());
                let result = editor.commit(plan, &mut j, &r);
                drop(j);
                if matches!(fault, Fault::Program) {
                    assert!(result.is_err());
                    drop(editor.into_flash());
                    let mut f = flash(&target, 262144, Fault::None, &r);
                    let mut j = FileStorage::open(&journal_path).unwrap();
                    recover_compressed(&mut f, &mut j, [23; 32], endian, limits(), compression, &r)
                        .unwrap();
                    drop((f, j));
                    editor = Jffs2Editor::open_compressed(
                        flash(&target, 262144, Fault::None, &r),
                        [23; 32],
                        endian,
                        limits(),
                        compression,
                        &r,
                    )
                    .unwrap();
                } else {
                    result.unwrap();
                }
                let plan = editor.collect(0, &r).unwrap();
                let journal_path = evidence.join(format!("{case}-gc.journal"));
                let mut j = journal(&journal_path, plan.journal_length());
                let result = editor.commit(plan, &mut j, &r);
                drop(j);
                drop(editor.into_flash());
                if matches!(fault, Fault::Erase) {
                    assert!(result.is_err());
                    let mut f = flash(&target, 262144, Fault::None, &r);
                    let mut j = FileStorage::open(&journal_path).unwrap();
                    recover_compressed(&mut f, &mut j, [23; 32], endian, limits(), compression, &r)
                        .unwrap();
                    drop((f, j));
                } else {
                    result.unwrap();
                }
                let framed = fs::read(&target).unwrap();
                assert_eq!(&framed[..8192], &[0x36; 8192]);
                assert_eq!(&framed[8192 + 262144..], &[0x93; 8192]);
                let image_digest = hash(&framed[8192..8192 + 262144]);
                if let Some(normal) = &normal_digest {
                    assert_eq!(&image_digest, normal);
                } else {
                    normal_digest = Some(image_digest);
                }
                let image = evidence.join(format!("{case}.jffs2"));
                fs::write(&image, &framed[8192..8192 + 262144]).unwrap();
                assert!(framed[8192..8192 + 65536].iter().all(|b| *b == 255));
                let volume = Jffs2Volume::open_compressed(
                    Arc::new(RawDisk::open(&image).unwrap()),
                    geometry(),
                    endian,
                    limits().read,
                    compression.read,
                    &r,
                )
                .unwrap();
                assert!(audit(&volume, limits().audit, &r).unwrap().is_clean());
                let file = volume.open_file(number, &r).unwrap();
                assert_eq!(
                    read_all(&file, 100000, &r).unwrap().get().as_slice(),
                    expected
                );
                drop((file, volume));
                assert_eq!(r.memory.used(), 0);
                let dump = run(
                    &tools.join("jffs2dump"),
                    &[
                        if big { "-b".into() } else { "-l".into() },
                        "-c".into(),
                        image.display().to_string(),
                    ],
                    &mut receipt,
                );
                let lower = String::from_utf8_lossy(&dump.stdout).to_lowercase();
                assert!(!lower.contains("wrong") && !lower.contains("bad crc"));
                fs::write(evidence.join(format!("{case}.dump")), &dump.stdout).unwrap();
                assert!(
                    dump.stdout
                        .windows(b"native-\xff".len())
                        .any(|w| w == b"native-\xff")
                );
                let extracted = evidence.join(format!("{case}-oracle"));
                oracle(&image, &extracted, big, &python, &mut receipt);
                let alias = fs::read(extracted.join("alias")).unwrap();
                let nested = fs::read(extracted.join("nested/payload")).unwrap();
                assert_eq!(alias, expected);
                assert_eq!(nested, expected);
                assert_eq!(
                    fs::read_link(extracted.join("link")).unwrap(),
                    PathBuf::from("nested/payload")
                );
                receipt.push_str(&format!("case={case} source_sha256={} image_sha256={} full_payload_bytes={} framework_sha256={} oracle_alias_sha256={} oracle_nested_sha256={} inode={} native_nonUTF8_name=dump-exact hardlinks=framework-native-identity symlink=native-exact framing=unchanged erased_victim=FF\n",hash(&source_bytes),hash(&framed[8192..8192+262144]),expected.len(),expected_hash,hash(&alias),hash(&nested),number));
                fs::write(&receipt_path, &receipt).unwrap();
            }
        }
    }
    sources(&mut receipt);
    for (path, expected) in paths.iter().zip(&hashes) {
        assert_eq!(
            hash(&fs::read(path).unwrap()),
            *expected,
            "changed tool/binary {path:?}"
        );
    }
    receipt.push_str(&format!(
        "end_unix_seconds={}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    receipt.push_str("source_tool_binary_end_revalidation=passed\nresult=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}
