use partmgr::{
    fs_core::*,
    fs_flash::*,
    fs_jffs2::*,
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use virtdisk::RawDisk;
const SOURCES: &[(&str, &[u8])] = &[
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
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
    (
        "tests/fs_jffs2_compression.rs",
        include_bytes!("fs_jffs2_compression.rs"),
    ),
    (
        "tests/fs_jffs2_compression_native.rs",
        include_bytes!("fs_jffs2_compression_native.rs"),
    ),
];
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(tool: &Path, args: &[String], receipt: &mut String) -> Vec<u8> {
    let output = Command::new(tool).args(args).output().unwrap();
    receipt.push_str(&format!(
        "argv={:?} {:?}\nstatus={} stdout_sha256={} stderr={}\n",
        tool,
        args,
        output.status,
        hash(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        output.status.success(),
        "{tool:?} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
#[test]
#[ignore = "enabled native codec gate requires JFFS2_CODEC_EVIDENCE/JFFS2_TOOLS/JFFS2_EXTRACTOR"]
fn native_mtd_zlib_rtime_both_endian_lazy_random_reads_crc_and_jefferson_complete_payload() {
    let evidence = PathBuf::from(
        std::env::var_os("JFFS2_CODEC_EVIDENCE")
            .expect("explicit fresh evidence directory required"),
    );
    assert!(evidence.is_dir());
    let receipt_path = evidence.join("jffs2-codec-v1.txt");
    assert!(!receipt_path.exists());
    fs::write(&receipt_path, "result=running\n").unwrap();
    let tools =
        PathBuf::from(std::env::var_os("JFFS2_TOOLS").expect("mtd-utils directory required"));
    let extractor =
        PathBuf::from(std::env::var_os("JFFS2_EXTRACTOR").expect("Jefferson executable required"));
    let python = PathBuf::from(
        fs::read_to_string(&extractor)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("#!")
            .unwrap(),
    );
    let parser_output = Command::new(&python)
        .args([
            "-c",
            "import jefferson.jffs2;print(jefferson.jffs2.__file__)",
        ])
        .output()
        .unwrap();
    assert!(parser_output.status.success());
    let parser = PathBuf::from(String::from_utf8(parser_output.stdout).unwrap().trim());
    let binary = std::env::current_exe().unwrap();
    let paths = [
        tools.join("mkfs.jffs2"),
        tools.join("jffs2dump"),
        extractor,
        python.clone(),
        parser,
        binary,
    ];
    let hashes = paths
        .iter()
        .map(|p| hash(&fs::read(p).unwrap()))
        .collect::<Vec<_>>();
    let mut receipt = String::from(
        "profile=jffs2-immutable-zlib-rtime-v1\ngeometry=logicalNOR erase65536 program4 FF explicit LE/BE; no hardware claims\ncache=none bounded-node-reinflation; editing=NONE/ZERO only\n",
    );
    for &(p, baked) in SOURCES {
        assert_eq!(fs::read(p).unwrap(), baked, "baked/live mismatch {p}");
        receipt.push_str(&format!("source={p} sha256={}\n", hash(baked)));
    }
    for (p, h) in paths.iter().zip(&hashes) {
        receipt.push_str(&format!("tool_or_binary={p:?} sha256={h}\n"));
    }
    let version = run(
        &tools.join("mkfs.jffs2"),
        &["--version".into()],
        &mut receipt,
    );
    receipt.push_str(&String::from_utf8_lossy(&version));
    receipt.push_str("read_limits=scan262144 nodes512 inodes64 fragments1024 names4096 work1000000; codec_limits=encoded_node4096 decoded_node4096 encoded_total262144 decoded_total262144 byte_work524288; memory4194304 decoder_workspace131072 cache0\n");
    let versions=run(&python,&["-c".into(),"import importlib.metadata as m;print('jefferson='+m.version('jefferson'));print('dissect.cstruct='+m.version('dissect.cstruct'));print('lzallright='+m.version('lzallright'))".into()],&mut receipt);
    receipt.push_str(&String::from_utf8_lossy(&versions));
    let tree = evidence.join("producer-tree");
    fs::create_dir(&tree).unwrap();
    let nested = tree.join("nested");
    fs::create_dir(&nested).unwrap();
    let payload = (0..98304)
        .map(|n| b"JFFS2 native compressed payload repeats reliably.\n"[n % 50])
        .collect::<Vec<_>>();
    fs::write(nested.join("payload"), &payload).unwrap();
    let expected_hash = hash(&payload);
    for big in [false, true] {
        for codec in ["zlib", "rtime"] {
            let name = format!("{}-{codec}", if big { "BE" } else { "LE" });
            let raw = evidence.join(format!("{name}.jffs2"));
            let args = vec![
                if big { "-b".into() } else { "-l".into() },
                "-f".into(),
                "-q".into(),
                "-e".into(),
                "65536".into(),
                "-s".into(),
                "4096".into(),
                "-p".into(),
                "262144".into(),
                "-x".into(),
                "lzo".into(),
                "-x".into(),
                if codec == "zlib" {
                    "rtime".into()
                } else {
                    "zlib".into()
                },
                "-X".into(),
                codec.into(),
                "-r".into(),
                tree.display().to_string(),
                "-o".into(),
                raw.display().to_string(),
            ];
            run(&tools.join("mkfs.jffs2"), &args, &mut receipt);
            let dump = run(
                &tools.join("jffs2dump"),
                &[
                    if big { "-b".into() } else { "-l".into() },
                    raw.display().to_string(),
                ],
                &mut receipt,
            );
            let text = String::from_utf8_lossy(&dump).to_lowercase();
            assert!(!text.contains("wrong") && !text.contains("bad crc"));
            fs::write(evidence.join(format!("{name}.dump")), dump).unwrap();
            let bytes = fs::read(&raw).unwrap();
            let mut at = 0;
            let mut compressed = 0;
            while at + 12 <= bytes.len() {
                let word = |p| {
                    if big {
                        u16::from_be_bytes(bytes[p..p + 2].try_into().unwrap())
                    } else {
                        u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap())
                    }
                };
                if word(at) != 0x1985 {
                    at += 4;
                    continue;
                }
                let n = if big {
                    u32::from_be_bytes(bytes[at + 4..at + 8].try_into().unwrap())
                } else {
                    u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap())
                } as usize;
                if word(at + 2) == 0xe002 && bytes[at + 56] == if codec == "zlib" { 6 } else { 2 } {
                    compressed += 1;
                }
                at += n.next_multiple_of(4);
            }
            assert!(
                compressed >= 20,
                "fixture must actually contain compressed multi-node payload"
            );
            let r = Resources {
                memory: Budget::new(4 << 20),
                cancellation: Cancellation::default(),
            };
            let source = Arc::new(RawDisk::open(&raw).unwrap());
            let e = if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            };
            let v = Jffs2Volume::open_compressed(
                source,
                FlashGeometry {
                    layout: FlashLayout::LogicalNor,
                    erased_byte: 255,
                    erase_bytes: 65536,
                    program_bytes: 4,
                    programming: FlashProgramming::ClearBitsOnly,
                },
                e,
                Jffs2ReadLimits {
                    scan_bytes: 262144,
                    nodes: 512,
                    inodes: 64,
                    fragments: 1024,
                    native_bytes: 4096,
                    work: 1_000_000,
                },
                Jffs2CompressionLimits {
                    compressed_node_bytes: 4096,
                    decoded_node_bytes: 4096,
                    compressed_bytes: 262144,
                    decoded_bytes: 262144,
                    work: 524288,
                },
                &r,
            )
            .unwrap();
            assert!(
                audit(
                    &v,
                    Jffs2AuditLimits {
                        entries: 512,
                        work: 512,
                        findings: 16
                    },
                    &r
                )
                .unwrap()
                .is_clean()
            );
            let tree = partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(
                v,
                Jffs2AuditLimits {
                    entries: 512,
                    work: 512,
                    findings: 16,
                },
                &r,
            )
            .unwrap();
            let root = tree.directory_page(&tree.root(), None, 16, &r).unwrap();
            let nested = &root
                .entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
                .unwrap()
                .object;
            let page = tree.directory_page(nested, None, 16, &r).unwrap();
            let inode = &page
                .entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
                .unwrap()
                .object;
            let f = tree.open_stream(inode, &StreamKind::Data, &r).unwrap();
            drop(page);
            drop(root);
            drop(tree);
            for (p, n) in [(0, 98304), (4091, 37), (67123, 193), (98001, 303)] {
                let before = r.memory.used();
                let mut b = vec![0; n];
                assert_eq!(f.read_at(p as u64, &mut b, &r).unwrap(), n);
                assert_eq!(b, payload[p..p + n]);
                assert_eq!(r.memory.used(), before);
            }
            drop(f);
            assert_eq!(r.memory.used(), 0);
            let destination = evidence.join(format!("{name}-extracted"));
            let extraction=run(&python,&["-c".into(),"import sys;from pathlib import Path;from jefferson.jffs2 import set_endianness,scan_fs,dump_fs;set_endianness(sys.argv[3]);p=Path(sys.argv[2]);p.mkdir();dump_fs(scan_fs(Path(sys.argv[1]).read_bytes(),sys.argv[3]),p)".into(),raw.display().to_string(),destination.display().to_string(),if big{">".into()}else{"<".into()}],&mut receipt);
            fs::write(evidence.join(format!("{name}.extractor.txt")), extraction).unwrap();
            assert_eq!(
                fs::read(destination.join("nested/payload")).unwrap(),
                payload
            );
            receipt.push_str(&format!("case={name} compressed_nodes={compressed} raw_sha256={} payload_sha256={expected_hash} random_reads=passed no_retained_payload_cache leases=refunded\n",hash(&bytes)));
        }
    }
    for &(p, baked) in SOURCES {
        assert_eq!(fs::read(p).unwrap(), baked, "source changed at end {p}");
    }
    for (p, h) in paths.iter().zip(hashes) {
        assert_eq!(hash(&fs::read(p).unwrap()), h, "tool/binary changed {p:?}");
    }
    receipt.push_str("source_tool_binary_end_revalidation=passed\nresult=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}
