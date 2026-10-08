//! Explicit mtd-utils and independent extraction gate; missing prerequisites are fatal.
use partmgr::{fs_core::*, fs_flash::*, fs_jffs2::*, fs_jffs2_audit::*, fs_jffs2_tree::*};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use virtdisk::{DiskView, RawDisk, ReadAt};
fn hash(p: &Path) -> String {
    let mut f = File::open(p).unwrap();
    let mut h = Sha256::new();
    let mut b = [0; 32768];
    loop {
        let n = f.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    format!("{:x}", h.finalize())
}
fn command(path: &Path, args: &[&str], receipt: &mut String) -> std::process::Output {
    receipt.push_str(&format!("argv={:?} {:?}\n", path, args));
    let out = Command::new(path)
        .args(args)
        .output()
        .expect("enabled gate requires executable tool");
    receipt.push_str(&format!(
        "status={} stdout={} stderr={}\n",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        out.status.success(),
        "native tool failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> Jffs2ReadLimits {
    Jffs2ReadLimits {
        scan_bytes: 1 << 20,
        nodes: 512,
        inodes: 64,
        fragments: 1024,
        native_bytes: 8192,
        work: 1_000_000,
    }
}
fn geometry() -> FlashGeometry {
    FlashGeometry {
        layout: FlashLayout::LogicalNor,
        erased_byte: 255,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 65536,
        program_bytes: 4,
    }
}
fn al() -> Jffs2AuditLimits {
    Jffs2AuditLimits {
        entries: 512,
        work: 1024,
        findings: 128,
    }
}
#[test]
#[ignore = "requires JFFS2_EVIDENCE, JFFS2_TOOLS and JFFS2_EXTRACTOR; enabled missing tools fail"]
fn native_logical_nor_both_endian_payload_and_symlink_gate() {
    let evidence = PathBuf::from(
        std::env::var_os("JFFS2_EVIDENCE")
            .expect("enabled gate requires durable evidence directory"),
    );
    fs::create_dir_all(&evidence).unwrap();
    let receipt_path = evidence.join("jffs2-logical-nor-none-v1.txt");
    fs::write(&receipt_path, "result=running\n").unwrap();
    let tools = PathBuf::from(
        std::env::var_os("JFFS2_TOOLS").expect("enabled gate requires mtd-utils directory"),
    );
    let extractor = PathBuf::from(
        std::env::var_os("JFFS2_EXTRACTOR")
            .expect("enabled gate requires independent Jefferson extractor"),
    );
    let mut receipt = String::from(
        "profile=jffs2-logical-nor-none-zero-v1\ngeometry=erase65536 program4 erasedFF explicit LE/BE no OOB\ntest=cargo test --all-features --locked --test fs_jffs2_native -- --ignored --nocapture\n",
    );
    for name in ["mkfs.jffs2", "jffs2dump"] {
        let path = tools.join(name);
        assert!(path.is_file());
        receipt.push_str(&format!("tool={} sha256={}\n", path.display(), hash(&path)));
        command(&path, &["--version"], &mut receipt);
    }
    assert!(extractor.is_file());
    receipt.push_str(&format!(
        "extractor={} executable_sha256={}\n",
        extractor.display(),
        hash(&extractor)
    ));
    let python = extractor
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("jefferson/bin/python");
    command(
        &python,
        &[
            "-c",
            "import importlib.metadata;print('jefferson='+importlib.metadata.version('jefferson'));print('dissect-cstruct='+importlib.metadata.version('dissect-cstruct'));print('lzallright='+importlib.metadata.version('lzallright'))",
        ],
        &mut receipt,
    );
    if let Some(archive) = std::env::var_os("JFFS2_SPEC_ARCHIVE") {
        let archive = PathBuf::from(archive);
        for name in ["jffs2.h", "scan.c", "readinode.c", "nodelist.c", "build.c"] {
            let source = archive.join(name);
            let target = evidence.join(format!("primary-{name}"));
            fs::copy(&source, &target).unwrap();
            receipt.push_str(&format!(
                "primary_reference={name} sha256={} retained={}\n",
                hash(&target),
                target.display()
            ));
        }
    }
    command(
        &python,
        &[
            "-c",
            "import jefferson.jffs2,pathlib,hashlib; p=pathlib.Path(jefferson.jffs2.__file__);print('extractor_source='+str(p));print('extractor_source_sha256='+hashlib.sha256(p.read_bytes()).hexdigest())",
        ],
        &mut receipt,
    );
    let root = evidence.join("authoring-input");
    fs::create_dir_all(root.join("nested")).unwrap();
    let expected: Vec<u8> = (0..90013).map(|n| ((n * 73 + 11) % 256) as u8).collect();
    fs::write(root.join("nested/payload"), &expected).unwrap();
    let alias = root.join("nested/alias");
    if !alias.exists() {
        fs::hard_link(root.join("nested/payload"), &alias).unwrap();
    }
    #[cfg(unix)]
    {
        let link = root.join("nested/link");
        if !link.symlink_metadata().is_ok() {
            std::os::unix::fs::symlink("payload", link).unwrap();
        }
    }
    receipt.push_str(&format!(
        "authoring_payload_sha256={}\n",
        hash(&root.join("nested/payload"))
    ));
    for (flag, endian, label) in [
        ("-l", Jffs2Endian::Little, "le"),
        ("-b", Jffs2Endian::Big, "be"),
    ] {
        let image = evidence.join(format!("{label}.img"));
        let rootstr = root.to_str().unwrap();
        let imagestr = image.to_str().unwrap();
        command(
            &tools.join("mkfs.jffs2"),
            &[
                "-r",
                rootstr,
                "-o",
                imagestr,
                flag,
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
        let before = hash(&image);
        let out = command(
            &tools.join("jffs2dump"),
            &[flag, "-c", imagestr],
            &mut receipt,
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout)
                .to_ascii_lowercase()
                .contains("wrong")
        );
        assert!(
            !String::from_utf8_lossy(&out.stderr)
                .to_ascii_lowercase()
                .contains("crc")
        );
        let extraction = evidence.join(format!("{label}-independent-extraction"));
        assert!(
            !extraction.exists(),
            "use a fresh evidence directory per run"
        );
        command(
            &extractor,
            &[imagestr, "-d", extraction.to_str().unwrap()],
            &mut receipt,
        );
        assert_eq!(
            fs::read(extraction.join("nested/payload")).unwrap(),
            expected
        );
        assert_eq!(
            fs::read_link(extraction.join("nested/link")).unwrap(),
            Path::new("payload")
        );
        let resources = r();
        let source: Arc<dyn ReadAt> = Arc::new(RawDisk::open(&image).unwrap());
        let volume = Jffs2Volume::open(source, geometry(), endian, limits(), &resources).unwrap();
        let report = audit(&volume, al(), &resources).unwrap();
        assert!(report.is_clean());
        receipt.push_str(&format!(
            "{label}_audit reachable={} historical={} erased_ranges={}\n",
            report.reachable_inodes(),
            report.historical_inodes(),
            report.free_ranges().len()
        ));
        drop(report);
        let tree = Jffs2TreeSource::inventory(volume, al(), &resources).unwrap();
        let page = tree
            .directory_page(&tree.root(), None, 32, &resources)
            .unwrap();
        let nested = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
            .unwrap()
            .object
            .clone();
        drop(page);
        let page = tree.directory_page(&nested, None, 32, &resources).unwrap();
        let payload = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
            .unwrap()
            .object
            .clone();
        let alias = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
            .unwrap()
            .object
            .clone();
        assert_eq!(alias, payload);
        let link = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"link".to_vec()))
            .unwrap();
        assert_eq!(
            tree.metadata(&link.object, &resources)
                .unwrap()
                .symlink_target,
            MetadataField::Known(NativeName::Bytes(b"payload".to_vec()))
        );
        drop(page);
        let file = tree
            .open_stream(&payload, &StreamKind::Data, &resources)
            .unwrap();
        assert_eq!(
            read_all(file.as_ref(), 100000, &resources)
                .unwrap()
                .get()
                .as_slice(),
            expected
        );
        let mut small = [0; 113];
        for p in [0, 4091, 65000, 89900] {
            let n = file.read_at(p, &mut small, &resources).unwrap();
            assert_eq!(&small[..n], &expected[p as usize..p as usize + n]);
        }
        drop(file);
        drop(tree);
        assert_eq!(resources.memory.used(), 0);
        assert_eq!(hash(&image), before);
        receipt.push_str(&format!("image={label} sha256={before} independent_payload_sha256={} hardlink_framework=passed symlink_native=passed\n",hash(&extraction.join("nested/payload"))));
        let mut corrupt = fs::read(&image).unwrap();
        let mut pos = 0usize;
        let mut payload_node = None;
        let get16 = |b: &[u8], p: usize| {
            if endian == Jffs2Endian::Little {
                u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
            } else {
                u16::from_be_bytes(b[p..p + 2].try_into().unwrap())
            }
        };
        let get32 = |b: &[u8], p: usize| {
            if endian == Jffs2Endian::Little {
                u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(b[p..p + 4].try_into().unwrap())
            }
        };
        while pos + 68 < corrupt.len() {
            if get16(&corrupt, pos) == 0x1985 {
                if get16(&corrupt, pos + 2) == 0xe002 && get32(&corrupt, pos + 48) > 0 {
                    payload_node = Some(pos);
                    break;
                }
                pos += (get32(&corrupt, pos + 4) as usize).next_multiple_of(4);
            } else {
                pos += 4;
            }
        }
        let payload_node = payload_node.expect("native fixture has a recorded data node");
        corrupt[payload_node + 68] ^= 1;
        let bad = evidence.join(format!("{label}-bad-data-crc.img"));
        fs::write(&bad, &corrupt).unwrap();
        let before_bad = hash(&bad);
        let out = command(
            &tools.join("jffs2dump"),
            &[flag, "-c", bad.to_str().unwrap()],
            &mut receipt,
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("Wrong data_crc"));
        assert!(
            Jffs2Volume::open(
                Arc::new(RawDisk::open(&bad).unwrap()),
                geometry(),
                endian,
                limits(),
                &resources
            )
            .is_err()
        );
        assert_eq!(resources.memory.used(), 0);
        assert_eq!(hash(&bad), before_bad);
        receipt.push_str(&format!("malformed={label} payload_node={payload_node} native_data_crc_rejection=passed reader_rejection=passed sha256={before_bad}\n"));
        let framed = evidence.join(format!("{label}-framed.img"));
        let mut f = File::create(&framed).unwrap();
        f.write_all(&[0xa5; 8192]).unwrap();
        std::io::copy(&mut File::open(&image).unwrap(), &mut f).unwrap();
        f.write_all(&[0x5a; 4096]).unwrap();
        drop(f);
        let framed_hash = hash(&framed);
        let source: Arc<dyn ReadAt> = Arc::new(RawDisk::open(&framed).unwrap());
        let source: Arc<dyn ReadAt> = Arc::new(DiskView::new(source, 8192, 262144).unwrap());
        let volume = Jffs2Volume::open(source, geometry(), endian, limits(), &resources).unwrap();
        assert!(audit(&volume, al(), &resources).unwrap().is_clean());
        drop(volume);
        assert_eq!(resources.memory.used(), 0);
        assert_eq!(hash(&framed), framed_hash);
        receipt.push_str(&format!(
            "framed={label} view_offset=8192 bytes=262144 guards=unchanged sha256={framed_hash}\n"
        ));
    }
    for path in [
        "src/fs_jffs2.rs",
        "src/fs_jffs2_audit.rs",
        "src/fs_jffs2_tree.rs",
        "tests/fs_jffs2.rs",
        "tests/fixtures/jffs2_clean.rs",
        "tests/fs_jffs2_native.rs",
        "docs/filesystem-jffs2-read.md",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        receipt.push_str(&format!("source={path} sha256={}\n", hash(Path::new(path))));
    }
    receipt.push_str("result=passed; offline logical NOR read/audit/tree only; no kernel mount, writes, GC or physical NAND claim\n");
    fs::write(receipt_path, receipt).unwrap();
}
