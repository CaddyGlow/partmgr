//! Explicit native xfsprogs gate; never silently succeeds when tools/evidence are absent.
use partmgr::{
    fs_core::*,
    fs_xfs::*,
    fs_xfs_audit::{XfsAuditFinding, XfsAuditLimits, audit},
    fs_xfs_tree::*,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};
use virtdisk::{DiskView, RawDisk, ReadAt};
fn resource() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn read_limits() -> XfsReadLimits {
    XfsReadLimits {
        allocation_groups: 8,
        inodes: 1024,
        metadata_records: 4096,
        extent_records: 1024,
        work: 500000,
        log_bytes: 128 << 20,
    }
}
fn audit_limits() -> XfsAuditLimits {
    XfsAuditLimits {
        blocks: 200000,
        entries: 4096,
        work: 1000000,
        findings: 512,
    }
}
fn tool(name: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("XFS_TOOLS") {
        let path = PathBuf::from(dir).join(name);
        assert!(path.is_file(), "enabled gate requires {}", path.display());
        path
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(name))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("enabled gate requires {name}"))
    }
}
fn command(name: &str, args: &[String], receipt: &mut String) -> Output {
    let path = tool(name);
    let out = Command::new(&path)
        .args(args)
        .output()
        .expect("required native command");
    receipt.push_str(&format!(
        "argv={:?} {:?}\nstatus={}\n{}{}",
        path,
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    out
}
fn hash(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut scratch = [0; 65536];
    loop {
        let n = file.read(&mut scratch).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&scratch[..n]);
    }
    hash.finalize().into()
}
fn hex(value: [u8; 32]) -> String {
    value.iter().map(|n| format!("{n:02x}")).collect()
}
fn crc(b: &mut [u8], offset: usize) {
    b[offset..offset + 4].fill(0);
    let mut c = u32::MAX;
    for &v in b.iter() {
        c ^= u32::from(v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0x82f63b78 } else { 0 };
        }
    }
    b[offset..offset + 4].copy_from_slice(&(!c).to_le_bytes());
}
fn q(b: &mut [u8], offset: usize, v: u64) {
    b[offset..offset + 8].copy_from_slice(&v.to_be_bytes())
}
fn patch_inode(path: &Path, number: u64, change: impl FnOnce(&mut [u8])) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(number * 512)).unwrap();
    let mut b = [0; 512];
    file.read_exact(&mut b).unwrap();
    change(&mut b);
    crc(&mut b, 100);
    file.seek(SeekFrom::Start(number * 512)).unwrap();
    file.write_all(&b).unwrap();
    file.sync_all().unwrap();
}
fn source(path: &Path) -> Arc<dyn ReadAt> {
    Arc::new(RawDisk::open(path).unwrap())
}
fn validate(path: &Path, expected: &[u8], byte_links: bool, offset: u64, receipt: &mut String) {
    let resources = resource();
    let input = if offset == 0 {
        source(path)
    } else {
        Arc::new(DiskView::new(source(path), offset, 400 << 20).unwrap()) as Arc<dyn ReadAt>
    };
    let volume = XfsVolume::open(input, read_limits(), &resources).unwrap();
    let audit = audit(&volume, audit_limits(), &resources).unwrap();
    assert!(audit.is_clean(), "{:?}", audit.findings());
    let file = volume.open_file(68, &resources).unwrap();
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        file.read_at(0, &mut actual, &resources).unwrap(),
        actual.len()
    );
    assert_eq!(actual, expected);
    for (offset, length) in [(0, 3), (4093, 13), (65521, 177), (expected.len() - 37, 37)] {
        let mut out = vec![0; length];
        file.read_at(offset as u64, &mut out, &resources).unwrap();
        assert_eq!(out, expected[offset..offset + length]);
    }
    let tree = XfsTreeSource::inventory(
        volume,
        XfsTreeLimits {
            objects: 32,
            entries: 64,
            depth: 8,
        },
        &resources,
    )
    .unwrap();
    let root = tree.root();
    let page = tree.directory_page(&root, None, 32, &resources).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, NativeName::Bytes(b"nested".to_vec()));
    let children = tree
        .directory_page(&page.entries[0].object, None, 32, &resources)
        .unwrap();
    if byte_links {
        assert_eq!(children.entries.len(), 2);
        assert_eq!(
            children.entries[0].name,
            NativeName::Bytes(b"alias".to_vec())
        );
        assert_eq!(children.entries[1].name, NativeName::Bytes(vec![b'x', 255]));
        assert_eq!(children.entries[0].object, children.entries[1].object);
    } else {
        assert_eq!(children.entries.len(), 1);
        assert_eq!(
            children.entries[0].name,
            NativeName::Bytes(b"payload".to_vec())
        );
    }
    receipt.push_str(&format!(
        "reader_tree_audit=passed source={} payload_sha256={} memory_peak_bound=33554432\n",
        path.display(),
        hex(Sha256::digest(&actual).into())
    ));
    drop(children);
    drop(page);
    drop(tree);
    drop(file);
    drop(audit);
    assert_eq!(resources.memory.used(), 0);
}
#[test]
#[ignore = "explicit enabled gate requires XFS_EVIDENCE and mkfs.xfs/xfs_db/xfs_repair/xfs_logprint"]
fn native_v5_leaf_inline_shortform_baseline() {
    let base = PathBuf::from(std::env::var_os("XFS_EVIDENCE").expect("XFS_EVIDENCE required"));
    fs::create_dir_all(&base).unwrap();
    let receipt_path = base.join("xfs-v5-leaf-inline-shortform-v1.txt");
    fs::write(
        &receipt_path,
        "result=running; no completed acceptance claim\n",
    )
    .unwrap();
    let mut receipt = format!(
        "profile=xfs-v5-leaf-inline-shortform-fresh-log-v1\ntest_argv={:?}\n",
        std::env::args_os().collect::<Vec<_>>()
    );
    receipt.push_str("primary_spec_url=https://cdn.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf\nprimary_spec_edition=3 revision3.14159265358 April2025\nprimary_spec_sha256=f2549bc83b8ddfeb629412b7a1f1381bf0f5c21feb224c949040ff68e547396a\n");
    if let Some(archive) = std::env::var_os("XFS_SPEC_ARCHIVE") {
        for name in [
            "xfs-filesystem-structure.pdf",
            "xfs_format.h",
            "xfs_log_format.h",
        ] {
            let original = PathBuf::from(&archive).join(name);
            let digest = hex(hash(&original));
            if name.ends_with(".pdf") {
                assert_eq!(
                    digest,
                    "f2549bc83b8ddfeb629412b7a1f1381bf0f5c21feb224c949040ff68e547396a"
                );
            }
            let retained = base.join(name);
            fs::copy(original, &retained).unwrap();
            receipt.push_str(&format!(
                "retained_primary_reference={} sha256={}\n",
                retained.display(),
                digest
            ));
        }
    }
    for name in ["mkfs.xfs", "xfs_db", "xfs_repair", "xfs_logprint"] {
        let path = tool(name).canonicalize().unwrap();
        receipt.push_str(&format!(
            "tool={name} resolved={} sha256={}\n",
            path.display(),
            hex(hash(&path))
        ));
        command(name, &["-V".into()], &mut receipt);
    }
    let bytes = (0..350123).map(|n| (n * 73 + 11) as u8).collect::<Vec<_>>();
    let payload = base.join("expected.bin");
    fs::write(&payload, &bytes).unwrap();
    let proto = base.join("prototype");
    let mut owner = Vec::new();
    for flag in ["-u", "-g"] {
        let out = Command::new("id")
            .arg(flag)
            .output()
            .expect("native gate requires id");
        assert!(out.status.success());
        receipt.push_str(&format!(
            "argv=id {flag}\n{}",
            String::from_utf8_lossy(&out.stdout)
        ));
        owner.push(
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .unwrap(),
        );
    }
    fs::write(
        &proto,
        format!(
            "dummy\n0 0\nd--755 {} {}\nnested d--755 {} {}\npayload ---640 {} {} {}\n$\n$\n",
            owner[0],
            owner[1],
            owner[0],
            owner[1],
            owner[0],
            owner[1],
            payload.display()
        ),
    )
    .unwrap();
    let native = base.join("native.img");
    let args=vec!["-f".into(),"-m".into(),"crc=1,finobt=0,rmapbt=0,reflink=0,bigtime=0,inobtcount=0,uuid=37373737-3737-3737-3737-373737373737".into(),"-n".into(),"parent=0".into(),"-i".into(),"sparse=0,nrext64=0,exchange=0".into(),"-d".into(),format!("file=1,name={},size=400m,agcount=4",native.display()),"-l".into(),"size=64m".into(),"-p".into(),proto.to_string_lossy().into_owned()];
    assert!(command("mkfs.xfs", &args, &mut receipt).status.success());
    for profile in [
        "native",
        "leading-hole",
        "allocated-unwritten",
        "hardlinks-byte-name",
    ] {
        let image = if profile == "native" {
            native.clone()
        } else {
            let path = base.join(format!("{profile}.img"));
            fs::copy(&native, &path).unwrap();
            if profile == "leading-hole" {
                patch_inode(&path, 68, |b| {
                    q(b, 56, 354219);
                    let hi = u64::from_be_bytes(b[176..184].try_into().unwrap());
                    q(b, 176, hi | (1 << 9));
                });
            } else if profile == "allocated-unwritten" {
                patch_inode(&path, 68, |b| {
                    let hi = u64::from_be_bytes(b[176..184].try_into().unwrap());
                    q(b, 176, hi | (1u64 << 63));
                });
            } else {
                patch_inode(&path, 67, |b| {
                    let mut dir = vec![2, 0];
                    dir.extend_from_slice(&64u32.to_be_bytes());
                    for (name, offset) in [(vec![b'x', 255], 0x60u16), (b"alias".to_vec(), 0x70u16)]
                    {
                        dir.push(name.len() as u8);
                        dir.extend_from_slice(&offset.to_be_bytes());
                        dir.extend_from_slice(&name);
                        dir.push(1);
                        dir.extend_from_slice(&68u32.to_be_bytes());
                    }
                    q(b, 56, dir.len() as u64);
                    b[176..].fill(0);
                    b[176..176 + dir.len()].copy_from_slice(&dir);
                });
                patch_inode(&path, 68, |b| {
                    b[16..20].copy_from_slice(&2u32.to_be_bytes())
                });
            }
            path
        };
        let expected = match profile {
            "leading-hole" => [vec![0; 4096], bytes.clone()].concat(),
            "allocated-unwritten" => vec![0; bytes.len()],
            _ => bytes.clone(),
        };
        let before = hash(&image);
        assert!(
            command(
                "xfs_repair",
                &["-n".into(), image.to_string_lossy().into_owned()],
                &mut receipt
            )
            .status
            .success()
        );
        assert_eq!(
            hash(&image),
            before,
            "read-only native checker mutated source"
        );
        for query in ["sb 0", "agf 0", "agi 0", "inode 64", "inode 67", "inode 68"] {
            let out = command(
                "xfs_db",
                &[
                    "-r".into(),
                    "-c".into(),
                    query.into(),
                    "-c".into(),
                    "p".into(),
                    image.to_string_lossy().into_owned(),
                ],
                &mut receipt,
            );
            assert!(out.status.success());
        }
        assert!(
            command(
                "xfs_logprint",
                &[image.to_string_lossy().into_owned()],
                &mut receipt
            )
            .status
            .success()
        );
        validate(
            &image,
            &expected,
            profile == "hardlinks-byte-name",
            0,
            &mut receipt,
        );
        let recovered = tempfile::Builder::new()
            .prefix(&format!("recovered-{profile}-"))
            .tempdir_in(&base)
            .unwrap()
            .keep();
        let request = format!("rdump -s {}", recovered.display());
        let out = command(
            "xfs_db",
            &[
                "-r".into(),
                "-c".into(),
                request,
                image.to_string_lossy().into_owned(),
            ],
            &mut receipt,
        );
        assert!(
            out.status.success(),
            "native recovery stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if profile == "hardlinks-byte-name" {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(
                fs::read(
                    recovered
                        .join("nested")
                        .join(std::ffi::OsStr::from_bytes(&[b'x', 255]))
                )
                .unwrap(),
                expected
            );
            assert_eq!(fs::read(recovered.join("nested/alias")).unwrap(), expected);
        } else {
            assert_eq!(
                fs::read(recovered.join("nested/payload")).unwrap(),
                expected
            );
        }
        assert_eq!(hash(&image), before, "native payload oracle mutated source");
        receipt.push_str(&format!(
            "source={} source_sha256={} native_payload_sha256={}\n",
            image.display(),
            hex(before),
            hex(Sha256::digest(&expected).into())
        ));
    }
    let framed = base.join("native-framed.raw");
    let mut out = File::create(&framed).unwrap();
    out.write_all(&[0xa5; 8192]).unwrap();
    io::copy(&mut File::open(&native).unwrap(), &mut out).unwrap();
    out.write_all(&[0x5a; 4096]).unwrap();
    out.sync_all().unwrap();
    drop(out);
    let before = hash(&framed);
    validate(&framed, &bytes, false, 8192, &mut receipt);
    assert_eq!(before, hash(&framed));
    let mut raw = File::open(&framed).unwrap();
    let mut prefix = [0; 8192];
    raw.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, [0xa5; 8192]);
    raw.seek(SeekFrom::End(-4096)).unwrap();
    let mut suffix = [0; 4096];
    raw.read_exact(&mut suffix).unwrap();
    assert_eq!(suffix, [0x5a; 4096]);
    receipt.push_str(&format!("container=raw nonzero_view_offset=8192 view_bytes=419430400 prefix_bytes=8192 suffix_bytes=4096 framing=unchanged sha256={}\n",hex(before)));
    let broken = base.join("crosslink.img");
    fs::copy(&native, &broken).unwrap();
    patch_inode(&broken, 68, |b| {
        let lo = u64::from_be_bytes(b[184..192].try_into().unwrap());
        q(b, 184, (4 << 21) | (lo & 0x1f_ffff));
    });
    let r = resource();
    let v = XfsVolume::open(source(&broken), read_limits(), &r).unwrap();
    let a = audit(&v, audit_limits(), &r).unwrap();
    assert!(!a.is_clean());
    assert!(a.free_ranges().is_empty());
    assert!(
        a.findings()
            .iter()
            .any(|f| matches!(f, XfsAuditFinding::CrossLink { .. }))
    );
    let crosslink_before = hash(&broken);
    let out = command(
        "xfs_repair",
        &["-n".into(), broken.to_string_lossy().into_owned()],
        &mut receipt,
    );
    assert!(
        !out.status.success(),
        "independent checker must reject modeled metadata crosslink"
    );
    assert_eq!(
        hash(&broken),
        crosslink_before,
        "native read-only checker changed malformed source"
    );
    receipt.push_str(&format!(
        "crosslink_reader_audit=defect_free_ranges_suppressed source_sha256={}\n",
        hex(hash(&broken))
    ));
    for path in [
        "src/fs_xfs.rs",
        "src/fs_xfs_audit.rs",
        "src/fs_xfs_tree.rs",
        "tests/fs_xfs.rs",
        "tests/fs_xfs_native.rs",
        "tests/fixtures/xfs_clean.rs",
        "docs/filesystem-xfs-read.md",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        receipt.push_str(&format!(
            "source={path} sha256={}\n",
            hex(hash(Path::new(path)))
        ));
    }
    receipt.push_str(
        "result=passed; immutable read/audit only, no mount/replay/write/discard authority\n",
    );
    fs::write(&receipt_path, receipt).unwrap();
}
