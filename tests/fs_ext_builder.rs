#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, ObjectId, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditLimits, audit},
    fs_ext_builder::*,
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
struct Source {
    bytes: Vec<u8>,
    length: AtomicU64,
    fail: AtomicBool,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("causal deferred ext2 read failure"));
        }
        b.copy_from_slice(
            self.bytes
                .get(o as usize..o as usize + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
struct Image {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail_write: bool,
    fail_flush: bool,
    corrupt: bool,
}
impl Image {
    fn new(n: usize) -> Self {
        Self {
            bytes: vec![0xa5; n],
            writes: 0,
            flushes: 0,
            fail_write: false,
            fail_flush: false,
            corrupt: false,
        }
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.bytes[o as usize..o as usize + b.len()]);
        if self.corrupt {
            b[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_write {
            return Err(io::Error::other("modeled write failure"));
        }
        let n = b.len().min(997);
        self.bytes[o as usize..o as usize + n].copy_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::other("modeled flush failure"))
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
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 23,
        generation: 7,
        native: vec![n],
    }
}
fn limits() -> ExtBuildLimits {
    ExtBuildLimits {
        objects: 2048,
        links: 4096,
        name_bytes: 65536,
        blocks: 65536,
        work: 4_000_000,
        depth: 32,
    }
}
fn options(bs: u32) -> ExtBuildOptions {
    ExtBuildOptions {
        block_size: bs,
        blocks_per_group: 4096,
        uuid: [0x42; 16],
    }
}
fn defaults() -> ExtBuildMetadata {
    ExtBuildMetadata {
        file_permissions: 0o640,
        directory_permissions: 0o750,
        uid: 0x12345678,
        gid: 0xabcd4321,
        timestamp: 946684800,
    }
}
fn source() -> Arc<Source> {
    let bytes = (0..350123).map(|n| (n * 73 + 11) as u8).collect::<Vec<_>>();
    Arc::new(Source {
        length: AtomicU64::new(bytes.len() as u64),
        fail: AtomicBool::new(false),
        bytes,
    })
}
fn plan(length: u64, bs: u32, s: Arc<Source>, reverse: bool, r: &Resources) -> ExtBuildPlan {
    let mut objects = vec![
        ExtBuildObject {
            identity: id(1),
            source: None,
        },
        ExtBuildObject {
            identity: id(2),
            source: Some(ExtBuildSource::ReadAt(s)),
        },
        ExtBuildObject {
            identity: id(3),
            source: Some(ExtBuildSource::ReadAt(Arc::new(ReadImage(vec![])))),
        },
    ];
    let mut links = vec![
        ExtBuildLink {
            object: id(1),
            parent: None,
            name: b"nested".to_vec(),
        },
        ExtBuildLink {
            object: id(2),
            parent: Some(id(1)),
            name: b"payload.bin".to_vec(),
        },
        ExtBuildLink {
            object: id(2),
            parent: None,
            name: b"alias.bin".to_vec(),
        },
        ExtBuildLink {
            object: id(3),
            parent: Some(id(1)),
            name: vec![b'x', 255],
        },
    ];
    if reverse {
        objects.reverse();
        links.reverse();
    }
    ExtBuildPlan::new(length, options(bs), objects, links, defaults(), limits(), r).unwrap()
}
fn check(bytes: Vec<u8>, s: &Source, r: &Resources) {
    let v = ExtVolume::open(Arc::new(ReadImage(bytes)), r).unwrap();
    let a = audit(
        &v,
        ExtAuditLimits {
            blocks: 65536,
            inodes: 65536,
            work: 4_000_000,
            directory_blocks: 4096,
            directory_entries: 4096,
            findings: 64,
        },
        r,
    )
    .unwrap();
    assert!(a.is_clean(), "{:?}", a.findings());
    let root = v.directory(2, 16, 128, r).unwrap();
    let alias = root
        .entries()
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias.bin".to_vec()))
        .unwrap();
    let nested = root
        .entries()
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
        .unwrap();
    let dir = v.directory(nested.inode, 16, 128, r).unwrap();
    let child = dir
        .entries()
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload.bin".to_vec()))
        .unwrap();
    assert_eq!(alias.inode, child.inode);
    let inode = v.inode(child.inode, r).unwrap();
    assert_eq!(inode.uid(), defaults().uid);
    assert_eq!(inode.gid(), defaults().gid);
    assert_eq!(inode.mode(), 0x8000 | 0o640);
    let f = v.open_file(child.inode, 4096, r).unwrap();
    let mut out = vec![0; s.bytes.len()];
    assert_eq!(f.read_at(0, &mut out, r).unwrap(), out.len());
    assert_eq!(out, s.bytes);
}
#[test]
fn multiple_group_geometry_hardlinks_indirect_and_determinism() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let s = source();
        let p = plan(16 << 20, bs, s.clone(), false, &r);
        let mut image = Image::new(16 << 20);
        let report = p.emit(&mut image, &r).unwrap();
        assert_eq!(image.flushes, 1);
        assert_eq!(report.files, 2);
        assert_eq!(
            report.sha256,
            <[u8; 32]>::from(Sha256::digest(&image.bytes))
        );
        check(image.bytes.clone(), &s, &r);
        let q = plan(16 << 20, bs, s, true, &r);
        let mut other = Image::new(16 << 20);
        q.emit(&mut other, &r).unwrap();
        assert_eq!(image.bytes, other.bytes);
    }
}
#[test]
fn stale_faults_and_budget_refund() {
    let r = resources();
    let s = source();
    let p = plan(16 << 20, 1024, s.clone(), false, &r);
    let held = r.memory.used();
    assert!(held > 0);
    let mut image = Image::new(16 << 20);
    s.length.store(1, Ordering::SeqCst);
    assert_eq!(
        p.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(image.writes, 0);
    s.length.store(s.bytes.len() as u64, Ordering::SeqCst);
    s.fail.store(true, Ordering::SeqCst);
    let error = p.emit(&mut image, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Io);
    assert_eq!(image.writes, 0);
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains("causal deferred ext2 read failure")
    );
    s.fail.store(false, Ordering::SeqCst);
    image.fail_write = true;
    assert_eq!(
        p.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::InterruptedWrite
    );
    image.fail_write = false;
    image.fail_flush = true;
    assert_eq!(
        p.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    image.fail_flush = false;
    image.corrupt = true;
    assert_eq!(
        p.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::InterruptedWrite
    );
    drop(p);
    assert_eq!(r.memory.used(), 0);
    let low = Resources {
        memory: Budget::new(1024),
        cancellation: Cancellation::default(),
    };
    assert!(
        ExtBuildPlan::new(
            16 << 20,
            options(1024),
            vec![],
            vec![],
            defaults(),
            limits(),
            &low
        )
        .is_err()
    );
    assert_eq!(low.memory.used(), 0);
}
#[test]
fn namespace_connectivity_collision_and_capacity_preflight() {
    let r = resources();
    let objects = vec![ExtBuildObject {
        identity: id(1),
        source: None,
    }];
    let links = vec![ExtBuildLink {
        object: id(1),
        parent: Some(id(1)),
        name: b"cycle".to_vec(),
    }];
    assert!(
        ExtBuildPlan::new(
            16 << 20,
            options(1024),
            objects,
            links,
            defaults(),
            limits(),
            &r
        )
        .is_err()
    );
    let objects = vec![ExtBuildObject {
        identity: id(1),
        source: Some(ExtBuildSource::ReadAt(source())),
    }];
    let links = vec![
        ExtBuildLink {
            object: id(1),
            parent: None,
            name: b"same".to_vec(),
        },
        ExtBuildLink {
            object: id(1),
            parent: None,
            name: b"same".to_vec(),
        },
    ];
    assert!(
        ExtBuildPlan::new(
            16 << 20,
            options(1024),
            objects,
            links,
            defaults(),
            limits(),
            &r
        )
        .is_err()
    );
    assert!(
        ExtBuildPlan::new(
            32 * 1024,
            options(1024),
            vec![ExtBuildObject {
                identity: id(1),
                source: Some(ExtBuildSource::ReadAt(source()))
            }],
            vec![ExtBuildLink {
                object: id(1),
                parent: None,
                name: b"too-large".to_vec()
            }],
            defaults(),
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
}
struct SparseFile {
    identity: ObjectId,
}
impl partmgr::fs_core::FileRead for SparseFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        70001
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let n = self.len().saturating_sub(at).min(out.len() as u64).min(157) as usize;
        for (i, b) in out[..n].iter_mut().enumerate() {
            let p = at + i as u64;
            *b = if (1024..65536).contains(&p) {
                0
            } else {
                (p * 31 + 7) as u8
            };
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(partmgr::fs_core::LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        panic!("materialization must use logical reads, not infer holes")
    }
}
#[test]
fn deferred_indexed_short_reads_materialize_holes_and_cancellation() {
    let r = resources();
    let f = Arc::new(SparseFile { identity: id(9) });
    let p = ExtBuildPlan::new(
        16 << 20,
        options(1024),
        vec![ExtBuildObject {
            identity: id(1),
            source: Some(ExtBuildSource::File(f)),
        }],
        vec![ExtBuildLink {
            object: id(1),
            parent: None,
            name: b"sparse".to_vec(),
        }],
        defaults(),
        limits(),
        &r,
    )
    .unwrap();
    let mut image = Image::new(16 << 20);
    let report = p.emit(&mut image, &r).unwrap();
    assert!(report.materialized_sparse);
    let v = ExtVolume::open(Arc::new(ReadImage(image.bytes)), &r).unwrap();
    let file = v.open_file(11, 4096, &r).unwrap();
    assert!(
        file.extents()
            .iter()
            .all(|e| matches!(e.kind, partmgr::fs_file::ExtentKind::Data(_)))
    );
    let mut bytes = vec![0; 70001];
    file.read_at(0, &mut bytes, &r).unwrap();
    assert!(bytes[1024..65536].iter().all(|b| *b == 0));
    assert_eq!(bytes[0], 7);
    assert_eq!(bytes[70000], (70000u64 * 31 + 7) as u8);
    r.cancellation.cancel();
    let mut fresh = Image::new(16 << 20);
    assert_eq!(
        p.emit(&mut fresh, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(fresh.writes, 0);
}
#[test]
#[ignore = "explicit native gate: EXT_BUILDER_EVIDENCE directory and e2fsck/debugfs required"]
fn native_e2fsck_debugfs_direct_builder() {
    let base = std::env::var_os("EXT_BUILDER_EVIDENCE").expect("EXT_BUILDER_EVIDENCE required");
    let base = std::path::PathBuf::from(base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("classic-ext2-direct-builder-v1.txt"),
        "result=running; no completed acceptance claim\n",
    )
    .unwrap();
    let mut receipt = String::from(
        "profile=classic-ext2-direct-builder-v1\nmetadata=explicit uid/gid/permissions/2000-01-01; sparse materialized; no symlinks or lost+found\n",
    );
    receipt.push_str(&format!(
        "test_argv={:?}\n",
        std::env::args_os().collect::<Vec<_>>()
    ));
    for tool in ["e2fsck", "debugfs"] {
        let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled gate requires tool in PATH")
            .canonicalize()
            .unwrap();
        receipt.push_str(&format!(
            "tool={tool} resolved={} sha256={:x}\n",
            binary.display(),
            Sha256::digest(std::fs::read(&binary).unwrap())
        ));
        let output = Command::new(tool)
            .arg("-V")
            .output()
            .expect("enabled gate requires native tool");
        receipt.push_str(&format!(
            "argv={tool} -V\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    for (size, bs) in [
        (16u64 << 20, 1024),
        (32u64 << 20, 1024),
        (16u64 << 20, 2048),
        (32u64 << 20, 4096),
    ] {
        let r = resources();
        let s = source();
        let mut hashes = Vec::new();
        for order in [false, true] {
            let p = plan(size, bs, s.clone(), order, &r);
            let mut image = Image::new(size as usize);
            let report = p.emit(&mut image, &r).unwrap();
            check(image.bytes.clone(), &s, &r);
            let path = base.join(format!("ext2-{size}-{bs}-{order}.img"));
            std::fs::write(&path, &image.bytes).unwrap();
            let out = Command::new("e2fsck")
                .args(["-f", "-n"])
                .arg(&path)
                .output()
                .unwrap();
            receipt.push_str(&format!(
                "argv=e2fsck -f -n {}\n{}{}",
                path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stdout)
            );
            let extracted = base.join(format!("payload-{size}-{bs}-{order}.bin"));
            let request = format!("dump /nested/payload.bin {}", extracted.display());
            let out = Command::new("debugfs")
                .args(["-R", &request])
                .arg(&path)
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(std::fs::read(&extracted).unwrap(), s.bytes);
            receipt.push_str(&format!(
                "argv=debugfs -R {request:?} {}\n{}{}",
                path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
            for request in [
                "stat /alias.bin",
                "stat /nested/payload.bin",
                "ls -l /nested",
            ] {
                let out = Command::new("debugfs")
                    .args(["-R", request])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(out.status.success());
                let text = String::from_utf8_lossy(&out.stdout);
                if request.starts_with("stat") {
                    assert!(text.contains("Links: 2"), "{text}");
                    assert!(text.contains("Inode: 12"), "{text}");
                    if bs == 1024 {
                        assert!(
                            text.contains("(DIND)"),
                            "double indirect fixture must be traversed: {text}"
                        );
                    }
                } else {
                    assert!(
                        text.contains("x\\xff"),
                        "native escaped non-UTF-8 name bytes absent: {text}"
                    );
                }
                receipt.push_str(&format!(
                    "argv=debugfs -R {request:?} {}\n{}{}",
                    path.display(),
                    text,
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            receipt.push_str(&format!(
                "image={} sha256={:x}\npayload_sha256={:x}\n",
                path.display(),
                Sha256::digest(&image.bytes),
                Sha256::digest(&s.bytes)
            ));
            hashes.push(report.sha256);
        }
        assert_eq!(hashes[0], hashes[1]);
    }
    for path in [
        "src/fs_ext_builder.rs",
        "tests/fs_ext_builder.rs",
        "docs/filesystem-ext-builder.md",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        receipt.push_str(&format!(
            "source={path} sha256={:x}\n",
            Sha256::digest(std::fs::read(path).unwrap())
        ));
    }
    let binary = std::env::current_exe().unwrap();
    receipt.push_str(&format!(
        "test_binary={} sha256={:x}\n",
        binary.display(),
        Sha256::digest(std::fs::read(&binary).unwrap())
    ));
    receipt.push_str("result=passed; modeled errors and actual flushes, not physical power loss\n");
    std::fs::write(base.join("classic-ext2-direct-builder-v1.txt"), receipt).unwrap();
}
