use partmgr::{fs_core::*, fs_jfs::*, fs_jfs_audit::*, fs_jfs_tree::*};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
#[path = "fixtures/jfs_clean.rs"]
mod fixture;
use fixture::*;
struct Source {
    bytes: Mutex<Vec<u8>>,
    length: AtomicU64,
    fail: AtomicBool,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes: Mutex::new(bytes),
            fail: AtomicBool::new(false),
            reads: Mutex::new(Vec::new()),
        }
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.reads.lock().unwrap().push((at, b.len()));
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("independent read failure"));
        }
        let bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(at).map_err(io::Error::other)?;
        b.copy_from_slice(
            bytes
                .get(start..start + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> JfsReadLimits {
    JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    }
}
fn audit_limits() -> JfsAuditLimits {
    JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    }
}
#[test]
fn independent_fixture() {
    let r = resources();
    let volume = JfsVolume::open(Arc::new(Source::new(jfs_seed())), limits(), &r).unwrap();
    let proof = audit_jfs(&volume, audit_limits(), &r).unwrap();
    assert!(proof.is_clean(), "{:?}", proof.findings());
    assert_eq!(proof.allocated_blocks(), 71);
    let file = volume
        .open_file(
            &volume.lookup(&[NativeName::Utf16(name())], &r).unwrap(),
            &r,
        )
        .unwrap();
    let mut out = vec![0xaa; 4 * BLOCK + 7];
    file.read_at(0, &mut out, &r).unwrap();
    assert!(out[BLOCK..2 * BLOCK].iter().all(|v| *v == 0));
    assert!(out[3 * BLOCK..].iter().all(|v| *v == 0));
    drop((volume, proof, file));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn malformed_geometry_log_inode_map_buddy_slots_extent_cycles_and_unsupported() {
    for operation in 0..14 {
        let r = resources();
        let mut b = jfs_seed();
        match operation {
            0 => p32(&mut b, 32768 + 40, 1),
            1 => p32(&mut b, 483 * BLOCK + 28, 0),
            2 => p32(&mut b, 32768 + 4, 3),
            3 => p32(&mut b, 32768 + 16, 512),
            4 => p32(&mut b, 29 * BLOCK + 4 * 512 + 52, 0xa1ff),
            5 => b[29 * BLOCK + 4 * 512 + 88] = 0x20,
            6 => b[33 * BLOCK + 4096 + 2560] ^= 1,
            7 => b[20 * BLOCK + 33] ^= 1,
            8 => pxd(&mut b, 29 * BLOCK + 4 * 512 + 224 + 40, 512, 1),
            9 => {
                b[90 * BLOCK + 16] = 0x84;
                pxd(&mut b, 90 * BLOCK + 40, 90, 1);
            }
            10 => b[29 * BLOCK + 2 * 512 + 224 + 24] = 0xff,
            11 => b[29 * BLOCK + 2 * 512 + 224 + 4 * 32] = 4,
            12 => p32(&mut b, 45056 + 24, 1),
            13 => p32(&mut b, 29 * BLOCK + 4 * 512 + 52, 0x680a4),
            _ => unreachable!(),
        };
        assert!(
            JfsVolume::open(Arc::new(Source::new(b)), limits(), &r).is_err(),
            "operation {operation}"
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn complete_allocation_inode_links_index_parent_mirror_defects_suppress_free() {
    for operation in 0..7 {
        let r = resources();
        let mut b = jfs_seed();
        match operation {
            0 => {
                let mut used: Vec<_> = (0..22).chain(23..35).collect();
                used.extend([90, 100, 102, 110, 112, 120]);
                rebuild_map(&mut b, &used)
            }
            1 => {
                let mut used: Vec<_> = (0..22).chain(23..35).collect();
                used.extend([90, 102, 110, 112]);
                rebuild_map(&mut b, &used)
            }
            2 => pxd(&mut b, 90 * BLOCK + 3 * 16 + 8, 100, 1),
            3 => p32(&mut b, 29 * BLOCK + 4 * 512 + 40, 1),
            4 => b[29 * BLOCK + 2 * 512 + 128 + 2] = 7,
            5 => p32(&mut b, 29 * BLOCK + 5 * 512 + 244, 5),
            6 => b[61440 + 36] ^= 1,
            _ => unreachable!(),
        };
        let v = JfsVolume::open(Arc::new(Source::new(b)), limits(), &r).unwrap();
        let report = audit_jfs(&v, audit_limits(), &r).unwrap();
        assert!(!report.is_clean(), "operation {operation}");
        assert!(report.free_ranges().is_empty());
        assert!(JfsTreeSource::inventory(v.clone(), audit_limits(), &r).is_err());
        drop((report, v));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn independent_caps_cancellation_deferred_failures_staleness_and_retained_leases() {
    for cap in 0..6 {
        let r = resources();
        let mut l = limits();
        match cap {
            0 => l.blocks = 1,
            1 => l.inodes = 1,
            2 => l.entries = 1,
            3 => l.pages = 0,
            4 => l.extents = 1,
            5 => l.work = 1,
            _ => unreachable!(),
        };
        assert_eq!(
            JfsVolume::open(Arc::new(Source::new(jfs_seed())), l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let source = Arc::new(Source::new(jfs_seed()));
    let volume = JfsVolume::open(source.clone(), limits(), &r).unwrap();
    let base = r.memory.used();
    let mut l = audit_limits();
    l.work = 1;
    assert_eq!(
        audit_jfs(&volume, l, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), base);
    l = audit_limits();
    l.depth = 0;
    assert_eq!(
        audit_jfs(&volume, l, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), base);
    let id = volume.lookup(&[NativeName::Utf16(name())], &r).unwrap();
    let file = volume.open_file(&id, &r).unwrap();
    source.fail.store(true, Ordering::Relaxed);
    assert_eq!(
        file.read_at(0, &mut [0; 1], &r).unwrap_err().kind,
        ErrorKind::Io
    );
    source.fail.store(false, Ordering::Relaxed);
    source.length.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.length.fetch_add(1, Ordering::Relaxed);
    source.bytes.lock().unwrap()[32768 + 36] ^= 1;
    assert_eq!(
        file.read_at(0, &mut [], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.bytes.lock().unwrap()[32768 + 36] ^= 1;
    let other = JfsVolume::open(Arc::new(Source::new(jfs_seed())), limits(), &r).unwrap();
    assert_eq!(
        other.metadata(&id, &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    drop((volume, other));
    assert!(r.memory.used() > 0);
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        JfsVolume::open(Arc::new(Source::new(jfs_seed())), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn directory_index_pages_native_cursor_binding_and_malformed_child_names() {
    let r = resources();
    let mut bytes = jfs_seed();
    external_directory(&mut bytes);
    let v = JfsVolume::open(Arc::new(Source::new(bytes.clone())), limits(), &r).unwrap();
    let report = audit_jfs(&v, audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 72);
    let tree = JfsTreeSource::inventory(v.clone(), audit_limits(), &r).unwrap();
    let a = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
    let b = tree
        .directory_page(&tree.root(), a.next.as_deref(), 8, &r)
        .unwrap();
    assert_eq!(a.entries[0].object, b.entries[1].object);
    assert_eq!(b.entries[1].name, NativeName::Utf16(name()));
    let child = tree
        .volume()
        .lookup(&[NativeName::Utf16("Box".encode_utf16().collect())], &r)
        .unwrap();
    assert_eq!(
        tree.directory_page(&child, a.next.as_deref(), 1, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop((report, tree, v, a, b));
    assert_eq!(r.memory.used(), 0);
    pxd(&mut bytes, 29 * BLOCK + 2 * 512 + 224 + 32, 512, 1);
    assert!(JfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "requires PARTMGR_JFS_NATIVE_EVIDENCE and installed jfsutils/TSK"]
fn native_formatter_checker_and_debugger_receipt() {
    use std::{
        fs,
        path::Path,
        process::{Command, Stdio},
    };
    fn digest(p: &Path) -> String {
        let out = Command::new("sha256sum").arg(p).output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }
    fn run(
        root: &Path,
        layer: &str,
        tool: &Path,
        args: &[&str],
        input: Option<&str>,
    ) -> (bool, String) {
        fs::write(
            root.join(format!("{layer}.command")),
            format!("{} {:?}\n", tool.display(), args),
        )
        .unwrap();
        let mut command = Command::new(tool);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        fs::write(root.join(format!("{layer}.stdout")), &out.stdout).unwrap();
        fs::write(root.join(format!("{layer}.stderr")), &out.stderr).unwrap();
        fs::write(root.join(format!("{layer}.status")), out.status.to_string()).unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
    let root =
        std::env::var("PARTMGR_JFS_NATIVE_EVIDENCE").expect("enabled gate requires evidence path");
    let root = Path::new(&root);
    fs::create_dir(root).expect("fresh evidence directory required");
    let mut bindings = Vec::new();
    for (name, bytes) in [
        (
            "src/fs_jfs.rs",
            include_bytes!("../src/fs_jfs.rs").as_slice(),
        ),
        (
            "src/fs_jfs_audit.rs",
            include_bytes!("../src/fs_jfs_audit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_tree.rs",
            include_bytes!("../src/fs_jfs_tree.rs").as_slice(),
        ),
        (
            "tests/fixtures/jfs_clean.rs",
            include_bytes!("fixtures/jfs_clean.rs").as_slice(),
        ),
        ("tests/fs_jfs.rs", include_bytes!("fs_jfs.rs").as_slice()),
    ] {
        let baked = root.join(name.replace("/", "_"));
        fs::write(&baked, bytes).unwrap();
        let hash = digest(&baked);
        assert_eq!(
            hash,
            digest(Path::new(name)),
            "source differs from test binary"
        );
        bindings.push((Path::new(name).to_owned(), hash));
    }
    let binary = std::env::current_exe().unwrap();
    bindings.push((binary.clone(), digest(&binary)));
    let tools = Path::new("/nix/store/fdm6pjmnk5l7kpprwmdmfcsig5yvy9nz-jfsutils-1.1.15/bin");
    let mkfs = tools.join("mkfs.jfs");
    let fsck = tools.join("fsck.jfs");
    let debug = tools.join("jfs_debugfs");
    let tsk = Path::new("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/fsstat");
    for p in [&mkfs, &fsck, &debug, tsk] {
        assert!(p.is_file(), "required tool missing {}", p.display());
        bindings.push((p.to_owned(), digest(p)));
    }
    fs::write(
        root.join("bindings.start"),
        bindings
            .iter()
            .map(|(p, h)| format!("{h} {}\n", p.display()))
            .collect::<String>(),
    )
    .unwrap();
    let image = root.join("formatted.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    assert!(
        run(
            root,
            "format",
            &mkfs,
            &["-q", image.to_str().unwrap()],
            None
        )
        .0
    );
    let original = digest(&image);
    let blank = run(
        root,
        "blank-fsck",
        &fsck,
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(blank.0 && blank.1.contains("Filesystem is clean"));
    assert_eq!(original, digest(&image));
    let mut bytes = fs::read(&image).unwrap();
    insert_native(&mut bytes);
    let inserted = root.join("inserted.img");
    fs::write(&inserted, &bytes).unwrap();
    let before = digest(&inserted);
    let checker = run(
        root,
        "inserted-fsck",
        &fsck,
        &["-n", inserted.to_str().unwrap()],
        None,
    );
    assert!(
        checker.0 && checker.1.contains("Filesystem is clean"),
        "{}",
        checker.1
    );
    let debugger = run(
        root,
        "debugger",
        &debug,
        &[inserted.to_str().unwrap()],
        Some("directory 2\ndirectory 5\ninode 4\nx\nxtree 4\n\nd\n\n\n\nx\nquit\n"),
    );
    assert!(
        debugger.0
            && debugger.1.contains("Alias")
            && debugger.1.contains("Box")
            && debugger.1.contains("Child"),
        "{}",
        debugger.1
    );
    let tsk_result = run(
        root,
        "tsk-capability",
        tsk,
        &["-f", "jfs", inserted.to_str().unwrap()],
        None,
    );
    assert!(
        !tsk_result.0 && tsk_result.1.to_lowercase().contains("unsupported"),
        "{}",
        tsk_result.1
    );
    assert_eq!(before, digest(&inserted));
    let r = resources();
    let volume = JfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    let audit = audit_jfs(&volume, audit_limits(), &r).unwrap();
    assert!(audit.is_clean(), "{:?}", audit.findings());
    assert_eq!(audit.allocated_blocks(), 349);
    let tree = JfsTreeSource::inventory(volume.clone(), audit_limits(), &r).unwrap();
    assert_eq!(tree.root(), volume.root_identity());
    let id = volume.lookup(&[NativeName::Utf16(name())], &r).unwrap();
    assert_eq!(
        id,
        volume
            .lookup(&[NativeName::Utf16("Alias".encode_utf16().collect())], &r)
            .unwrap()
    );
    let f = volume.open_file(&id, &r).unwrap();
    let mut payload = vec![0xaa; 4 * BLOCK + 7];
    f.read_at(0, &mut payload, &r).unwrap();
    for (i, byte) in payload.iter().enumerate() {
        assert_eq!(
            *byte,
            if i < BLOCK || (2 * BLOCK..3 * BLOCK).contains(&i) {
                ((i % BLOCK) * 17 % 251) as u8
            } else {
                0
            }
        );
    }
    drop((f, tree, audit, volume));
    assert_eq!(r.memory.used(), 0);
    assert_eq!(before, digest(&inserted));
    assert_eq!(original, digest(&image));
    for (p, h) in &bindings {
        assert_eq!(*h, digest(p), "binding changed {}", p.display());
    }
    fs::write(root.join("receipt.txt"),format!("status=passed\nprofile=Linux-v1-4KiB-inline-redone-log\nformatter-original-sha256={original}\ninserted-sha256={before}\nallocated-blocks=349\nraw-fixture-insertion=compiled independent constructor; sparse data, unwritten allocation, external extent and directory leaves, nested directory, two hardlinks\nindependent-oracle=fsck.jfs allocation/reference verification; jfs_debugfs native directory/inode output\nTSK=JFS unsupported, explicit attempted capability failure\npayload-oracle=known independent insertion bytes; no independent whole-file extraction tool\nexact-name-oracle=raw UTF16 fixture; debugger display truncates unpaired surrogate, not exact Unicode oracle\n")).unwrap();
}

#[test]
fn independently_encoded_small_hardlinks_share_identity_payload_and_allocation() {
    let r = resources();
    let mut bytes = jfs_seed();
    small_hardlink(&mut bytes);
    let volume = JfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    let directory = NativeName::Utf16("Box".encode_utf16().collect());
    let child = volume
        .lookup(
            &[
                directory.clone(),
                NativeName::Utf16("Child".encode_utf16().collect()),
            ],
            &r,
        )
        .unwrap();
    let peer = volume
        .lookup(
            &[
                directory,
                NativeName::Utf16("Peer".encode_utf16().collect()),
            ],
            &r,
        )
        .unwrap();
    assert_eq!(child, peer);
    let proof = audit_jfs(&volume, audit_limits(), &r).unwrap();
    assert!(proof.is_clean());
    assert_eq!(proof.allocated_blocks(), 71);
    for id in [&child, &peer] {
        let file = volume.open_file(id, &r).unwrap();
        let mut payload = [0; 7];
        assert_eq!(file.read_at(0, &mut payload, &r).unwrap(), 7);
        assert_eq!(&payload, b"nested!");
    }
    drop((volume, proof));
    assert_eq!(r.memory.used(), 0);
}
