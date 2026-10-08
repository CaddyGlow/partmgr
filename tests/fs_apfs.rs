use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_core::*};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
struct Bytes(Vec<u8>);
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.0
                .get(start..start + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn limits() -> ApfsReadLimits {
    ApfsReadLimits {
        blocks: 262144,
        checkpoint_blocks: 256,
        objects: 256,
        records: 256,
        work: 64 * 1024 * 1024,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn audit_limits() -> ApfsAuditLimits {
    ApfsAuditLimits {
        blocks: 262144,
        objects: 512,
        depth: 32,
        work: 64 * 1024 * 1024,
        findings: 64,
    }
}
#[test]
fn independent_native_layout_payloads_forks_and_full_allocation() {
    let r = resources();
    let c = ApfsContainer::open(Arc::new(Bytes(fixture::apfs_seed())), limits(), &r).unwrap();
    assert_eq!(c.source_scope() >> 64, 16);
    assert_eq!(c.checkpoint().xid, 1);
    let v = ApfsVolume::open(c.clone(), 1026, &r).unwrap();
    let report = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 51);
    let id = v
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    let file = v.open_file(&id, &r).unwrap();
    let mut b = vec![0xaa; 16384 + 13];
    assert_eq!(file.read_at(0, &mut b, &r).unwrap(), b.len());
    for (i, value) in b.iter().enumerate() {
        assert_eq!(
            *value,
            if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                0
            } else {
                (i % 4096 * 17 % 251) as u8
            }
        );
    }
    let fork = v.open_stream(&id, &StreamKind::ResourceFork, &r).unwrap();
    let mut b = [0; 8];
    assert_eq!(fork.read_at(0, &mut b, &r).unwrap(), 8);
    assert_eq!(&b, b"resource");
    drop((fork, file, report, v, c));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn checkpoint_complete_ephemeral_fallback_and_unsupported_newest() {
    let r = resources();
    let mut b = fixture::apfs_seed();
    fixture::next_checkpoint(&mut b);
    let c = ApfsContainer::open(Arc::new(Bytes(b.clone())), limits(), &r).unwrap();
    assert_eq!(c.checkpoint().xid, 2);
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(proof.is_clean(), "{:?}", proof.findings());
    drop(proof);
    drop(v);
    b[14 * 4096 + 100] ^= 1;
    let c = ApfsContainer::open(Arc::new(Bytes(b)), limits(), &r).unwrap();
    assert_eq!(c.checkpoint().xid, 1);
    drop(c);
    let mut b = fixture::apfs_seed();
    fixture::next_checkpoint(&mut b);
    fixture::p64(&mut b, 4 * 4096 + 64, 0x102);
    fixture::seal(&mut b[4 * 4096..5 * 4096]);
    assert_eq!(
        ApfsContainer::open(Arc::new(Bytes(b)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_checksums_mapping_tree_slots_native_records_and_feature_gates() {
    for case in 0..14 {
        let r = resources();
        let mut b = fixture::apfs_seed();
        match case {
            0 => b[40] ^= 1,
            1 => {
                fixture::p64(&mut b, 112, 511);
                fixture::seal(&mut b[..4096]);
            }
            2 => {
                fixture::p32(&mut b, 4096 + 36, 1024);
                fixture::seal(&mut b[4096..8192]);
            }
            3 => {
                fixture::p64(&mut b, 4096 + 40 + 32, 511);
                fixture::seal(&mut b[4096..8192]);
            }
            4 => {
                fixture::p32(&mut b, 4096 + 40 + 8, 8192);
                fixture::seal(&mut b[4096..8192]);
            }
            5 => b[10 * 4096 + 50] ^= 1,
            6 => {
                fixture::p16(&mut b, 18 * 4096 + 56, 65535);
                fixture::seal(&mut b[18 * 4096..19 * 4096]);
            }
            7 => {
                fixture::p16(&mut b, 22 * 4096 + 56 + 2, 1);
                fixture::seal(&mut b[22 * 4096..23 * 4096]);
            }
            8 => {
                fixture::p16(&mut b, 22 * 4096 + 48, 1);
                fixture::seal(&mut b[22 * 4096..23 * 4096]);
            }
            9 => {
                fixture::p64(&mut b, 19 * 4096 + 56, 1);
                fixture::seal(&mut b[19 * 4096..20 * 4096]);
            }
            10 => {
                fixture::p64(&mut b, 19 * 4096 + 264, 0);
                fixture::seal(&mut b[19 * 4096..20 * 4096]);
            }
            11 => {
                fixture::p64(&mut b, 19 * 4096 + 216, 1);
                fixture::seal(&mut b[19 * 4096..20 * 4096]);
            }
            12 => {
                let mut records = fixture::fs_records();
                records.retain(|(k, v)| {
                    !(u64::from_le_bytes(k[..8].try_into().unwrap()) >> 60 == 8
                        && u64::from_le_bytes(v[8..16].try_into().unwrap()) == 0)
                });
                b[22 * 4096..23 * 4096]
                    .copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
            }
            13 => {
                let mut records = fixture::fs_records();
                records.push((fixture::key(19, 7), vec![0; 24]));
                b[22 * 4096..23 * 4096]
                    .copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
            }
            _ => unreachable!(),
        }
        let opened = ApfsContainer::open(Arc::new(Bytes(b)), limits(), &r)
            .and_then(|c| ApfsVolume::open(c, 1026, &r));
        assert!(opened.is_err(), "case {case}");
        drop(opened);
        assert_eq!(r.memory.used(), 0, "case {case}");
    }
}
#[test]
fn allocation_crosslink_lost_free_counts_reference_and_copy_defects_suppress_free() {
    for case in 0..6 {
        let r = resources();
        let mut b = fixture::apfs_seed();
        match case {
            0 => {
                b[41 * 4096 + 140 / 8] |= 1 << (140 % 8);
                fixture::bitmap_counts(&mut b);
            }
            1 => {
                b[41 * 4096 + 100 / 8] &= !(1 << (100 % 8));
                fixture::bitmap_counts(&mut b);
            }
            2 => {
                fixture::p64(&mut b, 96, 3);
                fixture::seal(&mut b[..4096]);
            }
            3 | 4 => {
                let mut records = fixture::fs_records();
                for (k, v) in &mut records {
                    let key = u64::from_le_bytes(k[..8].try_into().unwrap());
                    if case == 3 && key == (3u64 << 60 | 16) {
                        fixture::p32(v, 56, 2);
                    }
                    if case == 4 && key == (8u64 << 60 | 18) {
                        fixture::p64(v, 8, 100);
                    }
                }
                b[22 * 4096..23 * 4096]
                    .copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
            }
            5 => {
                fixture::p64(&mut b, 10 * 4096 + 72, 1);
                fixture::seal(&mut b[10 * 4096..11 * 4096]);
            }
            _ => unreachable!(),
        }
        let c = ApfsContainer::open(Arc::new(Bytes(b)), limits(), &r).unwrap();
        if case == 3 {
            assert_eq!(
                ApfsVolume::open(c, 1026, &r).err().unwrap().kind,
                ErrorKind::InvalidData
            );
            assert_eq!(r.memory.used(), 0);
            continue;
        }
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let result = audit_apfs(&v, audit_limits(), &r);
        if case == 5 {
            assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidData);
        } else {
            let report = result.unwrap();
            assert!(!report.is_clean(), "case {case}");
            assert!(report.free_ranges().is_empty());
        }
        if case != 5 {
            let id = v
                .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
                .unwrap();
            assert!(v.open_file(&id, &r).is_err());
        }
        drop(v);
        assert_eq!(r.memory.used(), 0);
    }
}
struct MutableSource {
    bytes: Mutex<Vec<u8>>,
    length: AtomicU64,
    fail: AtomicBool,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl MutableSource {
    fn new(b: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(b.len() as u64),
            bytes: Mutex::new(b),
            fail: AtomicBool::new(false),
            reads: Mutex::new(Vec::new()),
        }
    }
}
impl ReadAt for MutableSource {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.reads.lock().unwrap().push((at, b.len()));
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("independent backend failure"));
        }
        let source = self.bytes.lock().unwrap();
        let start = usize::try_from(at).map_err(io::Error::other)?;
        b.copy_from_slice(
            source
                .get(start..start + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
#[test]
fn bounded_deferred_io_cancellation_source_stability_and_lease_refunds() {
    for case in 0..4 {
        let r = resources();
        let mut l = limits();
        match case {
            0 => l.blocks = 511,
            1 => l.checkpoint_blocks = 7,
            2 => l.objects = 3,
            3 => l.work = 1,
            _ => unreachable!(),
        };
        assert_eq!(
            ApfsContainer::open(Arc::new(Bytes(fixture::apfs_seed())), l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        ApfsContainer::open(Arc::new(Bytes(fixture::apfs_seed())), limits(), &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
    let r = resources();
    let source = Arc::new(MutableSource::new(fixture::apfs_seed()));
    let c = ApfsContainer::open(source.clone(), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let id = v
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    let file = v.open_file(&id, &r).unwrap();
    assert!(
        source
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, _)| !([100, 102, 110, 112].contains(&(at / 4096))))
    );
    let baseline = r.memory.used();
    assert!(baseline > 0);
    drop(v);
    assert_eq!(r.memory.used(), baseline);
    let cancel = resources();
    cancel.cancellation.cancel();
    assert_eq!(
        file.read_at(file.len(), &mut [], &cancel).unwrap_err().kind,
        ErrorKind::Cancelled
    );
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
    source.bytes.lock().unwrap()[22 * 4096 + 300] ^= 1;
    assert_eq!(
        file.read_at(0, &mut [0; 1], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn tree_pages_bind_native_directory_and_source() {
    use partmgr::fs_apfs_tree::ApfsTreeSource;
    let r = resources();
    let c = ApfsContainer::open(Arc::new(Bytes(fixture::apfs_seed())), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let tree = ApfsTreeSource::inventory(v, audit_limits(), &r).unwrap();
    let first = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
    let second = tree
        .directory_page(&tree.root(), first.next.as_deref(), 1, &r)
        .unwrap();
    assert_ne!(first.entries[0].object, second.entries[0].object);
    let child = tree
        .volume()
        .lookup(&[NativeName::Bytes(b"Box".to_vec())], &r)
        .unwrap();
    assert_eq!(
        tree.directory_page(&child, first.next.as_deref(), 1, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop((first, second, tree));
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "enabled native gate requires PARTMGR_APFS_NATIVE_EVIDENCE"]
fn native_formatter_checker_payload_and_fork_receipt() {
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
        std::env::var("PARTMGR_APFS_NATIVE_EVIDENCE").expect("enabled gate requires evidence path");
    let root = Path::new(&root);
    fs::create_dir(root).expect("fresh evidence directory required");
    let mut bindings = Vec::new();
    for (name, bytes) in [
        (
            "src/fs_apfs.rs",
            include_bytes!("../src/fs_apfs.rs").as_slice(),
        ),
        (
            "src/fs_apfs_index.rs",
            include_bytes!("../src/fs_apfs_index.rs").as_slice(),
        ),
        (
            "src/fs_apfs_audit.rs",
            include_bytes!("../src/fs_apfs_audit.rs").as_slice(),
        ),
        (
            "src/fs_apfs_tree.rs",
            include_bytes!("../src/fs_apfs_tree.rs").as_slice(),
        ),
        (
            "tests/fixtures/apfs_clean.rs",
            include_bytes!("fixtures/apfs_clean.rs").as_slice(),
        ),
        ("tests/fs_apfs.rs", include_bytes!("fs_apfs.rs").as_slice()),
    ] {
        let baked = root.join(name.replace('/', "_"));
        fs::write(&baked, bytes).unwrap();
        let hash = digest(&baked);
        assert_eq!(hash, digest(Path::new(name)), "source differs from binary");
        bindings.push((Path::new(name).to_owned(), hash));
    }
    let binary = std::env::current_exe().unwrap();
    bindings.push((binary.clone(), digest(&binary)));
    let apfs = Path::new("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin");
    let tsk = Path::new("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin");
    for p in [
        apfs.join("mkapfs"),
        apfs.join("apfsck"),
        tsk.join("pstat"),
        tsk.join("fsstat"),
        tsk.join("fls"),
        tsk.join("istat"),
        tsk.join("icat"),
    ] {
        assert!(p.is_file(), "required tool missing {}", p.display());
        bindings.push((p.clone(), digest(&p)));
    }
    let listing = || {
        bindings
            .iter()
            .map(|(p, h)| format!("{h} {}\n", p.display()))
            .collect::<String>()
    };
    fs::write(root.join("bindings.start"), listing()).unwrap();
    for (label, tool) in [
        ("formatter-version", apfs.join("mkapfs")),
        ("checker-version", apfs.join("apfsck")),
        ("oracle-version", tsk.join("fsstat")),
    ] {
        let _ = run(root, label, &tool, &["-V"], None);
    }
    let image = root.join("formatted.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    assert!(
        run(
            root,
            "format",
            &apfs.join("mkapfs"),
            &["-s", "-z", image.to_str().unwrap()],
            None
        )
        .0
    );
    let before = digest(&image);
    assert!(
        run(
            root,
            "blank-check",
            &apfs.join("apfsck"),
            &["-c", "-u", "-w", image.to_str().unwrap()],
            None
        )
        .0
    );
    assert_eq!(before, digest(&image));
    let mut bytes = fs::read(&image).unwrap();
    fixture::insert_native(&mut bytes);
    let populated = root.join("populated.img");
    fs::write(&populated, &bytes).unwrap();
    let before = digest(&populated);
    let path = populated.to_str().unwrap();
    assert!(
        run(
            root,
            "populated-check",
            &apfs.join("apfsck"),
            &["-c", "-u", "-w", path],
            None
        )
        .0
    );
    assert!(run(root, "pool", &tsk.join("pstat"), &[path], None).0);
    for (label, tool, extra) in [
        ("filesystem", "fsstat", None),
        ("directory", "fls", None),
        ("inode-file", "istat", Some("16")),
        ("inode-directory", "istat", Some("17")),
        ("inode-child", "istat", Some("18")),
    ] {
        let mut args = vec!["-P", "apfs", "-B", "171", "-f", "apfs", path];
        if let Some(id) = extra {
            args.push(id);
        }
        assert!(run(root, label, &tsk.join(tool), &args, None).0);
    }
    assert!(
        String::from_utf8_lossy(&fs::read(root.join("pool.stdout")).unwrap())
            .contains("Number of Free Blocks: 16181")
    );
    for (label, name) in [
        ("inode-file", "Aé-file"),
        ("inode-directory", "Box"),
        ("inode-child", "Child"),
    ] {
        assert!(
            fs::read_to_string(root.join(format!("{label}.stdout")))
                .unwrap()
                .contains(name)
        );
    }
    let r = resources();
    let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let report = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 203);
    let id = v
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    for (label, native, kind) in [
        ("data", "16", StreamKind::Data),
        ("resource", "16-4353-1", StreamKind::ResourceFork),
    ] {
        assert!(
            run(
                root,
                label,
                &tsk.join("icat"),
                &["-P", "apfs", "-B", "171", "-f", "apfs", path, native],
                None
            )
            .0
        );
        let oracle = fs::read(root.join(format!("{label}.stdout"))).unwrap();
        let file = v.open_stream(&id, &kind, &r).unwrap();
        let mut data = vec![0; file.len() as usize];
        assert_eq!(file.read_at(0, &mut data, &r).unwrap(), data.len());
        assert_eq!(data, oracle);
    }
    let child = v
        .lookup(
            &[
                NativeName::Bytes(b"Box".to_vec()),
                NativeName::Bytes(b"Child".to_vec()),
            ],
            &r,
        )
        .unwrap();
    assert!(
        run(
            root,
            "child-data",
            &tsk.join("icat"),
            &["-P", "apfs", "-B", "171", "-f", "apfs", path, "18"],
            None
        )
        .0
    );
    let mut data = [0; 7];
    assert_eq!(
        v.open_file(&child, &r)
            .unwrap()
            .read_at(0, &mut data, &r)
            .unwrap(),
        7
    );
    assert_eq!(
        data.as_slice(),
        fs::read(root.join("child-data.stdout")).unwrap()
    );
    let tree =
        partmgr::fs_apfs_tree::ApfsTreeSource::inventory(v.clone(), audit_limits(), &r).unwrap();
    assert_eq!(
        tree.directory_page(&tree.root(), None, 8, &r)
            .unwrap()
            .entries
            .len(),
        2
    );
    assert_eq!(before, digest(&populated));
    for distinct in [false, true] {
        let label = if distinct {
            "distinct-clone"
        } else {
            "private-stream-clone"
        };
        let mut bytes = fs::read(&populated).unwrap();
        fixture::insert_native_shared(&mut bytes, distinct);
        let image = root.join(format!("{label}.img"));
        fs::write(&image, &bytes).unwrap();
        let before = digest(&image);
        let path = image.to_str().unwrap();
        assert!(
            run(
                root,
                &format!("{label}-check"),
                &apfs.join("apfsck"),
                &["-c", "-u", "-w", path],
                None
            )
            .0
        );
        assert!(
            run(
                root,
                &format!("{label}-inode"),
                &tsk.join("istat"),
                &["-P", "apfs", "-B", "171", "-f", "apfs", path, "16"],
                None
            )
            .0
        );
        assert!(
            fs::read_to_string(root.join(format!("{label}-inode.stdout")))
                .unwrap()
                .contains("Number of Links: 2")
        );
        assert!(
            run(
                root,
                &format!("{label}-data"),
                &tsk.join("icat"),
                &["-P", "apfs", "-B", "171", "-f", "apfs", path, "21"],
                None
            )
            .0
        );
        let resources = Resources {
            memory: Budget::new(256 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits(), &resources).unwrap();
        let v = ApfsVolume::open(c, 1026, &resources).unwrap();
        let proof = audit_apfs(&v, audit_limits(), &resources).unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        assert_eq!(proof.allocated_blocks(), 203);
        let original = v
            .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &resources)
            .unwrap();
        let alias = v
            .lookup(
                &[
                    NativeName::Bytes(b"Box".to_vec()),
                    NativeName::Bytes(b"Alias".to_vec()),
                ],
                &resources,
            )
            .unwrap();
        assert_eq!(original, alias);
        let clone = v
            .lookup(&[NativeName::Bytes(b"Clone".to_vec())], &resources)
            .unwrap();
        let file = v.open_file(&clone, &resources).unwrap();
        let mut data = vec![0; file.len() as usize];
        file.read_at(0, &mut data, &resources).unwrap();
        assert_eq!(
            data,
            fs::read(root.join(format!("{label}-data.stdout"))).unwrap()
        );
        assert_eq!(data, fs::read(root.join("data.stdout")).unwrap());
        drop((file, proof, v));
        assert_eq!(resources.memory.used(), 0);
        assert_eq!(before, digest(&image));
        fs::write(root.join(format!("{label}.receipt")),format!("status=passed\nallocated_blocks=203\nhardlink_inode=16\nclone_inode=21\nsha256={before}\nprovenance=independent native record insertion; fixture source retained\n")).unwrap();
    }
    let multi = root.join("multivolume-history.img");
    fs::File::create(&multi)
        .unwrap()
        .set_len(fixture::MULTIVOLUME_LENGTH)
        .unwrap();
    assert!(
        run(
            root,
            "multivolume-format",
            &apfs.join("mkapfs"),
            &["-s", "-z", multi.to_str().unwrap()],
            None
        )
        .0
    );
    let mut extended = vec![0; 4 * 1024 * 1024];
    {
        use std::io::Read;
        fs::File::open(&multi)
            .unwrap()
            .read_exact(&mut extended)
            .unwrap();
    }
    fixture::insert_native_second_volume(&mut extended);
    fixture::next_checkpoint(&mut extended);
    let nx = extended[4 * 4096..5 * 4096].to_vec();
    extended[..4096].copy_from_slice(&nx);
    {
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .open(&multi)
            .unwrap()
            .write_all(&extended)
            .unwrap();
    }
    let before_multi = digest(&multi);
    assert!(
        run(
            root,
            "multivolume-history-check",
            &apfs.join("apfsck"),
            &["-c", "-u", "-w", multi.to_str().unwrap()],
            None
        )
        .0
    );
    assert!(
        run(
            root,
            "multivolume-history-pool",
            &tsk.join("pstat"),
            &[multi.to_str().unwrap()],
            None
        )
        .0
    );
    let pool = fs::read_to_string(root.join("multivolume-history-pool.stdout")).unwrap();
    assert!(pool.contains("NX xid: 2"));
    assert!(pool.contains("Number of Blocks:      131073"));
    assert!(pool.contains("Number of Free Blocks: 130624"));
    for (label, block) in [("multivolume-first", "403"), ("multivolume-second", "600")] {
        assert!(
            run(
                root,
                label,
                &tsk.join("fsstat"),
                &[
                    "-P",
                    "apfs",
                    "-B",
                    block,
                    "-f",
                    "apfs",
                    multi.to_str().unwrap()
                ],
                None
            )
            .0
        );
    }
    let broad = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let container = ApfsContainer::open(
        Arc::new(Padded(extended, fixture::MULTIVOLUME_LENGTH)),
        limits(),
        &broad,
    )
    .unwrap();
    assert_eq!(container.checkpoint().xid, 2);
    for oid in [1026, 1100] {
        let peer = ApfsVolume::open(container.clone(), oid, &broad).unwrap();
        let proof = audit_apfs(&peer, audit_limits(), &broad).unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        assert_eq!(proof.allocated_blocks(), 449);
        if oid == 1100 {
            assert!(
                peer.directory(&peer.root_identity(), &broad)
                    .unwrap()
                    .get()
                    .is_empty()
            );
        }
    }
    drop(container);
    assert_eq!(broad.memory.used(), 0);
    assert_eq!(before_multi, digest(&multi));
    fs::write(root.join("multivolume-history.receipt"),format!("status=passed\nselected_xid=2\nvolume_oids=1026,1100\nallocated_blocks=449\nsha256={before_multi}\nprovenance=independent native insertion into experimental formatter; helper source retained\n")).unwrap();
    for (p, h) in &bindings {
        assert_eq!(*h, digest(p), "bound input changed {}", p.display());
    }
    fs::write(root.join("bindings.end"), listing()).unwrap();
    fs::write(root.join("receipt.txt"),format!("status=passed\nallocated_blocks=203\npopulated_sha256={before}\nformatter=apfsprogs0.2.1 experimental Linux\noracle=TSK4.14.0+apfsck\nprovenance=independent raw fixture insertion into formatter image; compiled fixture retained\nfls_gap=normalization-sensitive names rendered incorrectly; istat names and checker retained\nmacOS_native_evidence=unavailable\n")).unwrap();
}

#[test]
fn all_volumes_and_historical_checkpoints_share_exact_container_proof() {
    let r = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut bytes = fixture::apfs_seed();
    fixture::second_volume(&mut bytes);
    let c = ApfsContainer::open(
        Arc::new(Padded(bytes.clone(), fixture::MULTIVOLUME_LENGTH)),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(c.checkpoint().volumes, vec![1026, 1100]);
    for oid in [1026, 1100] {
        let v = ApfsVolume::open(c.clone(), oid, &r).unwrap();
        let report = audit_apfs(&v, audit_limits(), &r).unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.allocated_blocks(), 69);
    }
    drop(c);
    assert_eq!(r.memory.used(), 0);
    fixture::next_checkpoint(&mut bytes);
    let c = ApfsContainer::open(
        Arc::new(Padded(bytes, fixture::MULTIVOLUME_LENGTH)),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(c.checkpoint().xid, 2);
    let v = ApfsVolume::open(c, 1100, &r).unwrap();
    let report = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 69);
    drop((report, v));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn historical_metadata_pins_allocation_and_unselected_defects_are_not_hidden() {
    let r = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut bytes = fixture::apfs_seed();
    fixture::relocated_checkpoint(&mut bytes);
    let c = ApfsContainer::open(Arc::new(Bytes(bytes.clone())), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let report = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 59);
    assert!(
        report
            .free_ranges()
            .iter()
            .all(|e| !(e.offset <= 19 * 4096 && 19 * 4096 < e.offset + e.length))
    );
    let baseline = r.memory.used();
    let capped = ApfsAuditLimits {
        objects: 12,
        ..audit_limits()
    };
    assert_eq!(
        audit_apfs(&v, capped, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        audit_apfs(&v, audit_limits(), &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(cancelled.memory.used(), 0);
    drop((report, v));
    assert_eq!(r.memory.used(), 0);
    let mut bytes = fixture::apfs_seed();
    fixture::second_volume(&mut bytes);
    fixture::p64(&mut bytes, 50 * 4096 + 264, 0);
    fixture::seal(&mut bytes[50 * 4096..51 * 4096]);
    let c = ApfsContainer::open(
        Arc::new(Padded(bytes, fixture::MULTIVOLUME_LENGTH)),
        limits(),
        &r,
    )
    .unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let baseline = r.memory.used();
    assert_eq!(
        audit_apfs(&v, audit_limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), baseline);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}

struct Padded(Vec<u8>, u64);
impl ReadAt for Padded {
    fn len(&self) -> u64 {
        self.1
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if at.checked_add(out.len() as u64).is_none_or(|n| n > self.1) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        out.fill(0);
        let at = usize::try_from(at).map_err(io::Error::other)?;
        if at < self.0.len() {
            let n = out.len().min(self.0.len() - at);
            out[..n].copy_from_slice(&self.0[at..at + n]);
        }
        Ok(())
    }
}

#[test]
fn historical_owner_conflicts_and_free_bits_suppress_all_free_ranges() {
    for free in [false, true] {
        let mut bytes = fixture::apfs_seed();
        fixture::relocated_checkpoint(&mut bytes);
        if free {
            bytes[43 * 4096 + 19 / 8] &= !(1 << (19 % 8));
            fixture::p32(&mut bytes, 44 * 4096 + 60, 454);
            fixture::seal(&mut bytes[44 * 4096..45 * 4096]);
            fixture::p64(&mut bytes, 14 * 4096 + 72, 454);
            fixture::seal(&mut bytes[14 * 4096..15 * 4096]);
        } else {
            let mut records = fixture::fs_records();
            for (key, value) in &mut records {
                if u64::from_le_bytes(key[..8].try_into().unwrap()) >> 60 == 8
                    && u64::from_le_bytes(key[8..16].try_into().unwrap()) == 0
                    && u64::from_le_bytes(key[..8].try_into().unwrap()) & 0x0fff_ffff_ffff_ffff
                        == 16
                {
                    fixture::p64(value, 8, 19);
                }
            }
            bytes[63 * 4096..64 * 4096]
                .copy_from_slice(&fixture::leaf(1027, 2, 0, 14, &records, false));
            let mut records = fixture::extent_records();
            fixture::p64(&mut records[0].0, 0, (2u64 << 60) | 19);
            bytes[64 * 4096..65 * 4096]
                .copy_from_slice(&fixture::leaf(64, 2, 0x40000000, 15, &records, false));
        }
        let r = Resources {
            memory: Budget::new(256 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits(), &r).unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
        assert!(!proof.is_clean());
        assert!(proof.free_ranges().is_empty());
        assert!(proof.findings().iter().any(|f| if free {
            matches!(f, ApfsAuditFinding::ReferencedFree { block: 19 })
        } else {
            matches!(f, ApfsAuditFinding::CrossLink { block: 19 })
        }));
        drop((proof, v));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn historical_headers_stale_deferred_handles_and_array_caps_refund() {
    let mut bytes = fixture::apfs_seed();
    fixture::relocated_checkpoint(&mut bytes);
    let r = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let raw = Arc::new(MutableSource::new(bytes));
    let c = ApfsContainer::open(raw.clone(), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let id = v
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    let file = v.open_file(&id, &r).unwrap();
    raw.bytes.lock().unwrap()[2 * 4096 + 1000] ^= 1;
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    drop((file, v));
    assert_eq!(r.memory.used(), 0);
    let mut bytes = fixture::apfs_seed();
    fixture::p32(&mut bytes, 10 * 4096 + 328, 336);
    fixture::seal(&mut bytes[10 * 4096..11 * 4096]);
    let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let baseline = r.memory.used();
    assert!(audit_apfs(&v, audit_limits(), &r).is_err());
    assert_eq!(r.memory.used(), baseline);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn regular_hardlinks_and_clones_have_exact_refs_and_deferred_shared_streams() {
    for distinct in [false, true] {
        let r = resources();
        let c = ApfsContainer::open(
            Arc::new(Bytes(fixture::shared_seed(distinct))),
            limits(),
            &r,
        )
        .unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        assert_eq!(proof.allocated_blocks(), 51);
        let original = v
            .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
            .unwrap();
        let alias = v
            .lookup(
                &[
                    NativeName::Bytes(b"Box".to_vec()),
                    NativeName::Bytes(b"Alias".to_vec()),
                ],
                &r,
            )
            .unwrap();
        let clone = v
            .lookup(&[NativeName::Bytes(b"Clone".to_vec())], &r)
            .unwrap();
        assert_eq!(original, alias);
        assert_ne!(original, clone);
        let source = v.open_file(&original, &r).unwrap();
        let cloned = v.open_file(&clone, &r).unwrap();
        let mut a = vec![0; source.len() as usize];
        let mut b = vec![0; cloned.len() as usize];
        source.read_at(0, &mut a, &r).unwrap();
        cloned.read_at(0, &mut b, &r).unwrap();
        assert_eq!(a, b);
        assert!(proof.free_ranges().iter().all(|e| {
            ![100, 102, 110]
                .iter()
                .any(|at| e.offset <= at * 4096 && at * 4096 < e.offset + e.length)
        }));
        drop((source, cloned, proof, v));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn sharing_history_and_multiple_volumes_keep_native_authority_separate() {
    let r = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    for distinct in [false, true] {
        let c = ApfsContainer::open(
            Arc::new(Bytes(fixture::shared_history_seed(distinct))),
            limits(),
            &r,
        )
        .unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        assert_eq!(proof.allocated_blocks(), 59);
        drop((proof, v));
        assert_eq!(r.memory.used(), 0);
    }
    let mut bytes = fixture::apfs_seed();
    fixture::second_volume(&mut bytes);
    let (fs, ext) = fixture::shared_records(true);
    bytes[53 * 4096..54 * 4096].copy_from_slice(&fixture::leaf(1101, 1, 0, 14, &fs, false));
    bytes[54 * 4096..55 * 4096].copy_from_slice(&fixture::leaf(54, 1, 0x40000000, 15, &ext, false));
    fixture::p64(&mut bytes, 50 * 4096 + 176, 22);
    fixture::p64(&mut bytes, 50 * 4096 + 184, 3);
    fixture::p64(&mut bytes, 50 * 4096 + 192, 1);
    fixture::p64(&mut bytes, 50 * 4096 + 88, 9);
    fixture::seal(&mut bytes[50 * 4096..51 * 4096]);
    let c = ApfsContainer::open(
        Arc::new(Padded(bytes, fixture::MULTIVOLUME_LENGTH)),
        limits(),
        &r,
    )
    .unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(!proof.is_clean());
    assert!(proof.free_ranges().is_empty());
    assert!(
        proof
            .findings()
            .contains(&ApfsAuditFinding::CrossLink { block: 100 })
    );
    drop((proof, v));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn rechecksummed_sibling_and_shared_reference_defects_fail_or_suppress_free() {
    for case in 0..12 {
        let (mut records, mut ext) = fixture::shared_records(case != 8);
        let mut bytes = fixture::shared_seed(case != 8);
        match case {
            0 => records.retain(|(k, _)| {
                u64::from_le_bytes(k[..8].try_into().unwrap()) != ((12u64 << 60) | 20)
            }),
            1 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((5u64 << 60) | 16)
                            && u64::from_le_bytes(k[8..16].try_into().unwrap()) == 20
                    })
                    .unwrap();
                v[10] = b'Z';
            }
            2 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((12u64 << 60) | 20)
                    })
                    .unwrap();
                fixture::p64(v, 0, 18);
            }
            3 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((5u64 << 60) | 16)
                            && u64::from_le_bytes(k[8..16].try_into().unwrap()) == 20
                    })
                    .unwrap();
                fixture::p64(v, 0, 2);
            }
            4 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((9u64 << 60) | 17)
                            && k[10..] == *b"Alias\0"
                    })
                    .unwrap();
                fixture::p64(v, 0, 17);
                fixture::p16(v, 16, 4);
            }
            5 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((3u64 << 60) | 16)
                    })
                    .unwrap();
                fixture::p32(v, 56, 3);
            }
            6 | 7 => fixture::p32(&mut ext[0].1, 16, if case == 6 { 1 } else { 3 }),
            8 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((6u64 << 60) | 16)
                    })
                    .unwrap();
                fixture::p32(v, 0, 1);
            }
            9 => {
                let (_, v) = records
                    .iter_mut()
                    .find(|(k, _)| {
                        u64::from_le_bytes(k[..8].try_into().unwrap()) == ((3u64 << 60) | 21)
                    })
                    .unwrap();
                fixture::p64(v, 48, 0x4200);
            }
            10 => fixture::p64(&mut ext[0].1, 8, 999),
            11 => fixture::p32(&mut ext[0].1, 16, u32::MAX),
            _ => unreachable!(),
        }
        bytes[22 * 4096..23 * 4096]
            .copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
        bytes[23 * 4096..24 * 4096]
            .copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &ext, false));
        let r = resources();
        let c = ApfsContainer::open(Arc::new(Bytes(bytes)), limits(), &r).unwrap();
        if [6, 7, 9].contains(&case) {
            let v = ApfsVolume::open(c, 1026, &r).unwrap();
            let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
            assert!(!proof.is_clean());
            assert!(proof.free_ranges().is_empty());
            drop((v, proof));
        } else {
            assert_eq!(
                ApfsVolume::open(c, 1026, &r).err().unwrap().kind,
                ErrorKind::InvalidData,
                "case{case}"
            );
        }
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn sharing_limits_cancellation_deferred_metadata_staleness_and_refunds() {
    let r = resources();
    let raw = Arc::new(MutableSource::new(fixture::shared_seed(false)));
    let c = ApfsContainer::open(raw.clone(), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let id = v
        .lookup(&[NativeName::Bytes(b"Clone".to_vec())], &r)
        .unwrap();
    let baseline = r.memory.used();
    assert!(
        raw.reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, _)| !([100, 102, 110, 112].contains(&(at / 4096))))
    );
    for cap in [
        ApfsAuditLimits {
            objects: 2,
            ..audit_limits()
        },
        ApfsAuditLimits {
            work: 32768,
            ..audit_limits()
        },
    ] {
        assert_eq!(
            audit_apfs(&v, cap, &r).err().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), baseline);
    }
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        v.open_file(&id, &cancelled).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(cancelled.memory.used(), 0);
    let file = v.open_file(&id, &r).unwrap();
    assert_eq!(
        file.read_at(file.len(), &mut [], &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    raw.fail.store(true, Ordering::Relaxed);
    assert_eq!(
        file.read_at(0, &mut [0; 1], &r).err().unwrap().kind,
        ErrorKind::Io
    );
    raw.fail.store(false, Ordering::Relaxed);
    raw.bytes.lock().unwrap()[22 * 4096 + 300] ^= 1;
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    drop((file, v));
    assert_eq!(r.memory.used(), 0);
}

#[path = "fixtures/apfs_resource.rs"]
mod resource_fixture;
#[test]
fn external_resource_unique_streams_have_exact_physical_refs_and_deferred_forks() {
    for shared in [false, true] {
        for defect in 0..7 {
            let r = resources();
            let c = ApfsContainer::open(
                Arc::new(Bytes(resource_fixture::seed(shared, defect))),
                limits(),
                &r,
            )
            .unwrap();
            let opened = ApfsVolume::open(c, 1026, &r);
            if (1..=4).contains(&defect) {
                assert!(opened.is_err(), "defect {defect}");
            } else {
                let v = opened.unwrap();
                let report = audit_apfs(&v, audit_limits(), &r).unwrap();
                assert_eq!(
                    report.is_clean(),
                    matches!(defect, 0 | 6),
                    "{:?}",
                    report.findings()
                );
                if defect == 5 {
                    assert!(report.free_ranges().is_empty());
                }
                for name in [b"A\xc3\xa9-file".as_slice(), b"Clone".as_slice()] {
                    let id = v.lookup(&[NativeName::Bytes(name.to_vec())], &r).unwrap();
                    let opened_fork = v.open_stream(&id, &StreamKind::ResourceFork, &r);
                    if defect == 5 {
                        assert!(opened_fork.is_err());
                        continue;
                    }
                    let fork = opened_fork.unwrap();
                    let mut bytes = [0; 8];
                    assert_eq!(fork.read_at(0, &mut bytes, &r).unwrap(), 8);
                    assert_eq!(&bytes, b"resource");
                }
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn external_named_xattrs_retain_exact_name_and_physical_reference_proof() {
    for shared in [false, true] {
        let r = resources();
        let c = ApfsContainer::open(
            Arc::new(Bytes(resource_fixture::generic_seed(shared, 0))),
            limits(),
            &r,
        )
        .unwrap();
        let v = ApfsVolume::open(c, 1026, &r).unwrap();
        let report = audit_apfs(&v, audit_limits(), &r).unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        let kind = StreamKind::Named(NativeName::Bytes("user/external.é".as_bytes().to_vec()));
        for name in [b"A\xc3\xa9-file".as_slice(), b"Clone".as_slice()] {
            let id = v.lookup(&[NativeName::Bytes(name.to_vec())], &r).unwrap();
            let stream = v.open_stream(&id, &kind, &r).unwrap();
            let mut bytes = [0; 8];
            assert_eq!(stream.read_at(0, &mut bytes, &r).unwrap(), 8);
            assert_eq!(&bytes, b"resource");
            assert!(v.open_stream(&id, &StreamKind::ResourceFork, &r).is_err());
        }
        drop((report, v));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn reserved_root_physical_owner_cannot_authorize_data_or_free_space() {
    let r = resources();
    let mut image = fixture::shared_seed(true);
    let (_, mut ext) = fixture::shared_records(true);
    for (_, value) in &mut ext {
        fixture::p64(value, 8, 2);
    }
    image[23 * 4096..24 * 4096].copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &ext, false));
    let c = ApfsContainer::open(Arc::new(Bytes(image)), limits(), &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let proof = audit_apfs(&v, audit_limits(), &r).unwrap();
    assert!(!proof.is_clean());
    assert!(proof.free_ranges().is_empty());
    let id = v
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    assert!(v.open_file(&id, &r).is_err());
    drop((proof, v));
    assert_eq!(r.memory.used(), 0);
}
