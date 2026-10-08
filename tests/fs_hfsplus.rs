use partmgr::{fs_core::*, fs_hfsplus::*, fs_hfsplus_audit::*, fs_hfsplus_tree::*};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
#[path = "fixtures/hfsplus_clean.rs"]
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
fn limits() -> HfsPlusReadLimits {
    HfsPlusReadLimits {
        blocks: 65536,
        nodes: 4096,
        records: 512,
        extents: 2048,
        work: 16 * 1024 * 1024,
    }
}
fn audit_limits() -> HfsPlusAuditLimits {
    HfsPlusAuditLimits {
        blocks: 65536,
        objects: 512,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    }
}
#[test]
fn indexed_overflow_and_resource_forks_common_native_tree_and_refunds() {
    for binary in [false, true] {
        let r = resources();
        let source = Arc::new(Source::new(hfsplus_seed(binary)));
        let volume = HfsPlusVolume::open(source.clone(), limits(), &r).unwrap();
        assert_eq!(volume.geometry().is_case_sensitive(), binary);
        let proof = audit_hfsplus(&volume, audit_limits(), &r).unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        assert_eq!(proof.allocated_blocks(), 19);
        drop(proof);
        assert!(
            source
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| !((12 * 4096)..(35 * 4096)).contains(at))
        );
        let id = volume
            .lookup(&[NativeName::Utf16(native_name(binary))], &r)
            .unwrap();
        let file = volume.open_fork(&id, &StreamKind::Data, &r).unwrap();
        let mut b = [0; 31];
        assert_eq!(file.read_at(8 * 4096 - 8, &mut b, &r).unwrap(), 31);
        let expected: Vec<_> = (8 * 4096 - 8..8 * 4096 + 23)
            .map(|i| (i * 17 % 251) as u8)
            .collect();
        assert_eq!(b.as_slice(), expected);
        let mut empty = [0; 2];
        assert_eq!(file.read_at(file.len(), &mut empty, &r).unwrap(), 0);
        assert!(file.read_at(file.len() + 1, &mut empty, &r).is_err());
        let tree = HfsPlusTreeSource::inventory(volume, audit_limits(), &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
        let next = tree
            .directory_page(&tree.root(), page.next.as_deref(), 1, &r)
            .unwrap();
        assert_eq!(page.entries.len() + next.entries.len(), 2);
        let metadata = tree.metadata(&id, &r).unwrap();
        assert_eq!(metadata.get().mode, MetadataField::Known(0x81a4));
        let streams = tree.streams(&id, &r).unwrap();
        assert_eq!(streams.get()[1].kind, StreamKind::ResourceFork);
        let resource = tree
            .open_stream(&id, &StreamKind::ResourceFork, &r)
            .unwrap();
        let mut out = [0; 5];
        resource.read_at(0, &mut out, &r).unwrap();
        assert_eq!(&out, b"RSRC!");
        drop((page, next, metadata, streams, resource, file, tree));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_node_offsets_children_cycles_flags_forks_and_budget_reject_without_panic() {
    for (at, value) in [
        (5 * 4096 + 14 + 2 + 18, 0xffu8),
        (6 * 4096 + 4094, 0xff),
        (2 * 4096 + 32, 0),
        (1024 + 4 + 2, 0),
        (1024 + 4 + 2, 0x20),
        (1024 + 44, 0xff),
        (1024 + 192 + 16, 0xff),
    ] {
        let r = resources();
        let mut image = hfsplus_seed(false);
        image[at] = value;
        assert!(
            HfsPlusVolume::open(Arc::new(Source::new(image)), limits(), &r).is_err(),
            "accepted malformed byte {at}"
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        HfsPlusVolume::open(Arc::new(Source::new(hfsplus_seed(false))), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn allocation_reference_counts_mirror_defects_suppress_free_proof() {
    for operation in 0..5 {
        let r = resources();
        let mut image = hfsplus_seed(false);
        match operation {
            0 => image[4096 + 40 / 8] |= 0x80,
            1 => image[4096 + 12 / 8] &= !(0x80 >> (12 % 8)),
            2 => {
                let leaf = 6 * 4096;
                let count =
                    u16::from_be_bytes(image[leaf + 10..leaf + 12].try_into().unwrap()) as usize;
                for i in 0..count {
                    let start = usize::from(u16::from_be_bytes(
                        image[leaf + 4096 - (i + 1) * 2..leaf + 4096 - i * 2]
                            .try_into()
                            .unwrap(),
                    ));
                    let key = usize::from(u16::from_be_bytes(
                        image[leaf + start..leaf + start + 2].try_into().unwrap(),
                    ));
                    let body = leaf + start + 2 + key;
                    if u16::from_be_bytes(image[body..body + 2].try_into().unwrap()) == 2 {
                        p32(&mut image, body + 168 + 16, 12);
                        break;
                    }
                }
            }
            3 => {
                let at = image.len() - 1024 + 40;
                p32(&mut image, at, 8192);
            }
            _ => p32(&mut image, 1024 + 32, 9),
        }
        let volume = HfsPlusVolume::open(Arc::new(Source::new(image)), limits(), &r).unwrap();
        let proof = audit_hfsplus(&volume, audit_limits(), &r).unwrap();
        assert!(!proof.is_clean(), "operation {operation}");
        assert!(proof.free_ranges().is_empty());
        drop((proof, volume));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn cancellation_io_change_scope_and_deferred_lease_lifetimes() {
    let r = resources();
    let source = Arc::new(Source::new(hfsplus_seed(false)));
    let volume = HfsPlusVolume::open(source.clone(), limits(), &r).unwrap();
    let id = volume
        .lookup(&[NativeName::Utf16("data".encode_utf16().collect())], &r)
        .unwrap();
    let file = volume.open_fork(&id, &StreamKind::Data, &r).unwrap();
    let other =
        HfsPlusVolume::open(Arc::new(Source::new(hfsplus_seed(false))), limits(), &r).unwrap();
    assert_eq!(
        other
            .open_fork(&id, &StreamKind::Data, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop((other, volume));
    assert!(r.memory.used() > 0);
    source.fail.store(true, Ordering::Relaxed);
    assert!(
        file.read_at(0, &mut [0; 4], &r)
            .unwrap_err()
            .source
            .is_some()
    );
    source.fail.store(false, Ordering::Relaxed);
    source.length.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        file.read_at(0, &mut [0; 4], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.length.fetch_sub(1, Ordering::Relaxed);
    source.bytes.lock().unwrap()[1024 + 68] ^= 1;
    assert_eq!(
        file.read_at(0, &mut [0; 4], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.bytes.lock().unwrap()[1024 + 68] ^= 1;
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(file.len(), &mut [], &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "enabled Linux hfsprogs/TSK gate requires fresh PARTMGR_HFSPLUS_EVIDENCE and all tools; macOS native evidence is separate"]
fn native_hfsprogs_tsk_catalog_forks_and_unchanged_validation() {
    use sha2::{Digest, Sha256};
    use std::{fs::File, os::unix::fs::FileExt, path::PathBuf, process::Command};
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_EVIDENCE").expect("explicit evidence directory required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let mut receipt = format!(
        "profile=bare-nonjournaled-HFSplus-ASCII-and-HFSX-binary\nreader_sha256={:x}\naudit_sha256={:x}\ntree_sha256={:x}\nfixture_sha256={:x}\ntest_sha256={:x}\nbinary_sha256={:x}\nmacOS_native_gate=not_run_linux_host\nfsck_layer=blocked_regular_file_device_block_size_ioctl_exit8\n",
        Sha256::digest(include_bytes!("../src/fs_hfsplus.rs")),
        Sha256::digest(include_bytes!("../src/fs_hfsplus_audit.rs")),
        Sha256::digest(include_bytes!("../src/fs_hfsplus_tree.rs")),
        Sha256::digest(include_bytes!("fixtures/hfsplus_clean.rs")),
        Sha256::digest(include_bytes!("fs_hfsplus.rs")),
        Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    let mut ordinal = 0;
    let mut run = |tool: &str, args: &[&str]| {
        ordinal += 1;
        let output = Command::new(tool)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("enabled gate missing {tool}: {e}"));
        std::fs::write(
            root.join(format!("{ordinal:03}-{tool}.stdout")),
            &output.stdout,
        )
        .unwrap();
        std::fs::write(
            root.join(format!("{ordinal:03}-{tool}.stderr")),
            &output.stderr,
        )
        .unwrap();
        receipt.push_str(&format!(
            "command={tool} args={args:?} status={} stdout_sha256={:x} stderr_sha256={:x}\n",
            output.status,
            Sha256::digest(&output.stdout),
            Sha256::digest(&output.stderr)
        ));
        assert!(
            output.status.success()
                || tool == "fsck.hfsplus"
                    && output.status.code() == Some(8)
                    && String::from_utf8_lossy(&output.stderr)
                        .contains("Can\'t get device block size"),
            "{tool}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    for tool in [
        "mkfs.hfsplus",
        "fsck.hfsplus",
        "fls",
        "icat",
        "istat",
        "fsstat",
    ] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled native tool required");
        std::fs::write(
            root.join(format!("tool-{tool}.txt")),
            format!(
                "path={} sha256={:x}\n",
                path.canonicalize().unwrap().display(),
                Sha256::digest(std::fs::read(path).unwrap())
            ),
        )
        .unwrap();
    }
    run("fls", &["-V"]);
    run("icat", &["-V"]);
    run("uname", &["-a"]);
    let mut layers = String::new();
    for binary in [false, true] {
        let profile = if binary { "hfsx" } else { "hfsplus" };
        let native = root.join(format!("{profile}-native.img"));
        File::create(&native)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let n = native.to_str().unwrap();
        if binary {
            run("mkfs.hfsplus", &["-s", "-v", "NativeVolume", n]);
        } else {
            run("mkfs.hfsplus", &["-v", "NativeVolume", n]);
        }
        run("fsck.hfsplus", &["-fn", n]);
        let formatted_sha = Sha256::digest(std::fs::read(&native).unwrap());
        let mut bytes = std::fs::read(&native).unwrap();
        let h = bytes[1024..1536].to_vec();
        let bs = u32::from_be_bytes(h[40..44].try_into().unwrap()) as usize;
        let total = u32::from_be_bytes(h[44..48].try_into().unwrap()) as usize;
        let at = |start: usize| {
            u32::from_be_bytes(h[start + 16..start + 20].try_into().unwrap()) as usize * bs
        };
        let bitmap = at(112);
        let extents = at(192);
        let catalog = at(272);
        let ns = u16::from_be_bytes(bytes[catalog + 32..catalog + 34].try_into().unwrap()) as usize;
        let leaf =
            u32::from_be_bytes(bytes[catalog + 16..catalog + 20].try_into().unwrap()) as usize;
        assert_eq!(
            leaf, 1,
            "independent native injector requires fresh one-leaf catalog"
        );
        let original = &bytes[catalog + ns..catalog + ns * 2];
        let count = u16::from_be_bytes(original[10..12].try_into().unwrap()) as usize;
        let mut records = Vec::new();
        for i in 0..count {
            let start =
                u16::from_be_bytes(original[ns - (i + 1) * 2..ns - i * 2].try_into().unwrap())
                    as usize;
            let end = u16::from_be_bytes(
                original[ns - (i + 2) * 2..ns - (i + 1) * 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let mut record = original[start..end].to_vec();
            let key = usize::from(u16::from_be_bytes(record[..2].try_into().unwrap())) + 2;
            if u16::from_be_bytes(record[key..key + 2].try_into().unwrap()) == 1 {
                p32(&mut record, key + 4, 2);
            }
            records.push(record);
        }
        let free: Vec<_> = (0..total)
            .filter(|i| bytes[bitmap + i / 8] & (0x80 >> (i % 8)) == 0)
            .collect();
        assert!(free.len() > 40);
        let data_extents: Vec<_> = (0..9).map(|i| (free[i * 2] as u32, 1u32)).collect();
        let resource_extent = free[19];
        let child_extent = free[21];
        let data_len = 9 * bs - 17;
        let data_payload: Vec<_> = (0..data_len).map(|i| (i * 31 % 251) as u8).collect();
        for (i, (start, _)) in data_extents.iter().enumerate() {
            let begin = i * bs;
            let end = (begin + bs).min(data_len);
            bytes[*start as usize * bs..*start as usize * bs + end - begin]
                .copy_from_slice(&data_payload[begin..end]);
        }
        bytes[resource_extent * bs..resource_extent * bs + 5].copy_from_slice(b"RSRC!");
        bytes[child_extent * bs..child_extent * bs + 7].copy_from_slice(b"nested!");
        for &(start, _) in &data_extents {
            bytes[bitmap + start as usize / 8] |= 0x80 >> (start % 8);
        }
        for start in [resource_extent, child_extent] {
            bytes[bitmap + start / 8] |= 0x80 >> (start % 8);
        }
        let mut file_fork = fork(data_len as u64, &data_extents[..8]);
        p32(&mut file_fork, 12, 9);
        let resource_fork = fork(5, &[(resource_extent as u32, 1)]);
        let child_fork = fork(7, &[(child_extent as u32, 1)]);
        let empty = fork(0, &[]);
        for (parent, name, body) in [
            (2, "DATA", object(16, false, 0, &file_fork, &resource_fork)),
            (2, "BOX", object(17, true, 1, &empty, &empty)),
            (
                16,
                "",
                thread(2, &"DATA".encode_utf16().collect::<Vec<_>>(), false),
            ),
            (
                17,
                "",
                thread(2, &"BOX".encode_utf16().collect::<Vec<_>>(), true),
            ),
            (17, "inside", object(18, false, 0, &child_fork, &empty)),
            (
                18,
                "",
                thread(17, &"inside".encode_utf16().collect::<Vec<_>>(), false),
            ),
        ] {
            let mut record = catalog_key(parent, &name.encode_utf16().collect::<Vec<_>>());
            record.extend_from_slice(&body);
            records.push(record);
        }
        records.sort_by_key(|r| {
            let parent = u32::from_be_bytes(r[2..6].try_into().unwrap());
            let count = u16::from_be_bytes(r[6..8].try_into().unwrap()) as usize;
            let name: Vec<_> = (0..count)
                .map(|i| {
                    let u = u16::from_be_bytes(r[8 + i * 2..10 + i * 2].try_into().unwrap());
                    if !binary && (65..=90).contains(&u) {
                        u + 32
                    } else {
                        u
                    }
                })
                .collect();
            (parent, name)
        });
        bytes[catalog + ns..catalog + ns * 2].copy_from_slice(&node(ns, 255, 1, 0, 0, &records));
        p32(&mut bytes, catalog + 14 + 6, records.len() as u32);
        let ens =
            u16::from_be_bytes(bytes[extents + 32..extents + 34].try_into().unwrap()) as usize;
        let old_free = u32::from_be_bytes(
            bytes[extents + 14 + 26..extents + 14 + 30]
                .try_into()
                .unwrap(),
        );
        let mut overflow = vec![0; 76];
        p16(&mut overflow, 0, 10);
        p32(&mut overflow, 4, 16);
        p32(&mut overflow, 8, 8);
        p32(&mut overflow, 12, data_extents[8].0);
        p32(&mut overflow, 16, 1);
        bytes[extents + ens..extents + ens * 2].copy_from_slice(&node(
            ens,
            255,
            1,
            0,
            0,
            &[overflow],
        ));
        for (field, value) in [(2, 1), (6, 1), (10, 1), (14, 1), (26, old_free - 1)] {
            p32(&mut bytes, extents + 14 + field, value);
        }
        p16(&mut bytes, extents + 14, 1);
        bytes[extents + 248] |= 0x40;
        let free_count = (0..total)
            .filter(|i| bytes[bitmap + i / 8] & (0x80 >> (i % 8)) == 0)
            .count();
        for base in [1024, bytes.len() - 1024] {
            p32(&mut bytes, base + 32, 2);
            p32(&mut bytes, base + 36, 1);
            p32(&mut bytes, base + 48, free_count as u32);
            p32(&mut bytes, base + 64, 19);
        }
        let injected = root.join(format!("{profile}-independent-tree.img"));
        std::fs::write(&injected, &bytes).unwrap();
        let p = injected.to_str().unwrap();
        let before = Sha256::digest(&bytes);
        run("fsck.hfsplus", &["-fn", p]);
        let stats = String::from_utf8(run("fsstat", &["-f", "hfs", p])).unwrap();
        let tsk_free: usize = stats
            .lines()
            .find_map(|line| line.strip_prefix("Number of Free Blocks: "))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(tsk_free, free_count);
        let listing = String::from_utf8(run("fls", &["-r", "-p", "-f", "hfs", p])).unwrap();
        assert!(
            listing.contains("DATA") && listing.contains("BOX/inside"),
            "{listing}"
        );
        assert_eq!(run("icat", &["-f", "hfs", p, "16"]), data_payload);
        assert_eq!(run("icat", &["-f", "hfs", p, "18"]), b"nested!");
        run("istat", &["-f", "hfs", p, "16"]);
        assert_eq!(run("icat", &["-f", "hfs", p, "16-4353-1"]), b"RSRC!");
        struct Host(File);
        impl ReadAt for Host {
            fn len(&self) -> u64 {
                self.0.metadata().unwrap().len()
            }
            fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
                FileExt::read_exact_at(&self.0, b, at)
            }
        }
        let r = resources();
        let volume =
            HfsPlusVolume::open(Arc::new(Host(File::open(&injected).unwrap())), limits(), &r)
                .unwrap();
        let proof = audit_hfsplus(&volume, audit_limits(), &r).unwrap();
        assert!(proof.is_clean(), "{profile} {:?}", proof.findings());
        let owned = proof.allocated_blocks();
        assert_eq!(owned as usize, total - tsk_free);
        drop(proof);
        let tree = HfsPlusTreeSource::inventory(volume, audit_limits(), &r).unwrap();
        let id = tree
            .volume()
            .lookup(&[NativeName::Utf16("DATA".encode_utf16().collect())], &r)
            .unwrap();
        let data = tree.open_stream(&id, &StreamKind::Data, &r).unwrap();
        let mut observed = vec![0; data_len];
        data.read_at(0, &mut observed, &r).unwrap();
        assert_eq!(observed, data_payload);
        let resource = tree
            .open_stream(&id, &StreamKind::ResourceFork, &r)
            .unwrap();
        let mut b = [0; 5];
        resource.read_at(0, &mut b, &r).unwrap();
        assert_eq!(&b, b"RSRC!");
        drop((data, resource, tree));
        assert_eq!(r.memory.used(), 0);
        assert_eq!(before, Sha256::digest(std::fs::read(&injected).unwrap()));
        assert_eq!(
            formatted_sha,
            Sha256::digest(std::fs::read(&native).unwrap())
        );
        layers.push_str(&format!("family={profile} allocated_blocks={owned} native_formatted_sha256={formatted_sha:x} validated_image_sha256={before:x} payload_sha256={:x} unchanged_validation=passed refund=passed\n",Sha256::digest(&data_payload)));
    }
    drop(run);
    receipt.push_str(&layers);
    receipt.push_str("status=passed\n");
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}
#[test]
fn comparison_is_read_from_hfsx_catalog_and_caps_fail_with_refunds() {
    let r = resources();
    let mut image = hfsplus_seed(false);
    for base in [1024, image.len() - 1024] {
        p16(&mut image, base, 0x4858);
        p16(&mut image, base + 2, 5);
    }
    let volume = HfsPlusVolume::open(Arc::new(Source::new(image)), limits(), &r).unwrap();
    assert_eq!(volume.geometry().family(), Family::HfsX);
    assert!(!volume.geometry().is_case_sensitive());
    assert!(
        volume
            .lookup(&[NativeName::Utf16("DATA".encode_utf16().collect())], &r)
            .is_ok()
    );
    let baseline = r.memory.used();
    let mut caps = audit_limits();
    caps.depth = 0;
    assert_eq!(
        audit_hfsplus(&volume, caps, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    caps = audit_limits();
    caps.work = 1;
    assert_eq!(
        audit_hfsplus(&volume, caps, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    for cap in 0..4 {
        let mut l = limits();
        match cap {
            0 => l.nodes = 1,
            1 => l.records = 1,
            2 => l.extents = 1,
            _ => l.work = 1,
        }
        assert_eq!(
            HfsPlusVolume::open(Arc::new(Source::new(hfsplus_seed(false))), l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let mut bytes = hfsplus_seed(false);
    bytes.extend_from_slice(&[0x93; 512]);
    assert_eq!(
        HfsPlusVolume::open(Arc::new(Source::new(bytes)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
}
