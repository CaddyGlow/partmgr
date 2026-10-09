#![cfg(feature = "std")]

#[path = "common/reader_contract.rs"]
mod reader_contract;
use partmgr::io;
use partmgr::{fs_core::*, fs_hfs::*, fs_hfs_audit::*, fs_hfs_tree::*};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use virtdisk::ReadAt;
#[path = "fixtures/hfs_clean.rs"]
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
fn limits() -> HfsReadLimits {
    HfsReadLimits {
        blocks: 65536,
        nodes: 4096,
        records: 512,
        extents: 2048,
        work: 16 * 1024 * 1024,
    }
}
fn audit_limits() -> HfsAuditLimits {
    HfsAuditLimits {
        blocks: 65536,
        objects: 512,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    }
}
#[test]
fn native_btree_overflow_two_forks_tree_metadata_and_refunds() {
    let r = resources();
    let source = Arc::new(Source::new(hfs_seed()));
    let volume = HfsVolume::open(source.clone(), limits(), &r).unwrap();
    assert_eq!(volume.root_identity().source >> 64, 14);
    let proof = audit_hfs(&volume, audit_limits(), &r).unwrap();
    assert!(proof.is_clean(), "{:?}", proof.findings());
    assert_eq!(proof.allocated_blocks(), 12);
    assert!(proof.free_ranges().iter().all(|e|e.offset>=BASE as u64&&e.offset+e.length<=(BASE+BLOCKS*512) as u64));
    drop(proof);
    assert!(
        source
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, _)| !((BASE + 12 * 512) as u64..(BASE + 23 * 512) as u64).contains(at))
    );
    let id = volume
        .lookup(&[NativeName::Bytes(b"dAtA".to_vec())], &r)
        .unwrap();
    // Retained-index lookup needs no directory-sized memory reservation.
    volume
        .lookup(
            &[NativeName::Bytes(b"dAtA".to_vec())],
            &Resources {
                memory: Budget::new(0),
                cancellation: Cancellation::default(),
            },
        )
        .unwrap();
    let file = volume.open_fork(&id, &StreamKind::Data, &r).unwrap();
    let mut b = [0; 31];
    assert_eq!(file.read_at(3 * 512 - 8, &mut b, &r).unwrap(), 31);
    let expected: Vec<_> = (3 * 512 - 8..3 * 512 + 23)
        .map(|n| (n * 17 % 251) as u8)
        .collect();
    assert_eq!(b.as_slice(), expected);
    assert_eq!(file.read_at(file.len(), &mut b, &r).unwrap(), 0);
    reader_contract::assert_eof_contract(&file, &r);
    let tree = HfsTreeSource::inventory(volume, audit_limits(), &r).unwrap();
    // A one-entry page must fit without charging a complete directory inventory.
    let page_resources = Resources {
        memory: Budget::new(1024),
        cancellation: r.cancellation.clone(),
    };
    let small_page = tree
        .directory_page(&tree.root(), None, 1, &page_resources)
        .unwrap();
    assert_eq!(small_page.entries.len(), 1);
    let cursor = small_page.next.clone().unwrap();
    drop(small_page);
    let small_next = tree
        .directory_page(&tree.root(), Some(&cursor), 1, &page_resources)
        .unwrap();
    assert_eq!(small_next.entries.len(), 1);
    drop(small_next);
    assert_eq!(page_resources.memory.used(), 0);
    let page = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
    assert_eq!(page.entries[0].name, NativeName::Bytes(b"Box".to_vec()));
    let next = tree
        .directory_page(&tree.root(), page.next.as_deref(), 2, &r)
        .unwrap();
    assert_eq!(next.entries[0].object, id);
    assert_eq!(tree.streams(&id, &r).unwrap().get().len(), 2);
    let resource = tree
        .open_stream(&id, &StreamKind::ResourceFork, &r)
        .unwrap();
    let mut b = [0; 5];
    resource.read_at(0, &mut b, &r).unwrap();
    assert_eq!(&b, b"RSRC!");
    let metadata = tree.metadata(&id, &r).unwrap();
    assert_eq!(metadata.get().mode, MetadataField::Absent);
    assert!(matches!(
        metadata.get().security,
        MetadataField::Uninspectable { .. }
    ));
    drop((metadata, resource, next, page, tree, file));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_bounds_offsets_index_cycle_dirty_wrapper_and_unknown_names() {
    for operation in 0..9 {
        let r = resources();
        let mut b = hfs_seed();
        match operation {
            0 => p16(&mut b, 1024 + 28, 1),
            1 => p32(&mut b, 1024 + 20, 511),
            2 => b[BASE + 6 * 512 + 510] = 255,
            3 => p32(&mut b, BASE + 5 * 512 + 14 + 38, 1),
            4 => p16(&mut b, 1024 + 10, 0),
            5 => p16(&mut b, 1024 + 124, 0x482b),
            6 => b[BASE + 6 * 512 + 14 + 7] = 0x80,
            7 => p16(&mut b, BASE + 5 * 512 + 10, 300),
            8 => p16(&mut b, 1024 + 134, 128),
            _ => unreachable!(),
        };
        assert!(
            HfsVolume::open(Arc::new(Source::new(b)), limits(), &r).is_err(),
            "operation {operation}"
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn complete_bitmap_crosslink_lost_free_mirror_and_reference_proof() {
    for operation in 0..6 {
        let r = resources();
        let mut b = hfs_seed();
        match operation {
            0 => b[1536 + 40 / 8] |= 0x80,
            1 => b[1536 + 12 / 8] &= !(0x80 >> (12 % 8)),
            2 => {
                let leaf = BASE + 6 * 512;
                let start =
                    u16::from_be_bytes(b[leaf + 504..leaf + 506].try_into().unwrap()) as usize;
                let data = leaf + start + b[leaf + start] as usize + 1;
                p16(&mut b, data + 86, 12);
            }
            3 => {
                let len = b.len();
                p16(&mut b, len - 1024 + 28, 5)
            }
            4 => p16(&mut b, 1024 + 12, 0),
            5 => {
                let leaf = BASE + 6 * 512;
                let start =
                    u16::from_be_bytes(b[leaf + 506..leaf + 508].try_into().unwrap()) as usize;
                let data = leaf + start + b[leaf + start] as usize + 1;
                p16(&mut b, data + 4, 9)
            }
            _ => unreachable!(),
        };
        let volume = HfsVolume::open(Arc::new(Source::new(b)), limits(), &r).unwrap();
        let report = audit_hfs(&volume, audit_limits(), &r).unwrap();
        assert!(!report.is_clean(), "operation {operation}");
        assert!(report.free_ranges().is_empty());
        assert!(HfsTreeSource::inventory(volume.clone(), audit_limits(), &r).is_err());
        drop((report, volume));
        assert_eq!(r.memory.used(), 0);
    }
    // Alternate MDB dates/counts may be stale by specification, without invalidating its geometry.
    let r = resources();
    let mut b = hfs_seed();
    let len = b.len();
    p32(&mut b, len - 1024 + 84, 0);
    let v = HfsVolume::open(Arc::new(Source::new(b)), limits(), &r).unwrap();
    assert!(audit_hfs(&v, audit_limits(), &r).unwrap().is_clean());
}
#[test]
fn caps_cancellation_failures_stability_foreign_identity_and_retained_leases() {
    for cap in 0..5 {
        let r = resources();
        let mut l = limits();
        match cap {
            0 => l.blocks = 1,
            1 => l.nodes = 1,
            2 => l.records = 1,
            3 => l.extents = 1,
            4 => l.work = 1,
            _ => unreachable!(),
        };
        assert_eq!(
            HfsVolume::open(Arc::new(Source::new(hfs_seed())), l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let source = Arc::new(Source::new(hfs_seed()));
    let v = HfsVolume::open(source.clone(), limits(), &r).unwrap();
    let baseline = r.memory.used();
    let mut l = audit_limits();
    l.work = 1;
    assert_eq!(
        audit_hfs(&v, l, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    let id = v
        .lookup(&[NativeName::Bytes(b"Data".to_vec())], &r)
        .unwrap();
    let file = v.open_fork(&id, &StreamKind::Data, &r).unwrap();
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
    source.bytes.lock().unwrap()[1024 + 2] ^= 1;
    assert_eq!(
        file.read_at(0, &mut [], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.bytes.lock().unwrap()[1024 + 2] ^= 1;
    let other = HfsVolume::open(Arc::new(Source::new(hfs_seed())), limits(), &r).unwrap();
    assert_eq!(
        other.metadata(&id, &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    drop((v, other));
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
        HfsVolume::open(Arc::new(Source::new(hfs_seed())), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "enabled native classic HFS gate requires explicit tool and evidence paths"]
fn native_hfsutils_catalog_two_forks_overflow_and_unchanged_validation() {
    let root = std::path::PathBuf::from(
        std::env::var("PARTMGR_HFS_EVIDENCE")
            .expect("set PARTMGR_HFS_EVIDENCE to fresh retained directory"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory");
    let tools = std::path::PathBuf::from(
        std::env::var("PARTMGR_HFSUTILS_TOOLS")
            .expect("set state-isolated hfsutils tool directory"),
    );
    let tsk = std::path::PathBuf::from(
        std::env::var("PARTMGR_HFS_TSK_TOOLS").expect("set TSK tools directory"),
    );
    let state = root.join("state");
    std::fs::create_dir(&state).unwrap();
    use sha2::{Digest, Sha256};
    let baked: [(&str, &[u8]); 5] = [
        ("src/fs_hfs.rs", include_bytes!("../src/fs_hfs.rs")),
        (
            "src/fs_hfs_audit.rs",
            include_bytes!("../src/fs_hfs_audit.rs"),
        ),
        (
            "src/fs_hfs_tree.rs",
            include_bytes!("../src/fs_hfs_tree.rs"),
        ),
        (
            "tests/fixtures/hfs_clean.rs",
            include_bytes!("fixtures/hfs_clean.rs"),
        ),
        ("tests/fs_hfs.rs", include_bytes!("fs_hfs.rs")),
    ];
    let mut observed = Vec::new();
    let mut provenance =
        String::from("profile=classic-HFS-bare-clean-alphanumeric-native-byte-comparison\n");
    for (path, bytes) in baked {
        let digest = Sha256::digest(bytes);
        assert_eq!(
            Sha256::digest(std::fs::read(path).unwrap()),
            digest,
            "source changed after compilation: {path}"
        );
        provenance.push_str(&format!("compiled_source={path} sha256={digest:x}\n"));
        observed.push((std::path::PathBuf::from(path), digest));
    }
    let binary = std::env::current_exe().unwrap();
    let digest = Sha256::digest(std::fs::read(&binary).unwrap());
    provenance.push_str(&format!(
        "test_binary={} sha256={digest:x}\n",
        binary.display()
    ));
    observed.push((binary, digest));
    for path in [
        tools.join("hformat"),
        tools.join("hcopy"),
        tools.join("hls"),
        tools.join("hmount"),
        tools.join("hmkdir"),
        tsk.join("fsstat"),
    ] {
        let digest = Sha256::digest(std::fs::read(&path).expect("required tool exists"));
        provenance.push_str(&format!("tool={} sha256={digest:x}\n", path.display()));
        observed.push((path, digest));
    }
    let tool_provenance = tools.parent().unwrap().join("provenance.json");
    let digest = Sha256::digest(
        std::fs::read(&tool_provenance).expect("required retained formatter build provenance"),
    );
    provenance.push_str(&format!(
        "formatter_build_provenance={} sha256={digest:x}\n",
        tool_provenance.display()
    ));
    observed.push((tool_provenance, digest));
    std::fs::write(root.join("start-provenance.txt"), &provenance).unwrap();
    let mut commands = String::new();
    let mut run = |tool: &std::path::Path, args: &[&str], layer: &str| {
        commands.push_str(&format!(
            "{layer}: {} {:?}; HFSUTILS_STATE_HOME={}\n",
            tool.display(),
            args,
            state.display()
        ));
        let output = std::process::Command::new(tool)
            .args(args)
            .env("HFSUTILS_STATE_HOME", &state)
            .output()
            .expect("required native tool available");
        std::fs::write(root.join(format!("{layer}.stdout")), &output.stdout).unwrap();
        std::fs::write(root.join(format!("{layer}.stderr")), &output.stderr).unwrap();
        std::fs::write(
            root.join(format!("{layer}.status")),
            output.status.to_string(),
        )
        .unwrap();
        output
    };
    let image = root.join("native.img");
    let path = image.to_str().unwrap();
    std::fs::File::create(&image)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    assert!(
        run(
            &tools.join("hformat"),
            &["-l", "NativeVolume", path],
            "format"
        )
        .status
        .success()
    );
    let payload: Vec<_> = (0..2041).map(|i| (i * 17 % 251) as u8).collect();
    let resource = b"RSRC!";
    let mut macbinary = vec![0; 128];
    macbinary[1] = 4;
    macbinary[2..6].copy_from_slice(b"Data");
    macbinary[65..73].copy_from_slice(b"TEXTPMGR");
    p32(&mut macbinary, 83, payload.len() as u32);
    p32(&mut macbinary, 87, resource.len() as u32);
    macbinary[122] = 129;
    macbinary[123] = 129;
    let mut crc = 0u16;
    for b in &macbinary[..124] {
        crc ^= u16::from(*b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    p16(&mut macbinary, 124, crc);
    macbinary.extend_from_slice(&payload);
    macbinary.resize(macbinary.len().next_multiple_of(128), 0);
    macbinary.extend_from_slice(resource);
    macbinary.resize(macbinary.len().next_multiple_of(128), 0);
    let macpath = root.join("input.bin");
    std::fs::write(&macpath, &macbinary).unwrap();
    assert!(
        run(
            &tools.join("hcopy"),
            &["-m", macpath.to_str().unwrap(), ":Data"],
            "copy-two-forks"
        )
        .status
        .success()
    );
    assert!(
        run(&tools.join("hmkdir"), &[":Box"], "mkdir")
            .status
            .success()
    );
    let childpath = root.join("child.payload");
    std::fs::write(&childpath, b"nested!").unwrap();
    assert!(
        run(
            &tools.join("hcopy"),
            &["-r", childpath.to_str().unwrap(), ":Box:Child"],
            "copy-child"
        )
        .status
        .success()
    );
    for i in 0..80 {
        let name = format!(":File{i:03}");
        assert!(
            run(
                &tools.join("hcopy"),
                &["-r", childpath.to_str().unwrap(), &name],
                &format!("copy-{i:03}")
            )
            .status
            .success()
        );
    }
    let native = std::fs::read(&image).unwrap();
    std::fs::write(root.join("formatter-copy-original.img"), &native).unwrap();
    let mut fragmented = native;
    let (id, blocks) = fragment_native_data(&mut fragmented);
    std::fs::write(&image, &fragmented).unwrap();
    let r = resources();
    let source = Arc::new(Source::new(fragmented.clone()));
    let v = HfsVolume::open(source, limits(), &r).unwrap();
    let proof = audit_hfs(&v, audit_limits(), &r).unwrap();
    assert!(proof.is_clean(), "{:?}", proof.findings());
    let allocated = proof.allocated_blocks();
    let rootentries = v.directory(&v.root_identity(), &r).unwrap();
    assert_eq!(rootentries.get().len(), 82);
    let object = v
        .lookup(&[NativeName::Bytes(b"Data".to_vec())], &r)
        .unwrap();
    assert_eq!(object.native, id.to_be_bytes());
    let tree = HfsTreeSource::inventory(v.clone(), audit_limits(), &r).unwrap();
    assert_eq!(tree.streams(&object, &r).unwrap().get().len(), 2);
    let file = v.open_fork(&object, &StreamKind::Data, &r).unwrap();
    let mut bytes = vec![0; payload.len()];
    file.read_at(0, &mut bytes, &r).unwrap();
    assert_eq!(bytes, payload);
    let rfile = v.open_fork(&object, &StreamKind::ResourceFork, &r).unwrap();
    let mut bytes = [0; 5];
    rfile.read_at(0, &mut bytes, &r).unwrap();
    assert_eq!(&bytes, resource);
    let before = run(std::path::Path::new("sha256sum"), &[path], "image-before");
    assert!(before.status.success());
    let mut permissions = std::fs::metadata(&image).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&image, permissions).unwrap();
    let mount = run(&tools.join("hmount"), &[path], "oracle-mount");
    assert!(mount.status.success());
    assert!(String::from_utf8_lossy(&mount.stdout).contains(&format!(
        "{} bytes free",
        (v.geometry().blocks() - allocated) * v.geometry().block_size()
    )));
    let listing = run(&tools.join("hls"), &["-l", ":"], "oracle-catalog");
    assert!(listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stdout).contains("Data"));
    assert!(String::from_utf8_lossy(&listing.stdout).contains("File079"));
    let nested = run(&tools.join("hls"), &["-l", ":Box"], "oracle-nested");
    assert!(nested.status.success());
    assert!(String::from_utf8_lossy(&nested.stdout).contains("Child"));
    let output = root.join("oracle-two-forks.bin");
    assert!(
        run(
            &tools.join("hcopy"),
            &["-m", ":Data", output.to_str().unwrap()],
            "oracle-forks"
        )
        .status
        .success()
    );
    let output = std::fs::read(output).unwrap();
    assert_eq!(
        u32::from_be_bytes(output[83..87].try_into().unwrap()) as usize,
        payload.len()
    );
    assert_eq!(
        u32::from_be_bytes(output[87..91].try_into().unwrap()) as usize,
        resource.len()
    );
    assert_eq!(&output[128..128 + payload.len()], &payload);
    let at = 128 + payload.len().next_multiple_of(128);
    assert_eq!(&output[at..at + resource.len()], resource);
    let tskversion = run(&tsk.join("fsstat"), &["-V"], "tsk-version");
    assert!(tskversion.status.success());
    let unsupported = run(
        &tsk.join("fsstat"),
        &["-f", "hfs", path],
        "tsk-classic-profile",
    );
    assert!(!unsupported.status.success());
    assert!(
        String::from_utf8_lossy(&unsupported.stderr)
            .contains("other than wrappers HFS+/HFSX file systems")
    );
    let after = run(std::path::Path::new("sha256sum"), &[path], "image-after");
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(std::fs::read(&image).unwrap(), fragmented);
    for source in [
        "src/fs_hfs.rs",
        "src/fs_hfs_audit.rs",
        "src/fs_hfs_tree.rs",
        "tests/fixtures/hfs_clean.rs",
        "tests/fs_hfs.rs",
    ] {
        let layer = format!("source-{}", source.replace('/', "-"));
        assert!(
            run(std::path::Path::new("sha256sum"), &[source], &layer)
                .status
                .success()
        );
    }
    for tool in ["hformat", "hcopy", "hls", "hmount", "hmkdir"] {
        assert!(
            run(
                std::path::Path::new("sha256sum"),
                &[tools.join(tool).to_str().unwrap()],
                &format!("tool-{tool}")
            )
            .status
            .success()
        );
    }
    assert!(
        run(
            std::path::Path::new("sha256sum"),
            &[tsk.join("fsstat").to_str().unwrap()],
            "tool-tsk-fsstat"
        )
        .status
        .success()
    );
    drop((proof, rootentries, tree, file, rfile, v));
    assert_eq!(r.memory.used(), 0);
    for (path, digest) in observed {
        assert_eq!(
            Sha256::digest(std::fs::read(&path).unwrap()),
            digest,
            "source/tool/binary changed during native gate: {}",
            path.display()
        );
    }
    provenance.push_str("source_tool_binary_revalidation=passed\n");
    std::fs::write(root.join("provenance.txt"), &provenance).unwrap();
    std::fs::write(root.join("commands.txt"), commands).unwrap();
    std::fs::write(root.join("receipt.txt"),format!("status=passed\nformatter=hfsutils 3.2.6 source, CLI-state override only\nfixture=formatter plus hcopy MacBinary data/resource, 80 sibling files, nested child; independent test-only raw data fork fragmentation/overflow insertion\ndata_cnid={id}\nphysical_data_blocks={blocks}\nallocated_blocks={allocated}\nframework=complete clean allocation/catalog audit, exact byte names, indexed overflow and both fork bytes matched\nhfsutils_oracle=catalog, free count, data/resource MacBinary readback passed\ntsk_classic_hfs=unsupported explicitly, version output retained\nmacos_fsck=not run\nunchanged_source=sha256 and byte equality\n")).unwrap();
}
#[test]
fn physical_tails_bad_blocks_optional_threads_and_audit_depth_findings_caps() {
    let r = resources();
    let mut bytes = hfs_seed();
    let leaf = BASE + 6 * 512;
    let at = u16::from_be_bytes(bytes[leaf + 504..leaf + 506].try_into().unwrap()) as usize;
    let data = leaf + at + bytes[leaf + at] as usize + 1;
    p32(&mut bytes, data + 26, 1);
    let volume = HfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    let proof = audit_hfs(&volume, audit_limits(), &r).unwrap();
    assert!(proof.is_clean());
    assert_eq!(proof.allocated_blocks(), 12);
    let id = volume
        .lookup(&[NativeName::Bytes(b"Data".to_vec())], &r)
        .unwrap();
    let file = volume.open_fork(&id, &StreamKind::Data, &r).unwrap();
    assert_eq!(file.len(), 1);
    let mut out = [0; 2];
    assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 1);
    let baseline = r.memory.used();
    let mut l = audit_limits();
    l.depth = 0;
    assert_eq!(
        audit_hfs(&volume, l, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    drop((proof, file, volume));
    assert_eq!(r.memory.used(), 0);
    // Actual CNID 5 overflow records own bad blocks, never free candidates.
    let mut bytes = hfs_seed();
    let mut badblock = vec![0; 20];
    badblock[0] = 7;
    p32(&mut badblock, 2, 5);
    extent(&mut badblock, 8, &[(40, 1)]);
    let original = bytes[BASE + 512 + 14..BASE + 512 + 34].to_vec();
    bytes[BASE + 512..BASE + 1024].copy_from_slice(&node(255, 1, 0, 0, &[badblock, original]));
    p32(&mut bytes, BASE + 20, 2);
    bytes[1536 + 40 / 8] |= 0x80;
    p16(&mut bytes, 1024 + 10, 0x300);
    p16(&mut bytes, 1024 + 34, 115);
    let volume = HfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    let proof = audit_hfs(&volume, audit_limits(), &r).unwrap();
    assert!(proof.is_clean(), "{:?}", proof.findings());
    assert_eq!(proof.allocated_blocks(), 13);
    assert!(
        !proof
            .free_ranges()
            .iter()
            .any(|e| e.offset <= (BASE + 40 * 512) as u64
                && e.offset + e.length > (BASE + 40 * 512) as u64)
    );
    drop((proof, volume));
    assert_eq!(r.memory.used(), 0);
    let mut bytes = hfs_seed();
    bytes[1536 + 40 / 8] |= 0x80;
    let volume = HfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    let mut l = audit_limits();
    l.findings = 0;
    let baseline = r.memory.used();
    assert_eq!(
        audit_hfs(&volume, l, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    let mut bytes = hfs_seed();
    p16(&mut bytes, BASE + 512 + 14 + 6, 4);
    assert!(HfsVolume::open(Arc::new(Source::new(bytes)), limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
