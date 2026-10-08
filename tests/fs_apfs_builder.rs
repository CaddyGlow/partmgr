use partmgr::{
    fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*, fs_apfs_tree::ApfsTreeSource, fs_core::*,
    storage::Storage,
};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[path = "fixtures/apfs_build_tree.rs"]
mod common_fixture;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.0
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
#[derive(Default)]
struct Faults {
    write: Option<usize>,
    flush: Option<usize>,
    read: bool,
    corrupt: bool,
    stale: Option<Arc<common_fixture::Controls>>,
}
#[derive(Default)]
struct Target {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fault: Faults,
    barriers: Vec<usize>,
}
#[cfg(unix)]
struct NativeTarget {
    file: std::fs::File,
    flushes: usize,
}
#[cfg(unix)]
impl Storage for NativeTarget {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.file, out, at)
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        std::os::unix::fs::FileExt::write_at(&self.file, b, at)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        self.flushes += 1;
        Ok(())
    }
}
#[cfg(unix)]
struct NativeRead(std::fs::File);
#[cfg(unix)]
impl ReadAt for NativeRead {
    fn len(&self) -> u64 {
        self.0.metadata().map_or(0, |m| m.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0, out, at)
    }
}
impl Storage for Target {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.fault.read {
            return Err(io::Error::other("modeled staging readback failure"));
        }
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        if self.fault.corrupt && !out.is_empty() {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let n = b.len().min(977);
        self.bytes[at as usize..at as usize + n].copy_from_slice(&b[..n]);
        if self.fault.write == Some(self.writes) {
            return Err(io::Error::other("modeled torn staging write"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        self.barriers.push(self.writes);
        if let Some(c) = &self.fault.stale {
            c.stale.store(true, std::sync::atomic::Ordering::Release);
        }
        if self.fault.flush == Some(self.flushes) {
            return Err(io::Error::other("modeled staging barrier failure"));
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    }
}
fn read_limits() -> ApfsReadLimits {
    ApfsReadLimits {
        blocks: 32768,
        checkpoint_blocks: 256,
        objects: 256,
        records: 512,
        work: 128 << 20,
    }
}
fn audit_limits() -> ApfsAuditLimits {
    ApfsAuditLimits {
        blocks: 32768,
        objects: 4096,
        depth: 64,
        work: 128 << 20,
        findings: 64,
    }
}
fn options() -> ApfsBuildOptions {
    ApfsBuildOptions {
        image_bytes: 2 << 20,
        container_uuid: [0x71; 16],
        volume_uuid: [0x72; 16],
        volume_label: b"Authored".to_vec(),
        names: ApfsBuildNames::ExactBytes,
        metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
            uid: 501,
            gid: 20,
            file_permissions: 0o644,
            directory_permissions: 0o755,
            timestamp: 1_500_000_000_123_456_789,
        }),
        limits: ApfsBuildLimits {
            objects: 128,
            occurrences: 256,
            name_bytes: 65536,
            depth: 32,
            blocks: 32768,
            work: 128 << 20,
            page_entries: 4,
        },
    }
}
fn source(r: &Resources) -> Arc<dyn TreeSource> {
    let c = ApfsContainer::open(
        Arc::new(Bytes(fixture::shared_seed(true))),
        read_limits(),
        r,
    )
    .unwrap();
    let v = ApfsVolume::open(c, 1026, r).unwrap();
    Arc::new(ApfsTreeSource::inventory(v, audit_limits(), r).unwrap())
}
#[test]
fn fresh_native_construction_preserves_names_hardlinks_holes_and_forks() {
    let r = resources();
    let source = source(&r);
    let baseline = r.memory.used();
    let plan = ApfsBuildPlan::plan(source.clone(), options(), &r).unwrap();
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        writes: 0,
        flushes: 0,
        ..Default::default()
    };
    let report = plan.emit(&mut target, &r).unwrap();
    assert!(target.flushes >= 5);
    assert!(report.metadata_transformed);
    let raw = Arc::new(Bytes(target.bytes));
    let proof = report
        .audit(raw.clone(), read_limits(), audit_limits(), &r)
        .unwrap();
    assert!(proof.is_clean());
    let volume = ApfsVolume::open(
        ApfsContainer::open(raw, read_limits(), &r).unwrap(),
        1026,
        &r,
    )
    .unwrap();
    let first = volume
        .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
        .unwrap();
    let alias = volume
        .lookup(
            &[
                NativeName::Bytes(b"Box".to_vec()),
                NativeName::Bytes(b"Alias".to_vec()),
            ],
            &r,
        )
        .unwrap();
    assert_eq!(first, alias);
    let file = volume.open_file(&first, &r).unwrap();
    let data = read_all(&file, 32768, &r).unwrap();
    assert_eq!(data.get().len(), 16397);
    assert!(data.get()[4096..8192].iter().all(|x| *x == 0));
    let fork = volume
        .open_stream(&first, &StreamKind::ResourceFork, &r)
        .unwrap();
    assert_eq!(
        read_all(&fork, 32, &r).unwrap().get().as_slice(),
        b"resource"
    );
    drop(fork);
    drop(data);
    drop(file);
    drop(volume);
    drop(proof);
    drop(plan);
    assert_eq!(r.memory.used(), baseline);
    drop(source);
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[cfg(unix)]
#[ignore = "requires PARTMGR_APFS_BUILD_EVIDENCE and installed apfsck/TSK; enabled missing tools fail"]
fn native_fresh_construction_checker_payload_and_fork_receipt() {
    native_fresh_gate(false);
}
#[test]
#[ignore = "requires explicit fresh named-xattr native evidence directory and checker/TSK"]
fn native_named_xattr_fresh_construction_files_directories_and_exact_values() {
    native_fresh_gate(true);
}
fn native_fresh_gate(named: bool) {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os(if named {
            "PARTMGR_APFS_NAMED_BUILD_EVIDENCE"
        } else {
            "PARTMGR_APFS_BUILD_EVIDENCE"
        })
        .expect("enabled gate requires evidence directory"),
    );
    fs::create_dir(&out).unwrap();
    let baked: [(&str, &[u8]); 18] = [
        (
            "tests/fixtures/apfs_resource.rs",
            include_bytes!("fixtures/apfs_resource.rs"),
        ),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        (
            "src/fs_apfs_builder.rs",
            include_bytes!("../src/fs_apfs_builder.rs"),
        ),
        (
            "src/fs_apfs_builder_disk.rs",
            include_bytes!("../src/fs_apfs_builder_disk.rs"),
        ),
        (
            "src/fs_apfs_builder_layout.rs",
            include_bytes!("../src/fs_apfs_builder_layout.rs"),
        ),
        ("src/fs_apfs.rs", include_bytes!("../src/fs_apfs.rs")),
        (
            "src/fs_apfs_index.rs",
            include_bytes!("../src/fs_apfs_index.rs"),
        ),
        (
            "src/fs_apfs_audit.rs",
            include_bytes!("../src/fs_apfs_audit.rs"),
        ),
        (
            "src/fs_apfs_retention.rs",
            include_bytes!("../src/fs_apfs_retention.rs"),
        ),
        (
            "src/fs_apfs_tree.rs",
            include_bytes!("../src/fs_apfs_tree.rs"),
        ),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        (
            "tests/fixtures/apfs_clean.rs",
            include_bytes!("fixtures/apfs_clean.rs"),
        ),
        (
            "tests/fixtures/apfs_build_tree.rs",
            include_bytes!("fixtures/apfs_build_tree.rs"),
        ),
        (
            "tests/fs_apfs_builder.rs",
            include_bytes!("fs_apfs_builder.rs"),
        ),
    ];
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = String::new();
    for (name, bytes) in baked {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap()),
            "compiled source differs: {name}"
        );
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        sources.push_str(&format!("{name} {:x}\n", Sha256::digest(bytes)));
    }
    fs::write(out.join("source-start.sha256"), &sources).unwrap();
    let binary = std::env::current_exe().unwrap();
    let binary_bytes = fs::read(&binary).unwrap();
    fs::write(out.join("compiled-test"), &binary_bytes).unwrap();
    fs::write(
        out.join("binary.sha256"),
        format!(
            "{} {:x}\n",
            binary.display(),
            Sha256::digest(fs::read(&binary).unwrap())
        ),
    )
    .unwrap();
    let apfs =
        PathBuf::from("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck");
    let tsk = PathBuf::from("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin");
    let paths = [
        apfs.clone(),
        tsk.join("pstat"),
        tsk.join("fsstat"),
        tsk.join("fls"),
        tsk.join("istat"),
        tsk.join("icat"),
    ];
    let tool_hashes = || {
        paths
            .iter()
            .map(|p| {
                format!(
                    "{} {:x}\n",
                    p.display(),
                    Sha256::digest(fs::read(p).expect("enabled missing independent tool"))
                )
            })
            .collect::<String>()
    };
    let tools = tool_hashes();
    fs::write(out.join("tools-start.sha256"), &tools).unwrap();
    for (i, path) in paths.iter().enumerate() {
        let version = Command::new(path)
            .arg("-V")
            .output()
            .expect("tool version spawn");
        fs::write(
            out.join(format!("version-{i}.command")),
            format!("{path:?} -V\n"),
        )
        .unwrap();
        fs::write(out.join(format!("version-{i}.stdout")), version.stdout).unwrap();
        fs::write(out.join(format!("version-{i}.stderr")), version.stderr).unwrap();
        fs::write(
            out.join(format!("version-{i}.status")),
            format!("{}\n", version.status),
        )
        .unwrap();
    }
    for tool in ["rustc", "cargo"] {
        let version = Command::new(tool).arg("--version").output().unwrap();
        fs::write(
            out.join(format!("{tool}.version")),
            [version.stdout, version.stderr].concat(),
        )
        .unwrap();
        assert!(version.status.success());
    }
    let r = Resources {
        memory: Budget::new(512 << 20),
        cancellation: Cancellation::default(),
    };
    let tree = Arc::new(common_fixture::Tree::new(if named { 3 } else { 1500 }));
    if named {
        tree.controls
            .named
            .store(true, std::sync::atomic::Ordering::Release);
        tree.controls
            .directory_named
            .store(true, std::sync::atomic::Ordering::Release);
    }
    let source: Arc<dyn TreeSource> = tree.clone();
    let mut o = options();
    o.image_bytes = 64 << 20;
    o.limits.objects = 1600;
    o.limits.occurrences = 1700;
    let plan = if named {
        ApfsBuildPlan::plan_with_named_xattrs(
            source.clone(),
            o,
            ApfsCheckpointCapacity::default(),
            ApfsNamedXattrLimits {
                streams: 16,
                name_bytes: 1024,
            },
            &r,
        )
    } else {
        ApfsBuildPlan::plan(source.clone(), o, &r)
    }
    .unwrap();
    assert_eq!(
        tree.controls
            .reads
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let image = out.join("authored.apfs");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&image)
        .unwrap();
    file.set_len(plan.image_bytes()).unwrap();
    file.sync_all().unwrap();
    let mut target = NativeTarget { file, flushes: 0 };
    let report = plan.emit(&mut target, &r).unwrap();
    for root in if named {
        Vec::new()
    } else {
        vec![21u64, 22, 23]
    } {
        let mut level = [0; 2];
        Storage::read_exact_at(&target, root * 4096 + 34, &mut level).unwrap();
        assert!(
            u16::from_le_bytes(level) > 0,
            "native gate exercises OMAP/catalog/extent internal nodes"
        );
    }
    let flushes = target.flushes;
    drop(target);
    let before = Sha256::digest(fs::read(&image).unwrap());
    let proof = report
        .audit(
            Arc::new(NativeRead(fs::File::open(&image).unwrap())),
            ApfsReadLimits {
                objects: 2048,
                records: 8192,
                ..read_limits()
            },
            audit_limits(),
            &r,
        )
        .unwrap();
    assert_eq!(proof.allocated_blocks(), report.allocated_blocks);
    let run = |label: &str, tool: &PathBuf, args: &[&str]| {
        fs::write(
            out.join(format!("{label}.command")),
            format!("{tool:?} {args:?}\n"),
        )
        .unwrap();
        let result = Command::new(tool)
            .args(args)
            .output()
            .expect("independent command spawn");
        fs::write(out.join(format!("{label}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{label}.stderr")), &result.stderr).unwrap();
        fs::write(
            out.join(format!("{label}.status")),
            format!("{}\n", result.status),
        )
        .unwrap();
        assert!(
            result.status.success(),
            "{label} {:?}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    };
    let image_arg = image.to_str().unwrap();
    let checker = run("apfsck", &apfs, &["-c", "-u", "-w", image_arg]);
    assert!(
        checker.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&checker.stderr)
    );
    let pool = run("pstat", &tsk.join("pstat"), &[image_arg]);
    assert!(String::from_utf8_lossy(&pool.stdout).contains(&format!(
        "Number of Free Blocks: {}",
        16384 - report.allocated_blocks
    )));
    run(
        "fsstat",
        &tsk.join("fsstat"),
        &["-P", "apfs", "-B", "19", "-f", "apfs", image_arg],
    );
    run(
        "fls",
        &tsk.join("fls"),
        &["-P", "apfs", "-B", "19", "-f", "apfs", "-r", image_arg],
    );
    let inode = run(
        "hardlink",
        &tsk.join("istat"),
        &["-P", "apfs", "-B", "19", "-f", "apfs", image_arg, "16"],
    );
    assert!(String::from_utf8_lossy(&inode.stdout).contains("Number of Links: 2"));
    assert!(String::from_utf8_lossy(&inode.stdout).contains("Aé-file"));
    let data = run(
        "data",
        &tsk.join("icat"),
        &["-P", "apfs", "-B", "19", "-f", "apfs", image_arg, "16"],
    );
    assert_eq!(data.stdout.len(), 16397);
    assert!(data.stdout[4096..8192].iter().all(|x| *x == 0));
    for (i, &actual) in data.stdout.iter().enumerate() {
        assert_eq!(
            actual,
            if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                0
            } else {
                (i % 4096 * 17 % 251) as u8
            }
        );
    }
    let fork = run(
        "resource",
        &tsk.join("icat"),
        &[
            "-P",
            "apfs",
            "-B",
            "19",
            "-f",
            "apfs",
            image_arg,
            "16-4353-1",
        ],
    );
    assert_eq!(fork.stdout, b"resource");
    let copy = run(
        "distinct-copy",
        &tsk.join("icat"),
        &["-P", "apfs", "-B", "19", "-f", "apfs", image_arg, "18"],
    );
    assert_eq!(copy.stdout, data.stdout);
    if named {
        for (inode, length) in [(16u64, 1usize), (17, 7001), (18, 1), (19, 1), (20, 1)] {
            let attribute_id = if inode == 16 || inode == 18 { 2 } else { 1 };
            let native = format!("{inode}-4354-{attribute_id}");
            let label = format!("named-{inode}");
            let actual = run(
                &label,
                &tsk.join("icat"),
                &["-P", "apfs", "-B", "19", "-f", "apfs", image_arg, &native],
            );
            let inode_arg = inode.to_string();
            let info = run(
                &format!("named-inode-{inode}"),
                &tsk.join("istat"),
                &[
                    "-P", "apfs", "-B", "19", "-f", "apfs", image_arg, &inode_arg,
                ],
            );
            let expected_name = if inode == 17 {
                "user/directory.é"
            } else {
                "alternate"
            };
            assert!(
                String::from_utf8(info.stdout)
                    .unwrap()
                    .contains(expected_name)
            );
            let expected: Vec<u8> = (0..length).map(|at| ((at * 13 + 7) % 251) as u8).collect();
            assert_eq!(actual.stdout, expected);
            fs::write(out.join(format!("{label}.expected")), expected).unwrap();
        }
        assert_eq!(plan.named_stream_outcomes().len(), 5);
    }
    assert_eq!(before, Sha256::digest(fs::read(&image).unwrap()));
    for (name, bytes) in baked {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap()),
            "source changed during gate: {name}"
        );
    }
    assert_eq!(tools, tool_hashes());
    assert_eq!(fs::read(&binary).unwrap(), binary_bytes);
    fs::write(out.join("source-end.sha256"), sources).unwrap();
    fs::write(out.join("tools-end.sha256"), tools).unwrap();
    fs::write(out.join("receipt.txt"), format!("status=passed\norigin=framework native fresh construction; no formatter/template\nsource=independent common TreeSource; no source codec or native image input\npolicy=content-only defaults; whole-block holes/hardlinks/embedded resource forks retained\nimage_sha256={before:x}\nallocated_blocks={}\nvolume_allocated_blocks={}\nflushes={flushes}\nnative_target=exclusive unpublished file; sync_all barriers; closed then reopened read-only\nmacos_native_evidence=unavailable\ncow_recovery=outside this offline construction gate\n", report.allocated_blocks, report.volume_allocated_blocks)).unwrap();
    drop(proof);
    drop(plan);
    drop(source);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn independent_common_tree_build_is_deterministic_and_constructs_multilevel_indexes() {
    use std::sync::atomic::Ordering;
    let r = resources();
    let tree = Arc::new(common_fixture::Tree::new(120));
    let baseline = r.memory.used();
    let plan = ApfsBuildPlan::plan(tree.clone(), options(), &r).unwrap();
    assert!(plan.outcomes().iter().any(|o| o.class == "attributes"
        && o.inspection == ApfsMetadataInspection::Opaque
        && matches!(o.decision, Preservation::Transform { .. })));
    assert_eq!(
        tree.controls.reads.load(Ordering::Relaxed),
        0,
        "payload remains deferred during planning"
    );
    let mut first = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    let a = plan.emit(&mut first, &r).unwrap();
    let mut second = Target {
        bytes: vec![0x39; plan.image_bytes() as usize],
        ..Default::default()
    };
    let b = plan.emit(&mut second, &r).unwrap();
    assert_eq!(a.sha256, b.sha256);
    assert_eq!(first.bytes, second.bytes);
    tree.controls.reverse.store(true, Ordering::Release);
    let reordered = ApfsBuildPlan::plan(tree.clone(), options(), &r).unwrap();
    let mut reverse = Target {
        bytes: vec![0x42; reordered.image_bytes() as usize],
        ..Default::default()
    };
    assert_eq!(
        reordered.emit(&mut reverse, &r).unwrap().sha256,
        a.sha256,
        "native output does not depend on source enumeration or pagination order"
    );
    drop(reordered);
    tree.controls.versions.store(true, Ordering::Release);
    let versioned = ApfsBuildPlan::plan(tree.clone(), options(), &r).unwrap();
    let mut different = Target {
        bytes: vec![0x42; versioned.image_bytes() as usize],
        ..Default::default()
    };
    assert_eq!(
        versioned.emit(&mut different, &r).unwrap().sha256,
        a.sha256,
        "per-object generations are bound independently, without assuming a root generation"
    );
    drop(versioned);
    assert!(
        u16::from_le_bytes(
            first.bytes[22 * 4096 + 34..22 * 4096 + 36]
                .try_into()
                .unwrap()
        ) > 0,
        "catalog was constructed as a native indexed tree"
    );
    assert!(
        u16::from_le_bytes(
            first.bytes[23 * 4096 + 34..23 * 4096 + 36]
                .try_into()
                .unwrap()
        ) > 0,
        "extent references were constructed as a native indexed tree"
    );
    let raw = Arc::new(Bytes(first.bytes));
    let proof = a
        .audit(raw.clone(), read_limits(), audit_limits(), &r)
        .unwrap();
    assert!(proof.is_clean());
    let v = ApfsVolume::open(
        ApfsContainer::open(raw, read_limits(), &r).unwrap(),
        1026,
        &r,
    )
    .unwrap();
    let id = v
        .lookup(&[NativeName::Bytes(b"File-0120".to_vec())], &r)
        .unwrap();
    let file = v.open_file(&id, &r).unwrap();
    assert_eq!(read_all(&file, 1, &r).unwrap().get().as_slice(), vec![0]);
    drop(file);
    drop(v);
    drop(proof);
    drop(plan);
    assert_eq!(r.memory.used(), baseline);
}

#[test]
fn preflight_caps_metadata_policy_extents_cancellation_and_refunds() {
    use std::sync::atomic::Ordering;
    for case in 0..8 {
        let r = resources();
        let tree = Arc::new(common_fixture::Tree::new(3));
        let mut o = options();
        match case {
            0 => o.metadata = ApfsBuildMetadata::RequirePreservation,
            1 => o.limits.objects = 2,
            2 => o.limits.occurrences = 1,
            3 => o.limits.name_bytes = 1,
            4 => o.limits.depth = 0,
            5 => o.limits.work = 1,
            6 => tree.controls.malformed.store(true, Ordering::Release),
            _ => r.cancellation.cancel(),
        };
        let error = match ApfsBuildPlan::plan(tree.clone(), o, &r) {
            Ok(_) => panic!("preflight accepted case {case}"),
            Err(e) => e,
        };
        assert_eq!(
            error.kind,
            match case {
                0 => ErrorKind::Unsupported,
                6 => ErrorKind::InvalidOperation,
                _ if case == 7 => ErrorKind::Cancelled,
                _ => ErrorKind::BudgetExhausted,
            }
        );
        assert_eq!(tree.controls.reads.load(Ordering::Relaxed), 0);
        assert_eq!(r.memory.used(), 0);
    }
    let r = Resources {
        memory: Budget::new(1024),
        cancellation: Cancellation::default(),
    };
    assert!(matches!(
        ApfsBuildPlan::plan(Arc::new(common_fixture::Tree::new(3)), options(), &r),
        Err(Error {
            kind: ErrorKind::BudgetExhausted,
            ..
        })
    ));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn staged_write_barrier_readback_and_source_failures_never_return_publication_evidence() {
    use std::sync::atomic::Ordering;
    let r = resources();
    let tree = Arc::new(common_fixture::Tree::new(3));
    let plan = ApfsBuildPlan::plan(tree.clone(), options(), &r).unwrap();
    let baseline = r.memory.used();
    let mut good = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    plan.emit(&mut good, &r).unwrap();
    assert_eq!(good.barriers.len(), 5);
    let mut cuts = vec![1];
    for &cut in &good.barriers {
        cuts.push(cut);
        if cut < good.writes {
            cuts.push(cut + 1);
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    for cut in cuts {
        let mut target = Target {
            bytes: vec![0xa7; plan.image_bytes() as usize],
            fault: Faults {
                write: Some(cut),
                ..Default::default()
            },
            ..Default::default()
        };
        let e = plan.emit(&mut target, &r).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Io);
        assert!(e.source.unwrap().to_string().contains("torn"));
        assert_eq!(target.writes, cut);
        assert_eq!(r.memory.used(), baseline);
    }
    for cut in 1..=5 {
        let mut target = Target {
            bytes: vec![0xa7; plan.image_bytes() as usize],
            fault: Faults {
                flush: Some(cut),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(plan.emit(&mut target, &r).unwrap_err().kind, ErrorKind::Io);
        assert_eq!(target.flushes, cut);
        assert_eq!(r.memory.used(), baseline);
    }
    for read in [false, true] {
        let mut target = Target {
            bytes: vec![0xa7; plan.image_bytes() as usize],
            fault: Faults {
                read,
                corrupt: !read,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            plan.emit(&mut target, &r).unwrap_err().kind,
            if read {
                ErrorKind::Io
            } else {
                ErrorKind::InvalidData
            }
        );
        assert!(
            target.bytes[..4096].iter().all(|x| *x == 0),
            "payload prerequisite failure precedes metadata/checkpoint publication"
        );
    }
    tree.controls.fail.store(true, Ordering::Release);
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    let e = plan.emit(&mut target, &r).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Io);
    assert!(e.source.unwrap().to_string().contains("fixture read cause"));
    tree.controls.fail.store(false, Ordering::Release);
    tree.controls.stale.store(true, Ordering::Release);
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    assert_eq!(
        plan.emit(&mut target, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.writes, 0);
    tree.controls.stale.store(false, Ordering::Release);
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        fault: Faults {
            stale: Some(tree.controls.clone()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        plan.emit(&mut target, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.flushes, 1);
    assert!(target.bytes[..4096].iter().all(|x| *x == 0));
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn explicit_name_conversion_collisions_specials_and_streams_are_not_silently_lost() {
    use std::sync::atomic::Ordering;
    for case in 0..5 {
        let r = resources();
        let tree = Arc::new(common_fixture::Tree::new(3));
        let mut o = options();
        match case {
            0 => tree.controls.utf16.store(true, Ordering::Release),
            1 => {
                tree.controls.utf16.store(true, Ordering::Release);
                tree.controls.collision.store(true, Ordering::Release);
                o.names = ApfsBuildNames::Utf16ToUtf8;
            }
            2 => tree.controls.special.store(true, Ordering::Release),
            3 => tree.controls.cycle.store(true, Ordering::Release),
            _ => tree.controls.named.store(true, Ordering::Release),
        };
        let e = match ApfsBuildPlan::plan(tree.clone(), o, &r) {
            Ok(_) => panic!("unsupported case accepted"),
            Err(e) => e,
        };
        assert_eq!(
            e.kind,
            if case == 1 || case == 3 {
                ErrorKind::InvalidOperation
            } else {
                ErrorKind::Unsupported
            }
        );
        assert_eq!(tree.controls.reads.load(Ordering::Relaxed), 0);
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let tree = Arc::new(common_fixture::Tree::new(3));
    tree.controls.utf16.store(true, Ordering::Release);
    let mut o = options();
    o.names = ApfsBuildNames::Utf16ToUtf8;
    let plan = ApfsBuildPlan::plan(tree.clone(), o, &r).unwrap();
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    let report = plan.emit(&mut target, &r).unwrap();
    let raw = Arc::new(Bytes(target.bytes));
    let proof = report
        .audit(raw.clone(), read_limits(), audit_limits(), &r)
        .unwrap();
    let v = ApfsVolume::open(
        ApfsContainer::open(raw, read_limits(), &r).unwrap(),
        1026,
        &r,
    )
    .unwrap();
    assert!(
        v.lookup(&[NativeName::Bytes("Aé-file".as_bytes().to_vec())], &r)
            .is_ok()
    );
    drop(v);
    drop(proof);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn deferred_lengths_owner_cancellation_and_reopened_hash_binding_are_checked() {
    use std::sync::atomic::Ordering;
    let r = resources();
    let tree = Arc::new(common_fixture::Tree::new(3));
    let plan = ApfsBuildPlan::plan(tree.clone(), options(), &r).unwrap();
    let baseline = r.memory.used();
    tree.controls.changed_length.store(true, Ordering::Release);
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    assert_eq!(
        plan.emit(&mut target, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.writes, 0);
    tree.controls.changed_length.store(false, Ordering::Release);
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    let report = plan.emit(&mut target, &r).unwrap();
    let mut low = read_limits();
    low.work = 1;
    assert!(matches!(
        report.audit(
            Arc::new(Bytes(target.bytes.clone())),
            low,
            audit_limits(),
            &r
        ),
        Err(Error {
            kind: ErrorKind::BudgetExhausted,
            ..
        })
    ));
    assert_eq!(r.memory.used(), baseline);
    target.bytes[500 * 4096] ^= 1;
    assert!(matches!(
        report.audit(
            Arc::new(Bytes(target.bytes)),
            read_limits(),
            audit_limits(),
            &r
        ),
        Err(Error {
            kind: ErrorKind::StalePlan,
            ..
        })
    ));
    assert_eq!(r.memory.used(), baseline);
    r.cancellation.cancel();
    let operation = Resources {
        memory: r.memory.clone(),
        cancellation: Cancellation::default(),
    };
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    assert_eq!(
        plan.emit(&mut target, &operation).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(target.writes, 0);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}

#[path = "fixtures/apfs_resource.rs"]
mod resource_fixture;
#[test]
fn named_xattr_capture_requires_explicit_mapping_and_preserves_exact_deferred_values() {
    let r = resources();
    let c = ApfsContainer::open(
        Arc::new(Bytes(resource_fixture::generic_seed(true, 0))),
        read_limits(),
        &r,
    )
    .unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let source: Arc<dyn TreeSource> =
        Arc::new(ApfsTreeSource::inventory(v, audit_limits(), &r).unwrap());
    let baseline = r.memory.used();
    assert!(ApfsBuildPlan::plan(source.clone(), options(), &r).is_err());
    assert_eq!(r.memory.used(), baseline);
    let plan = ApfsBuildPlan::plan_with_named_xattrs(
        source.clone(),
        options(),
        ApfsCheckpointCapacity::default(),
        ApfsNamedXattrLimits {
            streams: 2,
            name_bytes: 128,
        },
        &r,
    )
    .unwrap();
    assert_eq!(plan.named_stream_outcomes().len(), 2);
    for outcome in plan.named_stream_outcomes() {
        assert_eq!(
            outcome.name,
            NativeName::Bytes("user/external.é".as_bytes().to_vec())
        );
        assert_eq!(outcome.length, 8);
        assert_eq!(outcome.decision, Preservation::Preserve);
    }
    let mut target = Target {
        bytes: vec![0xa7; plan.image_bytes() as usize],
        ..Default::default()
    };
    let report = plan.emit(&mut target, &r).unwrap();
    let raw = Arc::new(Bytes(target.bytes));
    assert!(
        report
            .audit(raw.clone(), read_limits(), audit_limits(), &r)
            .unwrap()
            .is_clean()
    );
    let v = ApfsVolume::open(
        ApfsContainer::open(raw, read_limits(), &r).unwrap(),
        1026,
        &r,
    )
    .unwrap();
    for name in [b"A\xc3\xa9-file".as_slice(), b"Clone".as_slice()] {
        let object = v.lookup(&[NativeName::Bytes(name.to_vec())], &r).unwrap();
        let file = v
            .open_stream(
                &object,
                &StreamKind::Named(NativeName::Bytes("user/external.é".as_bytes().to_vec())),
                &r,
            )
            .unwrap();
        assert_eq!(
            read_all(&file, 8, &r).unwrap().get().as_slice(),
            b"resource"
        );
    }
    drop((v, plan));
    assert_eq!(r.memory.used(), baseline);
    assert!(
        ApfsBuildPlan::plan_with_named_xattrs(
            source.clone(),
            options(),
            ApfsCheckpointCapacity::default(),
            ApfsNamedXattrLimits {
                streams: 1,
                name_bytes: 128
            },
            &r
        )
        .is_err()
    );
    assert!(
        ApfsBuildPlan::plan_with_named_xattrs(
            source.clone(),
            options(),
            ApfsCheckpointCapacity::default(),
            ApfsNamedXattrLimits {
                streams: 2,
                name_bytes: 1
            },
            &r
        )
        .is_err()
    );
    drop(source);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn root_and_directory_named_values_are_deferred_and_stale_plans_do_not_write() {
    use std::sync::atomic::Ordering;
    let r = resources();
    let tree = Arc::new(common_fixture::Tree::new(3));
    tree.controls.root_named.store(true, Ordering::Release);
    tree.controls.directory_named.store(true, Ordering::Release);
    let plan = ApfsBuildPlan::plan_with_named_xattrs(
        tree.clone(),
        options(),
        ApfsCheckpointCapacity::default(),
        ApfsNamedXattrLimits {
            streams: 2,
            name_bytes: 128,
        },
        &r,
    )
    .unwrap();
    assert_eq!(tree.controls.reads.load(Ordering::Acquire), 0);
    assert_eq!(plan.named_stream_outcomes().len(), 2);
    let mut target = Target {
        bytes: vec![0; plan.image_bytes() as usize],
        ..Default::default()
    };
    let report = plan.emit(&mut target, &r).unwrap();
    let raw = Arc::new(Bytes(target.bytes));
    assert!(
        report
            .audit(raw.clone(), read_limits(), audit_limits(), &r)
            .unwrap()
            .is_clean()
    );
    let volume = ApfsVolume::open(
        ApfsContainer::open(raw, read_limits(), &r).unwrap(),
        1026,
        &r,
    )
    .unwrap();
    for path in [vec![], vec![NativeName::Bytes(b"Box".to_vec())]] {
        let object = volume.lookup(&path, &r).unwrap();
        let file = volume
            .open_stream(
                &object,
                &StreamKind::Named(NativeName::Bytes("user/directory.é".as_bytes().to_vec())),
                &r,
            )
            .unwrap();
        let actual = read_all(&file, 7001, &r).unwrap();
        let expected: Vec<u8> = (0..7001).map(|p| ((p * 13 + 7) % 251) as u8).collect();
        assert_eq!(actual.get().as_slice(), expected);
    }
    tree.controls.stale.store(true, Ordering::Release);
    let mut refused = Target {
        bytes: vec![0; plan.image_bytes() as usize],
        ..Default::default()
    };
    assert!(plan.emit(&mut refused, &r).is_err());
    assert_eq!(refused.writes, 0);
    drop((volume, plan, tree));
    assert_eq!(r.memory.used(), 0);
}
