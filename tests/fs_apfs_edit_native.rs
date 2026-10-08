#![cfg(feature = "std")]

//! Enabled native COW gate never skips missing tools. Initial source is freshly framework-authored.
#![cfg(unix)]
use partmgr::{
    fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*, fs_apfs_edit::*, fs_core::*, storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
#[path = "fixtures/apfs_build_tree.rs"]
mod fixture;
struct Store(File);
impl Storage for Store {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(out, at)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        self.0.write_at(input, at)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}
struct Input(ObjectId);
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        29
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = out.len().min(7).min(29u64.saturating_sub(at) as usize);
        for (i, v) in out[..n].iter_mut().enumerate() {
            *v = ((at + i as u64) * 31 + 9) as u8;
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        visit(LogicalExtent {
            offset: 0,
            length: 29,
            kind: ExtentKind::Data,
        })
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn checked(dir: &Path, label: &str, tool: &Path, args: &[String]) -> Vec<u8> {
    fs::write(
        dir.join(format!("{label}.command")),
        format!("{} {:?}\n", tool.display(), args),
    )
    .unwrap();
    let result = Command::new(tool)
        .args(args)
        .output()
        .expect("enabled native gate tool execution");
    fs::write(dir.join(format!("{label}.stdout")), &result.stdout).unwrap();
    fs::write(dir.join(format!("{label}.stderr")), &result.stderr).unwrap();
    fs::write(
        dir.join(format!("{label}.status")),
        format!("{:?}\n", result.status.code()),
    )
    .unwrap();
    assert!(
        result.status.success(),
        "{label}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}
const SOURCES: &[(&str, &[u8])] = &[
    (
        "src/fs_apfs_edit_namespace.rs",
        include_bytes!("../src/fs_apfs_edit_namespace.rs"),
    ),
    ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ("Cargo.lock", include_bytes!("../Cargo.lock")),
    ("src/lib.rs", include_bytes!("../src/lib.rs")),
    ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
    ("src/storage.rs", include_bytes!("../src/storage.rs")),
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
    (
        "src/fs_apfs_edit.rs",
        include_bytes!("../src/fs_apfs_edit.rs"),
    ),
    (
        "src/fs_apfs_edit_cow.rs",
        include_bytes!("../src/fs_apfs_edit_cow.rs"),
    ),
    (
        "src/fs_apfs_edit_disk.rs",
        include_bytes!("../src/fs_apfs_edit_disk.rs"),
    ),
    (
        "tests/fixtures/apfs_build_tree.rs",
        include_bytes!("fixtures/apfs_build_tree.rs"),
    ),
    (
        "tests/fs_apfs_edit_native.rs",
        include_bytes!("fs_apfs_edit_native.rs"),
    ),
];
#[test]
#[ignore = "requires PARTMGR_APFS_EDIT_EVIDENCE and exact installed apfsck/TSK; enabled missing tools fail"]
fn native_range_checkpoint_checker_payload_and_hardlink_resource_receipt() {
    let dir = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_EDIT_EVIDENCE").expect("enabled evidence directory"),
    );
    fs::create_dir(&dir).expect("fresh disposable evidence directory");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source_hashes = String::new();
    for (name, compiled) in SOURCES {
        assert_eq!(
            fs::read(root.join(name)).unwrap(),
            *compiled,
            "compiled source binding: {name}"
        );
        source_hashes.push_str(&format!("{name} {}\n", digest(compiled)));
    }
    fs::write(dir.join("source-start.sha256"), &source_hashes).unwrap();
    let source_dir = dir.join("compiled-source");
    fs::create_dir(&source_dir).unwrap();
    for (name, bytes) in SOURCES {
        let path = source_dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let exe = std::env::current_exe().unwrap();
    let binary = digest(&fs::read(&exe).unwrap());
    fs::copy(&exe, dir.join("compiled-test")).unwrap();
    assert_eq!(
        digest(&fs::read(dir.join("compiled-test")).unwrap()),
        binary
    );
    fs::write(
        dir.join("binary.sha256"),
        format!("{} {binary}\n", exe.display()),
    )
    .unwrap();
    let checker =
        PathBuf::from("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck");
    let tsk = PathBuf::from("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin");
    let tools = [
        checker.clone(),
        tsk.join("pstat"),
        tsk.join("fsstat"),
        tsk.join("icat"),
        tsk.join("istat"),
        tsk.join("fls"),
    ];
    let hashes: Vec<_> = tools
        .iter()
        .map(|path| {
            (
                path.clone(),
                digest(&fs::read(path).expect("enabled gate tool binary")),
            )
        })
        .collect();
    fs::write(
        dir.join("tools-start.sha256"),
        hashes
            .iter()
            .map(|(path, hash)| format!("{} {hash}\n", path.display()))
            .collect::<String>(),
    )
    .unwrap();
    for (index, tool) in tools.iter().enumerate() {
        let args = vec!["-V".to_string()];
        let label = format!("version-{index}");
        fs::write(
            dir.join(format!("{label}.command")),
            format!("{} {:?}\n", tool.display(), args),
        )
        .unwrap();
        let output = Command::new(tool).args(args).output().unwrap();
        fs::write(dir.join(format!("{label}.stdout")), output.stdout).unwrap();
        fs::write(dir.join(format!("{label}.stderr")), output.stderr).unwrap();
        fs::write(
            dir.join(format!("{label}.status")),
            format!("{:?}\n", output.status.code()),
        )
        .unwrap();
    }
    for tool in ["cargo", "rustc"] {
        let output = Command::new(tool).arg("--version").output().unwrap();
        fs::write(dir.join(format!("{tool}.version")), output.stdout).unwrap();
        assert!(output.status.success());
    }
    let r = Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let image = dir.join("cow.apfs");
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&image)
        .unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    file.sync_all().unwrap();
    let options = ApfsBuildOptions {
        image_bytes: 64 * 1024 * 1024,
        container_uuid: [0x51; 16],
        volume_uuid: [0x61; 16],
        volume_label: b"Native COW".to_vec(),
        names: ApfsBuildNames::ExactBytes,
        metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
            uid: 0,
            gid: 0,
            file_permissions: 0o644,
            directory_permissions: 0o755,
            timestamp: 1_500_000_000_123_456_789,
        }),
        limits: ApfsBuildLimits {
            objects: 32,
            occurrences: 64,
            name_bytes: 8192,
            depth: 8,
            blocks: 16384,
            work: 256 * 1024 * 1024,
            page_entries: 2,
        },
    };
    let mut target = Store(file);
    let plan = ApfsBuildPlan::plan(Arc::new(fixture::Tree::new(3)), options, &r).unwrap();
    plan.emit(&mut target, &r).unwrap();
    drop(plan);
    let original = fs::read(&image).unwrap();
    fs::write(dir.join("initial.sha256"), digest(&original)).unwrap();
    let limits = ApfsEditLimits {
        metadata_blocks: 128,
        attempts: 129,
        work: 64 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: 16384,
            checkpoint_blocks: 8,
            objects: 256,
            records: 256,
            work: 64 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks: 16384,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    };
    let mut editor = ApfsEditor::open(target, 1026, limits, &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let plan = editor
        .plan_range(
            &id,
            4091,
            Arc::new(Input(ObjectId {
                source: 99,
                generation: 7,
                native: vec![1],
            })),
            &r,
        )
        .unwrap();
    let anchor = editor.recovery_anchor();
    fs::write(dir.join("recovery-anchor.bin"), anchor.encode()).unwrap();
    File::open(dir.join("recovery-anchor.bin"))
        .unwrap()
        .sync_all()
        .unwrap();
    File::open(&dir).unwrap().sync_all().unwrap();
    let receipt = editor.commit_range(plan, &anchor, &r).unwrap();
    assert_eq!(receipt.xid, 2);
    assert!(editor.allocation_proof().is_clean());
    let allocated = editor.allocation_proof().allocated_blocks();
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let before = digest(&fs::read(&image).unwrap());
    assert_ne!(before, digest(&original));
    checked(
        &dir,
        "apfsck",
        &checker,
        &[
            "-c".into(),
            "-u".into(),
            "-w".into(),
            image.display().to_string(),
        ],
    );
    checked(
        &dir,
        "pstat",
        &tsk.join("pstat"),
        &[image.display().to_string()],
    );
    let prefix = vec![
        "-P".into(),
        "apfs".into(),
        "-B".into(),
        receipt.volume_block.to_string(),
        "-f".into(),
        "apfs".into(),
        image.display().to_string(),
    ];
    checked(&dir, "fsstat", &tsk.join("fsstat"), &prefix);
    checked(&dir, "fls", &tsk.join("fls"), &prefix);
    let mut args = prefix.clone();
    args.push("16".into());
    let data = checked(&dir, "data", &tsk.join("icat"), &args);
    let inode = checked(&dir, "inode", &tsk.join("istat"), &args);
    assert!(String::from_utf8_lossy(&inode).contains("Aé-file"));
    assert!(String::from_utf8_lossy(&inode).contains("Number of Links: 2"));
    let mut expected = vec![0; 16397];
    for (i, b) in expected.iter_mut().enumerate() {
        if !(4096..8192).contains(&i) && !(12288..16384).contains(&i) {
            *b = ((i % 4096) * 17 % 251) as u8;
        }
    }
    for i in 0..29 {
        expected[4091 + i] = (i * 31 + 9) as u8;
    }
    assert_eq!(data, expected);
    let mut resource = prefix;
    resource.push("16-4353-1".into());
    assert_eq!(
        checked(&dir, "resource", &tsk.join("icat"), &resource),
        b"resource"
    );
    assert_eq!(
        digest(&fs::read(&image).unwrap()),
        before,
        "validators changed image"
    );
    for (name, compiled) in SOURCES {
        assert_eq!(
            fs::read(root.join(name)).unwrap(),
            *compiled,
            "source changed during native gate: {name}"
        );
    }
    assert_eq!(digest(&fs::read(exe).unwrap()), binary);
    for (path, hash) in &hashes {
        assert_eq!(&digest(&fs::read(path).unwrap()), hash);
    }
    fs::write(dir.join("source-end.sha256"), source_hashes).unwrap();
    fs::write(
        dir.join("tools-end.sha256"),
        hashes
            .iter()
            .map(|(path, hash)| format!("{} {hash}\n", path.display()))
            .collect::<String>(),
    )
    .unwrap();
    fs::write(dir.join("receipt.txt"),format!("status=passed\nprofile=native retained-checkpoint existing-length range COW\nxid=2\nallocated={allocated}\nvolume_block={}\nimage_sha256={before}\nmetadata_policy=preserved native inode/attrs/fork/siblings\nbarriers=payload metadata ephemeral terminal-NX boot-hint\nboot_hint=terminal restored selected checkpoint\nmacos_native_evidence=unavailable\nremaining=create replace truncate hardlink rename unlink\n",receipt.volume_block)).unwrap();
}
