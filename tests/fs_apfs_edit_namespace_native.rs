#![cfg(feature = "std")]

//! Enabled native COW gate never skips missing tools. Initial source is freshly framework-authored.
#![cfg(unix)]
use partmgr::io;
use partmgr::{
    fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*, fs_apfs_edit::*, fs_core::*, storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
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
        Ok(self.0.read_exact_at(out, at)?)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        Ok(self.0.write_at(input, at)?)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(self.0.sync_all()?)
    }
}
struct FilteredTree {
    inner: fixture::Tree,
    operation: usize,
}
impl TreeSource for FilteredTree {
    fn root(&self) -> ObjectId {
        self.inner.root()
    }
    fn stability(&self) -> SourceStability {
        self.inner.stability()
    }
    fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.inner.metadata(id, r)
    }
    fn streams(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.inner.streams(id, r)
    }
    fn open_stream(
        &self,
        id: &ObjectId,
        kind: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.inner.open_stream(id, kind, r)
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.inner.revalidate(id, r)
    }
    fn directory_page(
        &self,
        id: &ObjectId,
        next: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        let mut page = self.inner.directory_page(id, next, maximum, r)?;
        let object = u64::from_le_bytes(id.native[..].try_into().unwrap());
        if object == 4 {
            if self.operation == 11 {
                page.entries.clear();
            } else if self.operation == 12 {
                page.entries
                    .retain(|e| e.name != NativeName::Bytes(b"Alias".to_vec()));
            }
        }
        Ok(page)
    }
}
struct TornBoot {
    inner: Store,
    armed: bool,
}
impl Storage for TornBoot {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(at, out)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        if at == 0 && self.armed {
            self.armed = false;
            let n = input.len().min(31);
            self.inner.0.write_all_at(&input[..n], at)?;
            self.inner.flush()?;
            return Err(io::Error::other("native gate durable torn block-zero hint"));
        }
        self.inner.write_at(at, input)
    }
}
struct Input(ObjectId);
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        8192 + 29
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = out
            .len()
            .min(7)
            .min((8192 + 29u64).saturating_sub(at) as usize);
        for (i, v) in out[..n].iter_mut().enumerate() {
            let pos = at + i as u64;
            *v = if (4096..8192).contains(&pos) {
                0
            } else {
                (pos * 31 + 9) as u8
            };
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        for (offset, length, kind) in [
            (0, 4096, ExtentKind::Data),
            (4096, 4096, ExtentKind::Hole),
            (8192, 29, ExtentKind::Data),
        ] {
            visit(LogicalExtent {
                offset,
                length,
                kind,
            })?;
        }
        Ok(())
    }
}
// Independent Apple object Fletcher calculation, not the production checksum helper.
fn native_checksum_valid(bytes: &[u8; 4096]) -> bool {
    let modulus = u64::from(u32::MAX);
    let (mut first, mut second) = (0u64, 0u64);
    for word in bytes[8..].as_chunks::<4>().0 {
        first = (first + u64::from(u32::from_le_bytes(*word))) % modulus;
        second = (second + first) % modulus;
    }
    let low = modulus - (first + second) % modulus;
    let high = modulus - (first + low) % modulus;
    u64::from_le_bytes(bytes[..8].try_into().unwrap()) == low | (high << 32)
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
        "tests/fs_apfs_edit_namespace_native.rs",
        include_bytes!("fs_apfs_edit_namespace_native.rs"),
    ),
];
#[test]
#[ignore = "requires PARTMGR_APFS_NAMESPACE_EVIDENCE and exact installed apfsck/TSK; enabled missing tools fail"]
fn native_namespace_and_data_checkpoint_checker_payload_receipts() {
    let dir = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_NAMESPACE_EVIDENCE").expect("enabled evidence directory"),
    );
    fs::create_dir(&dir).expect("fresh disposable evidence directory");
    let evidence = dir;
    for operation in 0..13 {
        let dir = evidence.join(format!("operation-{operation}"));
        fs::create_dir(&dir).unwrap();
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
        let plan = ApfsBuildPlan::plan(
            Arc::new(FilteredTree {
                inner: fixture::Tree::new(3),
                operation,
            }),
            options,
            &r,
        )
        .unwrap();
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
        let mut editor = ApfsEditor::open(
            TornBoot {
                inner: target,
                armed: true,
            },
            1026,
            limits,
            &r,
        )
        .unwrap();
        let id = editor.file_identity(16, &r).unwrap();
        let root_id = editor.directory_identity(2, &r).unwrap();
        let box_id = editor
            .directory(&root_id, &r)
            .unwrap()
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"Box".to_vec()))
            .unwrap()
            .object
            .clone();
        let input = Arc::new(Input(ObjectId {
            source: 99,
            generation: 7,
            native: vec![1],
        }));
        let m = ApfsCreateMetadata {
            permissions: 0o640,
            uid: 42,
            gid: 43,
            timestamp: 1_500_000_000_123_456_789,
        };
        let plan = match operation {
            0 => editor.plan_create(&root_id, "新-é".as_bytes(), input, m, &r),
            1 => editor.plan_create_directory(&root_id, b"NewDir", m, &r),
            2 => editor.plan_replace(&id, input, &r),
            3 => editor.plan_truncate(&id, 8199, &r),
            4 => editor.plan_truncate(&id, 24579, &r),
            5 => editor.plan_hardlink(&id, &box_id, b"Third", m.timestamp, &r),
            6 => editor.plan_rename(
                &root_id,
                "Aé-file".as_bytes(),
                &root_id,
                "Ré-named".as_bytes(),
                &r,
            ),
            7 => editor.plan_rename(&root_id, "Aé-file".as_bytes(), &box_id, b"Moved", &r),
            8 => editor.plan_unlink(&root_id, "Aé-file".as_bytes(), &r),
            9 => editor.plan_unlink(&box_id, b"Child", &r),
            10 => editor.plan_rename(&root_id, b"Box", &root_id, b"ChangedBox", &r),
            11 => editor.plan_unlink(&root_id, b"Box", &r),
            _ => editor.plan_unlink(&root_id, "Aé-file".as_bytes(), &r),
        }
        .unwrap_or_else(|e| panic!("operation {operation}: {e:?}"));
        let anchor = editor.recovery_anchor();
        fs::write(dir.join("recovery-anchor.bin"), anchor.encode()).unwrap();
        File::open(dir.join("recovery-anchor.bin"))
            .unwrap()
            .sync_all()
            .unwrap();
        File::open(&dir).unwrap().sync_all().unwrap();
        let volume_block = plan.planned_volume_block();
        let error = editor.commit_mutation(plan, &anchor, &r).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InterruptedWrite);
        assert_eq!(
            editor.directory_identity(2, &r).unwrap_err().kind,
            ErrorKind::InterruptedWrite
        );
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        let mut torn_boot = [0; 4096];
        File::open(&image)
            .unwrap()
            .read_exact_at(&mut torn_boot, 0)
            .unwrap();
        assert!(
            !native_checksum_valid(&torn_boot),
            "injected boot must be checksum-invalid"
        );
        fs::write(dir.join("torn-boot.bin"), torn_boot).unwrap();
        let torn_image_hash = digest(&fs::read(&image).unwrap());
        let pre_args = [
            "-c".to_string(),
            "-u".to_string(),
            "-w".to_string(),
            image.display().to_string(),
        ];
        let pre = Command::new(&checker).args(&pre_args).output().unwrap();
        fs::write(
            dir.join("pre-recovery-apfsck.command"),
            format!("{} {pre_args:?}\n", checker.display()),
        )
        .unwrap();
        fs::write(dir.join("pre-recovery-apfsck.stdout"), &pre.stdout).unwrap();
        fs::write(dir.join("pre-recovery-apfsck.stderr"), &pre.stderr).unwrap();
        fs::write(
            dir.join("pre-recovery-apfsck.status"),
            format!("{:?}\n", pre.status.code()),
        )
        .unwrap();
        assert!(
            !pre.status.success(),
            "native checker must reject the checksum-invalid boot"
        );
        assert_eq!(
            digest(&fs::read(&image).unwrap()),
            torn_image_hash,
            "pre-recovery checker changed image"
        );
        fs::write(dir.join("torn-image.sha256"), torn_image_hash).unwrap();
        // Cold reopen with the caller-retained anchor; no old owner or mutable decoder survives.
        let reopened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .unwrap();
        let editor = ApfsEditor::recover_with_anchor(
            TornBoot {
                inner: Store(reopened),
                armed: false,
            },
            &anchor,
            limits,
            &r,
        )
        .unwrap();
        assert_eq!(editor.checkpoint_xid(), 2);
        assert!(editor.allocation_proof().is_clean());
        let allocated = editor.allocation_proof().allocated_blocks();
        let current_root = editor.directory_identity(2, &r).unwrap();
        let created = if operation == 0 {
            let names = editor.directory(&current_root, &r).unwrap();
            let id = &names
                .iter()
                .find(|e| e.name == NativeName::Bytes("新-é".as_bytes().to_vec()))
                .unwrap()
                .object;
            Some(u64::from_be_bytes(id.native[..].try_into().unwrap()))
        } else {
            None
        };
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
            volume_block.to_string(),
            "-f".into(),
            "apfs".into(),
            image.display().to_string(),
        ];
        checked(&dir, "fsstat", &tsk.join("fsstat"), &prefix);
        checked(&dir, "fls", &tsk.join("fls"), &prefix);
        if operation == 12 {
            let mut args = prefix.clone();
            args.push("16".into());
            let output = Command::new(tsk.join("icat")).args(&args).output().unwrap();
            fs::write(
                dir.join("removed-inode.command"),
                format!("{} {:?}\n", tsk.join("icat").display(), args),
            )
            .unwrap();
            fs::write(dir.join("removed-inode.stdout"), &output.stdout).unwrap();
            fs::write(dir.join("removed-inode.stderr"), &output.stderr).unwrap();
            fs::write(
                dir.join("removed-inode.status"),
                format!("{:?}\n", output.status.code()),
            )
            .unwrap();
            assert!(!output.status.success());
        } else {
            let mut args = prefix.clone();
            args.push("16".into());
            let data = checked(&dir, "data", &tsk.join("icat"), &args);
            let inode = checked(&dir, "inode", &tsk.join("istat"), &args);
            let expected_name = match operation {
                6 => "Ré-named",
                7 => "Moved",
                8 => "Alias",
                _ => "Aé-file",
            };
            assert!(String::from_utf8_lossy(&inode).contains(expected_name));
            let links = match operation {
                5 => 3,
                8 | 11 => 1,
                _ => 2,
            };
            assert!(String::from_utf8_lossy(&inode).contains(&format!("Number of Links: {links}")));
            let mut expected = vec![0; 16397];
            for (i, b) in expected.iter_mut().enumerate() {
                if !(4096..8192).contains(&i) && !(12288..16384).contains(&i) {
                    *b = ((i % 4096) * 17 % 251) as u8;
                }
            }
            match operation {
                2 => {
                    expected = (0..8192 + 29)
                        .map(|at| {
                            if (4096..8192).contains(&at) {
                                0
                            } else {
                                (at * 31 + 9) as u8
                            }
                        })
                        .collect()
                }
                3 => expected.resize(8199, 0),
                4 => expected.resize(24579, 0),
                _ => {}
            }
            if let Some(created) = created {
                let mut args = prefix.clone();
                args.push(created.to_string());
                let got = checked(&dir, "created-data", &tsk.join("icat"), &args);
                let model: Vec<u8> = (0..8192 + 29)
                    .map(|at| {
                        if (4096..8192).contains(&at) {
                            0
                        } else {
                            (at * 31 + 9) as u8
                        }
                    })
                    .collect();
                assert_eq!(got, model);
                let inode = checked(&dir, "created-inode", &tsk.join("istat"), &args);
                assert!(String::from_utf8_lossy(&inode).contains("owner / group: 42 / 43"));
                assert!(String::from_utf8_lossy(&inode).contains("新-é"));
            }
            assert_eq!(data, expected);
            let mut resource = prefix.clone();
            resource.push("16-4353-1".into());
            assert_eq!(
                checked(&dir, "resource", &tsk.join("icat"), &resource),
                b"resource"
            );
        }
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
        fs::write(dir.join("receipt.txt"),format!("status=passed\nprofile=native retained-checkpoint namespace and DATA COW\nxid=2\nallocated={allocated}\nvolume_block={}\nimage_sha256={before}\nmetadata_policy=preserved native inode/attrs/fork/siblings\nbarriers=payload metadata ephemeral terminal-NX torn-boot followed by cold native recovery\nboot_hint=31-byte durable prefix independently Fletcher-invalid and native-rejected, then restored from highest complete checkpoint with retained anchor\nmacos_native_evidence=unavailable\nremaining=reclamation snapshots shared-clone mutation broader trees macOS\n",volume_block)).unwrap();
    }
}
