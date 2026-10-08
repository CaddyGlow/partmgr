use partmgr::{
    fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*, fs_apfs_edit::*, fs_core::*, storage::Storage,
};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[path = "fixtures/apfs_repeat.rs"]
mod repeat;
#[path = "fixtures/apfs_build_tree.rs"]
mod tree;
struct Disk {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let b = self.bytes.lock().unwrap();
        out.copy_from_slice(
            b.get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let n = input.len().min(67);
        self.bytes.lock().unwrap()[at as usize..at as usize + n].copy_from_slice(&input[..n]);
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Bytes(Vec<u8>);
impl virtdisk::ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.0[at as usize..at as usize + out.len()]);
        Ok(())
    }
}
struct Input(ObjectId, u8);
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
        out[..n].fill(self.1);
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: 29,
            kind: ExtentKind::Data,
        })
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(384 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits(blocks: u64) -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 256,
        attempts: 257,
        work: 1024 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks,
            checkpoint_blocks: 128,
            objects: 256,
            records: 256,
            work: 64 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn options() -> ApfsBuildOptions {
    ApfsBuildOptions {
        image_bytes: 2 * 1024 * 1024,
        container_uuid: [0x61; 16],
        volume_uuid: [0x71; 16],
        volume_label: b"Repeated COW".to_vec(),
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
            blocks: 512,
            work: 64 * 1024 * 1024,
            page_entries: 2,
        },
    }
}
#[test]
fn additive_default_is_byte_identical_and_extended_capacity_is_real_native_authoring() {
    let r = resources();
    let mut outputs = Vec::new();
    for capacity in [
        ApfsCheckpointCapacity::default(),
        ApfsCheckpointCapacity::default(),
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 64,
        },
    ] {
        let b = Arc::new(Mutex::new(vec![0; 2 * 1024 * 1024]));
        let mut disk = Disk {
            bytes: b.clone(),
            writes: Arc::new(AtomicUsize::new(0)),
        };
        let plan = if outputs.is_empty() {
            ApfsBuildPlan::plan(Arc::new(tree::Tree::new(3)), options(), &r)
        } else {
            ApfsBuildPlan::plan_with_checkpoint_capacity(
                Arc::new(tree::Tree::new(3)),
                options(),
                capacity,
                &r,
            )
        }
        .unwrap();
        let report = plan.emit(&mut disk, &r).unwrap();
        report
            .audit(
                Arc::new(Bytes(b.lock().unwrap().clone())),
                limits(512).read,
                limits(512).audit,
                &r,
            )
            .unwrap();
        drop(plan);
        outputs.push(b.lock().unwrap().clone());
        assert_eq!(r.memory.used(), 0);
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_ne!(outputs[1], outputs[2]);
    let nx = &outputs[2][..4096];
    assert_eq!(u32::from_le_bytes(nx[104..108].try_into().unwrap()), 32);
    assert_eq!(u32::from_le_bytes(nx[108..112].try_into().unwrap()), 64);
    for capacity in [
        ApfsCheckpointCapacity {
            descriptor_blocks: 7,
            data_blocks: 64,
        },
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 63,
        },
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 257,
        },
        ApfsCheckpointCapacity {
            descriptor_blocks: 130,
            data_blocks: 256,
        },
    ] {
        assert!(
            ApfsBuildPlan::plan_with_checkpoint_capacity(
                Arc::new(tree::Tree::new(3)),
                options(),
                capacity,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn independent_larger_ring_two_transactions_preserve_prior_retirement_xids_and_exhaust_safely() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(repeat::repeated_seed()));
    let original = bytes.lock().unwrap().clone();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut editor = ApfsEditor::open(
        Disk {
            bytes: bytes.clone(),
            writes: writes.clone(),
        },
        1026,
        limits(512),
        &r,
    )
    .unwrap();
    let mut expected = vec![0; 16397];
    for (i, v) in expected.iter_mut().enumerate() {
        if !(4096..8192).contains(&i) && !(12288..16384).contains(&i) {
            *v = ((i % 4096) * 17 % 251) as u8;
        }
    }
    let mut previous_queues: Vec<Vec<u8>> = Vec::new();
    for sequence in 0..2 {
        let id = editor.file_identity(16, &r).unwrap();
        let value = 0x91 + sequence;
        let offset = if sequence == 0 { 4091 } else { 8190 };
        let plan = editor
            .plan_range(
                &id,
                offset,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation: sequence as u64,
                        native: b"independent repeated source".to_vec(),
                    },
                    value,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(plan, &anchor, &r).unwrap();
        assert_eq!(editor.checkpoint_xid(), 2 + u64::from(sequence));
        expected[offset as usize..offset as usize + 29].fill(value);
        let fresh = editor.file_identity(16, &r).unwrap();
        let mut out = vec![0; 16397];
        assert_eq!(
            editor.read_file_at(&fresh, 0, &mut out, &r).unwrap(),
            out.len()
        );
        assert_eq!(out, expected);
        let view = bytes.lock().unwrap();
        let boot = &view[..4096];
        let data_base = u64::from_le_bytes(boot[120..128].try_into().unwrap()) as usize;
        let data_index = u32::from_le_bytes(boot[144..148].try_into().unwrap()) as usize;
        let sm = &view[(data_base + data_index + 1) * 4096..(data_base + data_index + 2) * 4096];
        assert_eq!(
            u64::from_le_bytes(sm[200..208].try_into().unwrap()),
            2 + 2 * u64::from(sequence)
        );
        assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(sm[256..264].try_into().unwrap()), 2);
        let main = &view[(data_base + data_index + 3) * 4096..(data_base + data_index + 4) * 4096];
        if sequence == 1 {
            let key_start = 56 + 4 * u32::from_le_bytes(main[36..40].try_into().unwrap()) as usize;
            let old_keys = &previous_queues[0];
            assert!(
                main[key_start..]
                    .windows(8)
                    .any(|w| w == 2u64.to_le_bytes())
            );
            assert!(!old_keys.is_empty());
        }
        previous_queues.push(main.to_vec());
        for block in [100, 102, 110, 112] {
            assert_eq!(
                &view[block * 4096..(block + 1) * 4096],
                &original[block * 4096..(block + 1) * 4096]
            );
        }
    }
    let before = bytes.lock().unwrap().clone();
    let calls = writes.load(Ordering::SeqCst);
    let id = editor.file_identity(16, &r).unwrap();
    assert!(editor.plan_truncate(&id, 1, &r).is_err());
    assert_eq!(writes.load(Ordering::SeqCst), calls);
    assert_eq!(*bytes.lock().unwrap(), before);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn framework_authored_capacity_supports_repeated_namespace_and_payload_transactions() {
    repeated_framework(None);
}
fn repeated_framework(evidence: Option<&std::path::Path>) {
    let r = resources();
    let bytes = Arc::new(Mutex::new(vec![0; 2 * 1024 * 1024]));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut disk = Disk {
        bytes: bytes.clone(),
        writes,
    };
    let build = ApfsBuildPlan::plan_with_checkpoint_capacity(
        Arc::new(tree::Tree::new(3)),
        options(),
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 64,
        },
        &r,
    )
    .unwrap();
    build.emit(&mut disk, &r).unwrap();
    drop(build);
    let mut editor = ApfsEditor::open(disk, 1026, limits(512), &r).unwrap();
    let input = |generation, value| {
        Arc::new(Input(
            ObjectId {
                source: 999,
                generation,
                native: b"repeated".to_vec(),
            },
            value,
        ))
    };
    let metadata = ApfsCreateMetadata {
        permissions: 0o640,
        uid: 42,
        gid: 43,
        timestamp: 123456789,
    };
    for operation in 0..2 {
        let root = editor.directory_identity(2, &r).unwrap();
        let entry = editor.directory(&root, &r).unwrap();
        let file = entry
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"Created".to_vec()))
            .map(|e| e.object.clone());
        let plan = match operation {
            0 => editor.plan_create(&root, b"Created", input(0, 0x91), metadata, &r),
            1 => editor.plan_replace(file.as_ref().unwrap(), input(1, 0x92), &r),
            2 => editor.plan_truncate(file.as_ref().unwrap(), 17, &r),
            3 => editor.plan_hardlink(file.as_ref().unwrap(), &root, b"Alias", 123456789, &r),
            4 => editor.plan_rename(&root, b"Created", &root, "Renamé".as_bytes(), &r),
            _ => editor.plan_unlink(&root, "Renamé".as_bytes(), &r),
        }
        .unwrap();
        let volume_block = plan.planned_volume_block();
        drop(entry);
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, &r).unwrap();
        assert_eq!(editor.checkpoint_xid(), 2 + operation);
        assert!(
            editor.directory(&root, &r).is_err(),
            "old generation must be rejected"
        );
        let root = editor.directory_identity(2, &r).unwrap();
        let entries = editor.directory(&root, &r).unwrap();
        let name: &[u8] = if operation >= 3 { b"Alias" } else { b"Created" };
        let id = &entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(name.to_vec()))
            .unwrap()
            .object;
        let length = if operation >= 2 { 17 } else { 29 };
        let mut payload = vec![0; length];
        assert_eq!(
            editor.read_file_at(id, 0, &mut payload, &r).unwrap(),
            length
        );
        assert_eq!(
            payload,
            vec![if operation == 0 { 0x91 } else { 0x92 }; length]
        );
        if operation == 5 {
            assert!(
                !entries
                    .iter()
                    .any(|e| e.name == NativeName::Bytes("Renamé".as_bytes().to_vec()))
            );
        }
        let view = bytes.lock().unwrap();
        let base = u64::from_le_bytes(view[120..128].try_into().unwrap()) as usize;
        let index = u32::from_le_bytes(view[144..148].try_into().unwrap()) as usize;
        let sm = &view[(base + index + 1) * 4096..(base + index + 2) * 4096];
        assert_eq!(
            u64::from_le_bytes(sm[200..208].try_into().unwrap()),
            2 * (operation + 1)
        );
        assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(sm[256..264].try_into().unwrap()), 2);
        if let Some(dir) = evidence {
            let image = dir.join(format!("checkpoint-{}.apfs", operation + 2));
            std::fs::write(&image, &*view).unwrap();
            let checker = std::process::Command::new(APFSCK)
                .args(["-c", "-u", "-w"])
                .arg(&image)
                .output()
                .expect("enabled native checker must exist");
            std::fs::write(
                dir.join(format!("checkpoint-{}.checker.stdout", operation + 2)),
                &checker.stdout,
            )
            .unwrap();
            std::fs::write(
                dir.join(format!("checkpoint-{}.checker.stderr", operation + 2)),
                &checker.stderr,
            )
            .unwrap();
            assert!(checker.status.success(), "native checker: {:?}", checker);
            assert!(checker.stdout.is_empty() && checker.stderr.is_empty());
            let inode = u64::from_be_bytes(id.native.as_slice().try_into().unwrap());
            let oracle = std::process::Command::new(ICAT)
                .args(["-P", "apfs", "-B", &volume_block.to_string(), "-f", "apfs"])
                .arg(&image)
                .arg(inode.to_string())
                .output()
                .expect("enabled TSK must exist");
            std::fs::write(
                dir.join(format!("checkpoint-{}.icat.stdout", operation + 2)),
                &oracle.stdout,
            )
            .unwrap();
            std::fs::write(
                dir.join(format!("checkpoint-{}.icat.stderr", operation + 2)),
                &oracle.stderr,
            )
            .unwrap();
            assert!(oracle.status.success());
            assert_eq!(oracle.stdout, payload);
            std::fs::write(
                dir.join(format!("checkpoint-{}.expected", operation + 2)),
                &payload,
            )
            .unwrap();
            assert_eq!(
                std::fs::read(&image).unwrap(),
                *view,
                "validators must not mutate image"
            );
            std::fs::write(
                dir.join(format!("checkpoint-{}.commands.txt", operation + 2)),
                format!(
                    "{APFSCK} -c -u -w {}\n{ICAT} -P apfs -B {volume_block} -f apfs {} {inode}\n",
                    image.display(),
                    image.display()
                ),
            )
            .unwrap();
        }
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

const APFSCK: &str = "/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
#[test]
#[ignore = "requires PARTMGR_APFS_REPEAT_EVIDENCE and pinned native checker/TSK; enabled missing tools fail"]
fn native_repeated_framework_checkpoints() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_APFS_REPEAT_EVIDENCE").expect("enabled evidence directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let binary = std::env::current_exe().unwrap();
    std::fs::copy(&binary, dir.join("compiled-test-executable")).unwrap();
    let sources: &[(&str, &[u8])] = &[
        (
            "src/fs_apfs_builder.rs",
            include_bytes!("../src/fs_apfs_builder.rs"),
        ),
        (
            "src/fs_apfs_builder_layout.rs",
            include_bytes!("../src/fs_apfs_builder_layout.rs"),
        ),
        (
            "src/fs_apfs_builder_disk.rs",
            include_bytes!("../src/fs_apfs_builder_disk.rs"),
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
            "src/fs_apfs_edit_namespace.rs",
            include_bytes!("../src/fs_apfs_edit_namespace.rs"),
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
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        (
            "tests/fixtures/apfs_clean.rs",
            include_bytes!("fixtures/apfs_clean.rs"),
        ),
        (
            "tests/fixtures/apfs_repeat.rs",
            include_bytes!("fixtures/apfs_repeat.rs"),
        ),
        (
            "tests/fixtures/apfs_build_tree.rs",
            include_bytes!("fixtures/apfs_build_tree.rs"),
        ),
        (
            "tests/fs_apfs_edit_repeat.rs",
            include_bytes!("fs_apfs_edit_repeat.rs"),
        ),
    ];
    for (name, bytes) in sources {
        assert_eq!(
            std::fs::read(name).unwrap(),
            *bytes,
            "compiled source binding"
        );
        let archive = dir.join("compiled-sources").join(name);
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        std::fs::write(archive, bytes).unwrap();
    }
    let tool_bytes = [std::fs::read(APFSCK).unwrap(), std::fs::read(ICAT).unwrap()];
    let guards = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT])
        .output()
        .unwrap();
    assert!(guards.status.success());
    std::fs::write(dir.join("start-binary-tools.sha256"), &guards.stdout).unwrap();
    repeated_framework(Some(&dir));
    for (name, bytes) in sources {
        assert_eq!(
            std::fs::read(name).unwrap(),
            *bytes,
            "source changed during gate"
        );
    }
    assert_eq!(std::fs::read(APFSCK).unwrap(), tool_bytes[0]);
    assert_eq!(std::fs::read(ICAT).unwrap(), tool_bytes[1]);
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        std::fs::read(dir.join("compiled-test-executable")).unwrap()
    );
    let end = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT])
        .output()
        .unwrap();
    assert!(end.status.success());
    assert_eq!(end.stdout, guards.stdout);
    std::fs::write(dir.join("end-binary-tools.sha256"), end.stdout).unwrap();
    std::fs::write(dir.join("receipt.json"), "{\"status\":\"passed\",\"transactions\":2,\"checkpoints\":[2,3],\"native_checker\":\"apfsprogs-0.2.1\",\"payload_oracle\":\"TSK-4.14.0 icat\",\"default_output_identical\":true,\"reclamation\":false}\n").unwrap();
}

struct BarrierDisk {
    disk: Disk,
    remaining: Arc<AtomicUsize>,
}
impl Storage for BarrierDisk {
    fn len(&self) -> io::Result<u64> {
        self.disk.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.disk.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        self.disk.write_at(at, input)
    }
    fn flush(&mut self) -> io::Result<()> {
        let n = self.remaining.load(Ordering::SeqCst);
        if n > 0 && self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
            return Err(io::Error::other("durable-write barrier cut"));
        }
        Ok(())
    }
}
#[test]
fn second_transaction_each_barrier_failure_cold_recovers_retained_history() {
    for barrier in 1..=5 {
        let r = resources();
        let bytes = Arc::new(Mutex::new(repeat::repeated_seed()));
        let remaining = Arc::new(AtomicUsize::new(0));
        let disk = || BarrierDisk {
            disk: Disk {
                bytes: bytes.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
            },
            remaining: remaining.clone(),
        };
        let mut editor = ApfsEditor::open(disk(), 1026, limits(512), &r).unwrap();
        for sequence in 0..2 {
            let id = editor.file_identity(16, &r).unwrap();
            let plan = editor
                .plan_range(
                    &id,
                    4091,
                    Arc::new(Input(
                        ObjectId {
                            source: 999,
                            generation: sequence,
                            native: b"cut".to_vec(),
                        },
                        0x91 + sequence as u8,
                    )),
                    &r,
                )
                .unwrap();
            let anchor = editor.recovery_anchor();
            if sequence == 0 {
                editor.commit_range(plan, &anchor, &r).unwrap();
            } else {
                remaining.store(barrier, Ordering::SeqCst);
                assert!(editor.commit_range(plan, &anchor, &r).is_err());
                drop(editor);
                let recovered =
                    ApfsEditor::recover_with_anchor(disk(), &anchor, limits(512), &r).unwrap();
                let xid = recovered.checkpoint_xid();
                assert!(xid == 2 || xid == 3);
                let fresh = recovered.file_identity(16, &r).unwrap();
                let mut payload = [0; 29];
                recovered
                    .read_file_at(&fresh, 4091, &mut payload, &r)
                    .unwrap();
                assert_eq!(payload, [if xid == 2 { 0x91 } else { 0x92 }; 29]);
                drop(recovered);
                break;
            }
        }
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn checksum_valid_internal_pool_size_must_match_native_topology() {
    let r = resources();
    let mut bytes = repeat::repeated_seed();
    fixture::p64(&mut bytes[129 * 4096..130 * 4096], 152, 32);
    fixture::seal(&mut bytes[129 * 4096..130 * 4096]);
    assert!(
        ApfsEditor::open(
            Disk {
                bytes: Arc::new(Mutex::new(bytes)),
                writes: Arc::new(AtomicUsize::new(0))
            },
            1026,
            limits(512),
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn independent_retention_classifies_live_history_separately_from_pending_and_refunds() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(repeat::repeated_seed()));
    let mut editor = ApfsEditor::open(
        Disk {
            bytes: bytes.clone(),
            writes: Arc::new(AtomicUsize::new(0)),
        },
        1026,
        limits(512),
        &r,
    )
    .unwrap();
    for generation in 0..2 {
        let id = editor.file_identity(16, &r).unwrap();
        let plan = editor
            .plan_range(
                &id,
                4091 + generation * 4099,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation,
                        native: b"retention oracle".to_vec(),
                    },
                    0x91 + generation as u8,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(plan, &anchor, &r).unwrap();
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let raw = bytes.lock().unwrap().clone();
    let container =
        ApfsContainer::open(Arc::new(Bytes(raw.clone())), limits(512).read, &r).unwrap();
    let volume = ApfsVolume::open(container, 1026, &r).unwrap();
    let baseline = r.memory.used();
    let proof = prove_apfs_retention(&volume, 2, limits(512).audit, &r).unwrap();
    assert_eq!(
        proof
            .retained_checkpoints()
            .iter()
            .map(|p| p.1)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(
        proof
            .retirement_candidates()
            .iter()
            .map(|p| p.1)
            .collect::<Vec<_>>(),
        [1]
    );
    let states: Vec<_> = (0..512).map(|b| proof.block(b).unwrap()).collect();
    assert!(states.iter().any(|s| s.pending && s.live));
    assert!(states.iter().any(|s| s.older_live && !s.live));
    assert!(
        states
            .iter()
            .any(|s| s.internal_pending && !s.internal_live)
    );
    assert!(proof.block(512).is_none());
    drop(proof);
    assert_eq!(r.memory.used(), baseline);
    for horizon in [0, 3, 4] {
        assert_eq!(
            prove_apfs_retention(&volume, horizon, limits(512).audit, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), baseline);
    }
    let mut capped = limits(512).audit;
    capped.work = 1;
    assert_eq!(
        prove_apfs_retention(&volume, 2, capped, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        prove_apfs_retention(&volume, 2, limits(512).audit, &cancelled)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(cancelled.memory.used(), 0);
    assert_eq!(*bytes.lock().unwrap(), raw);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    let mut editor = ApfsEditor::open(
        Disk {
            bytes: bytes.clone(),
            writes: Arc::new(AtomicUsize::new(0)),
        },
        1026,
        limits(512),
        &r,
    )
    .unwrap();
    let plan = editor.plan_checkpoint_retirement(2, &r).unwrap();
    let candidates = plan.checkpoints().to_vec();
    let anchor = editor.recovery_anchor();
    let receipt = editor
        .commit_checkpoint_retirement(plan, &anchor, &r)
        .unwrap();
    assert_eq!(receipt.retired_checkpoints, 1);
    assert_eq!(receipt.checkpoint_xid, 3);
    assert_eq!(receipt.released_blocks, 0);
    let after = bytes.lock().unwrap().clone();
    for (block, pair) in raw
        .chunks_exact(4096)
        .zip(after.chunks_exact(4096))
        .enumerate()
    {
        if candidates
            .iter()
            .any(|(address, _)| *address == block as u64)
        {
            assert_eq!(pair.1, &[0; 4096]);
        } else {
            assert_eq!(
                pair.0, pair.1,
                "retirement modified unrelated block {block}"
            );
        }
    }
    assert!(
        editor
            .plan_checkpoint_retirement(2, &r)
            .unwrap()
            .checkpoints()
            .is_empty()
    );
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
