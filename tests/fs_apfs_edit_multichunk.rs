use partmgr::{
    fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*, fs_apfs_edit::*, fs_core::*, storage::Storage,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[path = "fixtures/apfs_multichunk.rs"]
mod independent;
#[path = "fixtures/apfs_build_tree.rs"]
mod tree;
const LENGTH: u64 = independent::LENGTH;
#[derive(Clone)]
struct Sparse {
    blocks: BTreeMap<u64, Vec<u8>>,
    length: u64,
    writes: usize,
}
struct Disk(Arc<Mutex<Sparse>>);
fn read(s: &Sparse, at: u64, out: &mut [u8]) -> io::Result<()> {
    if at
        .checked_add(out.len() as u64)
        .is_none_or(|end| end > s.length)
    {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    out.fill(0);
    let mut done = 0;
    while done < out.len() {
        let offset = at + done as u64;
        let n = (4096 - (offset % 4096) as usize).min(out.len() - done);
        if let Some(b) = s.blocks.get(&(offset / 4096)) {
            out[done..done + n]
                .copy_from_slice(&b[offset as usize % 4096..offset as usize % 4096 + n]);
        }
        done += n;
    }
    Ok(())
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        read(&self.0.lock().unwrap(), at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        if at
            .checked_add(input.len() as u64)
            .is_none_or(|end| end > s.length)
        {
            return Err(io::ErrorKind::WriteZero.into());
        }
        s.writes += 1;
        let mut done = 0;
        while done < input.len() {
            let offset = at + done as u64;
            let n = (4096 - (offset % 4096) as usize).min(input.len() - done);
            let block = offset / 4096;
            if s.blocks.contains_key(&block) || input[done..done + n].iter().any(|b| *b != 0) {
                let b = s.blocks.entry(block).or_insert_with(|| vec![0; 4096]);
                b[offset as usize % 4096..offset as usize % 4096 + n]
                    .copy_from_slice(&input[done..done + n]);
            }
            done += n;
        }
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Frozen(Sparse);
impl virtdisk::ReadAt for Frozen {
    fn len(&self) -> u64 {
        self.0.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        read(&self.0, at, out)
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(384 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 256,
        attempts: 257,
        work: 1024 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: LENGTH / 4096,
            checkpoint_blocks: 128,
            objects: 256,
            records: 256,
            work: 64 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks: LENGTH / 4096,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn sparse(bytes: &[u8]) -> Sparse {
    Sparse {
        length: LENGTH,
        writes: 0,
        blocks: bytes
            .chunks(4096)
            .enumerate()
            .filter(|(_, b)| b.iter().any(|x| *x != 0))
            .map(|(i, b)| (i as u64, b.to_vec()))
            .collect(),
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
        let n = (29 - at.min(29)) as usize;
        let n = n.min(out.len()).min(7);
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
fn authored(r: &Resources) -> Arc<Mutex<Sparse>> {
    let bytes = Arc::new(Mutex::new(Sparse {
        length: LENGTH,
        blocks: BTreeMap::new(),
        writes: 0,
    }));
    let options = ApfsBuildOptions {
        image_bytes: LENGTH,
        container_uuid: [0x61; 16],
        volume_uuid: [0x71; 16],
        volume_label: b"Five chunks".to_vec(),
        names: ApfsBuildNames::ExactBytes,
        metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
            uid: 0,
            gid: 0,
            file_permissions: 0o644,
            directory_permissions: 0o755,
            timestamp: 123456789,
        }),
        limits: ApfsBuildLimits {
            objects: 32,
            occurrences: 64,
            name_bytes: 8192,
            depth: 8,
            blocks: LENGTH / 4096,
            work: 64 * 1024 * 1024,
            page_entries: 2,
        },
    };
    let plan = ApfsBuildPlan::plan_with_checkpoint_capacity(
        Arc::new(tree::Tree::new(3)),
        options,
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 64,
        },
        r,
    )
    .unwrap();
    let report = plan.emit(&mut Disk(bytes.clone()), r).unwrap();
    let mut hashing_read = limits().read;
    hashing_read.work += LENGTH;
    report
        .audit(
            Arc::new(Frozen(bytes.lock().unwrap().clone())),
            hashing_read,
            limits().audit,
            r,
        )
        .unwrap();
    drop(plan);
    bytes
}
fn sequence(
    bytes: Arc<Mutex<Sparse>>,
    r: &Resources,
    capacity: u64,
    evidence: Option<&std::path::Path>,
) {
    let original = bytes.lock().unwrap().clone();
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), r).unwrap();
    for operation in 0..capacity {
        let root = editor.directory_identity(2, r).unwrap();
        let entries = editor.directory(&root, r).unwrap();
        let file = entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"Created".to_vec()))
            .map(|e| e.object.clone());
        let input = || {
            Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: operation,
                    native: b"independent-input".to_vec(),
                },
                0x91 + operation as u8,
            ))
        };
        let metadata = ApfsCreateMetadata {
            permissions: 0o640,
            uid: 42,
            gid: 43,
            timestamp: 123456789,
        };
        let plan = match operation {
            0 => editor.plan_create(&root, b"Created", input(), metadata, r),
            1 => editor.plan_replace(file.as_ref().unwrap(), input(), r),
            2 => editor.plan_truncate(file.as_ref().unwrap(), 17, r),
            3 => editor.plan_hardlink(file.as_ref().unwrap(), &root, b"Alias", 123456789, r),
            4 => editor.plan_rename(&root, b"Created", &root, "Renamé".as_bytes(), r),
            5 => editor.plan_unlink(&root, "Renamé".as_bytes(), r),
            6 => editor.plan_unlink(&root, b"Alias", r),
            _ => editor.plan_create_directory(&root, b"Empty", metadata, r),
        }
        .unwrap();
        let volume_block = plan.planned_volume_block();
        drop(entries);
        let anchor = editor.recovery_anchor();
        editor.commit_mutation(plan, &anchor, r).unwrap();
        assert_eq!(editor.checkpoint_xid(), operation + 2);
        let root = editor.directory_identity(2, r).unwrap();
        let entries = editor.directory(&root, r).unwrap();
        if operation < 6 {
            let name = if operation >= 3 {
                b"Alias".as_slice()
            } else {
                b"Created"
            };
            let id = &entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(name.to_vec()))
                .unwrap()
                .object;
            let mut out = vec![0; if operation >= 2 { 17 } else { 29 }];
            let len = out.len();
            assert_eq!(editor.read_file_at(id, 0, &mut out, r).unwrap(), len);
            assert_eq!(out, vec![if operation == 0 { 0x91 } else { 0x92 }; len]);

            if let Some(dir) = evidence {
                native_checkpoint(
                    dir,
                    operation + 2,
                    volume_block,
                    id,
                    &out,
                    &bytes.lock().unwrap(),
                );
            }
        } else {
            assert!(
                !entries
                    .iter()
                    .any(|e| e.name == NativeName::Bytes(b"Alias".to_vec()))
            );
        }
        let s = bytes.lock().unwrap();
        for (&block, b) in &original.blocks {
            if block == 0 {
                continue;
            }
            assert_eq!(
                s.blocks.get(&block),
                Some(b),
                "historical block overwritten {block}"
            );
        }
    }
    let before = bytes.lock().unwrap().clone();
    let root = editor.directory_identity(2, r).unwrap();
    let metadata = ApfsCreateMetadata {
        permissions: 0o640,
        uid: 42,
        gid: 43,
        timestamp: 123456789,
    };
    assert!(
        editor
            .plan_create_directory(&root, b"Exhausted", metadata, r)
            .is_err()
    );
    assert_eq!(bytes.lock().unwrap().writes, before.writes);
    drop(editor);
}
#[test]
fn independent_multichunk_six_transactions_preserve_retirements_and_history() {
    let r = resources();
    sequence(
        Arc::new(Mutex::new(sparse(&independent::seed()))),
        &r,
        8,
        None,
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn framework_authored_multichunk_six_transactions_preserve_retirements_and_history() {
    let r = resources();
    sequence(authored(&r), &r, 6, None);
    assert_eq!(r.memory.used(), 0);
}

const APFSCK: &str = "/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
fn native_checkpoint(
    dir: &std::path::Path,
    xid: u64,
    volume: u64,
    id: &ObjectId,
    payload: &[u8],
    s: &Sparse,
) {
    use std::os::unix::fs::FileExt;
    let path = dir.join(format!("checkpoint-{xid}.apfs"));
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(s.length).unwrap();
    for (&block, b) in &s.blocks {
        file.write_all_at(b, block * 4096).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let before = std::process::Command::new("sha256sum")
        .arg(&path)
        .output()
        .unwrap();
    assert!(before.status.success());
    let checker = std::process::Command::new(APFSCK)
        .args(["-c", "-u", "-w"])
        .arg(&path)
        .output()
        .expect("enabled native checker");
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.checker.stdout")),
        &checker.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.checker.stderr")),
        &checker.stderr,
    )
    .unwrap();
    assert!(checker.status.success(), "native checker {checker:?}");
    assert!(checker.stdout.is_empty() && checker.stderr.is_empty());
    let inode = u64::from_be_bytes(id.native.as_slice().try_into().unwrap());
    let args = [
        "-P".to_owned(),
        "apfs".to_owned(),
        "-B".to_owned(),
        volume.to_string(),
        "-f".to_owned(),
        "apfs".to_owned(),
        path.display().to_string(),
        inode.to_string(),
    ];
    let oracle = std::process::Command::new(ICAT)
        .args(&args)
        .output()
        .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.icat.stdout")),
        &oracle.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.icat.stderr")),
        &oracle.stderr,
    )
    .unwrap();
    std::fs::write(dir.join(format!("checkpoint-{xid}.expected")), payload).unwrap();
    assert!(oracle.status.success());
    assert_eq!(oracle.stdout, payload);
    let after = std::process::Command::new("sha256sum")
        .arg(&path)
        .output()
        .unwrap();
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.unchanged.sha256")),
        after.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.commands.txt")),
        format!(
            "{APFSCK} -c -u -w {}\n{ICAT} {}\n",
            path.display(),
            args.join(" ")
        ),
    )
    .unwrap();
}
#[test]
#[ignore = "requires PARTMGR_APFS_MULTICHUNK_EVIDENCE and pinned checker/TSK; enabled missing tools fail"]
fn native_framework_multichunk_repeated_operations() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_APFS_MULTICHUNK_EVIDENCE").expect("enabled evidence directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();
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
            "tests/fixtures/apfs_build_tree.rs",
            include_bytes!("fixtures/apfs_build_tree.rs"),
        ),
        (
            "tests/fixtures/apfs_multichunk.rs",
            include_bytes!("fixtures/apfs_multichunk.rs"),
        ),
        (
            "tests/fs_apfs_edit_multichunk.rs",
            include_bytes!("fs_apfs_edit_multichunk.rs"),
        ),
    ];
    for (name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), *bytes);
        let p = dir.join("compiled-sources").join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let binary = std::env::current_exe().unwrap();
    std::fs::copy(&binary, dir.join("compiled-test-executable")).unwrap();
    let tools = [std::fs::read(APFSCK).unwrap(), std::fs::read(ICAT).unwrap()];
    let before = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT])
        .output()
        .unwrap();
    assert!(before.status.success());
    std::fs::write(dir.join("start-binary-tools.sha256"), &before.stdout).unwrap();
    let r = resources();
    sequence(authored(&r), &r, 6, Some(&dir));
    assert_eq!(r.memory.used(), 0);
    for (name, bytes) in sources {
        assert_eq!(
            std::fs::read(name).unwrap(),
            *bytes,
            "source changed during gate"
        );
    }
    assert_eq!(std::fs::read(APFSCK).unwrap(), tools[0]);
    assert_eq!(std::fs::read(ICAT).unwrap(), tools[1]);
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        std::fs::read(dir.join("compiled-test-executable")).unwrap()
    );
    let after = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT])
        .output()
        .unwrap();
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    std::fs::write(dir.join("end-binary-tools.sha256"), after.stdout).unwrap();
    std::fs::write(dir.join("receipt.json"),"{\"status\":\"passed\",\"chunks\":5,\"native_ip_blocks\":18,\"transactions\":6,\"retained_history\":true,\"reclamation\":false,\"checkpoints\":[2,3,4,5,6,7]}\n").unwrap();
}
