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
    authored_files(r, 3)
}
fn authored_files(r: &Resources, files: usize) -> Arc<Mutex<Sparse>> {
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
            objects: (files + 8).max(32),
            occurrences: (files * 2 + 16).max(64),
            name_bytes: (files * 512).max(8192),
            depth: 8,
            blocks: LENGTH / 4096,
            work: 64 * 1024 * 1024,
            page_entries: 2,
        },
    };
    let plan = ApfsBuildPlan::plan_with_checkpoint_capacity(
        Arc::new(tree::Tree::new(files)),
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
    hashing_read.objects = (files + 8).max(hashing_read.objects);
    hashing_read.records = (files * 6 + 16).max(hashing_read.records);
    report
        .audit(
            Arc::new(Frozen(bytes.lock().unwrap().clone())),
            hashing_read,
            ApfsAuditLimits {
                objects: (files * 8).max(limits().audit.objects),
                ..limits().audit
            },
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
    sequence_with_limits(bytes, r, capacity, evidence, limits())
}
fn multileaf_limits() -> ApfsEditLimits {
    let mut l = limits();
    l.metadata_blocks = 512;
    l.attempts = 513;
    l.read.objects = 2048;
    l.read.records = 8192;
    l.audit.objects = 32768;
    l
}
fn sequence_with_limits(
    bytes: Arc<Mutex<Sparse>>,
    r: &Resources,
    capacity: u64,
    evidence: Option<&std::path::Path>,
    l: ApfsEditLimits,
) {
    let original = bytes.lock().unwrap().clone();
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, l, r).unwrap();
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
const ISTAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
fn native_checkpoint(
    dir: &std::path::Path,
    xid: u64,
    volume: u64,
    id: &ObjectId,
    payload: &[u8],
    s: &Sparse,
) {
    let path = dir.join(format!("checkpoint-{xid}.apfs"));
    native_image(&path, s);
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
    let inode_report = std::process::Command::new(ISTAT)
        .args(&args)
        .output()
        .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.istat.stdout")),
        &inode_report.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.istat.stderr")),
        &inode_report.stderr,
    )
    .unwrap();
    assert!(inode_report.status.success());
    let report = String::from_utf8_lossy(&inode_report.stdout);
    assert!(report.contains("owner / group: 42 / 43"));
    assert!(report.contains(&format!(
        "Number of Links: {}",
        if xid == 5 || xid == 6 { 2 } else { 1 }
    )));
    let expected_name = if xid == 6 {
        "Renamé"
    } else if xid >= 7 {
        "Alias"
    } else {
        "Created"
    };
    assert!(
        report.contains(expected_name),
        "native primary name {report}"
    );
    let mut original_args = args.clone();
    original_args
        .last_mut()
        .unwrap()
        .clone_from(&"16".to_owned());
    let original = std::process::Command::new(ICAT)
        .args(&original_args)
        .output()
        .unwrap();
    assert!(original.status.success());
    let model: Vec<u8> = (0..16397)
        .map(|p| {
            if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                0
            } else {
                (p % 4096 * 17 % 251) as u8
            }
        })
        .collect();
    assert_eq!(original.stdout, model);
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.original-data.stdout")),
        &original.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.original-data.expected")),
        &model,
    )
    .unwrap();
    original_args
        .last_mut()
        .unwrap()
        .clone_from(&"16-4353-1".to_owned());
    let resource = std::process::Command::new(ICAT)
        .args(&original_args)
        .output()
        .unwrap();
    assert!(resource.status.success());
    assert_eq!(resource.stdout, b"resource");
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.original-resource.stdout")),
        &resource.stdout,
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("checkpoint-{xid}.original-resource.expected")),
        b"resource",
    )
    .unwrap();
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

fn native_image(path: &std::path::Path, image: &Sparse) {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::create(path).unwrap();
    file.set_len(image.length).unwrap();
    for (block, bytes) in &image.blocks {
        file.write_all_at(bytes, block * 4096).unwrap();
    }
    file.sync_all().unwrap();
}

fn fletcher_residues(bytes: &[u8]) -> [u64; 2] {
    const MODULUS: u64 = 0xffff_ffff;
    let mut plain = 0u64;
    let mut weighted = 0u64;
    for word in bytes[8..].as_chunks::<4>().0 {
        plain = (plain + u64::from(u32::from_le_bytes(*word))) % MODULUS;
        weighted = (weighted + plain) % MODULUS;
    }
    let low = u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap()));
    let high = u64::from(u32::from_le_bytes(bytes[4..8].try_into().unwrap()));
    [
        (plain + low + high) % MODULUS,
        (weighted + plain + low) % MODULUS,
    ]
}

fn native_reclamation_cold(dir: &std::path::Path, bytes: &Arc<Mutex<Sparse>>, r: &Resources) {
    std::fs::create_dir_all(dir).unwrap();
    let durable = Arc::new(Mutex::new(bytes.lock().unwrap().clone()));
    let control = Arc::new(Mutex::new(CutControl {
        write_durable: true,
        failed_flush_durable: true,
        cut_write: None,
        cut_flush: None,
        writes: 0,
        flushes: 0,
        trace: vec![],
    }));
    let disk = || CutDisk {
        live: bytes.clone(),
        durable: durable.clone(),
        control: control.clone(),
    };
    let mut editor = ApfsEditor::open(disk(), 1026, limits(), r).unwrap();
    let root = editor.directory_identity(2, r).unwrap();
    let id = editor
        .directory(&root, r)
        .unwrap()
        .iter()
        .find(|entry| entry.name == NativeName::Bytes(b"Alias".to_vec()))
        .unwrap()
        .object
        .clone();
    let replace = editor
        .plan_replace(
            &id,
            Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: 15,
                    native: b"cold reclaim independent final payload".to_vec(),
                },
                0x97,
            )),
            r,
        )
        .unwrap();
    let volume = replace.planned_volume_block();
    let anchor = editor.recovery_anchor();
    std::fs::write(dir.join("recovery-anchor.bin"), anchor.encode()).unwrap();
    editor.commit_mutation(replace, &anchor, r).unwrap();
    assert_eq!(editor.checkpoint_xid(), 15);
    native_checkpoint(dir, 15, volume, &id, &[0x97; 29], &bytes.lock().unwrap());
    let retire = editor.plan_checkpoint_retirement(14, r).unwrap();
    editor
        .commit_checkpoint_retirement(retire, &anchor, r)
        .unwrap();
    let reclaim = editor.plan_reclamation(r).unwrap();
    let volume = reclaim.planned_volume_block();
    {
        let mut c = control.lock().unwrap();
        c.cut_write = Some(17);
        c.writes = 0;
        c.flushes = 0;
        c.trace.clear();
    }
    assert!(editor.commit_reclamation(reclaim, &anchor, r).is_err());
    let image = durable.lock().unwrap().clone();
    let residues = fletcher_residues(&image.blocks[&0]);
    assert_ne!(
        residues,
        [0, 0],
        "torn boot must fail independent Fletcher residues"
    );
    std::fs::write(
        dir.join("before-recovery-fletcher.json"),
        format!("{{\"residues\":{residues:?},\"valid\":false}}\n"),
    )
    .unwrap();
    let before_path = dir.join("before-recovery.apfs");
    native_image(&before_path, &image);
    let before_hash = std::process::Command::new("sha256sum")
        .arg(&before_path)
        .output()
        .unwrap();
    assert!(before_hash.status.success());
    let checker = std::process::Command::new(APFSCK)
        .args(["-c", "-u", "-w"])
        .arg(&before_path)
        .output()
        .unwrap();
    std::fs::write(dir.join("before-recovery.checker.stdout"), &checker.stdout).unwrap();
    std::fs::write(dir.join("before-recovery.checker.stderr"), &checker.stderr).unwrap();
    std::fs::write(
        dir.join("before-recovery.command.txt"),
        format!("{APFSCK} -c -u -w {}\n", before_path.display()),
    )
    .unwrap();
    assert!(!checker.status.success());
    let after_hash = std::process::Command::new("sha256sum")
        .arg(&before_path)
        .output()
        .unwrap();
    assert!(after_hash.status.success());
    assert_eq!(before_hash.stdout, after_hash.stdout);
    std::fs::write(
        dir.join("before-recovery.unchanged.sha256"),
        before_hash.stdout,
    )
    .unwrap();
    assert!(ApfsContainer::open(Arc::new(Frozen(image)), limits().read, r).is_err());
    drop(editor);
    *bytes.lock().unwrap() = durable.lock().unwrap().clone();
    control.lock().unwrap().cut_write = None;
    let recovered = ApfsEditor::recover_with_anchor(disk(), &anchor, limits(), r).unwrap();
    assert_eq!(recovered.checkpoint_xid(), 16);
    assert_eq!(fletcher_residues(&bytes.lock().unwrap().blocks[&0]), [0, 0]);
    native_checkpoint(dir, 16, volume, &id, &[0x97; 29], &bytes.lock().unwrap());
    std::fs::write(dir.join("model.json"), "{\"torn_boot_prefix_bytes\":31,\"native_rejected_before_recovery\":true,\"recovered_xid\":16,\"data_bytes\":29,\"data_value\":151,\"original_sparse_bytes\":16397,\"original_resource_bytes\":8}\n").unwrap();
    drop(recovered);
}
const MULTICHUNK_COMPILED_SOURCES: &[(&str, &[u8])] = &[
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
        "src/fs_apfs_edit_tree.rs",
        include_bytes!("../src/fs_apfs_edit_tree.rs"),
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
    (
        "src/fs_apfs_retention.rs",
        include_bytes!("../src/fs_apfs_retention.rs"),
    ),
    (
        "src/fs_apfs_edit_retention.rs",
        include_bytes!("../src/fs_apfs_edit_retention.rs"),
    ),
    (
        "src/fs_apfs_edit_reclaim.rs",
        include_bytes!("../src/fs_apfs_edit_reclaim.rs"),
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
#[test]
#[ignore = "requires PARTMGR_APFS_MULTICHUNK_EVIDENCE and pinned checker/TSK; enabled missing tools fail"]
fn native_framework_multichunk_repeated_operations() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_APFS_MULTICHUNK_EVIDENCE").expect("enabled evidence directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let sources = MULTICHUNK_COMPILED_SOURCES;
    for (name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), *bytes);
        let p = dir.join("compiled-sources").join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let binary = std::env::current_exe().unwrap();
    std::fs::copy(&binary, dir.join("compiled-test-executable")).unwrap();
    let tools = [
        std::fs::read(APFSCK).unwrap(),
        std::fs::read(ICAT).unwrap(),
        std::fs::read(ISTAT).unwrap(),
    ];
    let before = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT, ISTAT])
        .output()
        .unwrap();
    assert!(before.status.success());
    std::fs::write(dir.join("start-binary-tools.sha256"), &before.stdout).unwrap();
    let r = resources();
    let authored_bytes = authored(&r);
    sequence(authored_bytes.clone(), &r, 6, Some(&dir));
    assert_eq!(r.memory.used(), 0);
    let retirement = dir.join("retirement");
    std::fs::create_dir_all(&retirement).unwrap();
    let mut editor = ApfsEditor::open(Disk(authored_bytes.clone()), 1026, limits(), &r).unwrap();
    let plan = editor.plan_checkpoint_retirement(6, &r).unwrap();
    assert_eq!(plan.checkpoints().len(), 5);
    let anchor = editor.recovery_anchor();
    let receipt = editor
        .commit_checkpoint_retirement(plan, &anchor, &r)
        .unwrap();
    assert_eq!(receipt.released_blocks, 0);
    let root = editor.directory_identity(2, &r).unwrap();
    let id = editor
        .directory(&root, &r)
        .unwrap()
        .iter()
        .find(|entry| entry.name == NativeName::Bytes(b"Alias".to_vec()))
        .unwrap()
        .object
        .clone();
    let image = authored_bytes.lock().unwrap();
    let volume_block = *image
        .blocks
        .iter()
        .find(|(_, bytes)| {
            &bytes[32..36] == b"APSB" && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == 7
        })
        .unwrap()
        .0;
    native_checkpoint(&retirement, 7, volume_block, &id, &[0x92; 17], &image);
    drop(image);
    let reclamation = dir.join("reclamation");
    std::fs::create_dir_all(&reclamation).unwrap();
    let mut models = String::from("[\n");
    for operation in 0..4 {
        if operation != 0 {
            let root = editor.directory_identity(2, &r).unwrap();
            let id = editor
                .directory(&root, &r)
                .unwrap()
                .iter()
                .find(|entry| entry.name == NativeName::Bytes(b"Alias".to_vec()))
                .unwrap()
                .object
                .clone();
            let input = Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: operation,
                    native: b"native repeated reclamation payload oracle".to_vec(),
                },
                0x93 + operation as u8,
            ));
            let plan = editor.plan_replace(&id, input, &r).unwrap();
            let volume = plan.planned_volume_block();
            editor.commit_mutation(plan, &anchor, &r).unwrap();
            native_checkpoint(
                &reclamation,
                editor.checkpoint_xid(),
                volume,
                &id,
                &[0x93 + operation as u8; 29],
                &authored_bytes.lock().unwrap(),
            );
            let horizon = editor.checkpoint_xid() - 1;
            let plan = editor.plan_checkpoint_retirement(horizon, &r).unwrap();
            editor
                .commit_checkpoint_retirement(plan, &anchor, &r)
                .unwrap();
        }
        let plan = editor.plan_reclamation(&r).unwrap();
        let main = plan.main_blocks();
        let internal = plan.internal_blocks();
        assert!(main > 0 && internal >= 2);
        let volume = plan.planned_volume_block();
        let receipt = editor.commit_reclamation(plan, &anchor, &r).unwrap();
        assert_eq!(
            (receipt.main_blocks, receipt.internal_blocks),
            (main, internal)
        );
        let root = editor.directory_identity(2, &r).unwrap();
        let id = editor
            .directory(&root, &r)
            .unwrap()
            .iter()
            .find(|entry| entry.name == NativeName::Bytes(b"Alias".to_vec()))
            .unwrap()
            .object
            .clone();
        let payload = if operation == 0 {
            vec![0x92; 17]
        } else {
            vec![0x93 + operation as u8; 29]
        };
        native_checkpoint(
            &reclamation,
            editor.checkpoint_xid(),
            volume,
            &id,
            &payload,
            &authored_bytes.lock().unwrap(),
        );
        models.push_str(&format!(
            "{}{{\"xid\":{},\"main_queue_removed\":{},\"ip_queue_removed\":{}}}",
            if operation == 0 { "" } else { ",\n" },
            editor.checkpoint_xid(),
            main,
            internal
        ));
    }
    models.push_str("\n]\n");
    std::fs::write(reclamation.join("models.json"), models).unwrap();
    assert_eq!(editor.checkpoint_xid(), 14);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    native_reclamation_cold(&dir.join("cold-reclamation"), &authored_bytes, &r);
    assert_eq!(r.memory.used(), 0);
    native_crossing(&dir.join("crossing"), &r);
    let many = dir.join("multileaf");
    std::fs::create_dir_all(&many).unwrap();
    let large_resources = Resources {
        memory: Budget::new(2 * 1024 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    sequence_with_limits(
        authored_files(&large_resources, 301),
        &large_resources,
        6,
        Some(&many),
        multileaf_limits(),
    );
    assert_eq!(large_resources.memory.used(), 0);
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
    assert_eq!(std::fs::read(ISTAT).unwrap(), tools[2]);
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        std::fs::read(dir.join("compiled-test-executable")).unwrap()
    );
    let after = std::process::Command::new("sha256sum")
        .arg(&binary)
        .args([APFSCK, ICAT, ISTAT])
        .output()
        .unwrap();
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    std::fs::write(dir.join("end-binary-tools.sha256"), after.stdout).unwrap();
    std::fs::write(dir.join("receipt.json"),"{\"status\":\"passed\",\"chunks\":5,\"native_ip_blocks\":18,\"initial_transactions\":6,\"retained_history\":true,\"reclamation\":true,\"reclamation_checkpoints\":[8,10,12,14],\"replacement_checkpoints\":[9,11,13],\"retired_descriptors\":5,\"retained_xids_after_retirement\":[6,7],\"descriptor_retirement_released_blocks\":0,\"checkpoints\":[2,3,4,5,6,7]}\n").unwrap();
}

struct WideInput {
    identity: ObjectId,
    length: u64,
    zero: bool,
}
impl FileRead for WideInput {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = (self.length.saturating_sub(at))
            .min(out.len() as u64)
            .min(509) as usize;
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = if self.zero {
                0
            } else {
                ((at + i as u64) * 29 % 251 + 1) as u8
            };
        }
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
            length: self.length,
            kind: ExtentKind::Data,
        })
    }
}
#[test]
fn zero_bitmap_chunk_crossing_copies_only_affected_chunks_and_coalesces_native_refs() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(sparse(&independent::crossing_seed())));
    let original = bytes.lock().unwrap().clone();
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let source = Arc::new(WideInput {
        identity: ObjectId {
            source: 999,
            generation: 0,
            native: b"independent wide source".to_vec(),
        },
        length: 8 * 1024 * 1024,
        zero: false,
    });
    let plan = editor.plan_replace(&id, source, &r).unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_mutation(plan, &anchor, &r).unwrap();
    let mut boot = [0; 4096];
    read(&bytes.lock().unwrap(), 0, &mut boot).unwrap();
    let base = u64::from_le_bytes(boot[120..128].try_into().unwrap());
    let index = u32::from_le_bytes(boot[144..148].try_into().unwrap()) as u64;
    let mut sm = [0; 4096];
    read(&bytes.lock().unwrap(), (base + index + 1) * 4096, &mut sm).unwrap();
    let cib_at = u64::from_le_bytes(sm[384..392].try_into().unwrap());
    let mut cib = [0; 4096];
    read(&bytes.lock().unwrap(), cib_at * 4096, &mut cib).unwrap();
    assert_eq!(u64::from_le_bytes(cib[40..48].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(cib[72..80].try_into().unwrap()), 2);
    assert_eq!(
        &cib[104..200],
        &original.blocks[&401][104..200],
        "untouched three chunk records must be exact"
    );
    assert_eq!(
        u64::from_le_bytes(sm[200..208].try_into().unwrap()),
        2,
        "zero-map has no old bitmap to retire"
    );
    assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), 2);
    let fresh = editor.file_identity(16, &r).unwrap();
    for offset in [0, 4091, 4 * 1024 * 1024, 8 * 1024 * 1024 - 129] {
        let mut out = [0; 129];
        assert_eq!(
            editor.read_file_at(&fresh, offset, &mut out, &r).unwrap(),
            out.len()
        );
        for (i, b) in out.iter().enumerate() {
            assert_eq!(*b, ((offset + i as u64) * 29 % 251 + 1) as u8);
        }
    }
    let bulk = editor.file_identity(47, &r).unwrap();
    let mut zero = [0; 31];
    assert_eq!(
        editor
            .read_file_at(&bulk, (32768 - 2000) * 4096 - 31, &mut zero, &r)
            .unwrap(),
        31
    );
    assert_eq!(zero, [0; 31]);
    for (block, b) in &original.blocks {
        if *block != 0 {
            assert_eq!(
                bytes.lock().unwrap().blocks.get(block),
                Some(b),
                "old metadata retained"
            );
        }
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[derive(Clone)]
struct CutControl {
    write_durable: bool,
    failed_flush_durable: bool,
    cut_write: Option<usize>,
    cut_flush: Option<usize>,
    writes: usize,
    flushes: usize,
    trace: Vec<(u64, usize)>,
}
struct CutDisk {
    live: Arc<Mutex<Sparse>>,
    durable: Arc<Mutex<Sparse>>,
    control: Arc<Mutex<CutControl>>,
}
impl Storage for CutDisk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.live.lock().unwrap().length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        read(&self.live.lock().unwrap(), at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let mut c = self.control.lock().unwrap();
        let cut = c.cut_write == Some(c.writes);
        c.writes += 1;
        c.trace.push((at, input.len()));
        let data = if cut {
            &input[..input.len().min(31)]
        } else {
            input
        };
        let n = Disk(self.live.clone()).write_at(at, data)?;
        if c.write_durable {
            Disk(self.durable.clone()).write_at(at, data)?;
        }
        if cut {
            return Err(io::Error::other("modeled torn native publication"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut c = self.control.lock().unwrap();
        let cut = c.cut_flush == Some(c.flushes);
        c.flushes += 1;
        if !cut || c.failed_flush_durable {
            *self.durable.lock().unwrap() = self.live.lock().unwrap().clone();
        }
        if cut {
            return Err(io::Error::other("modeled native barrier failure"));
        }
        Ok(())
    }
}
fn warm_two(r: &Resources) -> Sparse {
    let bytes = Arc::new(Mutex::new(sparse(&independent::seed())));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), r).unwrap();
    for generation in 0..2 {
        let id = editor.file_identity(16, r).unwrap();
        let plan = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation,
                        native: b"warm".to_vec(),
                    },
                    0x91 + generation as u8,
                )),
                r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(plan, &anchor, r).unwrap();
    }
    drop(editor);
    bytes.lock().unwrap().clone()
}
fn third_cut(
    initial: &Sparse,
    write: Option<usize>,
    flush: Option<usize>,
    write_durable: bool,
    failed_flush_durable: bool,
    crossing: bool,
    r: &Resources,
) -> Vec<(u64, usize)> {
    let live = Arc::new(Mutex::new(initial.clone()));
    let durable = Arc::new(Mutex::new(initial.clone()));
    let control = Arc::new(Mutex::new(CutControl {
        write_durable,
        failed_flush_durable,
        cut_write: write,
        cut_flush: flush,
        writes: 0,
        flushes: 0,
        trace: vec![],
    }));
    let disk = || CutDisk {
        live: live.clone(),
        durable: durable.clone(),
        control: control.clone(),
    };
    let mut editor = ApfsEditor::open(disk(), 1026, limits(), r).unwrap();
    let id = editor.file_identity(16, r).unwrap();
    let old_xid = editor.checkpoint_xid();
    let plan = if crossing {
        editor.plan_replace(
            &id,
            Arc::new(WideInput {
                identity: ObjectId {
                    source: 999,
                    generation: 3,
                    native: b"crossing cut input".to_vec(),
                },
                length: 8 * 1024 * 1024,
                zero: false,
            }),
            r,
        )
    } else {
        editor.plan_range(
            &id,
            4091,
            Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: 3,
                    native: b"cut source".to_vec(),
                },
                0xd3,
            )),
            r,
        )
    }
    .unwrap();
    let anchor = editor.recovery_anchor();
    let result = editor.commit_range(plan, &anchor, r);
    if write.is_some() || flush.is_some() {
        assert!(
            result.is_err(),
            "cut {write:?}/{flush:?} write_durable={write_durable} failed_flush_durable={failed_flush_durable}"
        );
        assert!(editor.file_identity(16, r).is_err());
    } else {
        result.unwrap();
    }
    let commit_trace = control.lock().unwrap().trace.clone();
    drop(editor);
    *live.lock().unwrap() = durable.lock().unwrap().clone();
    {
        let mut c = control.lock().unwrap();
        c.cut_write = None;
        c.cut_flush = None;
    }
    let recovered = ApfsEditor::recover_with_anchor(disk(), &anchor, limits(), r).unwrap();
    let xid = recovered.checkpoint_xid();
    assert!(xid == old_xid || xid == old_xid + 1);
    let id = recovered.file_identity(16, r).unwrap();
    let mut payload = [0; 29];
    assert_eq!(
        recovered.read_file_at(&id, 4091, &mut payload, r).unwrap(),
        29
    );
    let expected = if crossing && xid != old_xid {
        std::array::from_fn(|i| ((4091 + i as u64) * 29 % 251 + 1) as u8)
    } else {
        [if xid == old_xid { 0x92 } else { 0xd3 }; 29]
    };
    assert_eq!(payload, expected);
    let s = live.lock().unwrap();
    let boot = &s.blocks[&0];
    let base = u64::from_le_bytes(boot[120..128].try_into().unwrap());
    let index = u32::from_le_bytes(boot[144..148].try_into().unwrap()) as u64;
    let sm = &s.blocks[&(base + index + 1)];
    assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(sm[256..264].try_into().unwrap()), 2);
    assert_eq!(
        u64::from_le_bytes(sm[200..208].try_into().unwrap()),
        2 * (xid - 1)
    );
    drop(s);
    drop(recovered);
    for (&block, old) in &initial.blocks {
        if block != 0 {
            assert_eq!(live.lock().unwrap().blocks.get(&block), Some(old));
        }
    }
    commit_trace
}
#[test]
fn third_transaction_torn_publication_and_all_barriers_recover_four_persistence_models() {
    let r = resources();
    let initial = warm_two(&r);
    assert_eq!(r.memory.used(), 0);
    let trace = third_cut(&initial, None, None, true, true, false, &r);
    assert_eq!(r.memory.used(), 0);
    for write_durable in [false, true] {
        for failed_flush_durable in [false, true] {
            for barrier in 0..5 {
                third_cut(
                    &initial,
                    None,
                    Some(barrier),
                    write_durable,
                    failed_flush_durable,
                    false,
                    &r,
                );
                assert_eq!(r.memory.used(), 0);
            }
            for at in [0, 2, trace.len() - 3, trace.len() - 2, trace.len() - 1] {
                third_cut(
                    &initial,
                    Some(at),
                    None,
                    write_durable,
                    failed_flush_durable,
                    false,
                    &r,
                );
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn authorized_checkpoint_retirement_cuts_preserve_current_payload_and_all_allocations() {
    let r = resources();
    let initial = warm_two(&r);
    for write_durable in [false, true] {
        for failed_flush_durable in [false, true] {
            for cut_write in [true, false] {
                let live = Arc::new(Mutex::new(initial.clone()));
                let durable = Arc::new(Mutex::new(initial.clone()));
                let control = Arc::new(Mutex::new(CutControl {
                    write_durable,
                    failed_flush_durable,
                    cut_write: cut_write.then_some(0),
                    cut_flush: (!cut_write).then_some(0),
                    writes: 0,
                    flushes: 0,
                    trace: vec![],
                }));
                let disk = || CutDisk {
                    live: live.clone(),
                    durable: durable.clone(),
                    control: control.clone(),
                };
                let mut editor = ApfsEditor::open(disk(), 1026, limits(), &r).unwrap();
                let plan = editor.plan_checkpoint_retirement(2, &r).unwrap();
                let addresses = plan.checkpoints().to_vec();
                assert_eq!(addresses.len(), 1);
                let anchor = editor.recovery_anchor();
                assert!(
                    editor
                        .commit_checkpoint_retirement(plan, &anchor, &r)
                        .is_err()
                );
                assert_eq!(
                    editor.revalidate(&r).unwrap_err().kind,
                    ErrorKind::InterruptedWrite
                );
                drop(editor);
                *live.lock().unwrap() = durable.lock().unwrap().clone();
                {
                    let mut c = control.lock().unwrap();
                    c.cut_write = None;
                    c.cut_flush = None;
                }
                let recovered =
                    ApfsEditor::recover_with_anchor(disk(), &anchor, limits(), &r).unwrap();
                assert_eq!(recovered.checkpoint_xid(), 3);
                let id = recovered.file_identity(16, &r).unwrap();
                let mut patch = [0; 29];
                assert_eq!(
                    recovered.read_file_at(&id, 4091, &mut patch, &r).unwrap(),
                    29
                );
                assert_eq!(patch, [0x92; 29]);
                for (block, bytes) in &initial.blocks {
                    if !addresses.iter().any(|(at, _)| at == block) {
                        assert_eq!(
                            live.lock().unwrap().blocks.get(block),
                            Some(bytes),
                            "retirement cut changed block {block}"
                        );
                    }
                }
                drop(recovered);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn repeated_reclamation_reuses_native_retirements_beyond_previous_pool_capacity() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(warm_two(&r)));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    for generation in 0..12 {
        let id = editor.file_identity(16, &r).unwrap();
        let value = 0xa0 + generation as u8;
        let range = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation,
                        native: b"bounded repeating reclamation model".to_vec(),
                    },
                    value,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(range, &anchor, &r).unwrap();
        let horizon = editor.checkpoint_xid() - 1;
        let retirement = editor.plan_checkpoint_retirement(horizon, &r).unwrap();
        editor
            .commit_checkpoint_retirement(retirement, &anchor, &r)
            .unwrap();
        let reclaim = editor.plan_reclamation(&r).unwrap();
        assert!(reclaim.internal_blocks() >= 2);
        assert!(reclaim.main_blocks() >= 1);
        let counts = (reclaim.main_blocks(), reclaim.internal_blocks());
        let receipt = editor.commit_reclamation(reclaim, &anchor, &r).unwrap();
        assert_eq!((receipt.main_blocks, receipt.internal_blocks), counts);
        assert_eq!(editor.checkpoint_xid(), 5 + 2 * generation);
        let id = editor.file_identity(16, &r).unwrap();
        let mut actual = vec![0; 16397];
        assert_eq!(
            editor.read_file_at(&id, 0, &mut actual, &r).unwrap(),
            actual.len()
        );
        let mut expected: Vec<_> = (0..16397)
            .map(|i| {
                if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                    0
                } else {
                    ((i % 4096) * 17 % 251) as u8
                }
            })
            .collect();
        expected[4091..4120].fill(value);
        assert_eq!(actual, expected);
    }
    assert_eq!(editor.checkpoint_xid(), 27);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

fn reclaimable(r: &Resources) -> Sparse {
    let bytes = Arc::new(Mutex::new(warm_two(r)));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), r).unwrap();
    let id = editor.file_identity(16, r).unwrap();
    let range = editor
        .plan_range(
            &id,
            4091,
            Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: 3,
                    native: b"independent reclaimable history".to_vec(),
                },
                0x93,
            )),
            r,
        )
        .unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_range(range, &anchor, r).unwrap();
    let retirement = editor.plan_checkpoint_retirement(3, r).unwrap();
    editor
        .commit_checkpoint_retirement(retirement, &anchor, r)
        .unwrap();
    drop(editor);
    bytes.lock().unwrap().clone()
}

fn retained_payload_oracles(image: &Sparse, r: &Resources) {
    let highest = u64::from_le_bytes(image.blocks[&0][16..24].try_into().unwrap());
    for xid in 3..=highest {
        let header = image
            .blocks
            .iter()
            .find(|(block, bytes)| {
                **block != 0
                    && &bytes[32..36] == b"NXSB"
                    && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == xid
            })
            .unwrap()
            .1
            .clone();
        let mut model = image.clone();
        for (block, bytes) in &mut model.blocks {
            if *block != 0
                && &bytes[32..36] == b"NXSB"
                && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) > xid
            {
                bytes.fill(0);
            }
        }
        model.blocks.insert(0, header);
        let container = ApfsContainer::open(Arc::new(Frozen(model)), limits().read, r).unwrap();
        assert_eq!(container.checkpoint().xid, xid);
        let volume = ApfsVolume::open(container, 1026, r).unwrap();
        let id = volume
            .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], r)
            .unwrap();
        let file = volume.open_file(&id, r).unwrap();
        let mut payload = vec![0; 16397];
        assert_eq!(file.read_at(0, &mut payload, r).unwrap(), payload.len());
        let mut expected: Vec<_> = (0..16397)
            .map(|i| {
                if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                    0
                } else {
                    ((i % 4096) * 17 % 251) as u8
                }
            })
            .collect();
        expected[4091..4120].fill(if xid == 3 { 0x92 } else { 0x93 });
        assert_eq!(payload, expected, "retained checkpoint {xid} payload");
        let resource = volume
            .open_stream(&id, &StreamKind::ResourceFork, r)
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(resource.read_at(0, &mut bytes, r).unwrap(), 8);
        assert_eq!(&bytes, b"resource");
    }
}

fn reclaim_cut(
    initial: &Sparse,
    write: Option<usize>,
    flush: Option<usize>,
    write_durable: bool,
    failed_flush_durable: bool,
    r: &Resources,
) -> Vec<(u64, usize)> {
    let live = Arc::new(Mutex::new(initial.clone()));
    let durable = Arc::new(Mutex::new(initial.clone()));
    let control = Arc::new(Mutex::new(CutControl {
        write_durable,
        failed_flush_durable,
        cut_write: write,
        cut_flush: flush,
        writes: 0,
        flushes: 0,
        trace: vec![],
    }));
    let disk = || CutDisk {
        live: live.clone(),
        durable: durable.clone(),
        control: control.clone(),
    };
    let mut editor = ApfsEditor::open(disk(), 1026, limits(), r).unwrap();
    let plan = editor.plan_reclamation(r).unwrap();
    assert!(plan.main_blocks() > 0 && plan.internal_blocks() >= 2);
    let anchor = editor.recovery_anchor();
    let result = editor.commit_reclamation(plan, &anchor, r);
    if write.is_some() || flush.is_some() {
        assert!(result.is_err());
        assert_eq!(
            editor.revalidate(r).unwrap_err().kind,
            ErrorKind::InterruptedWrite
        );
    } else {
        assert!(result.is_ok());
    }
    let trace = control.lock().unwrap().trace.clone();
    drop(editor);
    *live.lock().unwrap() = durable.lock().unwrap().clone();
    {
        let mut c = control.lock().unwrap();
        c.cut_write = None;
        c.cut_flush = None;
    }
    let recovered = ApfsEditor::recover_with_anchor(disk(), &anchor, limits(), r).unwrap();
    let xid = recovered.checkpoint_xid();
    assert!(xid == 4 || xid == 5);
    let image = live.lock().unwrap().clone();
    let boot = &image.blocks[&0];
    let base = u64::from_le_bytes(boot[120..128].try_into().unwrap());
    let index = u32::from_le_bytes(boot[144..148].try_into().unwrap()) as u64;
    let sm = &image.blocks[&(base + index + 1)];
    let oldest = if xid == 4 { 2u64 } else { 3u64 };
    assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), oldest);
    assert_eq!(u64::from_le_bytes(sm[256..264].try_into().unwrap()), oldest);
    drop(recovered);
    assert_eq!(r.memory.used(), 0);
    retained_payload_oracles(&image, r);
    assert_eq!(r.memory.used(), 0);
    trace
}

#[test]
fn native_reclamation_all_positional_torn_writes_and_barriers_recover_four_models() {
    let r = resources();
    let initial = reclaimable(&r);
    assert_eq!(r.memory.used(), 0);
    let trace = reclaim_cut(&initial, None, None, true, true, &r);
    assert_eq!(trace.len(), 18);
    for write_durable in [false, true] {
        for failed_flush_durable in [false, true] {
            for ordinal in 0..trace.len() {
                reclaim_cut(
                    &initial,
                    Some(ordinal),
                    None,
                    write_durable,
                    failed_flush_durable,
                    &r,
                );
            }
            for barrier in 0..5 {
                reclaim_cut(
                    &initial,
                    None,
                    Some(barrier),
                    write_durable,
                    failed_flush_durable,
                    &r,
                );
            }
        }
    }
}

#[test]
fn reclamation_requires_explicit_retirement_and_refuses_cap_cancel_foreign_and_stale_before_writes()
{
    let r = resources();
    let unpruned = Arc::new(Mutex::new(warm_two(&r)));
    let editor = ApfsEditor::open(Disk(unpruned.clone()), 1026, limits(), &r).unwrap();
    let writes = unpruned.lock().unwrap().writes;
    assert_eq!(
        editor.plan_reclamation(&r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(unpruned.lock().unwrap().writes, writes);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let initial = reclaimable(&r);
    let low = Resources {
        memory: Budget::new(128 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let bytes = Arc::new(Mutex::new(initial.clone()));
    let editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &low).unwrap();
    let baseline = low.memory.used();
    assert_eq!(
        editor.plan_reclamation(&low).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), baseline);
    assert_eq!(bytes.lock().unwrap().writes, initial.writes);
    drop(editor);
    assert_eq!(low.memory.used(), 0);
    for failure in 0..4 {
        let owner_resources = resources();
        let bytes = Arc::new(Mutex::new(initial.clone()));
        let mut editor =
            ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &owner_resources).unwrap();
        let plan = editor.plan_reclamation(&owner_resources).unwrap();
        let anchor = editor.recovery_anchor();
        let error = match failure {
            0 => {
                owner_resources.cancellation.cancel();
                editor.commit_reclamation(plan, &anchor, &r).unwrap_err()
            }
            1 => {
                bytes.lock().unwrap().length -= 4096;
                editor
                    .commit_reclamation(plan, &anchor, &owner_resources)
                    .unwrap_err()
            }
            2 => {
                bytes.lock().unwrap().blocks.get_mut(&0).unwrap()[104] ^= 1;
                editor
                    .commit_reclamation(plan, &anchor, &owner_resources)
                    .unwrap_err()
            }
            _ => {
                let mut foreign =
                    ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &owner_resources)
                        .unwrap();
                let error = foreign
                    .commit_reclamation(plan, &anchor, &owner_resources)
                    .unwrap_err();
                drop(foreign);
                error
            }
        };
        assert_eq!(
            error.kind,
            if failure == 0 {
                ErrorKind::Cancelled
            } else {
                ErrorKind::StalePlan
            }
        );
        assert_eq!(bytes.lock().unwrap().writes, initial.writes);
        drop(editor);
        assert_eq!(owner_resources.memory.used(), 0);
    }
    assert_eq!(r.memory.used(), 0);
}

fn native_crossing(dir: &std::path::Path, r: &Resources) {
    use std::io::Read;
    use std::os::unix::fs::FileExt;
    std::fs::create_dir_all(dir).unwrap();
    let bytes = authored(r);
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), r).unwrap();
    let root = editor.directory_identity(2, r).unwrap();
    let metadata = ApfsCreateMetadata {
        permissions: 0o640,
        uid: 42,
        gid: 43,
        timestamp: 123456789,
    };
    let bulk_length = (32768 - 2000) * 4096;
    let bulk_source = Arc::new(WideInput {
        identity: ObjectId {
            source: 999,
            generation: 0,
            native: b"native zero bulk".to_vec(),
        },
        length: bulk_length,
        zero: true,
    });
    let plan = editor
        .plan_create(&root, b"Bulk", bulk_source, metadata, r)
        .unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_mutation(plan, &anchor, r).unwrap();
    let id = editor.file_identity(16, r).unwrap();
    let source = Arc::new(WideInput {
        identity: ObjectId {
            source: 999,
            generation: 1,
            native: b"native crossing input".to_vec(),
        },
        length: 8 * 1024 * 1024,
        zero: false,
    });
    let plan = editor.plan_replace(&id, source, r).unwrap();
    let volume = plan.planned_volume_block();
    let anchor = editor.recovery_anchor();
    editor.commit_mutation(plan, &anchor, r).unwrap();
    let s = bytes.lock().unwrap();
    let boot = &s.blocks[&0];
    let base = u64::from_le_bytes(boot[120..128].try_into().unwrap());
    let index = u32::from_le_bytes(boot[144..148].try_into().unwrap()) as u64;
    let sm = &s.blocks[&(base + index + 1)];
    let cib = &s.blocks[&u64::from_le_bytes(sm[384..392].try_into().unwrap())];
    assert_eq!(u64::from_le_bytes(cib[40..48].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(cib[72..80].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(sm[200..208].try_into().unwrap()), 5);
    assert_eq!(u64::from_le_bytes(sm[216..224].try_into().unwrap()), 2);
    let image = dir.join("two-chunk.apfs");
    let file = std::fs::File::create(&image).unwrap();
    file.set_len(s.length).unwrap();
    for (&block, b) in &s.blocks {
        file.write_all_at(b, block * 4096).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    drop(s);
    let before = std::process::Command::new("sha256sum")
        .arg(&image)
        .output()
        .unwrap();
    assert!(before.status.success());
    let checker = std::process::Command::new(APFSCK)
        .args(["-c", "-u", "-w"])
        .arg(&image)
        .output()
        .unwrap();
    std::fs::write(dir.join("checker.stdout"), &checker.stdout).unwrap();
    std::fs::write(dir.join("checker.stderr"), &checker.stderr).unwrap();
    assert!(checker.status.success(), "crossing checker {checker:?}");
    assert!(checker.stdout.is_empty() && checker.stderr.is_empty());
    let mut args = vec![
        "-P".to_owned(),
        "apfs".to_owned(),
        "-B".to_owned(),
        volume.to_string(),
        "-f".to_owned(),
        "apfs".to_owned(),
        image.display().to_string(),
        "16".to_owned(),
    ];
    let extracted = std::process::Command::new(ICAT)
        .args(&args)
        .output()
        .unwrap();
    assert!(extracted.status.success());
    let expected: Vec<u8> = (0..8 * 1024 * 1024u64)
        .map(|p| (p * 29 % 251 + 1) as u8)
        .collect();
    assert_eq!(extracted.stdout, expected);
    std::fs::write(dir.join("data.stdout"), &extracted.stdout).unwrap();
    std::fs::write(dir.join("data.expected"), &expected).unwrap();
    std::fs::write(dir.join("data.stderr"), extracted.stderr).unwrap();
    let inode = std::process::Command::new(ISTAT)
        .args(&args)
        .output()
        .unwrap();
    assert!(inode.status.success());
    let text = String::from_utf8_lossy(&inode.stdout);
    assert!(
        text.contains("Aé-file")
            && text.contains("Number of Links: 2")
            && text.contains("owner / group: 0 / 0")
    );
    std::fs::write(dir.join("inode.stdout"), &inode.stdout).unwrap();
    *args.last_mut().unwrap() = "16-4353-1".to_owned();
    let fork = std::process::Command::new(ICAT)
        .args(&args)
        .output()
        .unwrap();
    assert!(fork.status.success());
    assert_eq!(fork.stdout, b"resource");
    std::fs::write(dir.join("resource.stdout"), fork.stdout).unwrap();
    std::fs::write(dir.join("resource.expected"), b"resource").unwrap();
    let root = editor.directory_identity(2, r).unwrap();
    let entries = editor.directory(&root, r).unwrap();
    let bulk = &entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"Bulk".to_vec()))
        .unwrap()
        .object;
    let bulk_id = u64::from_be_bytes(bulk.native.as_slice().try_into().unwrap());
    *args.last_mut().unwrap() = bulk_id.to_string();
    let bulk_path = dir.join("bulk.stdout");
    let output = std::process::Command::new(ICAT)
        .args(&args)
        .stdout(std::fs::File::create(&bulk_path).unwrap())
        .output()
        .unwrap();
    assert!(output.status.success());
    std::fs::write(dir.join("bulk.stderr"), output.stderr).unwrap();
    let mut bulk_file = std::fs::File::open(&bulk_path).unwrap();
    let mut buffer = [0; 65536];
    let mut count = 0u64;
    loop {
        let n = bulk_file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        assert!(buffer[..n].iter().all(|b| *b == 0));
        count += n as u64;
    }
    assert_eq!(count, bulk_length);
    let after = std::process::Command::new("sha256sum")
        .arg(&image)
        .output()
        .unwrap();
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    std::fs::write(dir.join("unchanged.sha256"), after.stdout).unwrap();
    std::fs::write(dir.join("commands.txt"),format!("{APFSCK} -c -u -w {}\n{ICAT} -P apfs -B {volume} -f apfs {} 16\n{ISTAT} -P apfs -B {volume} -f apfs {} 16\n{ICAT} -P apfs -B {volume} -f apfs {} 16-4353-1\n{ICAT} {}\n",image.display(),image.display(),image.display(),image.display(),args.join(" "))).unwrap();
    std::fs::write(dir.join("model.json"),format!("{{\"xid\":3,\"touched_chunks\":[0,1],\"unchanged_chunks\":[2,3,4],\"data_bytes\":8388608,\"model\":\"(position*29%251)+1\",\"bulk_inode\":{bulk_id},\"bulk_zero_bytes\":{bulk_length},\"retirement_blocks\":5,\"oldest_retirement_xid\":2}}\n")).unwrap();
    drop(entries);
    drop(editor);
}

#[test]
fn multichunk_malformed_counts_ranges_and_bitmap_summaries_are_prewrite() {
    for mutation in 0..5 {
        let r = resources();
        let mut raw = independent::seed();
        match mutation {
            0 => {
                fixture::p64(&mut raw, 129 * 4096 + 56, u64::MAX);
                fixture::seal(&mut raw[129 * 4096..130 * 4096]);
            }
            1 => {
                fixture::p64(&mut raw, 401 * 4096 + 80, 32769);
                fixture::seal(&mut raw[401 * 4096..402 * 4096]);
            }
            2 => {
                fixture::p64(&mut raw, 401 * 4096 + 64, 999);
                fixture::seal(&mut raw[401 * 4096..402 * 4096]);
            }
            3 => {
                let at = 401 * 4096 + 60;
                let n = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
                fixture::p32(&mut raw, at, n + 1);
                fixture::seal(&mut raw[401 * 4096..402 * 4096]);
            }
            _ => {
                fixture::p64(&mut raw, 129 * 4096 + 216, 2);
                fixture::seal(&mut raw[129 * 4096..130 * 4096]);
            }
        }
        let state = Arc::new(Mutex::new(sparse(&raw)));
        assert!(ApfsEditor::open(Disk(state.clone()), 1026, limits(), &r).is_err());
        assert_eq!(state.lock().unwrap().writes, 0);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn multichunk_work_memory_cancellation_stale_bindings_and_length_are_prewrite() {
    let raw = independent::seed();
    for control in 0..5 {
        let r = if control == 0 {
            Resources {
                memory: Budget::new(128 * 1024 * 1024),
                cancellation: Cancellation::default(),
            }
        } else {
            resources()
        };
        let state = Arc::new(Mutex::new(sparse(&raw)));
        let mut bound = limits();
        if control == 1 {
            bound.work = 1;
        }
        let opened = ApfsEditor::open(Disk(state.clone()), 1026, bound, &r);
        if control == 1 {
            assert_eq!(opened.err().unwrap().kind, ErrorKind::BudgetExhausted);
        } else {
            let editor = opened.unwrap();
            let id = editor.file_identity(16, &r).unwrap();
            if control == 2 {
                r.cancellation.cancel();
            }
            if control == 3 {
                state.lock().unwrap().length -= 4096;
            }
            if control == 4 {
                state.lock().unwrap().blocks.get_mut(&19).unwrap()[304] ^= 1;
            }
            let result = editor.plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation: 0,
                        native: b"bounded".to_vec(),
                    },
                    0x91,
                )),
                &r,
            );
            assert!(result.is_err());
            let kind = result.err().unwrap().kind;
            assert_eq!(
                kind,
                match control {
                    0 => ErrorKind::BudgetExhausted,
                    2 => ErrorKind::Cancelled,
                    _ => ErrorKind::StalePlan,
                }
            );
            drop(editor);
        }
        assert_eq!(state.lock().unwrap().writes, 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn two_changed_bitmaps_cib_and_terminal_publication_cuts_cold_recover_four_models() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(sparse(&independent::crossing_seed())));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    for generation in 0..2 {
        let id = editor.file_identity(16, &r).unwrap();
        let plan = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 999,
                        generation,
                        native: b"warm crossing".to_vec(),
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
    let initial = bytes.lock().unwrap().clone();
    assert_eq!(r.memory.used(), 0);
    let trace = third_cut(&initial, None, None, true, true, true, &r);
    assert_eq!(r.memory.used(), 0);
    let n = trace.len();
    for write_durable in [false, true] {
        for failed_flush_durable in [false, true] {
            // Fullpayload has2048writes, followed by8roots and two changed bitmaps/CIB.
            for at in [2048 + 8, 2048 + 9, 2048 + 10, n - 3, n - 2, n - 1] {
                third_cut(
                    &initial,
                    Some(at),
                    None,
                    write_durable,
                    failed_flush_durable,
                    true,
                    &r,
                );
                assert_eq!(r.memory.used(), 0);
            }
            for barrier in [1, 3, 4] {
                third_cut(
                    &initial,
                    None,
                    Some(barrier),
                    write_durable,
                    failed_flush_durable,
                    true,
                    &r,
                );
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn multileaf_native_catalog_mutation_preserves_unaffected_names_streams_and_history() {
    let r = Resources {
        memory: Budget::new(2 * 1024 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let bytes = authored_files(&r, 1501);
    let l = multileaf_limits();
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, l, &r).unwrap();
    let anchor = editor.recovery_anchor();
    let root = editor.directory_identity(2, &r).unwrap();
    let before = editor.directory(&root, &r).unwrap();
    assert!(before.len() > 1500);
    let target = before
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"File-0004".to_vec()))
        .unwrap()
        .object
        .clone();
    let original_names: Vec<_> = before.iter().map(|e| e.name.clone()).collect();
    drop(before);
    let input = Arc::new(Input(
        ObjectId {
            source: 999,
            generation: 0,
            native: b"many-leaf-input".to_vec(),
        },
        0x9b,
    ));
    let plan = editor.plan_replace(&target, input, &r).unwrap();
    let receipt = editor.commit_mutation(plan, &anchor, &r).unwrap();
    assert_eq!(receipt.xid, 2);
    let root = editor.directory_identity(2, &r).unwrap();
    let after = editor.directory(&root, &r).unwrap();
    assert_eq!(
        after.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
        original_names
    );
    let target = after
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"File-0004".to_vec()))
        .unwrap()
        .object
        .clone();
    let mut payload = vec![0; 29];
    assert_eq!(
        editor.read_file_at(&target, 0, &mut payload, &r).unwrap(),
        29
    );
    assert_eq!(payload, vec![0x9b; 29]);
    drop(after);
    let rename = editor
        .plan_rename(&root, b"File-0004", &root, "Changed-é".as_bytes(), &r)
        .unwrap();
    editor.commit_mutation(rename, &anchor, &r).unwrap();
    let root = editor.directory_identity(2, &r).unwrap();
    let after = editor.directory(&root, &r).unwrap();
    assert!(
        !after
            .iter()
            .any(|e| e.name == NativeName::Bytes(b"File-0004".to_vec()))
    );
    assert!(
        after
            .iter()
            .any(|e| e.name == NativeName::Bytes("Changed-é".as_bytes().to_vec()))
    );
    drop(after);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let c =
        ApfsContainer::open(Arc::new(Frozen(bytes.lock().unwrap().clone())), l.read, &r).unwrap();
    let v = ApfsVolume::open(c, 1026, &r).unwrap();
    let proof = audit_apfs(&v, l.audit, &r).unwrap();
    assert!(
        proof.is_complete() && proof.is_clean(),
        "{:?}",
        proof.findings()
    );
    drop((proof, v));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn independently_split_native_catalog_reopens_mutates_and_rejects_dangling_child_before_write() {
    let r = resources();
    let raw = independent::indexed_seed();
    let bytes = Arc::new(Mutex::new(sparse(&raw)));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let input = Arc::new(Input(
        ObjectId {
            source: 999,
            generation: 0,
            native: b"raw-index-input".to_vec(),
        },
        0xac,
    ));
    let plan = editor.plan_range(&id, 4091, input, &r).unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_range(plan, &anchor, &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let mut data = [0; 29];
    assert_eq!(editor.read_file_at(&id, 4091, &mut data, &r).unwrap(), 29);
    assert_eq!(data, [0xac; 29]);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let mut bad = raw;
    // Rechecksum a root pointer to an absent virtual mapping: structural error, not checksum failure.
    fixture::p64(&mut bad, 23 * 4096 - 48, 1102);
    fixture::seal(&mut bad[22 * 4096..23 * 4096]);
    let bytes = Arc::new(Mutex::new(sparse(&bad)));
    assert!(ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).is_err());
    assert_eq!(bytes.lock().unwrap().writes, 0);
    assert_eq!(r.memory.used(), 0);
}

fn multileaf_cut(
    initial: &Sparse,
    write: Option<usize>,
    flush: Option<usize>,
    wd: bool,
    fd: bool,
    r: &Resources,
) -> Vec<(u64, usize)> {
    let mut l = limits();
    l.read.records = 1024;
    l.audit.objects = 2048;
    let live = Arc::new(Mutex::new(initial.clone()));
    let durable = Arc::new(Mutex::new(initial.clone()));
    let control = Arc::new(Mutex::new(CutControl {
        write_durable: wd,
        failed_flush_durable: fd,
        cut_write: write,
        cut_flush: flush,
        writes: 0,
        flushes: 0,
        trace: vec![],
    }));
    let disk = || CutDisk {
        live: live.clone(),
        durable: durable.clone(),
        control: control.clone(),
    };
    let mut owner = ApfsEditor::open(disk(), 1026, l, r).unwrap();
    let id = owner.file_identity(16, r).unwrap();
    let input = Arc::new(Input(
        ObjectId {
            source: 999,
            generation: 0,
            native: b"leaf-cut".to_vec(),
        },
        0xb7,
    ));
    let plan = owner.plan_range(&id, 4091, input, r).unwrap();
    let anchor = owner.recovery_anchor();
    let result = owner.commit_range(plan, &anchor, r);
    if write.is_some() || flush.is_some() {
        assert!(result.is_err());
        assert!(owner.file_identity(16, r).is_err());
    } else {
        result.unwrap();
    }
    let trace = control.lock().unwrap().trace.clone();
    drop(owner);
    *live.lock().unwrap() = durable.lock().unwrap().clone();
    control.lock().unwrap().cut_write = None;
    control.lock().unwrap().cut_flush = None;
    let owner = ApfsEditor::recover_with_anchor(disk(), &anchor, l, r).unwrap();
    let xid = owner.checkpoint_xid();
    assert!(xid == 1 || xid == 2);
    let id = owner.file_identity(16, r).unwrap();
    let mut bytes = vec![0; 16397];
    assert_eq!(
        owner.read_file_at(&id, 0, &mut bytes, r).unwrap(),
        bytes.len()
    );
    let mut expected: Vec<_> = (0..16397)
        .map(|p| {
            if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                0
            } else {
                (p % 4096 * 17 % 251) as u8
            }
        })
        .collect();
    if xid == 2 {
        expected[4091..4120].fill(0xb7);
    }
    assert_eq!(bytes, expected);
    let root = owner.directory_identity(2, r).unwrap();
    let names = owner.directory(&root, r).unwrap();
    assert_eq!(names.len(), 66);
    drop(names);
    drop(owner);
    for (at, bytes) in &initial.blocks {
        if *at != 0 {
            assert_eq!(
                live.lock().unwrap().blocks.get(at),
                Some(bytes),
                "retained tree page {at}"
            );
        }
    }
    assert_eq!(r.memory.used(), 0);
    trace
}
#[test]
fn multileaf_catalog_all_native_writes_and_barriers_cold_recover_four_models() {
    let r = Resources {
        memory: Budget::new(512 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let initial = authored_files(&r, 65).lock().unwrap().clone();
    let trace = multileaf_cut(&initial, None, None, false, false, &r);
    assert!(trace.len() > 20, "must cover extra native catalog pages");
    for model in 0..4 {
        for write in 0..trace.len() {
            multileaf_cut(
                &initial,
                Some(write),
                None,
                model & 1 != 0,
                model & 2 != 0,
                &r,
            );
        }
        for flush in 0..5 {
            multileaf_cut(
                &initial,
                None,
                Some(flush),
                model & 1 != 0,
                model & 2 != 0,
                &r,
            );
        }
    }
    eprintln!(
        "MULTILEAF_CUTS writes={} barriers=5 models=4 scenarios={}",
        trace.len(),
        4 * (trace.len() + 5)
    );
}

#[test]
fn reclaimed_metadata_can_become_payload_without_seeding_its_old_bytes() {
    let evidence =
        std::env::var_os("PARTMGR_APFS_SEED_REUSE_EVIDENCE").map(std::path::PathBuf::from);
    let executable = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    if let Some(dir) = &evidence {
        assert!(!dir.exists(), "fresh reuse evidence directory required");
        std::fs::create_dir_all(dir).unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            dir.join("compiled-test-executable"),
        )
        .unwrap();
        for &(name, bytes) in MULTICHUNK_COMPILED_SOURCES {
            assert_eq!(std::fs::read(name).unwrap(), bytes);
            let target = dir.join("compiled-sources").join(name);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
    }

    let r = resources();
    let state = authored(&r);
    let mut editor = ApfsEditor::open(Disk(state.clone()), 1026, limits(), &r).unwrap();
    let anchor = editor.recovery_anchor();
    for generation in 0..6 {
        let initial_id = editor.file_identity(16, &r).unwrap();
        let initial = editor
            .plan_range(
                &initial_id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 997,
                        generation,
                        native: b"predecessor for reuse".to_vec(),
                    },
                    0x97,
                )),
                &r,
            )
            .unwrap();
        editor.commit_range(initial, &anchor, &r).unwrap();
    }
    let retirement = editor.plan_checkpoint_retirement(6, &r).unwrap();
    editor
        .commit_checkpoint_retirement(retirement, &anchor, &r)
        .unwrap();
    let reclaim = editor.plan_reclamation(&r).unwrap();
    assert!(reclaim.main_blocks() > 0);
    editor.commit_reclamation(reclaim, &anchor, &r).unwrap();
    let before = state.lock().unwrap().blocks.clone();
    let id = editor.file_identity(16, &r).unwrap();
    let input = Arc::new(WideInput {
        identity: ObjectId {
            source: 998,
            generation: 0,
            native: b"reclaimed metadata payload reuse".to_vec(),
        },
        length: 8 * 1024 * 1024,
        zero: false,
    });
    let plan = editor.plan_replace(&id, input.clone(), &r).unwrap();
    editor.commit_range(plan, &anchor, &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let mut actual = vec![0; input.length as usize];
    assert_eq!(
        editor.read_file_at(&id, 0, &mut actual, &r).unwrap(),
        actual.len()
    );
    let expected: Vec<_> = (0..input.length)
        .map(|p| (p * 29 % 251 + 1) as u8)
        .collect();
    assert_eq!(actual, expected);
    if let Some(dir) = &evidence {
        std::fs::write(dir.join("actual-data.bin"), &actual).unwrap();
        std::fs::write(dir.join("expected-data.bin"), &expected).unwrap();
    }
    let after = state.lock().unwrap();
    assert!(
        before.iter().any(|(at, old)| {
            let native_type = u32::from_le_bytes(old[24..28].try_into().unwrap()) & 0xffff;
            matches!(native_type, 2 | 3)
                && after.blocks.get(at).is_some_and(|new| {
                    new != old
                        && expected
                            .windows(4096)
                            .step_by(4096)
                            .any(|payload| payload == new)
                })
        }),
        "actual payload must overwrite a former B-tree metadata block"
    );
    let retained: Vec<_> = before
        .iter()
        .filter(|(_, bytes)| {
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == 6
                && matches!(
                    u32::from_le_bytes(bytes[24..28].try_into().unwrap()) & 0xffff,
                    2 | 3
                )
        })
        .collect();
    assert!(!retained.is_empty());
    for (at, expected) in retained {
        assert_eq!(
            after.blocks.get(at),
            Some(expected),
            "retained predecessor metadata {at}"
        );
    }
    let frozen = Arc::new(Frozen(after.clone()));
    drop(after);
    let container = ApfsContainer::open(frozen, limits().read, &r).unwrap();
    let volume = ApfsVolume::open(container, 1026, &r).unwrap();
    let proof = audit_apfs(&volume, limits().audit, &r).unwrap();
    assert!(proof.is_complete() && proof.is_clean());
    drop(proof);
    drop(volume);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    if let Some(dir) = &evidence {
        for &(name, bytes) in MULTICHUNK_COMPILED_SOURCES {
            assert_eq!(std::fs::read(name).unwrap(), bytes);
        }
        assert_eq!(
            std::fs::read(std::env::current_exe().unwrap()).unwrap(),
            executable
        );
        std::fs::write(dir.join("receipt.json"), "{\"status\":\"passed\",\"actual_former_metadata_payload_reuse\":true,\"retained_predecessor_xid\":6,\"complete_fresh_audit\":true,\"data_bytes\":8388608,\"refund_bytes\":0}\n").unwrap();
    }
}
