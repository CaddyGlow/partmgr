#![cfg(feature = "std")]

use partmgr::{
    fs_apfs::*, fs_apfs_audit::ApfsAuditLimits, fs_apfs_builder::*, fs_apfs_edit::*, fs_core::*,
    storage::Storage,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "fixtures/apfs_cibs.rs"]
mod cibs;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "fixtures/apfs_multichunk.rs"]
mod independent;
#[allow(dead_code)]
#[path = "fixtures/apfs_build_tree.rs"]
mod tree;
const LENGTH: u64 = cibs::LENGTH;
#[derive(Clone)]
struct Sparse {
    blocks: BTreeMap<u64, Vec<u8>>,
    length: u64,
    writes: usize,
    read_calls: u64,
    read_bytes: u64,
    write_bytes: u64,
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
        let mut state = self.0.lock().unwrap();
        state.read_calls += 1;
        state.read_bytes += out.len() as u64;
        read(&state, at, out)
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
        s.write_bytes += input.len() as u64;
        let mut done = 0;
        while done < input.len() {
            let offset = at + done as u64;
            let n = (4096 - (offset % 4096) as usize).min(input.len() - done);
            let block = offset / 4096;
            if s.blocks.contains_key(&block) || input[done..done + n] != [0; 4096][..n] {
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
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 * 1024 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 256,
        attempts: 257,
        work: 16 * 1024 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: LENGTH / 4096,
            checkpoint_blocks: 128,
            objects: 256,
            records: 256,
            work: 1024 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks: LENGTH / 4096,
            objects: 512,
            depth: 32,
            work: 1024 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn sparse(bytes: &[u8]) -> Sparse {
    Sparse {
        length: LENGTH,
        writes: 0,
        read_calls: 0,
        read_bytes: 0,
        write_bytes: 0,
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

#[test]
fn two_cib_range_publication_preserves_untouched_cib() {
    let started = std::time::Instant::now();
    let r = resources();
    let original = cibs::seed();
    let untouched = original[402 * 4096..403 * 4096].to_vec();
    let bytes = Arc::new(Mutex::new(sparse(&original)));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let plan = editor
        .plan_range(
            &id,
            4091,
            Arc::new(Input(
                ObjectId {
                    source: 999,
                    generation: 0,
                    native: b"two CIB payload".to_vec(),
                },
                0x93,
            )),
            &r,
        )
        .unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_range(plan, &anchor, &r).unwrap();
    assert_eq!(editor.checkpoint_xid(), 2);
    assert_eq!(bytes.lock().unwrap().blocks.get(&402).unwrap(), &untouched);
    {
        let measured = bytes.lock().unwrap();
        println!(
            "charged_work={} target_read_calls={} target_read_bytes={} target_write_calls={} target_write_bytes={} elapsed_ms={}",
            editor.work_used(),
            measured.read_calls,
            measured.read_bytes,
            measured.writes,
            measured.write_bytes,
            started.elapsed().as_millis()
        );
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
struct Wide(ObjectId);
impl FileRead for Wide {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        8 * 1024 * 1024
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = (self.len() - at.min(self.len())).min(out.len() as u64) as usize;
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = ((at + i as u64) % 251) as u8;
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
            length: self.len(),
            kind: ExtentKind::Data,
        })
    }
}
#[test]
fn real_allocated_bulk_forces_payload_and_metadata_across_cib_boundary() {
    let started = std::time::Instant::now();
    let r = resources();
    let original = cibs::crossing_seed();
    let bytes = Arc::new(Mutex::new(sparse(&original)));
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let plan = editor
        .plan_replace(
            &id,
            Arc::new(Wide(ObjectId {
                source: 998,
                generation: 0,
                native: b"physical CIB crossing model".to_vec(),
            })),
            &r,
        )
        .unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_mutation(plan, &anchor, &r).unwrap();
    assert_eq!(editor.checkpoint_xid(), 2);
    let snapshot = bytes.lock().unwrap();
    let mut new_cibs = Vec::new();
    for (&address, block) in &snapshot.blocks {
        if u32::from_le_bytes(block[24..28].try_into().unwrap()) == 0x40000007
            && u64::from_le_bytes(block[16..24].try_into().unwrap()) == 2
        {
            new_cibs.push((address, block));
        }
    }
    assert_eq!(new_cibs.len(), 2);
    for (_, block) in new_cibs {
        let index = u32::from_le_bytes(block[32..36].try_into().unwrap());
        if index == 0 {
            // Untouched full chunks retain their native bitmap, XID and counts.
            assert_eq!(
                &block[72..40 + 126 * 32],
                &original[401 * 4096 + 72..401 * 4096 + 40 + 126 * 32]
            );
        } else {
            assert_eq!(index, 1);
        }
    }
    assert!(snapshot.blocks.contains_key(&(126 * 32768)));
    drop(snapshot);
    {
        let measured = bytes.lock().unwrap();
        println!(
            "charged_work={} target_read_calls={} target_read_bytes={} target_write_calls={} target_write_bytes={} elapsed_ms={}",
            editor.work_used(),
            measured.read_calls,
            measured.read_bytes,
            measured.writes,
            measured.write_bytes,
            started.elapsed().as_millis()
        );
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn two_cib_caps_and_cancellation_fail_before_any_write_and_refund() {
    let original = cibs::seed();
    for cancelled in [false, true] {
        let r = Resources {
            memory: Budget::new(128 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        if cancelled {
            r.cancellation.cancel();
        }
        let bytes = Arc::new(Mutex::new(sparse(&original)));
        assert!(ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).is_err());
        assert_eq!(bytes.lock().unwrap().writes, 0);
        assert_eq!(r.memory.used(), 0);
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
fn authored_files(r: &Resources, files: usize) -> Arc<Mutex<Sparse>> {
    let bytes = Arc::new(Mutex::new(Sparse {
        length: LENGTH,
        blocks: BTreeMap::new(),
        writes: 0,
        read_calls: 0,
        read_bytes: 0,
        write_bytes: 0,
    }));
    let options = ApfsBuildOptions {
        image_bytes: LENGTH,
        container_uuid: [0x61; 16],
        volume_uuid: [0x71; 16],
        volume_label: b"Two CIBs".to_vec(),
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

#[test]
#[ignore = "requires PARTMGR_APFS_CIBS_EVIDENCE and pinned native checker/TSK; missing tools fail"]
fn framework_constructs_two_native_cibs_and_repeated_publications() {
    let evidence = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_APFS_CIBS_EVIDENCE")
            .expect("enabled gate requires evidence directory"),
    );
    assert!(!evidence.exists(), "use a fresh evidence directory");
    std::fs::create_dir_all(&evidence).unwrap();
    let (sources, binary, tools) = native_start(&evidence);
    let started = std::time::Instant::now();
    let r = resources();
    let bytes = authored_files(&r, 3);
    let mut expected = sparse_model();
    native_validate(
        &evidence.join("authored-1"),
        &bytes.lock().unwrap(),
        1,
        &expected,
        false,
    );
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    for generation in 0..3 {
        let id = editor.file_identity(16, &r).unwrap();
        let plan = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 997,
                        generation,
                        native: b"authored two CIBs".to_vec(),
                    },
                    0x94 + generation as u8,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(plan, &anchor, &r).unwrap();
        assert_eq!(editor.checkpoint_xid(), generation + 2);
        expected[4091..4120].fill(0x94 + generation as u8);
        native_validate(
            &evidence.join(format!("authored-{}", generation + 2)),
            &bytes.lock().unwrap(),
            generation + 2,
            &expected,
            false,
        );
    }
    {
        let measured = bytes.lock().unwrap();
        println!(
            "charged_work={} target_read_calls={} target_read_bytes={} target_write_calls={} target_write_bytes={} elapsed_ms={}",
            editor.work_used(),
            measured.read_calls,
            measured.read_bytes,
            measured.writes,
            measured.write_bytes,
            started.elapsed().as_millis()
        );
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let bytes = Arc::new(Mutex::new(sparse(&cibs::crossing_seed())));
    native_validate(
        &evidence.join("boundary-1"),
        &bytes.lock().unwrap(),
        1,
        &sparse_model(),
        true,
    );
    let mut editor = ApfsEditor::open(Disk(bytes.clone()), 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    let plan = editor
        .plan_replace(
            &id,
            Arc::new(Wide(ObjectId {
                source: 996,
                generation: 0,
                native: b"native CIB boundary".to_vec(),
            })),
            &r,
        )
        .unwrap();
    let anchor = editor.recovery_anchor();
    editor.commit_mutation(plan, &anchor, &r).unwrap();
    let expected: Vec<u8> = (0..8 * 1024 * 1024u64).map(|p| (p % 251) as u8).collect();
    native_validate(
        &evidence.join("boundary-2"),
        &bytes.lock().unwrap(),
        2,
        &expected,
        true,
    );
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    native_end(&evidence, &sources, &binary, &tools);
    std::fs::write(evidence.join("receipt.json"), "{\"status\":\"passed\",\"profile\":\"127 chunks/two direct CIBs\",\"native_images\":6,\"macos_kernel\":false}\n").unwrap();
}

const APFSCK: &str = "/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
const ISTAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
type SourceBindings = Vec<(&'static str, &'static [u8])>;
fn native_start(dir: &std::path::Path) -> (SourceBindings, Vec<u8>, [Vec<u8>; 3]) {
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
        (
            "tests/fixtures/apfs_cibs.rs",
            include_bytes!("fixtures/apfs_cibs.rs"),
        ),
        (
            "tests/fs_apfs_edit_cibs.rs",
            include_bytes!("fs_apfs_edit_cibs.rs"),
        ),
    ];

    for &(name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), bytes);
        let path = dir.join("compiled-sources").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(dir.join("compiled-test-executable"), &binary).unwrap();
    let tools = [
        std::fs::read(APFSCK).expect("enabled native checker"),
        std::fs::read(ICAT).expect("enabled TSK icat"),
        std::fs::read(ISTAT).expect("enabled TSK istat"),
    ];
    hash_command(
        dir,
        "start-binary-tools",
        &[
            dir.join("compiled-test-executable").to_str().unwrap(),
            APFSCK,
            ICAT,
            ISTAT,
        ],
    );
    command(dir, "checker-version", APFSCK, &["-V"]); // Informational unsupported probe; actual checks require success.
    command(dir, "icat-version", ICAT, &["-V"]);
    command(dir, "istat-version", ISTAT, &["-V"]);
    (sources.to_vec(), binary, tools)
}
fn native_end(
    dir: &std::path::Path,
    sources: &SourceBindings,
    binary: &[u8],
    tools: &[Vec<u8>; 3],
) {
    for &(name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), bytes);
    }
    assert_eq!(
        std::fs::read(std::env::current_exe().unwrap()).unwrap(),
        binary
    );
    for (path, bytes) in [APFSCK, ICAT, ISTAT].into_iter().zip(tools) {
        assert_eq!(std::fs::read(path).unwrap(), *bytes);
    }
    hash_command(
        dir,
        "end-binary-tools",
        &[
            dir.join("compiled-test-executable").to_str().unwrap(),
            APFSCK,
            ICAT,
            ISTAT,
        ],
    );
}
fn command(dir: &std::path::Path, label: &str, tool: &str, args: &[&str]) -> std::process::Output {
    std::fs::write(
        dir.join(format!("{label}.command")),
        format!("{tool:?} {args:?}\n"),
    )
    .unwrap();
    let output = std::process::Command::new(tool)
        .args(args)
        .output()
        .unwrap();
    std::fs::write(dir.join(format!("{label}.stdout")), &output.stdout).unwrap();
    std::fs::write(dir.join(format!("{label}.stderr")), &output.stderr).unwrap();
    std::fs::write(
        dir.join(format!("{label}.status")),
        format!("{}\n", output.status),
    )
    .unwrap();
    output
}
fn hash_command(dir: &std::path::Path, label: &str, args: &[&str]) -> Vec<u8> {
    let output = command(dir, label, "sha256sum", args);
    assert!(output.status.success());
    output.stdout
}
fn sparse_model() -> Vec<u8> {
    (0..16397u64)
        .map(|p| {
            if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                0
            } else {
                (p % 4096 * 17 % 251) as u8
            }
        })
        .collect()
}
fn native_validate(dir: &std::path::Path, image: &Sparse, xid: u64, expected: &[u8], bulk: bool) {
    use sha2::{Digest, Sha256};
    use std::{io::Read, os::unix::fs::FileExt};
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("image.apfs");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(image.length).unwrap();
    for (block, bytes) in &image.blocks {
        file.write_all_at(bytes, block * 4096).unwrap();
    }
    file.sync_all().unwrap();
    let path = path.to_str().unwrap();
    let before = hash_command(dir, "image-before", &[path]);
    let checker = command(dir, "checker", APFSCK, &["-c", "-u", "-w", path]);
    assert!(checker.status.success(), "native checker {checker:?}");
    assert!(checker.stdout.is_empty() && checker.stderr.is_empty());
    let (&volume, _) = image
        .blocks
        .iter()
        .find(|(_, b)| {
            &b[32..36] == b"APSB" && u64::from_le_bytes(b[16..24].try_into().unwrap()) == xid
        })
        .unwrap();
    let block = volume.to_string();
    let args = ["-P", "apfs", "-B", block.as_str(), "-f", "apfs", path, "16"];
    let payload = command(dir, "data", ICAT, &args);
    assert!(payload.status.success());
    assert_eq!(payload.stdout, expected);
    std::fs::write(dir.join("data.expected"), expected).unwrap();
    let inode = command(dir, "inode", ISTAT, &args);
    assert!(inode.status.success());
    let report = String::from_utf8_lossy(&inode.stdout);
    assert!(report.contains("Filename:\tAé-file"), "{report}");
    assert!(
        report.contains(if bulk {
            "Number of Links: 1"
        } else {
            "Number of Links: 2"
        }),
        "{report}"
    );
    assert!(
        report.contains(if bulk {
            "owner / group: 501 / 20"
        } else {
            "owner / group: 0 / 0"
        }),
        "{report}"
    );
    let mut args = args;
    args[7] = "16-4353-1";
    let resource = command(dir, "resource", ICAT, &args);
    assert!(resource.status.success());
    assert_eq!(resource.stdout, b"resource");
    std::fs::write(dir.join("resource.expected"), b"resource").unwrap();
    if bulk {
        args[7] = "47";
        std::fs::write(dir.join("bulk.command"), format!("{ICAT:?} {args:?}\n")).unwrap();
        let mut child = std::process::Command::new(ICAT)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::from(
                std::fs::File::create(dir.join("bulk.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut buffer = vec![0u8; 1024 * 1024];
        let zeros = vec![0u8; buffer.len()];
        let mut count = 0u64;
        let mut hash = Sha256::new();
        let mut model = Sha256::new();
        loop {
            let n = stdout.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            assert_eq!(&buffer[..n], &zeros[..n]);
            count += n as u64;
            hash.update(&buffer[..n]);
            model.update(&zeros[..n]);
        }
        let status = child.wait().unwrap();
        std::fs::write(dir.join("bulk.status"), format!("{status}\n")).unwrap();
        assert!(status.success());
        assert_eq!(count, (126 * 32768 - 2000) * 4096);
        let actual = hash.finalize();
        let expected = model.finalize();
        assert_eq!(actual, expected);
        std::fs::write(
            dir.join("bulk.receipt"),
            format!("bytes={count}\nsha256={actual:x}\nmodel_sha256={expected:x}\n"),
        )
        .unwrap();
    }
    assert_eq!(hash_command(dir, "image-after", &[path]), before);
}

#[test]
fn repeated_two_cib_small_ranges_keep_fresh_proofs_and_bounded_work() {
    let r = resources();
    let original = cibs::seed();
    let untouched = original[402 * 4096..403 * 4096].to_vec();
    let state = Arc::new(Mutex::new(sparse(&original)));
    let mut editor = ApfsEditor::open(Disk(state.clone()), 1026, limits(), &r).unwrap();
    for generation in 0..3 {
        let before_work = editor.work_used();
        let before = state.lock().unwrap().clone();
        let started = std::time::Instant::now();
        let id = editor.file_identity(16, &r).unwrap();
        let value = 0xa0 + generation as u8;
        let plan = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 993,
                        generation,
                        native: b"three bounded small ranges".to_vec(),
                    },
                    value,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        editor.commit_range(plan, &anchor, &r).unwrap();
        let charged = editor.work_used() - before_work;
        assert!(
            charged < 10_000_000_000,
            "explicit repeated small-range work ceiling"
        );
        let current = state.lock().unwrap();
        assert_eq!(current.writes - before.writes, 20);
        assert!(current.read_calls - before.read_calls < 700);
        assert_eq!(current.blocks[&402], untouched);
        println!(
            "repeat={} charged_work={} target_read_calls={} target_read_bytes={} target_write_calls={} target_write_bytes={} elapsed_ms={}",
            generation,
            charged,
            current.read_calls - before.read_calls,
            current.read_bytes - before.read_bytes,
            current.writes - before.writes,
            current.write_bytes - before.write_bytes,
            started.elapsed().as_millis()
        );
        drop(current);
        assert!(editor.read_file_at(&id, 0, &mut [], &r).is_err());
        let id = editor.file_identity(16, &r).unwrap();
        let mut actual = vec![0; 16397];
        assert_eq!(
            editor.read_file_at(&id, 0, &mut actual, &r).unwrap(),
            actual.len()
        );
        let mut expected: Vec<_> = (0..16397)
            .map(|p| {
                if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                    0
                } else {
                    ((p % 4096) * 17 % 251) as u8
                }
            })
            .collect();
        expected[4091..4120].fill(value);
        assert_eq!(actual, expected);
    }
    assert_eq!(editor.checkpoint_xid(), 4);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
