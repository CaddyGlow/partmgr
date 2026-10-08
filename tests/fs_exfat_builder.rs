use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, ObjectId, Resources},
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_builder::*,
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    storage::Storage,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
struct Source {
    bytes: Vec<u8>,
    length: AtomicU64,
    fail: AtomicBool,
    changed: AtomicBool,
    reads: AtomicU64,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            fail: AtomicBool::new(false),
            changed: AtomicBool::new(false),
            reads: AtomicU64::new(0),
        }
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("causal deferred source failure"));
        }
        let at = at as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        if self.changed.load(Ordering::SeqCst) && !out.is_empty() {
            out[0] ^= 1;
        }
        Ok(())
    }
}
struct Image {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    short: usize,
    fail_write: bool,
    fail_flush: bool,
    corrupt_read: bool,
    source_change: Option<Arc<Source>>,
}
impl Image {
    fn new(n: usize) -> Self {
        Self {
            bytes: vec![0xa7; n],
            writes: 0,
            flushes: 0,
            short: usize::MAX,
            fail_write: false,
            fail_flush: false,
            corrupt_read: false,
            source_change: None,
        }
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = at as usize;
        out.copy_from_slice(&self.bytes[at..at + out.len()]);
        if self.corrupt_read {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_write {
            return Err(io::Error::other("modeled target write failure"));
        }
        let n = bytes.len().min(self.short);
        self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if let Some(source) = &self.source_change {
            source.changed.store(true, Ordering::SeqCst);
        }
        if self.fail_flush {
            Err(io::Error::other("modeled flush failure"))
        } else {
            Ok(())
        }
    }
}
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 1,
        generation: 0,
        native: vec![n],
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExfatBuildLimits {
    ExfatBuildLimits {
        objects: 200,
        name_units: 10000,
        clusters: 200000,
        depth: 16,
        directory_slots: 10000,
    }
}
fn options() -> ExfatBuildOptions {
    ExfatBuildOptions {
        cluster_shift: 3,
        volume_id: 0x12345678,
        name_profile: ExfatBuildNameProfile::RecommendedTable,
    }
}
fn entries(source: Arc<dyn ReadAt>) -> Vec<ExfatBuildEntry> {
    vec![
        ExfatBuildEntry {
            identity: id(1),
            parent: None,
            name: "EFI".encode_utf16().collect(),
            source: None,
        },
        ExfatBuildEntry {
            identity: id(2),
            parent: Some(id(1)),
            name: "BOOT".encode_utf16().collect(),
            source: None,
        },
        ExfatBuildEntry {
            identity: id(3),
            parent: Some(id(2)),
            name: "BOOTX64.EFI".encode_utf16().collect(),
            source: Some(ExfatBuildSource::ReadAt(source)),
        },
        ExfatBuildEntry {
            identity: id(4),
            parent: None,
            name: "Long ä name.txt".encode_utf16().collect(),
            source: Some(ExfatBuildSource::ReadAt(Arc::new(Source::new(
                b"unicode payload".to_vec(),
            )))),
        },
        ExfatBuildEntry {
            identity: id(5),
            parent: None,
            name: vec![0xd800, 88],
            source: Some(ExfatBuildSource::ReadAt(Arc::new(Source::new(Vec::new())))),
        },
    ]
}
fn plan(
    n: u64,
    entries: &[ExfatBuildEntry],
    r: &Resources,
) -> partmgr::fs_core::Result<ExfatBuildPlan> {
    ExfatBuildPlan::new(
        n,
        options(),
        entries,
        ExfatBuildMetadataPolicy::DeterministicDefaults,
        limits(),
        r,
    )
}
fn reader_limits() -> ExfatReadLimits {
    ExfatReadLimits {
        max_chain_clusters: 1000,
        max_directory_slots: 10000,
        max_upcase_bytes: 131072,
    }
}
fn verify(bytes: Vec<u8>, expected: &[u8], r: &Resources) {
    let source: Arc<dyn ReadAt> = Arc::new(Source::new(bytes));
    let report = audit_exfat(
        source.clone(),
        reader_limits(),
        ExfatAuditLimits {
            clusters: 200000,
            entries: 200,
            directory_slots: 10000,
            work: 500000,
            findings: 10,
        },
        r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    drop(report);
    let volume = ExfatVolume::open(source, reader_limits(), r).unwrap();
    let root = volume.root_directory(r).unwrap();
    assert!(root.lookup(&[0xd800, 88]).unwrap().unwrap().is_empty());
    let efi = volume
        .read_directory(
            root.lookup(&"efi".encode_utf16().collect::<Vec<_>>())
                .unwrap()
                .unwrap(),
            r,
        )
        .unwrap();
    let boot = volume
        .read_directory(
            efi.lookup(&"boot".encode_utf16().collect::<Vec<_>>())
                .unwrap()
                .unwrap(),
            r,
        )
        .unwrap();
    let file = volume
        .open_file(boot.entries().first().unwrap(), r)
        .unwrap();
    use partmgr::fs_core::FileRead;
    let mut out = vec![0; expected.len()];
    assert_eq!(file.read_at(0, &mut out, r).unwrap(), out.len());
    assert_eq!(out, expected);
    assert!(
        root.lookup(&"LONG Ä NAME.TXT".encode_utf16().collect::<Vec<_>>())
            .unwrap()
            .is_some()
    );
}
#[test]
fn deterministic_nested_native_tree_reopens_audits_and_zeroes_free_tail() {
    let r = resources();
    let payload: Vec<_> = (0..150001).map(|i| (i % 251) as u8).collect();
    let source = Arc::new(Source::new(payload.clone()));
    let mut entries = entries(source.clone());
    let p = plan(2 << 20, &entries, &r).unwrap();
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    let mut a = Image::new(2 << 20);
    a.short = 32749;
    let report = p.emit(&mut a, &r).unwrap();
    assert_eq!(a.flushes, 1);
    assert_eq!(report.files, 3);
    assert_eq!(report.verified_bytes, 2 << 20);
    assert!(a.bytes[(a.bytes.len() - 8192)..].iter().all(|&b| b == 0));
    verify(a.bytes.clone(), &payload, &r);
    drop(p);
    entries.reverse();
    let p = plan(2 << 20, &entries, &r).unwrap();
    let mut b = Image::new(2 << 20);
    assert_eq!(p.emit(&mut b, &r).unwrap().sha256, report.sha256);
    assert_eq!(a.bytes, b.bytes);
    drop(p);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn preflight_rejects_collisions_parents_bounds_and_capacity_without_payload_reads() {
    let source = Arc::new(Source::new(vec![1; 700]));
    for case in 0..7 {
        let r = resources();
        let mut e = entries(source.clone());
        match case {
            0 => e[4].name = "long Ä NAME.TXT".encode_utf16().collect(),
            1 => e[4].identity = id(3),
            2 => e[1].parent = Some(id(3)),
            3 => e[1].parent = Some(id(99)),
            4 => e[0].parent = Some(id(2)),
            5 => e[4].name = vec![47],
            _ => {
                e[2].source = Some(ExfatBuildSource::ReadAt(Arc::new(Source {
                    bytes: vec![],
                    length: AtomicU64::new(9 << 30),
                    fail: AtomicBool::new(false),
                    changed: AtomicBool::new(false),
                    reads: AtomicU64::new(0),
                })));
            }
        }
        assert!(plan(2 << 20, &e, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    let r = resources();
    let mut l = limits();
    l.directory_slots = 1;
    assert!(
        ExfatBuildPlan::new(
            2 << 20,
            options(),
            &entries(source),
            ExfatBuildMetadataPolicy::DeterministicDefaults,
            l,
            &r
        )
        .is_err()
    );
    assert!(plan(u64::MAX, &[], &r).is_err());
}
#[test]
fn cancellation_source_failure_staleness_and_target_uncertainty() {
    let r = resources();
    let source = Arc::new(Source::new(vec![42; 150000]));
    let p = plan(2 << 20, &entries(source.clone()), &r).unwrap();
    source.length.store(2, Ordering::SeqCst);
    let mut image = Image::new(2 << 20);
    assert_eq!(
        p.emit(&mut image, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(image.writes, 0);
    source.length.store(150000, Ordering::SeqCst);
    for case in 0..4 {
        let mut image = Image::new(2 << 20);
        match case {
            0 => source.fail.store(true, Ordering::SeqCst),
            1 => image.fail_write = true,
            2 => image.fail_flush = true,
            _ => image.corrupt_read = true,
        };
        let error = p.emit(&mut image, &r).unwrap_err();
        assert_eq!(
            error.kind,
            if case == 2 {
                ErrorKind::UncertainDurability
            } else if case == 0 {
                ErrorKind::Io
            } else {
                ErrorKind::InterruptedWrite
            }
        );
        if case == 0 || case == 1 || case == 2 {
            assert!(std::error::Error::source(&error).is_some());
        }
        source.fail.store(false, Ordering::SeqCst);
    }
    let r_cancel = resources();
    r_cancel.cancellation.cancel();
    let mut image = Image::new(2 << 20);
    assert_eq!(
        p.emit(&mut image, &r_cancel).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(image.writes, 0);
}

#[test]
#[ignore = "enabled gate requires evidence directory, fsck.exfat and Sleuth Kit fls/icat/ifind"]
fn native_32_64mib_nested_unicode_and_repeat_images() {
    use std::{ffi::OsStr, path::Path, process::Command};
    let evidence = std::env::var_os("PARTMGR_EXFAT_BUILDER_EVIDENCE")
        .expect("enabled gate requires evidence directory");
    std::fs::create_dir_all(&evidence).unwrap();
    let temp = tempfile::Builder::new()
        .prefix("exfat-builder-")
        .tempdir_in(&evidence)
        .unwrap();
    let fsck = std::env::var_os("PARTMGR_EXFAT_FSCK").unwrap_or_else(|| "fsck.exfat".into());
    let fls = std::env::var_os("PARTMGR_EXFAT_FLS").unwrap_or_else(|| "fls".into());
    let icat = std::env::var_os("PARTMGR_EXFAT_ICAT").unwrap_or_else(|| "icat".into());
    let ifind = std::env::var_os("PARTMGR_EXFAT_IFIND").unwrap_or_else(|| "ifind".into());
    let mut receipt = String::from(
        "schema=1\nprofile=exfat-direct-builder-tree-v1\nimplementation=direct-rust-byte-authoring\nsector_bytes=512\ncluster_bytes=4096\nmetadata=deterministic-defaults-2000-01-01UTC\n",
    );
    let mut command = |tool: &OsStr, args: &[&OsStr]| {
        let mut cmd = Command::new(tool);
        cmd.args(args);
        let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
        receipt.push_str(&format!(
            "command={cmd:?}\nexit={}\nstdout={}\nstderr={}\n",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
        out
    };
    for tool in [&fsck, &fls, &icat, &ifind] {
        command(tool, &[OsStr::new("-V")]); // fsck.exfat's version mode returns usage status16. 
        assert!(command(OsStr::new("sha256sum"), &[tool]).status.success());
    }
    let payload: Vec<_> = (0..150001).map(|n| ((n * 11 + 7) % 251) as u8).collect();
    let mut unicode_fold_validated = true;
    for mib in [32_u64, 64] {
        let r = resources();
        let mut tree = entries(Arc::new(Source::new(payload.clone())));
        tree[4].name = "EMPTY.BIN".encode_utf16().collect();
        let mut images = Vec::new();
        let mut digests = Vec::new();
        for order in 0..2 {
            let image = temp.path().join(format!("tree-{mib}-{order}.exfat"));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&image)
                .unwrap()
                .set_len(mib << 20)
                .unwrap();
            let plan = plan(mib << 20, &tree, &r).unwrap();
            let report = {
                let mut output = partmgr::storage::FileStorage::open(&image).unwrap();
                plan.emit(&mut output, &r).unwrap()
            };
            digests.push(report.sha256);
            drop(plan);
            images.push(image);
            tree.reverse();
        }
        assert_eq!(digests[0], digests[1]);
        assert_eq!(
            std::fs::read(&images[0]).unwrap(),
            std::fs::read(&images[1]).unwrap()
        );
        assert_eq!(r.memory.used(), 0);
        for image in &images {
            assert!(
                command(&fsck, &[OsStr::new("-n"), image.as_os_str()])
                    .status
                    .success()
            );
            assert!(
                command(OsStr::new("sha256sum"), &[image.as_os_str()])
                    .status
                    .success()
            );
            let source: Arc<dyn ReadAt> = Arc::new(virtdisk::RawDisk::open(image).unwrap());
            let report = audit_exfat(
                source,
                reader_limits(),
                ExfatAuditLimits {
                    clusters: 200000,
                    entries: 200,
                    directory_slots: 10000,
                    work: 500000,
                    findings: 10,
                },
                &r,
            )
            .unwrap();
            assert!(report.is_clean());
        }
        let listing = command(
            &fls,
            &[
                OsStr::new("-f"),
                OsStr::new("exfat"),
                OsStr::new("-r"),
                OsStr::new("-p"),
                images[0].as_os_str(),
            ],
        );
        assert!(listing.status.success());
        let listing = String::from_utf8(listing.stdout).unwrap();
        for (name, expected) in [
            ("EFI/BOOT/BOOTX64.EFI", payload.as_slice()),
            ("Long ä name.txt", b"unicode payload".as_slice()),
            ("EMPTY.BIN", b"".as_slice()),
        ] {
            let line = listing
                .lines()
                .find(|line| line.split_once('\t').is_some_and(|(_, path)| path == name))
                .unwrap_or_else(|| panic!("missing {name}: {listing}"));
            let inode = line
                .split_once(':')
                .unwrap()
                .0
                .split_whitespace()
                .last()
                .unwrap();
            let out = command(
                &icat,
                &[
                    OsStr::new("-f"),
                    OsStr::new("exfat"),
                    images[0].as_os_str(),
                    OsStr::new(inode),
                ],
            );
            assert!(out.status.success());
            assert_eq!(out.stdout, expected);
            let extracted = temp
                .path()
                .join(format!("native-payload-{mib}-{}.bin", name.len()));
            std::fs::write(&extracted, out.stdout).unwrap();
            assert!(
                command(OsStr::new("sha256sum"), &[extracted.as_os_str()])
                    .status
                    .success()
            );
            let path = if name == "EFI/BOOT/BOOTX64.EFI" {
                "efi/boot/bootx64.efi"
            } else {
                name
            };
            let found = command(
                &ifind,
                &[
                    OsStr::new("-f"),
                    OsStr::new("exfat"),
                    OsStr::new("-n"),
                    OsStr::new(path),
                    images[0].as_os_str(),
                ],
            );
            assert!(
                found.status.success(),
                "native path comparison failed: {}",
                String::from_utf8_lossy(&found.stderr)
            );
            assert_eq!(
                String::from_utf8(found.stdout).unwrap().trim(),
                inode,
                "native lookup path {path}"
            );
            if name == "Long ä name.txt" {
                let probe = command(
                    &ifind,
                    &[
                        OsStr::new("-f"),
                        OsStr::new("exfat"),
                        OsStr::new("-n"),
                        OsStr::new("LONG Ä NAME.TXT"),
                        images[0].as_os_str(),
                    ],
                );
                assert!(probe.status.success());
                let result = String::from_utf8(probe.stdout).unwrap();
                if result.trim() != inode {
                    assert_eq!(result.trim(), "File not found");
                    unicode_fold_validated = false;
                }
            }
        }
    }
    for file in [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fs_exfat_builder.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fs_exfat_builder.rs"),
        std::env::current_exe().unwrap(),
    ] {
        assert!(
            command(OsStr::new("sha256sum"), &[file.as_os_str()])
                .status
                .success()
        );
    }
    receipt.push_str(&format!(
        "native_unicode_upcase_lookup={}\n",
        if unicode_fold_validated {
            "passed"
        } else {
            "gap-TSK-ifind-no-full-volume-upcase"
        }
    ));
    receipt.push_str("native_fsck=passed\nnative_nested_payload_names=passed\nwhole_volume_audit=passed\nreversed_input_repeat_hash=passed\nstatus=passed\n");
    let retained = temp.keep();
    std::fs::write(
        Path::new(&evidence).join("exfat-direct-builder-tree-v1.txt"),
        format!("artifact_directory={}\n{receipt}", retained.display()),
    )
    .unwrap();
}

#[test]
fn file_read_reauthoring_multi_cluster_upcase_and_changed_source_verification() {
    let r = resources();
    let payload = vec![13; 150001];
    let source = Arc::new(Source::new(payload));
    let tree = entries(source.clone());
    let p = plan(2 << 20, &tree, &r).unwrap();
    let mut image = Image::new(2 << 20);
    p.emit(&mut image, &r).unwrap();
    drop(p);
    let volume = ExfatVolume::open(
        Arc::new(Source::new(image.bytes.clone())),
        reader_limits(),
        &r,
    )
    .unwrap();
    let root = volume.root_directory(&r).unwrap();
    let efi = volume
        .read_directory(
            root.lookup(&"EFI".encode_utf16().collect::<Vec<_>>())
                .unwrap()
                .unwrap(),
            &r,
        )
        .unwrap();
    let boot = volume
        .read_directory(efi.entries().first().unwrap(), &r)
        .unwrap();
    let file = Arc::new(
        volume
            .open_file(boot.entries().first().unwrap(), &r)
            .unwrap(),
    );
    let mut tree = entries(source.clone());
    tree[2].source = Some(ExfatBuildSource::File(file));
    let p = plan(2 << 20, &tree, &r).unwrap();
    let mut second = Image::new(2 << 20);
    p.emit(&mut second, &r).unwrap();
    assert_eq!(image.bytes, second.bytes);
    drop(p);
    drop(tree);
    drop(boot);
    drop(efi);
    drop(root);
    drop(volume);
    let mut opt = options();
    opt.cluster_shift = 0;
    let p = ExfatBuildPlan::new(
        2 << 20,
        opt,
        &[],
        ExfatBuildMetadataPolicy::DeterministicDefaults,
        limits(),
        &r,
    )
    .unwrap();
    let mut empty = Image::new(2 << 20);
    p.emit(&mut empty, &r).unwrap();
    let source_image: Arc<dyn ReadAt> = Arc::new(Source::new(empty.bytes));
    let report = audit_exfat(
        source_image,
        reader_limits(),
        ExfatAuditLimits {
            clusters: 200000,
            entries: 200,
            directory_slots: 10000,
            work: 500000,
            findings: 10,
        },
        &r,
    )
    .unwrap();
    assert!(report.is_clean());
    drop(report);
    drop(p);
    let p = plan(2 << 20, &entries(source.clone()), &r).unwrap();
    let mut changed = Image::new(2 << 20);
    changed.source_change = Some(source);
    let error = p.emit(&mut changed, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert!(error.to_string().contains("verification byte mismatch"));
    drop(p);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn directory_growth_upcased_order_and_scratch_limit_preflight() {
    let r = resources();
    let empty = Arc::new(Source::new(Vec::new()));
    let mut tree = Vec::new();
    for (i, name) in ["B".to_string(), "a".to_string()]
        .into_iter()
        .chain((0..160).map(|i| format!("root file {i:03}.bin")))
        .enumerate()
    {
        tree.push(ExfatBuildEntry {
            identity: ObjectId {
                source: 7,
                generation: 0,
                native: (i as u32).to_le_bytes().to_vec(),
            },
            parent: None,
            name: name.encode_utf16().collect(),
            source: Some(ExfatBuildSource::ReadAt(empty.clone())),
        })
    }
    let mut opt = options();
    opt.cluster_shift = 0;
    let p = ExfatBuildPlan::new(
        2 << 20,
        opt,
        &tree,
        ExfatBuildMetadataPolicy::DeterministicDefaults,
        limits(),
        &r,
    )
    .unwrap();
    let low = Resources {
        memory: Budget::new(2 * 65536 - 1),
        cancellation: Cancellation::default(),
    };
    let mut untouched = Image::new(2 << 20);
    assert_eq!(
        p.emit(&mut untouched, &low).unwrap_err().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(untouched.writes, 0);
    assert!(untouched.bytes.iter().all(|&b| b == 0xa7));
    let mut image = Image::new(2 << 20);
    p.emit(&mut image, &r).unwrap();
    let source: Arc<dyn ReadAt> = Arc::new(Source::new(image.bytes));
    let report = audit_exfat(
        source.clone(),
        reader_limits(),
        ExfatAuditLimits {
            clusters: 200000,
            entries: 200,
            directory_slots: 10000,
            work: 500000,
            findings: 10,
        },
        &r,
    )
    .unwrap();
    assert!(report.is_clean());
    assert_eq!(report.objects(), 163);
    drop(report);
    let volume = ExfatVolume::open(source, reader_limits(), &r).unwrap();
    let root = volume.root_directory(&r).unwrap();
    assert_eq!(root.entries()[0].name(), &[97]);
    assert_eq!(root.entries()[1].name(), &[66]);
    assert!(root.allocation_clusters().len() > 1);
    assert_eq!(empty.reads.load(Ordering::SeqCst), 0);
}
