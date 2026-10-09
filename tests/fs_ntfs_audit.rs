#![cfg(feature = "std")]

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean;
use ntfs_clean::*;
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs::NtfsReadLimits,
    fs_ntfs_audit::{NtfsAuditFinding, NtfsAuditLimits, audit_ntfs},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;
struct Image {
    bytes: Vec<u8>,
    reads: AtomicU64,
    length: AtomicU64,
    fail: AtomicU64,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        let n = bytes.len() as u64;
        Self {
            bytes,
            reads: AtomicU64::new(0),
            length: AtomicU64::new(n),
            fail: AtomicU64::new(u64::MAX),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if o >= self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected read failure"));
        }
        let p = usize::try_from(o).map_err(io::Error::other)?;
        b.copy_from_slice(
            self.bytes
                .get(p..p + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn audit_limits() -> NtfsAuditLimits {
    NtfsAuditLimits {
        clusters: 2048,
        records: 128,
        attributes: 1024,
        ranges: 256,
        entries: 128,
        index_blocks: 32,
        depth: 8,
        work: 50000,
        findings: 64,
        free_ranges: 64,
    }
}
#[test]
fn complete_counts_eof_tails_hardlinks_and_refunds() {
    let r = r();
    {
        let report = audit_ntfs(
            Arc::new(Image::new(ntfs_audit_seed())),
            limits(),
            audit_limits(),
            &r,
        )
        .unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.allocated_records(), 18);
        assert_eq!(report.allocated_clusters(), 335);
        assert_eq!(report.owned_clusters(), 335);
        assert_eq!(report.bad_clusters(), 0);
        assert_eq!(
            report.free_ranges().iter().map(|e| e.length).sum::<u64>(),
            (1024 - 335) * 512
        );
        assert!(
            report
                .free_ranges()
                .iter()
                .all(|e| e.offset >= 512 && e.offset + e.length <= 1024 * 512)
        );
    }
    assert_eq!(r.memory.used(), 0);
}
fn bitmap_offset() -> usize {
    2048 + 6 * 1024 + 56 + resident(0x30, &name_value("$Bitmap", 5), 2).len() + 24
}
#[test]
fn lost_referenced_free_and_crosslinks_have_no_free_proof() {
    for (cluster, set, expected) in [(700, true, 0), (90, false, 1)] {
        let mut b = ntfs_audit_seed();
        let p = bitmap_offset() + cluster / 8;
        if set {
            b[p] |= 1 << (cluster % 8);
        } else {
            b[p] &= !(1 << (cluster % 8));
        }
        let r = r();
        let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
        assert!(report.is_complete());
        assert!(report.free_ranges().is_empty());
        assert!(report.findings().iter().any(|f| match f {
            NtfsAuditFinding::LostAllocation { cluster: 700, .. } => expected == 0,
            NtfsAuditFinding::ReferencedFree { cluster: 90 } => expected == 1,
            _ => false,
        }));
    }
    let mut b = ntfs_audit_seed();
    put(
        &mut b,
        24,
        &[
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
            nonresident(&[0x11, 1, 90, 0], 1, 100, 100, false),
        ],
        false,
        2,
    );
    let r = r();
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::CrossLink { cluster: 90, .. }))
    );
    assert!(report.free_ranges().is_empty());
}
#[test]
fn mirror_dirty_flags_and_record_bitmap_are_independent() {
    for (p, value, kind) in [
        (500 * 512 + 1000, 1, 0),
        (
            2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10,
            1,
            1,
        ),
        (
            2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10,
            2,
            2,
        ),
    ] {
        let mut b = ntfs_audit_seed();
        b[p] = value;
        let r = r();
        let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
        assert!(report.free_ranges().is_empty());
        assert!(report.findings().iter().any(|f| match f {
            NtfsAuditFinding::MirrorRecord { record: 0 } => kind == 0,
            NtfsAuditFinding::Dirty => kind == 1,
            NtfsAuditFinding::VolumeFlags { flags: 2 } => kind == 2,
            _ => false,
        }));
    }
    let mut b = ntfs_audit_seed();
    let bitmap = 2048
        + 56
        + resident(0x30, &name_value("$MFT", 5), 2).len()
        + nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    b[bitmap + 3] &= !1;
    let mirror = b[2048..2048 + 4096].to_vec();
    b[500 * 512..508 * 512].copy_from_slice(&mirror);
    let r = r();
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::RecordBitmap { record: 24, .. }))
    );
    assert!(report.findings().iter().any(|f| matches!(
        f,
        NtfsAuditFinding::ReferenceToFreeRecord { record: 24, .. }
    )));
    assert!(report.free_ranges().is_empty());
}
#[test]
fn bounds_cancellation_io_work_and_diagnostic_caps_refund() {
    let image = Arc::new(Image::new(ntfs_audit_seed()));
    let r = r();
    r.cancellation.cancel();
    assert_eq!(
        audit_ntfs(image.clone(), limits(), audit_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(image.reads.load(Ordering::Relaxed), 0);
    for kind in 0..3 {
        let r = self::r();
        let mut cap = audit_limits();
        match kind {
            0 => cap.work = 0,
            1 => cap.clusters = 1,
            _ => cap.free_ranges = 0,
        }
        assert_eq!(
            audit_ntfs(image.clone(), limits(), cap, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = self::r();
    image.fail.store(400 * 512, Ordering::Relaxed);
    let e = audit_ntfs(image, limits(), audit_limits(), &r)
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::Io);
    assert!(e.source.is_some());
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "explicit native NTFS allocation gate requires mkntfs/ntfscp/ntfsinfo/TSK and fresh evidence"]
fn native_complete_ownership() {
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    let out = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_AUDIT_EVIDENCE").expect("evidence directory required"),
    );
    fs::create_dir(&out).unwrap();
    let mut receipt = format!(
        "profile=NTFS3.1-base-record-all-attribute-ownership-and-native-index-audit\nreader_sha256={:x}\naudit_sha256={:x}\nfixture_sha256={:x}\ntest_binary_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_ntfs.rs")),
        Sha256::digest(include_bytes!("../src/fs_ntfs_audit.rs")),
        Sha256::digest(include_bytes!("fixtures/ntfs_clean.rs")),
        Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    for tool in ["mkntfs", "ntfscp", "ntfsinfo", "fls", "icat"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("native tool required");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
    }
    let run = |receipt: &mut String, tool: &str, args: Vec<String>| {
        let output = Command::new(tool)
            .args(&args)
            .output()
            .expect("required tool");
        let n = receipt.matches("command=").count();
        fs::write(out.join(format!("{n}-{tool}.stdout")), &output.stdout).unwrap();
        fs::write(out.join(format!("{n}-{tool}.stderr")), &output.stderr).unwrap();
        receipt.push_str(&format!(
            "command={tool} {args:?} status={} stdout_sha256={:x} stderr_sha256={:x}\n",
            output.status,
            Sha256::digest(&output.stdout),
            Sha256::digest(&output.stderr)
        ));
        fs::write(out.join("receipt.txt"), &*receipt).unwrap();
        assert!(
            output.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    for (tool, arg) in [
        ("mkntfs", "--version"),
        ("ntfscp", "--version"),
        ("ntfsinfo", "--version"),
        ("fls", "-V"),
        ("icat", "-V"),
        ("uname", "-a"),
    ] {
        run(&mut receipt, tool, vec![arg.into()]);
    }
    let image = out.join("native.ntfs");
    fs::File::create(&image).unwrap().set_len(64 << 20).unwrap();
    run(
        &mut receipt,
        "mkntfs",
        vec!["-F".into(), "-Q".into(), image.display().to_string()],
    );
    let payload = (0..131089)
        .map(|i| ((i * 31 + i / 13 + 7) % 251) as u8)
        .collect::<Vec<_>>();
    let host = out.join("payload.bin");
    fs::write(&host, &payload).unwrap();
    for i in 0..48 {
        run(
            &mut receipt,
            "ntfscp",
            vec![
                image.display().to_string(),
                host.display().to_string(),
                format!("/file-{i:03}.bin"),
            ],
        );
    }
    let before = fs::read(&image).unwrap();
    let source_hash = format!("{:x}", Sha256::digest(&before));
    let info = String::from_utf8(run(
        &mut receipt,
        "ntfsinfo",
        vec!["-m".into(), image.display().to_string()],
    ))
    .unwrap();
    let number = |label: &str| {
        info.lines()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let cluster_count = number("Volume Size in Clusters");
    let free_count = number("Free Clusters");
    let listing = String::from_utf8(run(
        &mut receipt,
        "fls",
        vec!["-f".into(), "ntfs".into(), image.display().to_string()],
    ))
    .unwrap();
    for name in ["file-000.bin", "file-047.bin"] {
        let line = listing
            .lines()
            .find(|l| l.ends_with(&format!(":\t{name}")))
            .unwrap();
        let reference = line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        assert_eq!(
            run(
                &mut receipt,
                "icat",
                vec![image.display().to_string(), reference.into()]
            ),
            payload
        );
    }
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let cap = NtfsAuditLimits {
        clusters: 20000,
        records: 512,
        attributes: 10000,
        ranges: 4096,
        entries: 1024,
        index_blocks: 128,
        depth: 32,
        work: 1000000,
        findings: 2048,
        free_ranges: 10000,
    };
    let report = audit_ntfs(
        Arc::new(Image::new(before)),
        NtfsReadLimits {
            attributes: 64,
            runs: 256,
            names: 16,
        },
        cap,
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.clusters(), cluster_count);
    assert_eq!(report.allocated_clusters(), cluster_count - free_count);
    assert_eq!(report.owned_clusters(), report.allocated_clusters());
    assert_eq!(
        report
            .free_ranges()
            .iter()
            .map(|e| e.length / 4096)
            .sum::<u64>(),
        free_count
    );
    receipt.push_str(&format!("allocated_clusters={} owned_clusters={} free_clusters={free_count} records={} attributes={} work={} findings={:?}\n",report.allocated_clusters(),report.owned_clusters(),report.allocated_records(),report.attributes(),report.work(),report.findings()));
    drop(report);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&image).unwrap())),
        source_hash
    );
    receipt.push_str(&format!("source_sha256={source_hash}\nstatus=passed\n"));
    fs::write(out.join("receipt.txt"), receipt).unwrap();
}
fn sync_mirror(b: &mut [u8]) {
    let bytes = b[2048..2048 + 4096].to_vec();
    b[500 * 512..508 * 512].copy_from_slice(&bytes);
}
fn mft_bitmap_offset() -> usize {
    2048 + 56
        + resident(0x30, &name_value("$MFT", 5), 2).len()
        + nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24
}
#[test]
fn incomplete_record_and_orphan_parent_suppress_all_free() {
    let mut b = ntfs_audit_seed();
    let p = mft_bitmap_offset();
    b[p + 2] |= 1;
    let c = bitmap_offset() + 700 / 8;
    b[c] |= 1 << (700 % 8);
    sync_mirror(&mut b);
    let r = r();
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(!report.is_complete());
    assert!(report.free_ranges().is_empty());
    assert!(report.findings().iter().any(|f| matches!(
        f,
        NtfsAuditFinding::RecordBitmap {
            record: 16,
            allocated: true,
            in_use: false
        }
    )));
    assert!(
        !report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::LostAllocation { .. }))
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
    let mut b = ntfs_audit_seed();
    b[mft_bitmap_offset() + 3] |= 4;
    put(
        &mut b,
        26,
        &[
            resident(0x30, &name_value("orphan", 1), 2),
            resident(0x80, b"orphan", 3),
        ],
        false,
        1,
    );
    sync_mirror(&mut b);
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(report.findings().iter().any(|f| matches!(
        f,
        NtfsAuditFinding::InvalidNameParent {
            record: 26,
            parent: 1
        }
    )));
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::UnreachableRecord { record: 26 }))
    );
    assert!(report.free_ranges().is_empty());
}
#[test]
fn named_bad_allocations_and_unsupported_owners_are_not_ignored() {
    let mut b = ntfs_audit_seed();
    let mut bad = nonresident(&[0x11, 1, 95, 0x02, 0xff, 3, 0], 1024, 1024 * 512, 0, false);
    bad = named_allocation(bad, 0x80, "$Bad", 4);
    put(
        &mut b,
        8,
        &[
            resident(0x30, &name_value("$BadClus", 5), 2),
            resident(0x80, &[], 3),
            bad,
        ],
        false,
        1,
    );
    b[bitmap_offset() + 95 / 8] |= 1 << (95 % 8);
    let r = r();
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.bad_clusters(), 1);
    assert_eq!(report.owned_clusters(), 336);
    drop(report);
    let mut b = ntfs_audit_seed();
    put(
        &mut b,
        25,
        &[
            resident(0x20, &[], 1),
            resident(0x30, &name_value("gamma", 5), 2),
        ],
        false,
        1,
    );
    assert_eq!(
        audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
    let mut b = ntfs_audit_seed();
    b[mft_bitmap_offset() + 4] |= 1;
    sync_mirror(&mut b);
    assert_eq!(
        audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidData
    );
    assert_eq!(r.memory.used(), 0);
}
struct Trap(Image);
impl ReadAt for Trap {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        if o < 92 * 512 && o + b.len() as u64 > 90 * 512 {
            return Err(io::Error::other("payload must not be read by audit"));
        }
        self.0.read_exact_at(o, b)
    }
}
struct Change(Image);
impl ReadAt for Change {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(o, b)?;
        if self.0.reads.load(Ordering::Relaxed) == 7 {
            self.0.length.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }
}
#[test]
fn no_data_prefetch_and_source_changes_findings_budget_are_explicit() {
    let r = r();
    let report = audit_ntfs(
        Arc::new(Trap(Image::new(ntfs_audit_seed()))),
        limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean());
    drop(report);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(
        audit_ntfs(
            Arc::new(Change(Image::new(ntfs_audit_seed()))),
            limits(),
            audit_limits(),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(r.memory.used(), 0);
    let mut b = ntfs_audit_seed();
    b[bitmap_offset() + 700 / 8] |= 1 << (700 % 8);
    let mut cap = audit_limits();
    cap.findings = 0;
    assert_eq!(
        audit_ntfs(Arc::new(Image::new(b)), limits(), cap, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_directory_reference_cycles_are_diagnosed() {
    let mut b = ntfs_audit_seed();
    let mut root = root_attribute(&[terminal(Some(0))], true);
    d(&mut root, 40, 2048);
    root[44] = 4;
    let allocation = named_allocation(
        nonresident(&[0x21, 4, 0x90, 1, 0], 4, 2048, 2048, false),
        0xa0,
        "$I30",
        5,
    );
    put(
        &mut b,
        5,
        &[
            resident(0x30, &name_value(".", 5), 2),
            resident(0x30, &name_value("cycle", 11), 3),
            root,
            allocation,
            named_resident(0xb0, &[1, 0, 0, 0, 0, 0, 0, 0], 6),
        ],
        true,
        2,
    );
    let mut child = index_entry(5, "cycle", None);
    q(&mut child, 16, 11 | (7 << 48));
    d(&mut child, 16 + 56, 0x10000000);
    let mut root = root_attribute(&[child, terminal(None)], false);
    d(&mut root, 40, 2048);
    root[44] = 4;
    put(
        &mut b,
        11,
        &[resident(0x30, &name_value("$Extend", 5), 2), root],
        true,
        1,
    );
    let r = r();
    let report = audit_ntfs(Arc::new(Image::new(b)), limits(), audit_limits(), &r).unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::DirectoryAlias { record: 5 }))
    );
    assert!(report.free_ranges().is_empty());
}

#[test]
fn short_name_policy_remains_visible_in_audit_without_becoming_dirty() {
    let mut bytes = ntfs_audit_seed();
    let flags_at =
        2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10;
    w(&mut bytes, flags_at, 0x0080);
    let report = audit_ntfs(Arc::new(Image::new(bytes)), limits(), audit_limits(), &r()).unwrap();
    assert_eq!(report.volume_flags(), 0x0080);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| matches!(finding, NtfsAuditFinding::VolumeFlags { flags: 0x0080 }))
    );
    assert!(
        !report
            .findings()
            .iter()
            .any(|finding| matches!(finding, NtfsAuditFinding::Dirty))
    );
}
