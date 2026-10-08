#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_exfat_audit::*,
    fs_exfat_volume::ExfatReadLimits,
};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
const SECTOR: usize = 512;
const HEAP: usize = 56 * SECTOR;
fn cluster(n: u32) -> usize {
    HEAP + (n as usize - 2) * SECTOR
}
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn seal(b: &mut [u8]) {
    for base in [0, 12 * SECTOR] {
        let sum = (0..11 * SECTOR)
            .filter(|i| ![106, 107, 112].contains(i))
            .fold(0_u32, |n, i| {
                (n >> 1 | (n & 1) << 31).wrapping_add(u32::from(b[base + i]))
            });
        for at in (base + 11 * SECTOR..base + 12 * SECTOR).step_by(4) {
            put32(b, at, sum);
        }
    }
}
fn uppercase(unit: u16) -> u16 {
    if (97..=122).contains(&unit) {
        unit - 32
    } else {
        unit
    }
}
fn fix_set(b: &mut [u8], at: usize) {
    let bytes = (usize::from(b[at + 1]) + 1) * 32;
    let sum = (0..bytes)
        .filter(|i| *i != 2 && *i != 3)
        .fold(0_u16, |n, i| {
            (n >> 1 | (n & 1) << 15).wrapping_add(u16::from(b[at + i]))
        });
    put16(b, at + 2, sum);
}
#[allow(clippy::too_many_arguments)] // Independent fixture encodes the on-disk stream fields directly.
fn entry(
    b: &mut [u8],
    slot: usize,
    name: &[u16],
    first: u32,
    length: u64,
    valid: u64,
    contiguous: bool,
    directory: bool,
) -> usize {
    let secondary = 1 + name.len().div_ceil(15);
    b[slot..slot + (secondary + 1) * 32].fill(0);
    b[slot] = 0x85;
    b[slot + 1] = secondary as u8;
    put16(b, slot + 4, if directory { 0x10 } else { 0x20 });
    for at in [8, 12, 16] {
        put32(b, slot + at, 0x0021_0000);
    }
    b[slot + 22..slot + 25].fill(0x80);
    let stream = slot + 32;
    b[stream] = 0xc0;
    b[stream + 1] = if contiguous { 3 } else { 1 };
    b[stream + 3] = name.len() as u8;
    let hash = name
        .iter()
        .flat_map(|u| uppercase(*u).to_le_bytes())
        .fold(0_u16, |n, b| {
            (n >> 1 | (n & 1) << 15).wrapping_add(u16::from(b))
        });
    put16(b, stream + 4, hash);
    put64(b, stream + 8, valid);
    put32(b, stream + 20, first);
    put64(b, stream + 24, length);
    for (i, part) in name.chunks(15).enumerate() {
        let at = slot + (2 + i) * 32;
        b[at] = 0xc1;
        for (j, unit) in part.iter().enumerate() {
            put16(b, at + 2 + j * 2, *unit);
        }
    }
    fix_set(b, slot);
    slot + (secondary + 1) * 32
}
fn fixture() -> Vec<u8> {
    // Independent specification constructor; no production builder/parser creates these bytes.
    let mut b = vec![0; 2 * 1024 * 1024];
    b[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    put64(&mut b, 72, (2 * 1024 * 1024 / SECTOR) as u64);
    put32(&mut b, 80, 24);
    put32(&mut b, 84, 32);
    put32(&mut b, 88, 56);
    put32(&mut b, 92, 4096 - 56);
    put32(&mut b, 96, 2);
    put32(&mut b, 100, 0x12345678);
    b[105] = 1;
    b[108] = 9;
    b[110] = 1;
    b[112] = 255;
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    for n in 1..=8 {
        put32(&mut b, (n + 1) * SECTOR - 4, 0xaa550000);
    }
    b.copy_within(..12 * SECTOR, 12 * SECTOR);
    seal(&mut b);
    put32(&mut b, 24 * SECTOR, 0xfffffff8);
    put32(&mut b, 24 * SECTOR + 4, u32::MAX);
    for n in [2, 3, 4, 9] {
        put32(&mut b, 24 * SECTOR + n as usize * 4, u32::MAX);
    }
    put32(&mut b, 24 * SECTOR + 7 * 4, 9);
    for n in [2, 3, 4, 5, 6, 7, 9, 10, 11] {
        let bit = n - 2;
        b[cluster(3) + bit / 8] |= 1 << (bit % 8);
    }
    b[cluster(2)] = 0x81;
    put32(&mut b, cluster(2) + 20, 3);
    put64(&mut b, cluster(2) + 24, 505);
    // Full custom Unicode table using compressed identity runs and mandatory ASCII mappings.
    let mut upcase = vec![0xffff_u16, 97];
    upcase.extend(65..=90);
    upcase.extend([0xffff, 65413]);
    let raw: Vec<_> = upcase.iter().flat_map(|n| n.to_le_bytes()).collect();
    b[cluster(4)..cluster(4) + raw.len()].copy_from_slice(&raw);
    let sum = raw.iter().fold(0_u32, |n, b| {
        (n >> 1 | (n & 1) << 31).wrapping_add(u32::from(*b))
    });
    let at = cluster(2) + 32;
    b[at] = 0x82;
    put32(&mut b, at + 4, sum);
    put32(&mut b, at + 20, 4);
    put64(&mut b, at + 24, raw.len() as u64);
    let at = entry(
        &mut b,
        cluster(2) + 64,
        &"prefixNoChain.bin".encode_utf16().collect::<Vec<_>>(),
        5,
        700,
        600,
        true,
        false,
    );
    let at = entry(&mut b, at, &[0xd800, 88], 7, 900, 900, false, false);
    entry(
        &mut b,
        at,
        &"nested".encode_utf16().collect::<Vec<_>>(),
        10,
        512,
        512,
        true,
        true,
    );
    entry(
        &mut b,
        cluster(10),
        &"inside".encode_utf16().collect::<Vec<_>>(),
        11,
        5,
        5,
        true,
        false,
    );
    for i in 0..1024 {
        b[cluster(5) + i] = ((i * 17 + 3) % 251) as u8;
    } // Tail contains poison, not zeros.
    for i in 0..512 {
        b[cluster(7) + i] = ((i * 13 + 9) % 251) as u8;
        b[cluster(9) + i] = (((i + 512) * 13 + 9) % 251) as u8;
    }
    b[cluster(11)..cluster(11) + 5].copy_from_slice(b"child");
    b
}

struct Source(Vec<u8>);
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let bytes = self
            .0
            .get(
                at..at
                    .checked_add(out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            )
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExfatAuditLimits {
    ExfatAuditLimits {
        clusters: 5000,
        entries: 100,
        directory_slots: 256,
        work: 20000,
        findings: 100,
    }
}
fn read_limits() -> ExfatReadLimits {
    ExfatReadLimits {
        max_chain_clusters: 512,
        max_directory_slots: 128,
        max_upcase_bytes: 131072,
    }
}
fn run(bytes: Vec<u8>, r: &Resources) -> partmgr::fs_core::Result<ExfatAuditReport> {
    audit_exfat(Arc::new(Source(bytes)), read_limits(), limits(), r)
}
#[test]
fn complete_ownership_includes_invalid_data_tail_and_free_ranges() {
    let r = resources();
    let report = run(fixture(), &r).unwrap();
    assert!(report.is_clean());
    assert!(report.namespace_complete());
    assert_eq!(report.objects(), 5);
    assert_eq!(report.owned_clusters(), 9);
    assert_eq!(report.allocated_clusters(), 9);
    assert_eq!(report.bad_clusters(), 0);
    assert_eq!(
        report
            .free_ranges()
            .iter()
            .map(|range| range.length)
            .sum::<u64>(),
        (4040 - 9) * 512
    );
    assert!(
        report
            .free_ranges()
            .iter()
            .all(|range| range.offset >= HEAP as u64)
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
fn bitmap(bytes: &mut [u8], cluster: u32, allocated: bool) {
    let index = (cluster - 2) as usize;
    let at = cluster_offset_bitmap() + index / 8;
    if allocated {
        bytes[at] |= 1 << (index % 8)
    } else {
        bytes[at] &= !(1 << (index % 8))
    }
}
fn cluster_offset_bitmap() -> usize {
    cluster(3)
}
#[test]
fn crosslinks_lost_bitmap_mismatch_and_percent_suppress_free_ranges() {
    for (case, mut bytes) in (0..4).map(|n| (n, fixture())) {
        match case {
            0 => {
                put32(&mut bytes, cluster(10) + 32 + 20, 5);
                fix_set(&mut bytes, cluster(10));
            }
            1 => bitmap(&mut bytes, 12, true),
            2 => bitmap(&mut bytes, 11, false),
            _ => bytes[112] = 1,
        }
        let report = run(bytes, &resources()).unwrap();
        assert!(report.namespace_complete());
        assert!(!report.is_clean());
        assert!(report.free_ranges().is_empty());
        assert!(report.findings().iter().any(|f| matches!(
            (case, f),
            (0, ExfatAuditFinding::CrossLink { cluster: 5 })
                | (1, ExfatAuditFinding::LostAllocation { cluster: 12 })
                | (2, ExfatAuditFinding::ReferencedFree { cluster: 11 })
                | (3, ExfatAuditFinding::PercentInUse { .. })
        )));
    }
}
#[test]
fn directory_alias_and_malformed_descendants_are_incomplete() {
    for case in 0..5 {
        let mut bytes = fixture();
        match case {
            0 => {
                entry(
                    &mut bytes,
                    cluster(10) + 96,
                    &[65],
                    10,
                    512,
                    512,
                    true,
                    true,
                );
            }
            1 => {
                put32(&mut bytes, 24 * SECTOR + 7 * 4, 7);
            }
            2 => {
                bytes[cluster(10) + 2] ^= 1;
            }
            3 => {
                entry(
                    &mut bytes,
                    cluster(2) + 384,
                    &[66],
                    9,
                    1024,
                    1024,
                    true,
                    true,
                );
            }
            _ => {
                entry(&mut bytes, cluster(10) + 96, &[67], 2, 512, 512, true, true);
            }
        }
        let report = run(bytes, &resources()).unwrap();
        assert!(!report.namespace_complete());
        assert!(!report.is_clean());
        assert!(report.free_ranges().is_empty());
        assert!(report.findings().iter().any(|f| matches!(
            f,
            ExfatAuditFinding::DuplicateDirectory { .. } | ExfatAuditFinding::InvalidObject { .. }
        )));
    }
}
#[test]
fn stale_contiguous_and_free_fat_values_are_not_chain_ownership() {
    let mut bytes = fixture();
    put32(&mut bytes, 24 * SECTOR + 5 * 4, 0xfffffff7);
    put32(&mut bytes, 24 * SECTOR + 12 * 4, 123);
    assert!(run(bytes, &resources()).unwrap().is_clean());
    let mut bytes = fixture();
    bitmap(&mut bytes, 12, true);
    put32(&mut bytes, 24 * SECTOR + 12 * 4, 0xfffffff7);
    let report = run(bytes, &resources()).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.bad_clusters(), 1);
    assert_eq!(report.allocated_clusters(), 10);
    let mut bytes = fixture();
    put32(&mut bytes, 24 * SECTOR + 12 * 4, 0xfffffff7);
    let report = run(bytes, &resources()).unwrap();
    assert!(
        report
            .findings()
            .contains(&ExfatAuditFinding::BadClusterFree { cluster: 12 })
    );
    assert!(report.free_ranges().is_empty());
}
#[test]
fn explicit_bounds_cancellation_and_strict_profile_errors_return_no_report() {
    for case in 0..5 {
        let mut limits = limits();
        match case {
            0 => limits.clusters = 4039,
            1 => limits.entries = 4,
            2 => limits.directory_slots = 16,
            3 => limits.work = 30,
            _ => limits.findings = 0,
        };
        let mut bytes = fixture();
        if case == 4 {
            bitmap(&mut bytes, 12, true)
        };
        let r = resources();
        let err = audit_exfat(Arc::new(Source(bytes)), read_limits(), limits, &r)
            .err()
            .unwrap();
        assert_eq!(err.kind, ErrorKind::BudgetExhausted);
        assert_eq!(r.memory.used(), 0);
    }
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        run(fixture(), &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    let r = resources();
    r.cancellation.cancel();
    assert_eq!(run(fixture(), &r).err().unwrap().kind, ErrorKind::Cancelled);
    let mut bytes = fixture();
    bytes[106] = 2;
    assert_eq!(
        run(bytes, &resources()).err().unwrap().kind,
        ErrorKind::Unsupported
    );
}

#[test]
#[ignore = "enabled native gate requires mkfs.exfat, fsck.exfat and sha256sum"]
fn native_read_only_audit_agrees_with_exfatprogs_clean_and_crosslinked_images() {
    use std::{ffi::OsStr, process::Command};
    let mkfs = std::env::var_os("PARTMGR_EXFAT_MKFS").unwrap_or_else(|| "mkfs.exfat".into());
    let fsck = std::env::var_os("PARTMGR_EXFAT_FSCK").unwrap_or_else(|| "fsck.exfat".into());
    let evidence = std::env::var_os("PARTMGR_EXFAT_AUDIT_EVIDENCE").map(std::path::PathBuf::from);
    let temp = if let Some(path) = &evidence {
        std::fs::create_dir_all(path).unwrap();
        tempfile::Builder::new()
            .prefix("exfat-audit-")
            .tempdir_in(path)
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let mut receipt = String::from(
        "schema=1\nprofile=exfat-audit-basic-v1\nsource_stability=caller-guaranteed-read-only\n",
    );
    let mut command = |tool: &OsStr, args: &[&OsStr]| {
        let mut cmd = Command::new(tool);
        cmd.args(args);
        let output = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
        receipt.push_str(&format!(
            "command={cmd:?}\nexit={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
        output
    };
    for tool in [&mkfs, &fsck] {
        command(tool, &[OsStr::new("-V")]);
        let hash = command(OsStr::new("sha256sum"), &[tool]);
        assert!(hash.status.success());
    }
    let native = temp.path().join("native.exfat");
    std::fs::File::create(&native)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    assert!(
        command(&mkfs, &[OsStr::new("--no-discard"), native.as_os_str()])
            .status
            .success()
    );
    assert!(
        command(&fsck, &[OsStr::new("-n"), native.as_os_str()])
            .status
            .success()
    );
    let report = audit_exfat(
        Arc::new(virtdisk::RawDisk::open(&native).unwrap()),
        ExfatReadLimits {
            max_chain_clusters: 512,
            max_directory_slots: 512,
            max_upcase_bytes: 131072,
        },
        ExfatAuditLimits {
            clusters: 20000,
            entries: 100,
            directory_slots: 1024,
            work: 50000,
            findings: 100,
        },
        &resources(),
    )
    .unwrap();
    assert!(report.is_clean());
    // Scalar-name version allows native tools to diagnose without surrogate conversion.
    for defective in [false, true] {
        let mut bytes = fixture();
        entry(
            &mut bytes,
            cluster(2) + 192,
            &"CHAIN.BIN".encode_utf16().collect::<Vec<_>>(),
            7,
            900,
            900,
            false,
            false,
        );
        if defective {
            put32(&mut bytes, cluster(10) + 32 + 20, 5);
            fix_set(&mut bytes, cluster(10));
        }
        let image = temp.path().join(if defective {
            "crosslink.exfat"
        } else {
            "clean.exfat"
        });
        std::fs::write(&image, &bytes).unwrap();
        let before = command(OsStr::new("sha256sum"), &[image.as_os_str()]);
        assert!(before.status.success());
        let result = command(&fsck, &[OsStr::new("-n"), image.as_os_str()]);
        assert_eq!(
            result.status.success(),
            !defective,
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        let report = audit_exfat(
            Arc::new(virtdisk::RawDisk::open(&image).unwrap()),
            read_limits(),
            limits(),
            &resources(),
        )
        .unwrap();
        assert_eq!(report.is_clean(), !defective);
        if defective {
            assert!(
                report
                    .findings()
                    .contains(&ExfatAuditFinding::CrossLink { cluster: 5 })
            );
            assert!(report.free_ranges().is_empty());
        }
        let after = command(OsStr::new("sha256sum"), &[image.as_os_str()]);
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(std::fs::read(&image).unwrap(), bytes);
    }
    for path in [
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fs_exfat_audit.rs"),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fs_exfat_volume.rs"),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fs_exfat_audit.rs"),
        std::env::current_exe().unwrap(),
    ] {
        assert!(
            command(OsStr::new("sha256sum"), &[path.as_os_str()])
                .status
                .success()
        );
    }
    receipt.push_str("native_mkfs_audit=passed\nindependent_clean_fixture=passed\nindependent_crosslink_diagnosis=passed\nsource_unchanged=passed\nstatus=passed\n");
    if let Some(path) = evidence {
        let retained = temp.keep();
        std::fs::write(
            path.join("exfat-audit-basic-v1.txt"),
            format!("artifact_directory={}\n{receipt}", retained.display()),
        )
        .unwrap();
    }
}

#[test]
fn folded_name_collision_rejects_disjoint_allocation_namespaces() {
    // Both entry sets and name hashes are independently valid; the extra file
    // owns a freshly allocated cluster, so ownership alone cannot find this.
    for duplicate_name in ["prefixNoChain.bin", "PREFIXNOCHAIN.BIN"] {
        let mut bytes = fixture();
        bitmap(&mut bytes, 12, true);
        entry(
            &mut bytes,
            cluster(2) + 384,
            &duplicate_name.encode_utf16().collect::<Vec<_>>(),
            12,
            5,
            5,
            true,
            false,
        );
        let r = resources();
        let error = run(bytes, &r)
            .err()
            .expect("root collision must reject audit");
        assert_eq!(error.kind, ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("duplicate exFAT up-cased native name")
        );
        assert_eq!(r.memory.used(), 0);
    }
    let mut bytes = fixture();
    bitmap(&mut bytes, 12, true);
    entry(
        &mut bytes,
        cluster(10) + 96,
        &"INSIDE".encode_utf16().collect::<Vec<_>>(),
        12,
        5,
        5,
        true,
        false,
    );
    let report = run(bytes, &resources()).unwrap();
    assert!(!report.namespace_complete());
    assert!(!report.is_clean());
    assert!(report.free_ranges().is_empty());
    assert!(report.findings().iter().any(|finding| matches!(finding, ExfatAuditFinding::InvalidObject { message, .. } if message.contains("duplicate exFAT up-cased native name"))));
    assert!(
        !report
            .findings()
            .iter()
            .any(|finding| matches!(finding, ExfatAuditFinding::CrossLink { .. }))
    );
}
