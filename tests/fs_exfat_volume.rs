#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, ExtentKind, FileRead, Resources},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
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
fn limits() -> ExfatReadLimits {
    ExfatReadLimits {
        max_chain_clusters: 512,
        max_directory_slots: 128,
        max_upcase_bytes: 131072,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(2 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
struct Source {
    bytes: Vec<u8>,
    length: AtomicU64,
    fail: AtomicBool,
    reads: AtomicU64,
    payload_reads: AtomicU64,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            fail: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            payload_reads: AtomicU64::new(0),
        }
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("injected contextual exFAT failure"));
        }
        if at >= cluster(5) as u64 && at < (cluster(9) + 512) as u64 {
            self.payload_reads.fetch_add(1, Ordering::AcqRel);
        }
        let at = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(at..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
#[test]
fn indexed_contiguous_chained_utf16_and_valid_length_semantics() {
    let r = resources();
    let source = Arc::new(Source::new(fixture()));
    let volume = ExfatVolume::open(source.clone(), limits(), &r).unwrap();
    let root = volume.root_directory(&r).unwrap();
    assert_eq!(root.entries().len(), 3);
    let first = root
        .lookup(&"PREFIXNOCHAIN.BIN".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .unwrap();
    assert_eq!(first.raw_metadata().len(), 4);
    let file = volume.open_file(first, &r).unwrap();
    assert_eq!(first.valid_data_length(), 600);
    let mut out = [0; 150];
    file.read_at(550, &mut out, &r).unwrap();
    assert_eq!(
        &out[..50],
        &(550..600)
            .map(|i| ((i * 17 + 3) % 251) as u8)
            .collect::<Vec<_>>()
    );
    assert!(out[50..].iter().all(|b| *b == 0));
    let count = source.payload_reads.load(Ordering::Acquire);
    file.read_at(600, &mut out, &r).unwrap();
    assert!(out[..100].iter().all(|b| *b == 0));
    assert_eq!(source.payload_reads.load(Ordering::Acquire), count);
    let mut extents = Vec::new();
    file.visit_extents(&r, &mut |extent| {
        extents.push(extent);
        Ok(())
    })
    .unwrap();
    assert_eq!(extents.len(), 2);
    assert_eq!(extents[0].length, 600);
    assert_eq!(extents[1].kind, ExtentKind::Unwritten);
    assert_eq!(extents[1].length, 100);
    let chain = volume
        .open_file(root.lookup(&[0xd800, 88]).unwrap().unwrap(), &r)
        .unwrap();
    chain.read_at(490, &mut out, &r).unwrap();
    assert_eq!(
        out,
        std::array::from_fn(|i| (((i + 490) * 13 + 9) % 251) as u8)
    );
    let nested = volume
        .read_directory(
            root.lookup(&"nested".encode_utf16().collect::<Vec<_>>())
                .unwrap()
                .unwrap(),
            &r,
        )
        .unwrap();
    let child = volume.open_file(&nested.entries()[0], &r).unwrap();
    let mut bytes = [0; 5];
    child.read_at(0, &mut bytes, &r).unwrap();
    assert_eq!(&bytes, b"child");
    let retained = file.clone();
    drop(file);
    drop(chain);
    drop(child);
    drop(nested);
    drop(root);
    drop(volume);
    assert!(r.memory.used() > 0);
    retained.read_at(7, &mut bytes, &r).unwrap();
    drop(retained);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn strict_system_and_file_corruptions_are_rejected() {
    for mutate in [
        |b: &mut Vec<u8>| b[cluster(3)] &= !1,
        |b: &mut Vec<u8>| b[cluster(4) + 4] ^= 1,
        |b: &mut Vec<u8>| put32(b, 24 * SECTOR + 2 * 4, 2),
        |b: &mut Vec<u8>| b[cluster(2) + 64 + 2] ^= 1,
        |b: &mut Vec<u8>| {
            b[cluster(2) + 64 + 32 + 4] ^= 1;
            fix_set(b, cluster(2) + 64);
        },
        |b: &mut Vec<u8>| {
            put64(b, cluster(2) + 64 + 32 + 8, 701);
            fix_set(b, cluster(2) + 64);
        },
        |b: &mut Vec<u8>| {
            b[cluster(2) + 64 + 32] = 0xe0;
            fix_set(b, cluster(2) + 64);
        },
        |b: &mut Vec<u8>| {
            b[cluster(2) + 64 + 32 + 1] = 7;
            fix_set(b, cluster(2) + 64);
        },
        |b: &mut Vec<u8>| b[cluster(2) + 15 * 32] = 0x83,
        |b: &mut Vec<u8>| {
            b[106] = 2;
            b[12 * SECTOR + 106] = 2;
        },
    ] {
        let mut bytes = fixture();
        mutate(&mut bytes);
        let r = resources();
        assert!(ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    for mutate in [
        |b: &mut Vec<u8>| b[cluster(3)] &= !(1 << 3),
        |b: &mut Vec<u8>| {
            put32(b, 24 * SECTOR + 7 * 4, 7);
        },
        |b: &mut Vec<u8>| {
            put32(b, 24 * SECTOR + 9 * 4, 11);
        },
        |b: &mut Vec<u8>| {
            put32(b, cluster(2) + 64 + 32 + 20, 2);
            fix_set(b, cluster(2) + 64);
        },
    ] {
        let mut bytes = fixture();
        mutate(&mut bytes);
        let r = resources();
        let volume = ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
        let root = volume.root_directory(&r).unwrap();
        let entry = if volume.open_file(&root.entries()[0], &r).is_err() {
            &root.entries()[0]
        } else {
            &root.entries()[1]
        };
        assert!(volume.open_file(entry, &r).is_err());
    }
}
#[test]
fn source_cancellation_io_limits_staleness_and_foreign_identity() {
    let r = resources();
    let source = Arc::new(Source::new(fixture()));
    let volume = ExfatVolume::open(source.clone(), limits(), &r).unwrap();
    let root = volume.root_directory(&r).unwrap();
    let file = volume.open_file(&root.entries()[0], &r).unwrap();
    let mut out = [0; 8];
    source.fail.store(true, Ordering::Release);
    assert!(file.read_at(0, &mut out, &r).unwrap_err().source.is_some());
    source.fail.store(false, Ordering::Release);
    source.length.fetch_add(1, Ordering::AcqRel);
    assert_eq!(
        file.read_at(0, &mut out, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.length.fetch_sub(1, Ordering::AcqRel);
    let other = ExfatVolume::open(Arc::new(Source::new(fixture())), limits(), &r).unwrap();
    assert_eq!(
        other.open_file(&root.entries()[0], &r).err().unwrap().kind,
        ErrorKind::InvalidOperation
    );
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(9999, &mut out, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    let low = Resources {
        memory: Budget::new(8192),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        ExfatVolume::open(Arc::new(Source::new(fixture())), limits(), &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
}

fn uncompressed_table(bytes: &mut [u8], bad_ascii: bool) {
    let mut table: Vec<u16> = (0..=65535).map(uppercase).collect();
    table[0xe4] = 0xc4;
    if bad_ascii {
        table[97] = 97;
    }
    let serialized: Vec<u8> = table.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let start = cluster(20);
    bytes[start..start + serialized.len()].copy_from_slice(&serialized);
    for n in 20..=275 {
        put32(
            bytes,
            24 * SECTOR + n as usize * 4,
            if n == 275 { u32::MAX } else { n + 1 },
        );
        let bit = (n - 2) as usize;
        bytes[cluster(3) + bit / 8] |= 1 << (bit % 8);
    }
    bytes[cluster(3)] &= !(1 << 2);
    put32(bytes, 24 * SECTOR + 4 * 4, 0);
    let sum = serialized.iter().fold(0_u32, |n, b| {
        (n >> 1 | (n & 1) << 31).wrapping_add(u32::from(*b))
    });
    let at = cluster(2) + 32;
    put32(bytes, at + 4, sum);
    put32(bytes, at + 20, 20);
    put64(bytes, at + 24, serialized.len() as u64);
}
#[test]
fn full_custom_upcase_uncompressed_mapping_and_native_collisions() {
    let mut bytes = fixture();
    uncompressed_table(&mut bytes, false);
    let r = resources();
    let volume = ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &r).unwrap();
    assert!(volume.names_equal(&[0xe4], &[0xc4]));
    assert!(volume.names_equal(&[97], &[65]));
    let root = volume.root_directory(&r).unwrap();
    assert_eq!(root.entries().len(), 3);
    let mut bytes = fixture();
    uncompressed_table(&mut bytes, true);
    assert!(ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &resources()).is_err());
    let mut bytes = fixture();
    entry(
        &mut bytes,
        cluster(2) + 192,
        &"PREFIXNOCHAIN.BIN".encode_utf16().collect::<Vec<_>>(),
        7,
        900,
        900,
        false,
        false,
    );
    let error = ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &resources())
        .err()
        .unwrap();
    assert!(error.context.contains("duplicate"));
}
#[test]
fn unsupported_profiles_and_bounded_work_fail_explicitly() {
    for flags in [2_u16, 4, 16] {
        let mut bytes = fixture();
        put16(&mut bytes, 106, flags);
        put16(&mut bytes, 12 * SECTOR + 106, flags);
        assert_eq!(
            ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &resources())
                .err()
                .unwrap()
                .kind,
            ErrorKind::Unsupported
        );
    }
    let mut bytes = fixture();
    bytes[110] = 2;
    bytes[12 * SECTOR + 110] = 2;
    put32(&mut bytes, 88, 88);
    put32(&mut bytes, 12 * SECTOR + 88, 88);
    put32(&mut bytes, 92, 4096 - 88);
    put32(&mut bytes, 12 * SECTOR + 92, 4096 - 88);
    seal(&mut bytes);
    assert_eq!(
        ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &resources())
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    let mut short = limits();
    short.max_directory_slots = 8;
    assert_eq!(
        ExfatVolume::open(Arc::new(Source::new(fixture())), short, &resources())
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    let r = resources();
    let mut small = limits();
    small.max_chain_clusters = 1;
    let volume = ExfatVolume::open(Arc::new(Source::new(fixture())), small, &r).unwrap();
    let root = volume.root_directory(&r).unwrap();
    assert_eq!(
        volume.open_file(&root.entries()[0], &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
}

#[test]
#[ignore = "explicit native gate requires mkfs.exfat, fsck.exfat, fls and icat"]
fn native_empty_volume_and_independent_manual_payload_oracle() {
    use std::{ffi::OsStr, path::Path, process::Command};
    fn command(program: &OsStr, args: &[&OsStr], receipt: &mut String) -> std::process::Output {
        let mut command = Command::new(program);
        command.args(args);
        receipt.push_str(&format!("command={command:?}\n"));
        let output = command
            .output()
            .unwrap_or_else(|e| panic!("{command:?}: {e}"));
        receipt.push_str(&format!(
            "exit={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
        assert!(output.status.success(), "{receipt}");
        output
    }
    let mkfs = std::env::var_os("PARTMGR_EXFAT_MKFS").unwrap_or_else(|| "mkfs.exfat".into());
    let fsck = std::env::var_os("PARTMGR_EXFAT_FSCK").unwrap_or_else(|| "fsck.exfat".into());
    let fls = std::env::var_os("PARTMGR_EXFAT_FLS").unwrap_or_else(|| "fls".into());
    let icat = std::env::var_os("PARTMGR_EXFAT_ICAT").unwrap_or_else(|| "icat".into());
    let evidence = std::env::var_os("PARTMGR_EXFAT_VOLUME_EVIDENCE").map(std::path::PathBuf::from);
    let temp = if let Some(path) = &evidence {
        std::fs::create_dir_all(path).unwrap();
        tempfile::Builder::new()
            .prefix("exfat-volume-")
            .tempdir_in(path)
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let mut receipt = String::from("profile=exfat-volume-basic-v1\nstatus=running\n");
    for tool in [&mkfs, &fsck] {
        let output = Command::new(tool).arg("-V").output().unwrap();
        receipt.push_str(&format!(
            "version={tool:?} exit={} stdout={} stderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    for tool in [&fls, &icat] {
        command(tool, &[OsStr::new("-V")], &mut receipt);
    }
    let native = temp.path().join("native.exfat");
    std::fs::File::create(&native)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    command(
        &mkfs,
        &[OsStr::new("--no-discard"), native.as_os_str()],
        &mut receipt,
    );
    command(&fsck, &[OsStr::new("-n"), native.as_os_str()], &mut receipt);
    let r = resources();
    let volume = ExfatVolume::open(
        Arc::new(virtdisk::RawDisk::open(&native).unwrap()),
        ExfatReadLimits {
            max_chain_clusters: 512,
            max_directory_slots: 512,
            max_upcase_bytes: 131072,
        },
        &r,
    )
    .unwrap();
    assert!(volume.root_directory(&r).unwrap().entries().is_empty());
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    // Unicode names with unpaired surrogates cannot be portably requested from native tools;
    // use a separately authored scalar-name variant for independent namespace/payload checks.
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
    let manual = temp.path().join("manual.exfat");
    std::fs::write(&manual, &bytes).unwrap();
    command(&fsck, &[OsStr::new("-n"), manual.as_os_str()], &mut receipt);
    let volume = ExfatVolume::open(
        Arc::new(virtdisk::RawDisk::open(&manual).unwrap()),
        limits(),
        &resources(),
    )
    .unwrap();
    let root = volume.root_directory(&resources()).unwrap();
    assert_eq!(root.entries().len(), 3);
    let listing = command(
        &fls,
        &[
            OsStr::new("-f"),
            OsStr::new("exfat"),
            OsStr::new("-r"),
            manual.as_os_str(),
        ],
        &mut receipt,
    );
    let listing = String::from_utf8(listing.stdout).unwrap();
    let mut extract = |name: &str| {
        let line = listing
            .lines()
            .find(|line| line.split_once('\t').is_some_and(|(_, n)| n == name))
            .unwrap_or_else(|| panic!("missing {name}: {listing}"));
        let id = line
            .split_once(':')
            .unwrap()
            .0
            .split_whitespace()
            .last()
            .unwrap();
        command(
            &icat,
            &[
                OsStr::new("-f"),
                OsStr::new("exfat"),
                manual.as_os_str(),
                OsStr::new(id),
            ],
            &mut receipt,
        )
        .stdout
    };
    let expected: Vec<_> = (0..900).map(|i| ((i * 13 + 9) % 251) as u8).collect();
    assert_eq!(extract("CHAIN.BIN"), expected);
    assert_eq!(extract("inside"), b"child");
    let expected: Vec<_> = (0..700)
        .map(|i| {
            if i < 600 {
                ((i * 17 + 3) % 251) as u8
            } else {
                0
            }
        })
        .collect();
    let forensic = extract("prefixNoChain.bin");
    assert_eq!(&forensic[..600], &expected[..600]);
    assert_eq!(forensic.len(), 700);
    let file = volume.open_file(&root.entries()[0], &resources()).unwrap();
    let mut logical = vec![0xff; 700];
    assert_eq!(file.read_at(0, &mut logical, &resources()).unwrap(), 700);
    assert_eq!(logical, expected);
    receipt.push_str(&format!(
        "native_vdl_tail_zero={}\n",
        forensic[600..].iter().all(|&b| b == 0)
    ));
    receipt.push_str("native_empty_root=passed\nmanual_native_fsck=passed\nnative_chained_payload=passed\nnative_nested_payload=passed\nnative_initialized_prefix=passed\nreader_valid_data_length=passed\nnative_vdl_semantic_oracle=gap-forensic-icat-exposes-uninitialized-bytes\nstatus=passed-basic-profile\n");
    for (name, payload) in [
        (
            "chain.expected",
            (0..900)
                .map(|i| ((i * 13 + 9) % 251) as u8)
                .collect::<Vec<_>>(),
        ),
        ("contiguous.logical", logical),
        ("contiguous.forensic", forensic),
    ] {
        let path = temp.path().join(name);
        std::fs::write(&path, payload).unwrap();
        command(OsStr::new("sha256sum"), &[path.as_os_str()], &mut receipt);
    }
    for path in [&manual, &native] {
        command(OsStr::new("sha256sum"), &[path.as_os_str()], &mut receipt);
    }
    for file in [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fs_exfat_volume.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fs_exfat_volume.rs"),
    ] {
        command(OsStr::new("sha256sum"), &[file.as_os_str()], &mut receipt);
    }
    if let Some(path) = evidence {
        let retained = temp.keep();
        std::fs::write(
            path.join("exfat-volume-basic-v1.txt"),
            format!("artifact_directory={}\n{receipt}", retained.display()),
        )
        .unwrap();
    }
}

#[test]
fn large_caps_charge_tiny_known_streams_and_directories_by_actual_size() {
    let r = resources();
    let volume = ExfatVolume::open(
        Arc::new(Source::new(fixture())),
        ExfatReadLimits {
            max_chain_clusters: 4000,
            max_directory_slots: 500_000,
            max_upcase_bytes: 131072,
        },
        &r,
    )
    .unwrap();
    let root = volume.root_directory(&r).unwrap();
    let baseline = r.memory.used();
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for _ in 0..8 {
        files.push(volume.open_file(&root.entries()[0], &r).unwrap());
        directories.push(volume.read_directory(&root.entries()[2], &r).unwrap());
    }
    let mut payload = [0xff; 700];
    assert_eq!(files[7].read_at(0, &mut payload, &r).unwrap(), 700);
    assert!(payload[600..].iter().all(|&b| b == 0));
    assert_eq!(
        directories[7].entries()[0].name(),
        &"inside".encode_utf16().collect::<Vec<_>>()
    );
    assert!(r.memory.used() - baseline < 400_000);
    drop(files);
    drop(directories);
    assert_eq!(r.memory.used(), baseline);
    drop(root);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn source_scopes_are_distinct_across_fat_and_exfat_engines() {
    // Independent minimal FAT12 geometry, deliberately opened first in this test.
    let mut fat = vec![0u8; 100 * 512];
    put16(&mut fat, 11, 512);
    fat[13] = 1;
    put16(&mut fat, 14, 1);
    fat[16] = 1;
    put16(&mut fat, 17, 16);
    put16(&mut fat, 19, 100);
    fat[21] = 0xf8;
    put16(&mut fat, 22, 1);
    fat[510..512].copy_from_slice(&[0x55, 0xaa]);
    let fat = partmgr::fs_fat::FatVolume::open(Arc::new(Source::new(fat))).unwrap();
    let r = resources();
    let exfat = ExfatVolume::open(Arc::new(Source::new(fixture())), limits(), &r).unwrap();
    assert_ne!(fat.root_identity().source, exfat.root_identity().source);
    assert_eq!(fat.root_identity().source >> 64, 0);
    assert_eq!(exfat.root_identity().source >> 64, 3);
}
