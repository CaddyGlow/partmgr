#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_core::{
        Budget, Cancellation, ErrorKind, MetadataField, NativeName, Resources, StreamKind,
        TreeSource,
    },
    fs_exfat_tree::{ExfatTreeLimits, ExfatTreeSource},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
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
    entry(
        &mut b,
        cluster(2) + 384,
        &"large.bin".encode_utf16().collect::<Vec<_>>(),
        20,
        130123,
        100003,
        true,
        false,
    );
    for n in 20..20 + 130123usize.div_ceil(512) {
        let bit = n - 2;
        b[cluster(3) + bit / 8] |= 1 << (bit % 8);
    }
    for i in 0..130123 {
        b[cluster(20) + i] = ((i * 19 + 7) % 251) as u8;
    }
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
fn tree_limits() -> ExfatTreeLimits {
    ExfatTreeLimits {
        objects: 16,
        directory_clusters: 16,
    }
}
fn open(bytes: Vec<u8>, r: &Resources) -> ExfatTreeSource {
    ExfatTreeSource::inventory(
        ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), r).unwrap(),
        tree_limits(),
        r,
    )
    .unwrap()
}
#[test]
fn exact_utf16_pages_opaque_metadata_and_deferred_large_payload() {
    let r = resources();
    let tree = open(fixture(), &r);
    let root = tree.root();
    let page = tree.directory_page(&root, None, 2, &r).unwrap();
    assert_eq!(page.entries[1].name, NativeName::Utf16(vec![0xd800, 88]));
    let second = tree
        .directory_page(&root, page.next.as_deref(), 2, &r)
        .unwrap();
    assert!(second.next.is_none());
    let large = &second.entries[1].object;
    let metadata = tree.metadata(large, &r).unwrap();
    assert!(matches!(metadata.created, MetadataField::Opaque { .. }));
    assert!(matches!(metadata.native_flags, MetadataField::Known(ref v) if v == &[0x20, 0]));
    let nested = tree
        .directory_page(&second.entries[0].object, None, 1, &r)
        .unwrap();
    assert_eq!(nested.entries.len(), 1);
    let streams = tree.streams(large, &r).unwrap();
    assert_eq!(streams[0].length, 130123);
    let file = tree.open_stream(large, &StreamKind::Data, &r).unwrap();
    let mut buffer = [0; 4096];
    let mut at = 0usize;
    while at < 130123 {
        let n = file.read_at(at as u64, &mut buffer, &r).unwrap();
        assert!(n > 0);
        for (i, value) in buffer[..n].iter().enumerate() {
            assert_eq!(
                *value,
                if at + i < 100003 {
                    (((at + i) * 19 + 7) % 251) as u8
                } else {
                    0
                }
            );
        }
        at += n;
    }
    drop((metadata, streams, nested, page, second, tree));
    assert!(r.memory.used() > 0);
    assert_eq!(file.read_at(99999, &mut buffer[..10], &r).unwrap(), 10);
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn limits_cancellation_scope_and_length_revalidation_refund() {
    for cap in [
        ExfatTreeLimits {
            objects: 5,
            directory_clusters: 16,
        },
        ExfatTreeLimits {
            objects: 16,
            directory_clusters: 1,
        },
    ] {
        let r = resources();
        let volume = ExfatVolume::open(Arc::new(Source::new(fixture())), limits(), &r).unwrap();
        assert_eq!(
            ExfatTreeSource::inventory(volume, cap, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let source = Arc::new(Source::new(fixture()));
    let tree = ExfatTreeSource::inventory(
        ExfatVolume::open(source.clone(), limits(), &r).unwrap(),
        tree_limits(),
        &r,
    )
    .unwrap();
    let other_resources = resources();
    let other = open(fixture(), &other_resources);
    assert_eq!(
        tree.metadata(&other.root(), &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    let page = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
    assert!(
        other
            .directory_page(&other.root(), page.next.as_deref(), 1, &r)
            .is_err()
    );
    source.length.fetch_sub(1, Ordering::AcqRel);
    assert_eq!(
        tree.revalidate(&tree.root(), &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    source.length.fetch_add(1, Ordering::AcqRel);
    r.cancellation.cancel();
    assert_eq!(
        tree.metadata(&tree.root(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    drop((page, tree, other));
    assert_eq!(r.memory.used(), 0);
    assert_eq!(other_resources.memory.used(), 0);
}
#[test]
fn directory_alias_cycle_and_folded_duplicate_rejected() {
    let mut alias = fixture();
    entry(
        &mut alias,
        cluster(2) + 384,
        &"alias".encode_utf16().collect::<Vec<_>>(),
        10,
        512,
        512,
        true,
        true,
    );
    let mut cycle = fixture();
    entry(
        &mut cycle,
        cluster(10),
        &"cycle".encode_utf16().collect::<Vec<_>>(),
        10,
        512,
        512,
        true,
        true,
    );
    let mut folded = fixture();
    entry(
        &mut folded,
        cluster(2) + 384,
        &"NESTED".encode_utf16().collect::<Vec<_>>(),
        20,
        130123,
        100003,
        true,
        false,
    );
    let mut overlap = fixture();
    // Distinct first clusters still alias a later directory allocation cluster.
    entry(
        &mut overlap,
        cluster(2) + 288,
        &"nested".encode_utf16().collect::<Vec<_>>(),
        10,
        1024,
        1024,
        false,
        true,
    );
    put32(&mut overlap, 24 * SECTOR + 10 * 4, 11);
    put32(&mut overlap, 24 * SECTOR + 11 * 4, u32::MAX);
    overlap[cluster(10)..cluster(10) + 1024].fill(0);
    entry(
        &mut overlap,
        cluster(2) + 384,
        &"alias".encode_utf16().collect::<Vec<_>>(),
        11,
        512,
        512,
        true,
        true,
    );
    for bytes in [alias, cycle, overlap, folded] {
        let r = resources();
        let result = ExfatVolume::open(Arc::new(Source::new(bytes)), limits(), &r)
            .and_then(|v| ExfatTreeSource::inventory(v, tree_limits(), &r));
        assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidData);
        assert_eq!(r.memory.used(), 0);
    }
}
