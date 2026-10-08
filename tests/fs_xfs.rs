#[path = "common/reader_contract.rs"]
mod reader_contract;
use partmgr::{
    fs_core::*,
    fs_xfs::*,
    fs_xfs_audit::{XfsAuditFinding, XfsAuditLimits, audit},
    fs_xfs_tree::*,
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
    reads: AtomicU64,
    fail: AtomicBool,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(false),
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
            return Err(io::Error::other("causal XFS source failure"));
        }
        out.copy_from_slice(
            self.bytes
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> XfsReadLimits {
    XfsReadLimits {
        allocation_groups: 8,
        inodes: 256,
        metadata_records: 4096,
        extent_records: 256,
        work: 1_000_000,
        log_bytes: 128 << 20,
    }
}
fn audit_limits() -> XfsAuditLimits {
    XfsAuditLimits {
        blocks: 200000,
        entries: 1024,
        work: 1_000_000,
        findings: 512,
    }
}
#[path = "fixtures/xfs_clean.rs"]
mod clean_fixture;
use clean_fixture::{crc, d, q, short, xfs_seed as fixture};
#[test]
fn independent_crc_sparse_hardlinks_metadata_and_complete_audit() {
    let r = r();
    let s = Arc::new(Source::new(fixture()));
    let v = XfsVolume::open(s.clone(), limits(), &r).unwrap();
    let report = audit(&v, audit_limits(), &r).unwrap();
    assert!(report.is_complete());
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_inodes(), 5);
    assert!(!report.free_ranges().is_empty());
    let f = v.open_file(67, &r).unwrap();
    reader_contract::assert_eof_contract(&f, &r);
    let mut b = vec![9; 16384];
    f.read_at(0, &mut b, &r).unwrap();
    assert!(b[..4096].iter().all(|b| *b == 0));
    assert!(b[12288..].iter().all(|b| *b == 0));
    assert_eq!(&b[4096..12288], &s.bytes[16 * 4096..18 * 4096]);
    let mut extents = Vec::new();
    f.visit_extents(&r, &mut |e| {
        extents.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(extents.len(), 3);
    assert_eq!(extents[0].kind, ExtentKind::Hole);
    let tree = XfsTreeSource::inventory(
        v,
        XfsTreeLimits {
            objects: 16,
            entries: 16,
            depth: 8,
        },
        &r,
    )
    .unwrap();
    let root = tree.root();
    let page = tree.directory_page(&root, None, 1, &r).unwrap();
    assert!(page.next.is_some());
    let next = tree
        .directory_page(&root, page.next.as_deref(), 1, &r)
        .unwrap();
    let dir = next
        .entries
        .iter()
        .chain(page.entries.iter())
        .find(|e| e.kind == ObjectKind::Directory)
        .unwrap();
    let child = tree.directory_page(&dir.object, None, 10, &r).unwrap();
    assert_eq!(child.entries[0].name, NativeName::Bytes(vec![b'x', 255]));
    let alias = next
        .entries
        .iter()
        .chain(page.entries.iter())
        .find(|e| e.kind == ObjectKind::File)
        .unwrap();
    assert_eq!(alias.object, child.entries[0].object);
    let metadata = tree.metadata(&alias.object, &r).unwrap();
    assert_eq!(metadata.mode, MetadataField::Known(0x81a0));
    assert_eq!(
        metadata.owner,
        MetadataField::Known([1234u32.to_be_bytes(), 5678u32.to_be_bytes()].concat())
    );
    assert!(matches!(metadata.created, MetadataField::Known(_)));
    let payload = tree
        .open_stream(&alias.object, &StreamKind::Data, &r)
        .unwrap();
    drop(child);
    drop(next);
    drop(page);
    drop(metadata);
    drop(tree);
    drop(f);
    drop(report);
    assert!(r.memory.used() > 0);
    let mut random = [0; 31];
    payload.read_at(4099, &mut random, &r).unwrap();
    assert_eq!(random, s.bytes[16 * 4096 + 3..16 * 4096 + 34]);
    drop(payload);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn allocated_unwritten_is_zero_and_retained_allocation_owned() {
    let r = r();
    let mut b = fixture();
    q(&mut b[67 * 512..68 * 512], 176, (1u64 << 63) | (1 << 9));
    crc(&mut b[67 * 512..68 * 512], 100);
    let s = Arc::new(Source::new(b));
    let v = XfsVolume::open(s.clone(), limits(), &r).unwrap();
    let a = audit(&v, audit_limits(), &r).unwrap();
    assert!(a.is_clean());
    let f = v.open_file(67, &r).unwrap();
    let reads = s.reads.load(Ordering::SeqCst);
    let mut out = [17; 8192];
    f.read_at(4096, &mut out, &r).unwrap();
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(s.reads.load(Ordering::SeqCst), reads);
    let mut kinds = Vec::new();
    f.visit_extents(&r, &mut |e| {
        kinds.push(e.kind);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        kinds,
        [ExtentKind::Hole, ExtentKind::Unwritten, ExtentKind::Hole]
    );
}
#[test]
fn defects_suppress_free_ranges_and_caps_refund() {
    let r = r();
    let mut b = fixture();
    q(&mut b[67 * 512..68 * 512], 184, (4 << 21) | 2);
    crc(&mut b[67 * 512..68 * 512], 100);
    let v = XfsVolume::open(Arc::new(Source::new(b)), limits(), &r).unwrap();
    let a = audit(&v, audit_limits(), &r).unwrap();
    assert!(!a.is_clean());
    assert!(a.free_ranges().is_empty());
    assert!(
        a.findings()
            .iter()
            .any(|f| matches!(f, XfsAuditFinding::CrossLink { .. }))
    );
    assert!(
        a.findings()
            .iter()
            .any(|f| matches!(f, XfsAuditFinding::LostAllocation { .. }))
    );
    drop(a);
    drop(v);
    assert_eq!(r.memory.used(), 0);
    let mut low = limits();
    low.work = 1;
    assert_eq!(
        XfsVolume::open(Arc::new(Source::new(fixture())), low, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    let low = Resources {
        memory: Budget::new(1024),
        cancellation: Cancellation::default(),
    };
    assert!(XfsVolume::open(Arc::new(Source::new(fixture())), limits(), &low).is_err());
    assert_eq!(low.memory.used(), 0);
}
#[test]
fn checksums_features_log_cancel_and_stale_are_explicit() {
    let r = r();
    let mut b = fixture();
    b[42] ^= 1;
    assert_eq!(
        XfsVolume::open(Arc::new(Source::new(b)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidData
    );
    let mut b = fixture();
    d(&mut b, 212, 4);
    for ag in 0..4 {
        let start = ag * 64 * 4096;
        d(&mut b[start..start + 512], 212, 4);
        crc(&mut b[start..start + 512], 224);
    }
    assert_eq!(
        XfsVolume::open(Arc::new(Source::new(b)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    let mut b = fixture();
    b[(2 * 64 + 12) * 4096 + 1024] = 1;
    assert_eq!(
        XfsVolume::open(Arc::new(Source::new(b)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    let s = Arc::new(Source::new(fixture()));
    let v = XfsVolume::open(s.clone(), limits(), &r).unwrap();
    let f = v.open_file(67, &r).unwrap();
    s.length.store(1, Ordering::SeqCst);
    assert_eq!(
        v.check_stability(&r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert!(f.read_at(4096, &mut [0; 1], &r).is_err());
    s.length.store(s.bytes.len() as u64, Ordering::SeqCst);
    r.cancellation.cancel();
    assert_eq!(
        f.read_at(0, &mut [0; 1], &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(f);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn allocation_identical_namespace_defects_and_foreign_tokens_fail() {
    let r = r();
    let mut b = fixture();
    let dir = short(
        64,
        &[(b"first", 68, 2), (b"second", 68, 2), (b"alias", 67, 1)],
    );
    let root = &mut b[64 * 512..65 * 512];
    q(root, 56, dir.len() as u64);
    root[176..].fill(0);
    root[176..176 + dir.len()].copy_from_slice(&dir);
    crc(root, 100);
    let v = XfsVolume::open(Arc::new(Source::new(b)), limits(), &r).unwrap();
    let a = audit(&v, audit_limits(), &r).unwrap();
    assert!(!a.is_clean());
    assert!(a.free_ranges().is_empty());
    assert!(
        a.findings()
            .iter()
            .any(|f| matches!(f, XfsAuditFinding::DirectoryTopology { .. }))
    );
    assert!(
        XfsTreeSource::inventory(
            v,
            XfsTreeLimits {
                objects: 16,
                entries: 16,
                depth: 8
            },
            &r
        )
        .is_err()
    );
    drop(a);
    let mut b = fixture();
    let dir = short(64, &[(b"same", 68, 2), (b"same", 67, 1)]);
    let root = &mut b[64 * 512..65 * 512];
    q(root, 56, dir.len() as u64);
    root[176..].fill(0);
    root[176..176 + dir.len()].copy_from_slice(&dir);
    crc(root, 100);
    assert_eq!(
        XfsVolume::open(Arc::new(Source::new(b)), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidData
    );
    let first = XfsTreeSource::inventory(
        XfsVolume::open(Arc::new(Source::new(fixture())), limits(), &r).unwrap(),
        XfsTreeLimits {
            objects: 16,
            entries: 16,
            depth: 8,
        },
        &r,
    )
    .unwrap();
    let second = XfsTreeSource::inventory(
        XfsVolume::open(Arc::new(Source::new(fixture())), limits(), &r).unwrap(),
        XfsTreeLimits {
            objects: 16,
            entries: 16,
            depth: 8,
        },
        &r,
    )
    .unwrap();
    let page = first.directory_page(&first.root(), None, 1, &r).unwrap();
    assert!(
        second
            .directory_page(&second.root(), page.next.as_deref(), 1, &r)
            .is_err()
    );
    assert!(second.revalidate(&first.root(), &r).is_err());
    drop(page);
    drop(first);
    drop(second);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn zero_ranges_revalidate_both_contexts_and_causal_errors_survive() {
    let r = r();
    let s = Arc::new(Source::new(fixture()));
    let v = XfsVolume::open(s.clone(), limits(), &r).unwrap();
    let file = v.open_file(67, &r).unwrap();
    let other = Resources {
        memory: r.memory.clone(),
        cancellation: Cancellation::default(),
    };
    s.fail.store(true, Ordering::SeqCst);
    let error = file.read_at(4096, &mut [0; 1], &other).unwrap_err();
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains("causal XFS source failure")
    );
    let mut zero = [1; 31];
    file.read_at(0, &mut zero, &other).unwrap();
    assert_eq!(zero, [0; 31]);
    s.length.store(1, Ordering::SeqCst);
    assert_eq!(
        file.read_at(0, &mut zero, &other).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    s.length.store(s.bytes.len() as u64, Ordering::SeqCst);
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(0, &mut zero, &other).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(file);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
