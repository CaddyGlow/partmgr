use partmgr::{
    fs_core::*,
    fs_flash::*,
    fs_jffs2::*,
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
    fs_jffs2_tree::*,
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
    len: AtomicU64,
    fail: AtomicBool,
}
impl Source {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            len: AtomicU64::new(bytes.len() as u64),
            bytes,
            fail: AtomicBool::new(false),
        }
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.len.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("causal JFFS2 fixture error"));
        }
        b.copy_from_slice(
            self.bytes
                .get(p as usize..p as usize + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> Jffs2ReadLimits {
    Jffs2ReadLimits {
        scan_bytes: 1 << 20,
        nodes: 128,
        inodes: 32,
        fragments: 128,
        native_bytes: 4096,
        work: 100000,
    }
}
fn al() -> Jffs2AuditLimits {
    Jffs2AuditLimits {
        entries: 128,
        work: 128,
        findings: 16,
    }
}
fn geo() -> FlashGeometry {
    FlashGeometry {
        erased_byte: 255,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 4096,
        program_bytes: 4,
        layout: FlashLayout::LogicalNor,
    }
}
#[path = "fixtures/jffs2_clean.rs"]
mod fixture;
use fixture::{crc, dir, dword, jffs2_seed as seed};
#[test]
fn independent_both_endian_versions_deletion_sparse_native_tree_and_leases() {
    for big in [false, true] {
        let r = r();
        let s = Arc::new(Source::new(seed(big)));
        let v = Jffs2Volume::open(
            s,
            geo(),
            if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            },
            limits(),
            &r,
        )
        .unwrap();
        let report = audit(&v, al(), &r).unwrap();
        assert!(report.is_clean() && report.is_complete());
        assert_eq!(report.reachable_inodes(), 4);
        assert_eq!(report.historical_inodes(), 1);
        assert_eq!(report.free_ranges().len(), 1);
        drop(report);
        let f = v.open_file(2, &r).unwrap();
        assert_eq!(read_all(&f, 16, &r).unwrap().bytes, b"abXY\0\0");
        let tree = Jffs2TreeSource::inventory(v, al(), &r).unwrap();
        let root = tree.root();
        assert_eq!(root.source >> 64, 10);
        let page = tree.directory_page(&root, None, 1, &r).unwrap();
        assert_eq!(page.entries[0].name, NativeName::Bytes(b"file".to_vec()));
        let next = tree
            .directory_page(&root, page.next.as_deref(), 1, &r)
            .unwrap();
        let nested = next.entries[0].object.clone();
        drop(page);
        drop(next);
        let entries = tree.directory_page(&nested, None, 8, &r).unwrap();
        let link = entries
            .entries
            .iter()
            .find(|e| e.kind == ObjectKind::Symlink)
            .unwrap();
        assert_eq!(
            tree.metadata(&link.object, &r).unwrap().symlink_target,
            MetadataField::Known(NativeName::Bytes(b"../file".to_vec()))
        );
        let file = entries
            .entries
            .iter()
            .find(|e| e.kind == ObjectKind::File)
            .unwrap();
        assert_eq!(file.object, *f.identity());
        drop(entries);
        drop(tree);
        assert!(r.memory.used() > 0);
        assert_eq!(read_all(&f, 16, &r).unwrap().bytes, b"abXY\0\0");
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn crc_geometry_compression_work_and_budget_are_explicit() {
    let r = r();
    let mut b = seed(false);
    b[136] ^= 1;
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(b)),
            geo(),
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
    let mut compressed = seed(false);
    compressed[68 + 56] = 6;
    let c = crc(&compressed[68..68 + 60]);
    dword(&mut compressed, 68 + 64, c, false);
    let error = Jffs2Volume::open(
        Arc::new(Source::new(compressed)),
        geo(),
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    let mut name_crc = seed(false);
    let at = name_crc.windows(4).position(|b| b == b"file").unwrap();
    name_crc[at] ^= 1;
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(name_crc)),
            geo(),
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    let mut b = seed(false);
    b[4] = 255;
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(b)),
            geo(),
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    let mut g = geo();
    g.layout = FlashLayout::PhysicalNand {
        page_bytes: 2048,
        spare_bytes: 64,
    };
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(seed(false))),
            g,
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    let mut l = limits();
    l.work = 1;
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(seed(false))),
            geo(),
            Jffs2Endian::Little,
            l,
            &r
        )
        .is_err()
    );
    let tiny = Resources {
        memory: Budget::new(100),
        cancellation: Cancellation::default(),
    };
    assert!(
        Jffs2Volume::open(
            Arc::new(Source::new(seed(false))),
            geo(),
            Jffs2Endian::Little,
            limits(),
            &tiny
        )
        .is_err()
    );
    assert_eq!(tiny.memory.used(), 0);
}
#[test]
fn namespace_aliases_suppress_erased_ranges_and_deferred_faults_remain_errors() {
    let r = r();
    let mut b = seed(false);
    let append = dir(3, 3, 1, b"cycle", 4, false);
    let pos = b.iter().rposition(|x| *x != 255).unwrap() + 1;
    let pos = pos.next_multiple_of(4);
    b[pos..pos + append.len()].copy_from_slice(&append);
    let v = Jffs2Volume::open(
        Arc::new(Source::new(b)),
        geo(),
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    let report = audit(&v, al(), &r).unwrap();
    assert!(!report.is_clean());
    assert!(report.free_ranges().is_empty());
    drop(report);
    drop(v);
    let s = Arc::new(Source::new(seed(false)));
    let v = Jffs2Volume::open(s.clone(), geo(), Jffs2Endian::Little, limits(), &r).unwrap();
    let f = v.open_file(2, &r).unwrap();
    drop(v);
    s.fail.store(true, Ordering::Relaxed);
    let e = f.read_at(0, &mut [0; 2], &r).unwrap_err();
    assert!(std::error::Error::source(&e).is_some());
    s.fail.store(false, Ordering::Relaxed);
    s.len.store(4096, Ordering::Relaxed);
    assert!(f.read_at(4, &mut [0; 2], &r).is_err());
    s.len.store(8192, Ordering::Relaxed);
    r.cancellation.cancel();
    assert!(f.read_at(4, &mut [0; 2], &r).is_err());
    drop(f);
    assert_eq!(r.memory.used(), 0);
}
