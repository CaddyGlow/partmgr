#![cfg(feature = "std")]

use partmgr::fs_file::{ExtentFile, ExtentKind, FileExtent};
use partmgr::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use virtdisk::ReadAt;

struct Source {
    calls: AtomicUsize,
    fail: bool,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        1 << 40
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(io::Error::other("injected read failure"));
        }
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (offset + i as u64) as u8;
        }
        Ok(())
    }
}
fn extent(offset: u64, length: u64, kind: ExtentKind) -> FileExtent {
    FileExtent {
        offset,
        length,
        kind,
    }
}

#[test]
fn random_access_large_file_is_bounded_and_adjacent_reads_coalesce() {
    let source = Arc::new(Source {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let file = ExtentFile::new(
        source.clone(),
        1 << 39,
        vec![
            extent(0, 4096, ExtentKind::Data(8192)),
            extent(4096, 4096, ExtentKind::Data(12288)),
            extent(8192, (1 << 39) - 8192, ExtentKind::Hole),
        ],
        3,
    )
    .unwrap();
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
    assert_eq!(file.extents().len(), 2);
    let mut out = [0; 4096];
    assert_eq!(file.read_at(2048, &mut out).unwrap(), out.len());
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    for (i, byte) in out.iter().enumerate() {
        assert_eq!(*byte, (10240 + i) as u8);
    }
    file.read_at((1 << 38) + 3, &mut out).unwrap();
    assert_eq!(out, [0; 4096]);
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn holes_unwritten_eof_and_errors_are_explicit() {
    let source = Arc::new(Source {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let file = ExtentFile::new(
        source,
        8,
        vec![
            extent(0, 2, ExtentKind::Data(7)),
            extent(2, 3, ExtentKind::Hole),
            extent(5, 3, ExtentKind::Unwritten),
        ],
        3,
    )
    .unwrap();
    let mut out = [99; 10];
    assert_eq!(file.read_at(1, &mut out).unwrap(), 7);
    assert_eq!(out, [8, 0, 0, 0, 0, 0, 0, 99, 99, 99]);
    assert_eq!(file.read_at(8, &mut out).unwrap(), 0);
    assert!(file.read_at(9, &mut []).is_err());
    assert_eq!(file.extents()[1].kind, ExtentKind::Hole);
    assert_eq!(file.extents()[2].kind, ExtentKind::Unwritten);
    let failing = ExtentFile::new(
        Arc::new(Source {
            calls: AtomicUsize::new(0),
            fail: true,
        }),
        1,
        vec![extent(0, 1, ExtentKind::Data(0))],
        1,
    )
    .unwrap();
    assert_eq!(
        failing.read_at(0, &mut out).unwrap_err().to_string(),
        "injected read failure"
    );
}

#[test]
fn malformed_maps_and_index_budget_fail_before_io() {
    let source = Arc::new(Source {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    for map in [
        vec![extent(1, 2, ExtentKind::Hole)],
        vec![extent(0, 0, ExtentKind::Hole)],
        vec![extent(0, 4, ExtentKind::Data(u64::MAX))],
        vec![extent(0, 3, ExtentKind::Hole)],
    ] {
        assert!(ExtentFile::new(source.clone(), 4, map, 5).is_err());
    }
    assert!(ExtentFile::new(source.clone(), 4, vec![extent(0, 4, ExtentKind::Hole)], 0).is_err());
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn cloned_handles_read_independent_positions_concurrently() {
    let source = Arc::new(Source {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let file = ExtentFile::new(
        source.clone(),
        65536,
        vec![extent(0, 65536, ExtentKind::Data(4096))],
        1,
    )
    .unwrap();
    let threads: Vec<_> = (0..8)
        .map(|reader| {
            let file = file.clone();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 37];
                for request in 0..100 {
                    let offset = reader * 4096 + request;
                    assert_eq!(file.read_at(offset, &mut buffer).unwrap(), 37);
                    for (i, byte) in buffer.iter().enumerate() {
                        assert_eq!(*byte, (4096 + offset + i as u64) as u8);
                    }
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(source.calls.load(Ordering::Relaxed), 800);
}
