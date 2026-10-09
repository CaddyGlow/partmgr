#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_core::*,
    fs_flash::*,
    fs_jffs2::*,
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use virtdisk::ReadAt;
#[allow(dead_code)]
#[path = "fixtures/jffs2_clean.rs"]
mod fixture;
struct Source {
    bytes: Vec<u8>,
    fail: AtomicBool,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("codec causal input failure"));
        }
        b.copy_from_slice(
            self.bytes
                .get(p as usize..p as usize + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn geometry() -> FlashGeometry {
    FlashGeometry {
        layout: FlashLayout::LogicalNor,
        erased_byte: 255,
        erase_bytes: 4096,
        program_bytes: 4,
        programming: FlashProgramming::ClearBitsOnly,
    }
}
fn limits() -> Jffs2ReadLimits {
    Jffs2ReadLimits {
        scan_bytes: 8192,
        nodes: 128,
        inodes: 32,
        fragments: 128,
        native_bytes: 4096,
        work: 100000,
    }
}
fn codecs() -> Jffs2CompressionLimits {
    Jffs2CompressionLimits {
        compressed_node_bytes: 4096,
        decoded_node_bytes: 4096,
        compressed_bytes: 8192,
        decoded_bytes: 8192,
        work: 16384,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    }
}
fn stored_zlib(payload: &[u8]) -> Vec<u8> {
    let n = payload.len() as u16;
    let mut b = vec![0x78, 1, 1];
    b.extend(n.to_le_bytes());
    b.extend((!n).to_le_bytes());
    b.extend(payload);
    let (mut a, mut c) = (1u32, 0u32);
    for &v in payload {
        a = (a + u32::from(v)) % 65521;
        c = (c + a) % 65521;
    }
    b.extend(((c << 16) | a).to_be_bytes());
    b
}
fn node(codec: u8, bytes: &[u8], decoded: u32, version: u32, offset: u32, big: bool) -> Vec<u8> {
    let mut b = vec![0; 68];
    b[..2].copy_from_slice(&if big {
        0x1985u16.to_be_bytes()
    } else {
        0x1985u16.to_le_bytes()
    });
    b[2..4].copy_from_slice(&if big {
        0xe002u16.to_be_bytes()
    } else {
        0xe002u16.to_le_bytes()
    });
    for (p, n) in [
        (4, 68 + bytes.len() as u32),
        (12, 2),
        (16, version),
        (20, 0x81a0),
        (28, 300),
        (44, offset),
        (48, bytes.len() as u32),
        (52, decoded),
        (60, fixture::crc(bytes)),
    ] {
        fixture::dword(&mut b, p, n, big);
    }
    b[56] = codec;
    let c = fixture::crc(&b[..8]);
    fixture::dword(&mut b, 8, c, big);
    let c = fixture::crc(&b[..60]);
    fixture::dword(&mut b, 64, c, big);
    b.extend(bytes);
    b.resize(b.len().next_multiple_of(4), 255);
    b
}
fn image(codec: u8, encoded: &[u8], decoded: u32, big: bool) -> Vec<u8> {
    let mut b = fixture::jffs2_seed(big);
    let a = node(codec, encoded, decoded, 4, 0, big);
    let z = node(0, b"native", 6, 5, 17, big);
    b[4108..4108 + a.len()].copy_from_slice(&a);
    b[4108 + a.len()..4108 + a.len() + z.len()].copy_from_slice(&z);
    b
}
#[test]
fn both_endian_rtime_zlib_version_overlay_holes_lazy_ranges_tree_and_refunds() {
    for big in [false, true] {
        for codec in [2, 6] {
            let r = resources();
            let data = if codec == 2 {
                vec![b'A', 255]
            } else {
                stored_zlib(&[b'A'; 256])
            };
            let source = Arc::new(Source {
                bytes: image(codec, &data, 256, big),
                fail: AtomicBool::new(false),
            });
            let e = if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            };
            assert_eq!(
                Jffs2Volume::open(source.clone(), geometry(), e, limits(), &r)
                    .err()
                    .unwrap()
                    .kind,
                ErrorKind::Unsupported
            );
            let v =
                Jffs2Volume::open_compressed(source.clone(), geometry(), e, limits(), codecs(), &r)
                    .unwrap();
            assert!(
                audit(
                    &v,
                    Jffs2AuditLimits {
                        entries: 128,
                        work: 128,
                        findings: 16
                    },
                    &r
                )
                .unwrap()
                .is_clean()
            );
            let f = v.open_file(2, &r).unwrap();
            drop(v);
            let mut expected = vec![b'A'; 300];
            expected[17..23].copy_from_slice(b"native");
            expected[256..].fill(0);
            for (p, n) in [(0, 300), (14, 17), (247, 53), (299, 1)] {
                let before = r.memory.used();
                let mut b = vec![9; n];
                assert_eq!(f.read_at(p as u64, &mut b, &r).unwrap(), n);
                assert_eq!(b, expected[p..p + n]);
                assert_eq!(r.memory.used(), before);
            }
            let low = Resources {
                memory: Budget::new(1),
                cancellation: Cancellation::default(),
            };
            assert_eq!(
                f.read_at(0, &mut [0; 1], &low).unwrap_err().kind,
                ErrorKind::BudgetExhausted
            );
            source.fail.store(true, Ordering::Relaxed);
            let error = f.read_at(0, &mut [0; 1], &r).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Io);
            assert!(error.source.is_some());
            drop(f);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn malformed_streams_crc_expansion_and_total_caps_reject_before_audit() {
    let mut bad_adler = stored_zlib(&[b'A'; 256]);
    *bad_adler.last_mut().unwrap() ^= 1;
    let mut trailing = stored_zlib(&[b'A'; 256]);
    trailing.push(0);
    for (codec, data, size) in [
        (2, vec![b'A'], 256),
        (2, vec![b'A', 255], 255),
        (2, vec![b'A', 0, 0, 0], 1),
        (6, bad_adler, 256),
        (6, trailing, 256),
        (6, stored_zlib(&[b'A'; 256]), 255),
        (3, vec![1], 1),
    ] {
        let r = resources();
        let source = Arc::new(Source {
            bytes: image(codec, &data, size, false),
            fail: AtomicBool::new(false),
        });
        assert!(
            Jffs2Volume::open_compressed(
                source,
                geometry(),
                Jffs2Endian::Little,
                limits(),
                codecs(),
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
    for which in 0..4 {
        let r = resources();
        let mut l = codecs();
        match which {
            0 => l.decoded_node_bytes = 128,
            1 => l.compressed_node_bytes = 1,
            2 => l.decoded_bytes = 128,
            _ => l.work = 1,
        }
        let source = Arc::new(Source {
            bytes: image(2, &[b'A', 255], 256, false),
            fail: AtomicBool::new(false),
        });
        assert_eq!(
            Jffs2Volume::open_compressed(source, geometry(), Jffs2Endian::Little, limits(), l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
}
struct OwnedBackend {
    bytes: Vec<u8>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
}
impl partmgr::storage::Storage for OwnedBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.bytes[p as usize..p as usize + b.len()]);
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Err(io::Error::other("unexpected compressed-history mutation"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn owned_editor_rejects_compressed_histories_before_writes_and_refunds() {
    for codec in [2, 6] {
        let r = resources();
        let encoded = if codec == 2 {
            vec![b'A', 255]
        } else {
            stored_zlib(&[b'A'; 256])
        };
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flash = FlashImage::new(
            OwnedBackend {
                bytes: image(codec, &encoded, 256, false),
                writes: writes.clone(),
            },
            geometry(),
            &[],
            FlashLimits {
                bad_blocks: 0,
                operation_bytes: 8192,
                scratch_bytes: 128,
            },
            &r,
        )
        .unwrap();
        let l = partmgr::fs_jffs2_edit::Jffs2EditLimits {
            read: limits(),
            audit: Jffs2AuditLimits {
                entries: 128,
                work: 128,
                findings: 16,
            },
            journal_bytes: 32768,
            slots: 32,
            file_bytes: 2048,
            scratch_bytes: 128,
        };
        assert_eq!(
            partmgr::fs_jffs2_edit::Jffs2Editor::open(flash, [7; 32], Jffs2Endian::Little, l, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Unsupported
        );
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert_eq!(r.memory.used(), 0);
    }
}
