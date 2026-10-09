use partmgr::{
    fs_core::{Budget, Cancellation, Resources, StreamKind, TreeSource},
    fs_flash::{FlashGeometry, FlashLayout, FlashProgramming},
    fs_jffs2::{Jffs2CompressionLimits, Jffs2Endian, Jffs2ReadLimits, Jffs2Volume},
    fs_jffs2_audit::{Jffs2AuditLimits, audit},
    fs_jffs2_tree::Jffs2TreeSource,
};
use std::sync::Arc;
#[path = "../../tests/fixtures/jffs2_clean.rs"]
#[allow(dead_code)]
mod fixture;
pub(crate) fn geometry() -> FlashGeometry {
    FlashGeometry {
        erased_byte: 255,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 4096,
        program_bytes: 4,
        layout: FlashLayout::LogicalNor,
    }
}
pub(crate) fn limits() -> Jffs2ReadLimits {
    Jffs2ReadLimits {
        scan_bytes: 1 << 20,
        nodes: 256,
        inodes: 64,
        fragments: 256,
        native_bytes: 8192,
        work: 100000,
    }
}
pub(crate) fn audit_limits() -> Jffs2AuditLimits {
    Jffs2AuditLimits {
        entries: 256,
        work: 1024,
        findings: 32,
    }
}
fn rtime_seed(big: bool, decoded_size: u32) -> Vec<u8> {
    // Independent native RTIME pair: literal A followed by 255 overlapping copies.
    let mut bytes = fixture::jffs2_seed(big);
    let mut header = bytes[68..136].to_vec();
    for (offset, value) in [
        (4, 70),
        (16, 4),
        (28, 256),
        (44, 0),
        (48, 2),
        (52, decoded_size),
    ] {
        fixture::dword(&mut header, offset, value, big);
    }
    header[56] = 2;
    let checksum = fixture::crc(&header[..8]);
    fixture::dword(&mut header, 8, checksum, big);
    fixture::dword(&mut header, 60, fixture::crc(&[b'A', 255]), big);
    let checksum = fixture::crc(&header[..60]);
    fixture::dword(&mut header, 64, checksum, big);
    bytes[4096..4164].copy_from_slice(&header);
    bytes[4164..4166].copy_from_slice(&[b'A', 255]);
    bytes
}
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let little = fixture::jffs2_seed(false);
    let mut corrupt = little.clone();
    corrupt[136] ^= 1;
    let mut compressed = little.clone();
    compressed[68 + 56] = 6; // Zlib, deliberately outside the none/zero profile.
    let checksum = fixture::crc(&compressed[68..68 + 60]);
    fixture::dword(&mut compressed, 68 + 64, checksum, false);
    let mut bad_length = little.clone();
    bad_length[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    vec![
        little.clone(),
        fixture::jffs2_seed(true),
        corrupt,
        compressed,
        bad_length,
        little[..511].to_vec(),
        vec![255; 8192],
        rtime_seed(false, 256),
        rtime_seed(true, 256),
        rtime_seed(false, 255),
    ]
}
pub(crate) fn run(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    for endian in [Jffs2Endian::Little, Jffs2Endian::Big] {
        let _ = super::jffs2_edit::run(data, endian);
        for codec in [
            partmgr::fs_jffs2_builder::Jffs2BuildCompression::Rtime,
            partmgr::fs_jffs2_builder::Jffs2BuildCompression::Zlib,
        ] {
            let _ = super::jffs2_edit::run_compressed_range(data, endian, codec);
        }
        for compressed in [false, true] {
            run_read(data, endian, compressed);
        }
    }
}
fn run_read(data: &[u8], endian: Jffs2Endian, compressed: bool) {
    let r = Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    };
    let source = Arc::new(super::Bytes(data.to_vec()));
    let opened = if compressed {
        Jffs2Volume::open_compressed(
            source,
            geometry(),
            endian,
            limits(),
            Jffs2CompressionLimits {
                compressed_node_bytes: 4096,
                decoded_node_bytes: 4096,
                compressed_bytes: 1 << 20,
                decoded_bytes: 1 << 20,
                work: 2 << 20,
            },
            &r,
        )
    } else {
        Jffs2Volume::open(source, geometry(), endian, limits(), &r)
    };
    if let Ok(volume) = opened {
        if let Ok(report) = audit(&volume, audit_limits(), &r) {
            if !report.is_clean() {
                assert!(report.free_ranges().is_empty());
            }
            for extent in report.free_ranges() {
                assert_eq!(extent.offset % 4096, 0);
                assert_eq!(extent.length % 4096, 0);
                let start = extent.offset as usize;
                let end = start.checked_add(extent.length as usize).unwrap();
                assert!(data[start..end].iter().all(|b| *b == 255));
            }
        }
        if let Ok(tree) = Jffs2TreeSource::inventory(volume, audit_limits(), &r) {
            let root = tree.root();
            let _ = tree.metadata(&root, &r);
            let mut retained = Vec::new();
            let mut directories = vec![root.clone()];
            for _ in 0..8 {
                let Some(directory) = directories.pop() else {
                    break;
                };
                if let Ok(page) = tree.directory_page(&directory, None, 16, &r) {
                    for entry in &page.entries {
                        let _ = tree.metadata(&entry.object, &r);
                        let _ = tree.streams(&entry.object, &r);
                        if let Ok(file) = tree.open_stream(&entry.object, &StreamKind::Data, &r) {
                            let mut out = [0; 73];
                            for at in [0, 2, 4095, file.len(), u64::MAX] {
                                if let Ok(n) = file.read_at(at, &mut out, &r) {
                                    assert!(n <= out.len());
                                    if at >= file.len() {
                                        assert_eq!(n, 0);
                                    }
                                }
                            }
                            let _ = file.visit_extents(&r, &mut |_| Ok(()));
                            if retained.len() < 16 {
                                retained.push(file);
                            }
                        }
                        if entry.kind == partmgr::fs_core::ObjectKind::Directory
                            && directories.len() < 16
                        {
                            directories.push(entry.object.clone());
                        }
                    }
                    if let Some(next) = &page.next {
                        let _ = tree.directory_page(&directory, Some(next), 16, &r);
                    }
                }
            }
            let _ = tree.directory_page(&root, Some(data.get(..40).unwrap_or(data)), 8, &r);
            drop(tree);
            for file in &retained {
                let _ = file.read_at(0, &mut [0; 19], &r);
            }
            r.cancellation.cancel();
            for file in &retained {
                assert!(file.read_at(file.len(), &mut [], &r).is_err());
            }
        }
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn seed_reaches_both_endian_reconstruction_audit_native_tree_and_deferred_reads() {
    use partmgr::fs_core::read_all;
    for (big, endian) in [(false, Jffs2Endian::Little), (true, Jffs2Endian::Big)] {
        let seed = fixture::jffs2_seed(big);
        run(&seed);
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let volume = Jffs2Volume::open(
            Arc::new(super::Bytes(seed)),
            geometry(),
            endian,
            limits(),
            &r,
        )
        .unwrap();
        let report = audit(&volume, audit_limits(), &r).unwrap();
        assert!(report.is_complete() && report.is_clean());
        assert_eq!(report.reachable_inodes(), 4);
        assert_eq!(report.historical_inodes(), 1);
        drop(report);
        let file = volume.open_file(2, &r).unwrap();
        let tree = Jffs2TreeSource::inventory(volume, audit_limits(), &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 8, &r).unwrap();
        assert_eq!(page.entries.len(), 2);
        drop(page);
        drop(tree);
        assert_eq!(read_all(&file, 16, &r).unwrap().get(), b"abXY\0\0");
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn compressed_seeds_reach_lazy_decode_and_reject_checksummed_bad_expansion() {
    use partmgr::fs_core::read_all;
    for (big, endian) in [(false, Jffs2Endian::Little), (true, Jffs2Endian::Big)] {
        let seed = rtime_seed(big, 256);
        run(&seed);
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let source = Arc::new(super::Bytes(seed));
        assert!(Jffs2Volume::open(source.clone(), geometry(), endian, limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
        let caps = Jffs2CompressionLimits {
            compressed_node_bytes: 4096,
            decoded_node_bytes: 4096,
            compressed_bytes: 1 << 20,
            decoded_bytes: 1 << 20,
            work: 2 << 20,
        };
        let volume =
            Jffs2Volume::open_compressed(source, geometry(), endian, limits(), caps, &r).unwrap();
        let report = audit(&volume, audit_limits(), &r).unwrap();
        assert!(report.is_complete() && report.is_clean());
        drop(report);
        let file = volume.open_file(2, &r).unwrap();
        drop(volume);
        assert_eq!(read_all(&file, 256, &r).unwrap().get(), &vec![b'A'; 256]);
        drop(file);
        assert_eq!(r.memory.used(), 0);
        assert!(
            Jffs2Volume::open_compressed(
                Arc::new(super::Bytes(rtime_seed(big, 255))),
                geometry(),
                endian,
                limits(),
                caps,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
}
