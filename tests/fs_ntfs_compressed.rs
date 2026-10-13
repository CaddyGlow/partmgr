#![cfg(feature = "std")]
//! Hand-authored NTFS/LZNT1 fixtures; these tests are not native Windows evidence.
#[path = "fixtures/ntfs_basic.rs"]
mod basic;
use basic::*;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, FileRead, Resources},
    fs_ntfs::{NtfsCompressionLimits, NtfsReadLimits, NtfsStreamLimits, NtfsVolume},
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use virtdisk::ReadAt;

struct Image {
    bytes: Vec<u8>,
    payload_reads: AtomicUsize,
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if at >= 90 * 512 {
            self.payload_reads.fetch_add(1, Ordering::Relaxed);
        }
        let at = at as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn read_limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn stream_limits() -> NtfsStreamLimits {
    NtfsStreamLimits {
        extension_records: 8,
        list_entries: 32,
        list_bytes: 4096,
        attributes: 64,
        runs: 64,
        work: 1000000,
    }
}
fn compression_limits() -> NtfsCompressionLimits {
    NtfsCompressionLimits {
        max_unit_bytes: 65536,
        max_units_per_read: 32,
        max_work: 10000,
    }
}
fn compressed(
    mapping: &[u8],
    clusters: u64,
    length: u64,
    initialized: u64,
    physical: u64,
    name: &[u16],
) -> Vec<u8> {
    let run_at = (72 + name.len() * 2).next_multiple_of(8);
    let mut attr = vec![0; (run_at + mapping.len()).next_multiple_of(8)];
    let size = attr.len();
    d(&mut attr, 0, 0x80);
    d(&mut attr, 4, size as u32);
    attr[8] = 1;
    attr[9] = name.len() as u8;
    if !name.is_empty() {
        w(&mut attr, 10, 72);
    }
    w(&mut attr, 12, 1);
    w(&mut attr, 14, 3);
    q(&mut attr, 24, clusters - 1);
    w(&mut attr, 32, run_at as u16);
    w(&mut attr, 34, 4);
    q(&mut attr, 40, clusters * 512);
    q(&mut attr, 48, length);
    q(&mut attr, 56, initialized);
    q(&mut attr, 64, physical);
    for (index, unit) in name.iter().enumerate() {
        w(&mut attr, 72 + index * 2, *unit);
    }
    attr[run_at..run_at + mapping.len()].copy_from_slice(mapping);
    attr
}
fn seed(attr: Vec<u8>, directory: bool) -> Arc<Image> {
    let mut bytes = fixture();
    let mut file = record(24, &[attr]);
    if directory {
        w(&mut file, 22, 3);
    }
    bytes[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&file);
    // Each literal A followed by a distance-one token expands to a 4096-byte chunk.
    bytes[90 * 512..91 * 512].fill(0);
    bytes[90 * 512..90 * 512 + 12]
        .copy_from_slice(&[3, 0xb0, 2, b'A', 0xfc, 0x0f, 3, 0xb0, 2, b'A', 0xfc, 0x0f]);
    Arc::new(Image {
        bytes,
        payload_reads: AtomicUsize::new(0),
    })
}

#[test]
fn compressed_stream_requires_opt_in_and_preserves_plain_compatibility() {
    let r = resources();
    let source = seed(
        compressed(&[0x11, 1, 90, 1, 15, 0], 16, 8192, 8192, 512, &[]),
        false,
    );
    {
        let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
        let id = volume.stream_identity(24, &r).unwrap();
        assert_eq!(
            volume
                .open_stream(&id, &[], stream_limits(), &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            volume
                .data_streams(&id, stream_limits(), &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Unsupported
        );
        let streams = volume
            .data_streams_with_compression(&id, stream_limits(), compression_limits(), &r)
            .unwrap();
        assert!(streams.get()[0].compressed);
        assert_eq!(streams.get()[0].length, 8192);
        let file = volume
            .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
            .unwrap();
        let mut out = vec![0; 8192];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 8192);
        assert_eq!(out, vec![b'A'; 8192]);
        let mut cross_chunk = [0; 9];
        file.read_at(4093, &mut cross_chunk, &r).unwrap();
        assert_eq!(cross_chunk, [b'A'; 9]);
    }
    assert_eq!(r.memory.used(), 0);
    let plain = Arc::new(Image {
        bytes: fixture(),
        payload_reads: AtomicUsize::new(0),
    });
    let volume = NtfsVolume::open(plain, read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = [0; 5];
    file.read_at(0, &mut out, &r).unwrap();
    assert_eq!(&out, b"hello");
}

#[test]
fn compressed_raw_and_zero_units_cross_boundaries() {
    let r = resources();
    let mut source = seed(
        compressed(
            &[0x11, 1, 90, 1, 15, 0x11, 16, 1, 1, 16, 0],
            48,
            24576,
            24576,
            17 * 512,
            &[],
        ),
        false,
    );
    Arc::get_mut(&mut source).unwrap().bytes[91 * 512..107 * 512].fill(b'R');
    let volume = NtfsVolume::open(source.clone(), read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = vec![9; 24576];
    file.read_at(0, &mut out, &r).unwrap();
    assert_eq!(&out[..8192], vec![b'A'; 8192]);
    assert_eq!(&out[8192..16384], vec![b'R'; 8192]);
    assert_eq!(&out[16384..], vec![0; 8192]);
    let before = source.payload_reads.load(Ordering::Relaxed);
    file.read_at(16384, &mut out[..100], &r).unwrap();
    assert_eq!(source.payload_reads.load(Ordering::Relaxed), before);
}

#[test]
fn initialized_tail_is_zero_without_reading_payload() {
    for (mapping, physical) in [
        (&[0x11, 1, 90, 1, 15, 0][..], 512),
        (&[0x11, 16, 90, 0][..], 8192),
    ] {
        let r = resources();
        let source = seed(compressed(mapping, 16, 8192, 5000, physical, &[]), false);
        let volume = NtfsVolume::open(source.clone(), read_limits(), &r).unwrap();
        let id = volume.stream_identity(24, &r).unwrap();
        let file = volume
            .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
            .unwrap();
        let mut out = [9; 100];
        let before = source.payload_reads.load(Ordering::Relaxed);
        file.read_at(5000, &mut out, &r).unwrap();
        assert_eq!(out, [0; 100]);
        assert_eq!(source.payload_reads.load(Ordering::Relaxed), before);
        file.read_at(4950, &mut out, &r).unwrap();
        assert_eq!(&out[50..], &[0; 50]);
    }
}

#[test]
fn malformed_codec_does_not_publish_current_unit_output() {
    let r = resources();
    let mut source = seed(
        compressed(&[0x11, 1, 90, 1, 15, 0], 16, 8192, 8192, 512, &[]),
        false,
    );
    Arc::get_mut(&mut source).unwrap().bytes[90 * 512..91 * 512].fill(0xff);
    let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = [0x77; 100];
    assert_eq!(
        file.read_at(0, &mut out, &r).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert_eq!(out, [0x77; 100]);
}

#[test]
fn compression_preflight_rejects_bad_geometry_accounting_and_map_order() {
    for kind in 0..4 {
        let r = resources();
        let mapping = if kind == 2 {
            &[1, 1, 0x11, 15, 90, 0][..]
        } else {
            &[0x11, 1, 90, 1, 15, 0][..]
        };
        let mut attr = compressed(
            mapping,
            16,
            8192,
            8192,
            if kind == 1 {
                1024
            } else if kind == 2 {
                15 * 512
            } else {
                512
            },
            &[],
        );
        if kind == 0 {
            w(&mut attr, 34, 3);
        }
        let source = seed(attr, false);
        let volume = NtfsVolume::open(source.clone(), read_limits(), &r).unwrap();
        let id = volume.stream_identity(24, &r).unwrap();
        let mut cap = compression_limits();
        if kind == 3 {
            cap.max_unit_bytes = 4096;
        }
        let before = source.payload_reads.load(Ordering::Relaxed);
        let error = volume
            .open_stream_with_compression(&id, &[], stream_limits(), cap, &r)
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            match kind {
                0 => ErrorKind::Unsupported,
                3 => ErrorKind::BudgetExhausted,
                _ => ErrorKind::InvalidData,
            }
        );
        assert_eq!(source.payload_reads.load(Ordering::Relaxed), before);
    }
}

#[test]
fn exact_ads_including_directory_is_compressed_independently() {
    for directory in [false, true] {
        let r = resources();
        let name = [0x41, 0xd800];
        let source = seed(
            compressed(&[0x11, 1, 90, 1, 15, 0], 16, 8192, 8192, 512, &name),
            directory,
        );
        let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
        let id = volume.stream_identity(24, &r).unwrap();
        let streams = volume
            .data_streams_with_compression(&id, stream_limits(), compression_limits(), &r)
            .unwrap();
        assert_eq!(streams.get()[0].name, name);
        let file = volume
            .open_stream_with_compression(&id, &name, stream_limits(), compression_limits(), &r)
            .unwrap();
        let mut out = [0; 16];
        file.read_at(200, &mut out, &r).unwrap();
        assert_eq!(out, [b'A'; 16]);
    }
}

#[test]
fn fragmented_physical_runs_assemble_one_raw_unit() {
    let r = resources();
    let mut source = seed(
        compressed(&[0x11, 8, 90, 0x11, 8, 20, 0], 16, 8192, 8192, 8192, &[]),
        false,
    );
    let bytes = &mut Arc::get_mut(&mut source).unwrap().bytes;
    bytes[90 * 512..98 * 512].fill(b'F');
    bytes[110 * 512..118 * 512].fill(b'S');
    let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = vec![0; 8192];
    file.read_at(0, &mut out, &r).unwrap();
    assert_eq!(&out[..4096], vec![b'F'; 4096]);
    assert_eq!(&out[4096..], vec![b'S'; 4096]);
}

#[test]
fn attribute_list_segments_can_split_a_compression_unit() {
    let r = resources();
    let mut first = compressed(&[0x11, 1, 90, 1, 7, 0], 8, 8192, 8192, 512, &[]);
    q(&mut first, 40, 8192);
    let mut source = seed(first.clone(), false);
    let mut list = vec![];
    for (low, number, instance) in [(0, 24, 3), (8, 26, 9)] {
        let mut entry = vec![0; 32];
        d(&mut entry, 0, 0x80);
        w(&mut entry, 4, 32);
        q(&mut entry, 8, low);
        q(&mut entry, 16, number | (7 << 48));
        w(&mut entry, 24, instance);
        list.extend(entry);
    }
    let mut continuation = vec![0; 72];
    d(&mut continuation, 0, 0x80);
    d(&mut continuation, 4, 72);
    continuation[8] = 1;
    w(&mut continuation, 12, 1);
    w(&mut continuation, 14, 9);
    q(&mut continuation, 16, 8);
    q(&mut continuation, 24, 15);
    w(&mut continuation, 32, 64);
    w(&mut continuation, 34, 4);
    continuation[64..67].copy_from_slice(&[1, 8, 0]);
    let mut extension = record(26, &[continuation]);
    q(&mut extension, 32, 24 | (7 << 48));
    let bytes = &mut Arc::get_mut(&mut source).unwrap().bytes;
    bytes[2048 + 24 * 1024..2048 + 25 * 1024]
        .copy_from_slice(&record(24, &[resident(0x20, &list, 4), first]));
    bytes[2048 + 26 * 1024..2048 + 27 * 1024].copy_from_slice(&extension);
    let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let streams = volume
        .data_streams_with_compression(&id, stream_limits(), compression_limits(), &r)
        .unwrap();
    assert_eq!(streams.get()[0].segments, 2);
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = vec![0; 8192];
    file.read_at(0, &mut out, &r).unwrap();
    assert_eq!(out, vec![b'A'; 8192]);
}

#[test]
fn read_limits_and_cancellation_prevent_output_publication() {
    for kind in 0..3 {
        let r = resources();
        let source = seed(
            compressed(&[0x11, 1, 90, 1, 15, 0], 16, 8192, 8192, 512, &[]),
            false,
        );
        let volume = NtfsVolume::open(source.clone(), read_limits(), &r).unwrap();
        let id = volume.stream_identity(24, &r).unwrap();
        let mut cap = compression_limits();
        if kind == 0 {
            cap.max_units_per_read = 0;
        }
        let file = volume
            .open_stream_with_compression(&id, &[], stream_limits(), cap, &r)
            .unwrap();
        let read_resources = if kind == 1 {
            Resources {
                memory: Budget::new(1),
                cancellation: Cancellation::default(),
            }
        } else {
            resources()
        };
        if kind == 2 {
            read_resources.cancellation.cancel();
        }
        let mut out = [0x77; 10];
        let before = source.payload_reads.load(Ordering::Relaxed);
        assert_eq!(
            file.read_at(0, &mut out, &read_resources)
                .err()
                .unwrap()
                .kind,
            if kind == 2 {
                ErrorKind::Cancelled
            } else {
                ErrorKind::BudgetExhausted
            }
        );
        assert_eq!(out, [0x77; 10]);
        assert_eq!(source.payload_reads.load(Ordering::Relaxed), before);
        assert_eq!(read_resources.memory.used(), 0);
    }
}

#[test]
fn malformed_later_unit_preserves_completed_unit_and_hides_failed_unit() {
    let r = resources();
    let mut source = seed(
        compressed(
            &[0x11, 1, 90, 1, 15, 0x11, 1, 1, 1, 15, 0],
            32,
            16384,
            16384,
            1024,
            &[],
        ),
        false,
    );
    Arc::get_mut(&mut source).unwrap().bytes[91 * 512..92 * 512].fill(0xff);
    let volume = NtfsVolume::open(source, read_limits(), &r).unwrap();
    let id = volume.stream_identity(24, &r).unwrap();
    let file = volume
        .open_stream_with_compression(&id, &[], stream_limits(), compression_limits(), &r)
        .unwrap();
    let mut out = vec![0x77; 16384];
    assert_eq!(
        file.read_at(0, &mut out, &r).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert_eq!(&out[..8192], vec![b'A'; 8192]);
    assert_eq!(&out[8192..], vec![0x77; 8192]);
}
