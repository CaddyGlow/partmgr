//! Borrowed USN framing throughput, independent of journal extraction or replay.
use super::{Case, RunMetrics};
use partmgr::fs_ntfs_usn::{
    FileReference, Provenance, RecordLimits, Records, StreamLimits, UsnRecord, decode_record,
};
use partmgr::io::{self, ReadAt};
use std::hint::black_box;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct Source {
    bytes: Arc<[u8]>,
    reads: AtomicU64,
    read_bytes: AtomicU64,
}

impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let input = self
            .bytes
            .get(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(input);
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

const LIMITS: RecordLimits = RecordLimits {
    record_bytes: 1024,
    name_units: 255,
};
const SOURCE: Provenance = Provenance {
    evidence_id: [0x55; 32],
    offset: 4096,
};

fn name(index: usize) -> String {
    match index % 4 {
        0 => format!("report-{index:08}.txt"),
        1 => format!("build-artifact-{index:08}-release.dll"),
        2 => format!("資料-{index:08}-résumé.docx"),
        _ => format!("archive-{index:08}-😀.zip"),
    }
}

fn encoded(index: usize, major: u16) -> Vec<u8> {
    let units: Vec<_> = name(index).encode_utf16().collect();
    let common = if major == 2 { 24 } else { 40 };
    let header = common + 36;
    let length = (header + units.len() * 2).next_multiple_of(8);
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[4..6].copy_from_slice(&major.to_le_bytes());
    let file = (index as u64 + 32) | (7 << 48);
    let parent = 5 | (3u64 << 48);
    bytes[8..16].copy_from_slice(&file.to_le_bytes());
    let parent_offset = if major == 2 { 16 } else { 24 };
    bytes[parent_offset..parent_offset + 8].copy_from_slice(&parent.to_le_bytes());
    if major == 3 {
        bytes[16..24].copy_from_slice(&0x1020_3040_5060_7080u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x8877_6655_4433_2211u64.to_le_bytes());
    }
    bytes[common..common + 8].copy_from_slice(&(8192 + index as u64 * 128).to_le_bytes());
    bytes[common + 8..common + 16]
        .copy_from_slice(&(132_000_000_000_000_000u64 + index as u64).to_le_bytes());
    bytes[common + 16..common + 20].copy_from_slice(&0x8000_0100u32.to_le_bytes());
    bytes[common + 20..common + 24].copy_from_slice(&1u32.to_le_bytes());
    bytes[common + 24..common + 28].copy_from_slice(&42u32.to_le_bytes());
    bytes[common + 28..common + 32].copy_from_slice(&0x20u32.to_le_bytes());
    bytes[common + 32..common + 34].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
    bytes[common + 34..common + 36].copy_from_slice(&(header as u16).to_le_bytes());
    for (destination, unit) in bytes[header..header + units.len() * 2]
        .chunks_exact_mut(2)
        .zip(units)
    {
        destination.copy_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn validate(record: UsnRecord<'_>, index: usize, major: u16, offset: usize) {
    assert_eq!(record.major, major);
    assert_eq!(record.minor, 0);
    assert_eq!(record.provenance.offset, SOURCE.offset + offset as u64);
    assert_eq!(record.usn, 8192 + index as i64 * 128);
    assert_eq!(
        record.timestamp_ticks,
        132_000_000_000_000_000 + index as i64
    );
    assert_eq!(record.reason.raw, 0x8000_0100);
    assert_eq!(record.source.raw, 1);
    assert_eq!(record.security_id, 42);
    assert_eq!(record.file_attributes, 0x20);
    assert!(record.name.units().eq(name(index).encode_utf16()));
    let file = (index as u64 + 32) | (7 << 48);
    let parent = 5 | (3u64 << 48);
    if major == 2 {
        assert_eq!(record.file, FileReference::V2(file));
        assert_eq!(record.parent, FileReference::V2(parent));
    } else {
        let mut expected_file = [0; 16];
        expected_file[..8].copy_from_slice(&file.to_le_bytes());
        expected_file[8..].copy_from_slice(&0x1020_3040_5060_7080u64.to_le_bytes());
        let mut expected_parent = [0; 16];
        expected_parent[..8].copy_from_slice(&parent.to_le_bytes());
        expected_parent[8..].copy_from_slice(&0x8877_6655_4433_2211u64.to_le_bytes());
        assert_eq!(record.file, FileReference::V3(expected_file));
        assert_eq!(record.parent, FileReference::V3(expected_parent));
    }
}

fn fingerprint(record: UsnRecord<'_>) -> u64 {
    let record = black_box(record);
    record.usn as u64
        ^ (u64::from(record.major) << 56)
        ^ u64::from(record.reason.raw)
        ^ record.name.bytes().len() as u64
        ^ record.provenance.offset
}

fn metrics(checksum: u64) -> RunMetrics {
    RunMetrics {
        checksum,
        backend_reads: 0,
        backend_bytes: 0,
    }
}

fn parse(bytes: &[u8], limits: StreamLimits) -> u64 {
    let mut cursor = Records::new(black_box(bytes), SOURCE, limits);
    let mut checksum = 0u64;
    while let Some(record) = cursor.next_record(|| false).unwrap() {
        checksum = checksum.wrapping_add(fingerprint(record));
    }
    assert_eq!(cursor.decoded_records(), limits.records);
    assert_eq!(cursor.consumed_bytes(), bytes.len());
    checksum
}

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for major in [2, 3] {
        let bytes = encoded(3, major);
        let record = decode_record(&bytes, SOURCE, LIMITS).unwrap();
        validate(record, 3, major, 0);
        let expected = fingerprint(record).wrapping_mul(1024);
        cases.push(Case {
            name: format!("usn/decode-record/v{major}"),
            size: bytes.len(),
            operations: 1024,
            run: Box::new(move || {
                let mut checksum = 0u64;
                for _ in 0..1024 {
                    let record = decode_record(black_box(&bytes), SOURCE, LIMITS).unwrap();
                    checksum = checksum.wrapping_add(fingerprint(record));
                }
                assert_eq!(checksum, expected);
                metrics(checksum)
            }),
        });
    }
    for count in [128, 8192, 65536] {
        let mut bytes = Vec::with_capacity(count * 144);
        for index in 0..count {
            bytes.extend_from_slice(&encoded(index, if index % 2 == 0 { 2 } else { 3 }));
        }
        let limits = StreamLimits {
            record: LIMITS,
            records: count,
            bytes: bytes.len(),
        };
        let mut cursor = Records::new(&bytes, SOURCE, limits);
        let mut expected = 0u64;
        let mut index = 0;
        while let Some(record) = cursor.next_record(|| false).unwrap() {
            validate(
                record,
                index,
                if index % 2 == 0 { 2 } else { 3 },
                cursor.consumed_bytes() - record.raw().len(),
            );
            expected = expected.wrapping_add(fingerprint(record));
            index += 1;
        }
        assert_eq!(index, count);
        assert_eq!(cursor.consumed_bytes(), bytes.len());
        let bytes: Arc<[u8]> = bytes.into();
        let source = Source {
            bytes: Arc::clone(&bytes),
            reads: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
        };
        cases.push(Case {
            name: "usn/stream/mixed-v2-v3".into(),
            size: bytes.len(),
            operations: count as u64,
            run: Box::new(move || {
                let checksum = parse(&bytes, limits);
                assert_eq!(checksum, expected);
                metrics(checksum)
            }),
        });
        cases.push(Case {
            name: "usn/load-parse/mixed-v2-v3".into(),
            size: limits.bytes,
            operations: count as u64,
            run: Box::new(move || {
                source.reads.store(0, Ordering::Relaxed);
                source.read_bytes.store(0, Ordering::Relaxed);
                let mut loaded = vec![0; limits.bytes];
                source.read_exact_at(0, &mut loaded).unwrap();
                let checksum = parse(&loaded, limits);
                assert_eq!(checksum, expected);
                RunMetrics {
                    checksum,
                    backend_reads: source.reads.load(Ordering::Relaxed),
                    backend_bytes: source.read_bytes.load(Ordering::Relaxed),
                }
            }),
        });
    }
    cases
}
