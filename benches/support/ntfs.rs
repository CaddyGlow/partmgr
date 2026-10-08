//! MFT bootstrap, sequential FILE parsing, and resident/nonresident stream opening.
use super::{Case, RunMetrics};
use partmgr::{
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsVolume},
    io::{self, ReadAt},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[allow(dead_code)]
#[path = "../../tests/fixtures/ntfs_basic.rs"]
mod fixture;

struct Source {
    bytes: Vec<u8>,
    reads: AtomicU64,
    read_bytes: AtomicU64,
}
impl Source {
    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.read_bytes.store(0, Ordering::Relaxed);
    }
    fn metrics(&self, checksum: u64) -> RunMetrics {
        RunMetrics {
            checksum,
            backend_reads: self.reads.load(Ordering::Relaxed),
            backend_bytes: self.read_bytes.load(Ordering::Relaxed),
        }
    }
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
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}
fn image(records: usize) -> Vec<u8> {
    use fixture::{nonresident, q, record, resident, w};
    let clusters = records * 2;
    let mut bytes = vec![0; (clusters + 16) * 512];
    bytes[3..11].copy_from_slice(b"NTFS    ");
    w(&mut bytes, 11, 512);
    bytes[13] = 1;
    q(&mut bytes, 40, (clusters + 16) as u64);
    q(&mut bytes, 48, 4);
    q(&mut bytes, 56, (clusters + 8) as u64);
    bytes[64] = (-10i8) as u8;
    bytes[68] = (-10i8) as u8;
    w(&mut bytes, 510, 0xaa55);
    let length = (clusters as u32).to_le_bytes();
    let mapping = [0x13, length[0], length[1], length[2], 4, 0];
    let mut info = vec![0; 12];
    info[8..10].copy_from_slice(&[3, 1]);
    for number in 0..records {
        let attrs = if number == 0 {
            vec![nonresident(
                &mapping,
                clusters as u64,
                (records * 1024) as u64,
                (records * 1024) as u64,
                false,
            )]
        } else if number == 3 {
            vec![resident(0x70, &info, 1)]
        } else {
            let units: Vec<_> = format!("file-{number:08}-資料.txt")
                .encode_utf16()
                .collect();
            let mut name = vec![0; 66 + units.len() * 2];
            q(&mut name, 0, 5 | (7 << 48));
            name[64] = units.len() as u8;
            name[65] = 1;
            for (i, unit) in units.iter().enumerate() {
                w(&mut name, 66 + i * 2, *unit);
            }
            let data = if number % 2 == 0 {
                resident(0x80, &[0x51; 128], 3)
            } else {
                let at = ((clusters + 6) as u32).to_le_bytes();
                nonresident(&[0x31, 1, at[0], at[1], at[2], 0], 1, 512, 512, false)
            };
            vec![resident(0x10, &[0; 48], 1), resident(0x30, &name, 2), data]
        };
        let at = 2048 + number * 1024;
        bytes[at..at + 1024].copy_from_slice(&record(number as u32, &attrs));
    }
    bytes[(clusters + 6) * 512..(clusters + 7) * 512].fill(0x51);
    bytes
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn scan(volume: &NtfsVolume, records: usize, r: &Resources) -> u64 {
    let mut checksum = 0;
    for number in 0..records {
        let record = std::hint::black_box(volume.record(number as u64, r).unwrap());
        checksum += u64::from_le_bytes(record.identity().native.as_slice().try_into().unwrap());
        for name in record.names() {
            if let NativeName::Utf16(units) = &name.name {
                checksum += units.iter().map(|u| u64::from(*u)).sum::<u64>();
            }
        }
    }
    checksum
}
fn streams(volume: &NtfsVolume, records: usize, r: &Resources) -> u64 {
    (4..records)
        .map(|number| {
            let file = std::hint::black_box(volume.open_file(number as u64, r).unwrap());
            file.len()
        })
        .sum()
}
pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for records in [64, 1024, 8192] {
        let source = Arc::new(Source {
            bytes: image(records),
            reads: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
        });
        let r = resources();
        let volume = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        assert_eq!(volume.record_count(), records as u64);
        for number in [4, 5, records - 1] {
            let file = volume.open_file(number as u64, &r).unwrap();
            let mut payload = vec![0; file.len() as usize];
            assert_eq!(file.read_at(0, &mut payload, &r).unwrap(), payload.len());
            assert!(payload.iter().all(|b| *b == 0x51));
            let record = volume.record(number as u64, &r).unwrap();
            assert_eq!(
                record.names()[0].name,
                NativeName::Utf16(
                    format!("file-{number:08}-資料.txt")
                        .encode_utf16()
                        .collect()
                )
            );
        }
        let expected = scan(&volume, records, &r);
        let open_source = source.clone();
        cases.push(Case {
            name: "ntfs/mft/bootstrap".into(),
            size: records,
            operations: 1,
            run: Box::new(move || {
                open_source.reset();
                let r = resources();
                let volume = NtfsVolume::open(open_source.clone(), limits(), &r).unwrap();
                open_source.metrics(volume.record_count())
            }),
        });
        let scan_source = source.clone();
        cases.push(Case {
            name: "ntfs/mft/load-parse".into(),
            size: records,
            operations: records as u64,
            run: Box::new(move || {
                scan_source.reset();
                let checksum = scan(&volume, records, &r);
                assert_eq!(checksum, expected);
                scan_source.metrics(checksum)
            }),
        });
        let r = resources();
        let volume = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        let expected = ((records - 4) / 2 * (128 + 512)) as u64;
        assert_eq!(streams(&volume, records, &r), expected);
        cases.push(Case {
            name: "ntfs/mft/open-stream".into(),
            size: records,
            operations: (records - 4) as u64,
            run: Box::new(move || {
                source.reset();
                source.metrics(streams(&volume, records, &r))
            }),
        });
    }
    cases
}
