#![cfg(feature = "std")]

// Independent raw LFS extent fixtures; no production encoder or endpoint helper.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs_logfile::{NtfsLogFileLimits, NtfsLogRecordLimits, inspect_logfile_record},
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;

const PAGE: usize = 4096;
const LENGTH: usize = 64 * PAGE;
const FIRST: usize = 4 * PAGE;
const SEQUENCE: u16 = 19;
fn w(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn q(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn lsn(generation: u64, offset: usize) -> u64 {
    (generation << 16) | (offset as u64 / 8)
}
fn protect(b: &mut [u8], usa: usize, marker: u16) {
    w(b, usa, marker);
    for sector in 1..=8 {
        let at = sector * 512 - 2;
        let previous = u16::from_le_bytes([b[at], b[at + 1]]);
        w(b, usa + 2 * sector, previous);
        w(b, at, marker);
    }
}
fn restart(marker: u16) -> Vec<u8> {
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"RSTR");
    w(&mut b, 4, 32);
    w(&mut b, 6, 9);
    d(&mut b, 16, PAGE as u32);
    d(&mut b, 20, PAGE as u32);
    w(&mut b, 24, 56);
    w(&mut b, 26, 1);
    w(&mut b, 28, 1);
    q(&mut b, 56, lsn(9, FIRST + 64));
    w(&mut b, 64, 1);
    w(&mut b, 66, u16::MAX);
    w(&mut b, 68, 0);
    d(&mut b, 72, 48);
    w(&mut b, 76, 224);
    w(&mut b, 78, 64);
    q(&mut b, 80, LENGTH as u64);
    w(&mut b, 92, 48);
    w(&mut b, 94, 64);
    w(&mut b, 136, u16::MAX);
    w(&mut b, 138, u16::MAX);
    w(&mut b, 140, SEQUENCE);
    d(&mut b, 148, 8);
    b[152..160].copy_from_slice(b"N\0T\0F\0S\0");
    protect(&mut b, 32, marker);
    b
}
fn record_header(query: u64, length: usize, flags: u16) -> [u8; 48] {
    let mut b = [0; 48];
    q(&mut b, 0, query);
    q(&mut b, 8, 0x1122334455667788);
    q(&mut b, 16, 0x8877665544332211);
    d(&mut b, 24, length as u32);
    w(&mut b, 28, SEQUENCE);
    w(&mut b, 30, 0);
    d(&mut b, 32, 1);
    d(&mut b, 36, 0x12345678);
    w(&mut b, 40, flags);
    b
}
fn ordinary(last: u64, ended: u64, count: u16, position: u16, next: usize) -> Vec<u8> {
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"RCRD");
    w(&mut b, 4, 40);
    w(&mut b, 6, 9);
    q(&mut b, 8, last);
    d(&mut b, 16, 1);
    w(&mut b, 20, count);
    w(&mut b, 22, position);
    w(&mut b, 24, next as u16);
    q(&mut b, 32, ended);
    b
}
fn base() -> Vec<u8> {
    let mut b = vec![0xff; LENGTH];
    b[..PAGE].copy_from_slice(&restart(0xabc1));
    b[PAGE..2 * PAGE].copy_from_slice(&restart(0xabc2));
    b
}
// A two-page transfer can wrap from the last ordinary slot to offset 16384.
fn fixture(start: usize, payload: &[u8]) -> (Vec<u8>, u64) {
    let mut b = base();
    let query = lsn(7, start);
    let mut remaining = payload;
    let first_page = start / PAGE * PAGE;
    let first_capacity = PAGE - start % PAGE - 48;
    let multi = payload.len() > first_capacity;
    let mut page = ordinary(
        query,
        if multi { query - 1 } else { query },
        if multi { 2 } else { 1 },
        1,
        if multi {
            64
        } else {
            (start % PAGE + 48 + payload.len()).next_multiple_of(8)
        },
    );
    page[start % PAGE..start % PAGE + 48].copy_from_slice(&record_header(
        query,
        payload.len(),
        u16::from(multi),
    ));
    let n = remaining.len().min(first_capacity);
    page[start % PAGE + 48..start % PAGE + 48 + n].copy_from_slice(&remaining[..n]);
    remaining = &remaining[n..];
    protect(&mut page, 40, 0xd001);
    b[first_page..first_page + PAGE].copy_from_slice(&page);
    if multi {
        assert!(remaining.len() <= PAGE - 64);
        let wrapped = first_page + PAGE == LENGTH;
        let next_page = if wrapped { FIRST } else { first_page + PAGE };
        let last = lsn(if wrapped { 8 } else { 7 }, next_page + 64);
        let mut page = ordinary(
            last,
            query,
            2,
            2,
            (64 + remaining.len()).next_multiple_of(8),
        );
        page[64..64 + remaining.len()].copy_from_slice(remaining);
        protect(&mut page, 40, 0xd002);
        b[next_page..next_page + PAGE].copy_from_slice(&page);
    }
    (b, query)
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn restart_limits() -> NtfsLogFileLimits {
    NtfsLogFileLimits {
        restart_page_bytes: PAGE,
        clients: 1,
        work: 10000,
    }
}
fn limits() -> NtfsLogRecordLimits {
    NtfsLogRecordLimits {
        pages: 8,
        payload_bytes: 32768,
        work: 10000,
    }
}
struct Image {
    bytes: Vec<u8>,
    length: AtomicU64,
    fail: u64,
    cancel_at: u64,
    stale_at: u64,
    cancellation: Cancellation,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            fail: u64::MAX,
            cancel_at: u64::MAX,
            stale_at: u64::MAX,
            cancellation: Cancellation::default(),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset == self.fail {
            return Err(io::Error::other("independent late record failure"));
        }
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        if offset == self.cancel_at {
            self.cancellation.cancel();
        }
        if offset == self.stale_at {
            self.length.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[test]
fn inclusive_endpoint_counts_header_for_empty_payload_and_excludes_padding() {
    for (start, length) in [
        (FIRST + 64, 0),
        (FIRST + 64, 1),
        (FIRST + 64, 7),
        (FIRST + PAGE - 48, 0),
        (FIRST + 64, PAGE - 112),
    ] {
        let payload = vec![0x73; length];
        let (bytes, query) = fixture(start, &payload);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        let extent = report.extent().unwrap();
        assert_eq!(extent.final_byte_offset(), (start + 48 + length - 1) as u64);
        assert_eq!(extent.final_page_offset(), (start / PAGE * PAGE) as u64);
        assert_eq!(extent.physical_wraps(), 0);
        let mut observation = *report.header().unwrap();
        observation.payload_bytes = u32::MAX;
        assert_eq!(observation.payload_bytes, u32::MAX);
        assert_eq!(report.extent(), Some(extent));
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
fn ring_fixture(version: u16, start: usize, length: usize) -> (Vec<u8>, u64, usize, usize) {
    let first = if version == 1 { FIRST } else { 34 * PAGE };
    let mut image = base();
    for at in [0, PAGE] {
        w(&mut image, at + 28, version);
        w(&mut image, at + 26, if version == 1 { 1 } else { 0 });
    }
    let query = lsn(7, start);
    let mut pages: Vec<Vec<u8>> = (0..LENGTH / PAGE)
        .map(|_| ordinary(query + 8, query, 1, 1, 64))
        .collect();
    let header = record_header(query, length, 1);
    pages[start / PAGE][start % PAGE..start % PAGE + 48].copy_from_slice(&header);
    let mut at = start / PAGE;
    let mut position = start % PAGE + 48;
    let mut remaining = length;
    let mut visits = 1;
    loop {
        let count = remaining.min(PAGE - position);
        pages[at][position..position + count].fill(0x51);
        remaining -= count;
        if remaining == 0 {
            break;
        }
        at += 1;
        if at == LENGTH / PAGE {
            at = first / PAGE;
        }
        position = 64;
        visits += 1;
    }
    for (index, mut page) in pages.into_iter().enumerate().skip(first / PAGE) {
        protect(&mut page, 40, 0xd123);
        image[index * PAGE..(index + 1) * PAGE].copy_from_slice(&page);
    }
    (image, query, at, visits)
}
#[test]
fn continuation_endpoints_follow_version_specific_physical_wrap_without_lsn_inference() {
    for version in [1, 2] {
        for (start, length, wraps) in [
            (LENGTH - PAGE + PAGE - 48, 1, 1),
            (LENGTH - PAGE + 4000, 4050, 1),
            (
                if version == 1 {
                    FIRST + 4000
                } else {
                    34 * PAGE + 4000
                },
                4050,
                0,
            ),
        ] {
            let (bytes, query, endpage, visits) = ring_fixture(version, start, length);
            let r = resources();
            let mut cap = limits();
            cap.pages = visits;
            cap.work = 100000;
            let report = inspect_logfile_record(
                Arc::new(Image::new(bytes)),
                restart_limits(),
                cap,
                query,
                &r,
            )
            .unwrap();
            assert!(report.complete(), "{:?}", report.stopping_error());
            let extent = report.extent().unwrap();
            let first_count = (PAGE - start % PAGE - 48).min(length);
            let remainder = length - first_count;
            let last_count = if remainder == 0 {
                first_count
            } else {
                (remainder - 1) % (PAGE - 64) + 1
            };
            assert_eq!(extent.final_page_offset(), (endpage * PAGE) as u64);
            assert_eq!(
                extent.final_byte_offset(),
                (endpage * PAGE + 64 + last_count - 1) as u64
            );
            assert_eq!(extent.physical_wraps(), wraps);
            assert!(!report.active_window_complete());
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn near_full_ring_revisits_first_page_prefix_and_reports_one_actual_wrap() {
    for version in [1, 2] {
        let first = if version == 1 { FIRST } else { 34 * PAGE };
        let n = (LENGTH - first) / PAGE;
        let length = n * (PAGE - 64) - 56;
        let start = first + 3000;
        let (bytes, query, endpage, visits) = ring_fixture(version, start, length);
        assert_eq!(visits, n + 1);
        let r = resources();
        let mut cap = limits();
        cap.pages = visits;
        cap.payload_bytes = length;
        cap.work = length + 10000;
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            cap,
            query,
            &r,
        )
        .unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        let extent = report.extent().unwrap();
        assert_eq!(extent.final_page_offset(), first as u64);
        assert_eq!(endpage * PAGE, first);
        assert_eq!(extent.final_byte_offset(), (start - 9) as u64);
        assert_eq!(extent.physical_wraps(), 1);
        assert_eq!(
            report.pages().first().unwrap().offset(),
            report.pages().last().unwrap().offset()
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
        cap.pages = n;
        let partial = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            cap,
            query,
            &r,
        )
        .unwrap();
        assert!(!partial.complete());
        assert!(partial.extent().is_none());
        drop(partial);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_final_page_and_final_source_guards_never_publish_extent() {
    for mode in 0..3 {
        let (mut bytes, query) = fixture(FIRST + 64, &[0x19; 32]);
        if mode == 0 {
            bytes[FIRST + 510] ^= 1;
        }
        let r = resources();
        let mut image = Image::new(bytes);
        if mode == 1 {
            image.stale_at = FIRST as u64;
        }
        if mode == 2 {
            image.cancel_at = FIRST as u64;
            image.cancellation = r.cancellation.clone();
        }
        let report =
            inspect_logfile_record(Arc::new(image), restart_limits(), limits(), query, &r).unwrap();
        assert!(!report.complete());
        assert!(report.extent().is_none());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
