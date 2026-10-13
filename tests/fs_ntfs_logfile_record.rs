#![cfg(feature = "std")]

// Independent byte authoring from the 1.1 LFS layouts; no production encoder.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
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
            start % PAGE + 48 + payload.len()
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
        let mut page = ordinary(last, query, 2, 2, 64 + remaining.len());
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
fn independently_authored_single_record_restores_payload_sector_trailers() {
    let payload: Vec<u8> = (0..1200).map(|n| (n % 251) as u8).collect();
    let (bytes, query) = fixture(FIRST + 64, &payload);
    let raw = bytes[FIRST..FIRST + PAGE].to_vec();
    let r = resources();
    let report = inspect_logfile_record(
        Arc::new(Image::new(bytes)),
        restart_limits(),
        limits(),
        query,
        &r,
    )
    .unwrap();
    assert!(report.complete());
    assert_eq!(report.payload(), Some(payload.as_slice()));
    let header = report.header().unwrap();
    assert_eq!(header.this_lsn, query);
    assert_eq!(header.previous_lsn, 0x1122334455667788);
    assert_eq!(header.undo_next_lsn, 0x8877665544332211);
    assert_eq!(header.transaction_id, 0x12345678);
    assert_eq!(report.pages().len(), 1);
    assert_eq!(report.pages()[0].raw(), raw);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn payload_assembles_across_pages_and_physical_wrap_without_selecting_a_tail() {
    let payload: Vec<u8> = (0..1024).map(|n| (n % 239) as u8).collect();
    for start in [FIRST + 4000, LENGTH - PAGE + 4000] {
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
        assert!(
            report.complete(),
            "start {start}: {:?}",
            report.stopping_error()
        );
        assert_eq!(report.payload(), Some(payload.as_slice()));
        assert_eq!(report.pages().len(), 2);
        assert_eq!(
            report.pages()[1].offset(),
            if start / PAGE == 63 {
                FIRST as u64
            } else {
                (start / PAGE + 1) as u64 * PAGE as u64
            }
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn address_admission_rejects_restart_tail_header_and_split_record_header_positions() {
    let (bytes, _) = fixture(FIRST + 64, &[1; 32]);
    for query in [
        0,
        lsn(7, 2 * PAGE + 64),
        lsn(7, FIRST + 56),
        lsn(7, FIRST + PAGE - 40),
        lsn(7, LENGTH),
    ] {
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.stopping_error().is_some());
        assert!(report.payload().is_none());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn record_identity_client_type_flags_and_exact_lsn_are_checked() {
    for (relative, width, value) in [
        (0, 8, 99),
        (28, 2, 20),
        (30, 2, 1),
        (32, 4, 3),
        (40, 2, 0x8000),
    ] {
        let (mut bytes, query) = fixture(FIRST + 64, &[1; 32]);
        let at = FIRST + 64 + relative;
        match width {
            8 => q(&mut bytes, at, value),
            4 => d(&mut bytes, at, value as u32),
            _ => w(&mut bytes, at, value as u16),
        }
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete(), "relative {relative}");
        assert!(report.stopping_error().is_some());
        assert!(report.payload().is_none());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn torn_page_and_invalid_usa_never_expose_record_payload() {
    for (relative, value) in [(510, 0), (4, 38), (6, 8)] {
        let (mut bytes, query) = fixture(FIRST + 64, &[1; 32]);
        w(&mut bytes, FIRST + relative, value);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.payload().is_none());
        assert!(report.stopping_error().is_some());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn independent_page_payload_and_work_caps_preserve_failure_and_refund() {
    let (bytes, query) = fixture(FIRST + 4000, &[1; 1024]);
    for caps in [
        NtfsLogRecordLimits {
            pages: 1,
            ..limits()
        },
        NtfsLogRecordLimits {
            payload_bytes: 100,
            ..limits()
        },
        NtfsLogRecordLimits {
            work: 0,
            ..limits()
        },
    ] {
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            caps,
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert!(report.payload().is_none());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn late_io_cancellation_and_source_change_retain_first_page_without_complete_payload() {
    for mode in 0..3 {
        let (bytes, query) = fixture(FIRST + 4000, &[1; 1024]);
        let r = resources();
        let mut source = Image::new(bytes);
        match mode {
            0 => source.fail = (FIRST + PAGE) as u64,
            1 => {
                source.cancel_at = (FIRST + PAGE) as u64;
                source.cancellation = r.cancellation.clone();
            }
            _ => source.stale_at = (FIRST + PAGE) as u64,
        }
        let report =
            inspect_logfile_record(Arc::new(source), restart_limits(), limits(), query, &r)
                .unwrap();
        assert!(!report.complete());
        assert!(report.payload().is_none());
        assert!(report.pages().len() >= 2);
        assert!(report.pages()[0].read_complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            match mode {
                0 => ErrorKind::Io,
                1 => ErrorKind::Cancelled,
                _ => ErrorKind::StalePlan,
            }
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn wrapped_continuation_may_retain_the_original_record_lsn() {
    let payload = [0x73; 1024];
    let (mut bytes, query) = fixture(LENGTH - PAGE + 4000, &payload);
    q(&mut bytes, FIRST + 8, query);
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
    assert_eq!(report.payload(), Some(payload.as_slice()));
    assert!(!report.active_window_complete());
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn local_page_lsn_and_final_last_ended_evidence_bound_exact_record_assembly() {
    for mode in 0..4 {
        let (mut bytes, query) = fixture(FIRST + 4000, &[1; 1024]);
        match mode {
            0 => q(&mut bytes, FIRST + 8, query - 1),
            1 => q(&mut bytes, FIRST + 32, query),
            2 => d(&mut bytes, FIRST + PAGE + 16, 0),
            _ => q(&mut bytes, FIRST + PAGE + 32, query - 1),
        }
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete(), "mode {mode}");
        assert!(report.stopping_error().is_some());
        assert!(report.payload().is_none());
        assert!(!report.active_window_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn oversized_declared_payload_and_incompatible_restart_copies_fail_without_payload() {
    for mode in 0..2 {
        let (mut bytes, query) = fixture(FIRST + 64, &[1; 32]);
        if mode == 0 {
            d(&mut bytes, FIRST + 64 + 24, u32::MAX);
        } else {
            q(&mut bytes, PAGE + 56, lsn(9, FIRST + 72));
        }
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.stopping_error().is_some());
        assert!(report.payload().is_none());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn pre_cancel_and_insufficient_restart_memory_fail_without_read_evidence_or_leaks() {
    let (bytes, query) = fixture(FIRST + 64, &[1; 32]);
    for cancelled in [false, true] {
        let r = Resources {
            memory: Budget::new(if cancelled { 1 << 20 } else { 1 }),
            cancellation: Cancellation::default(),
        };
        if cancelled {
            r.cancellation.cancel();
        }
        let error = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .err()
        .unwrap();
        assert_eq!(
            error.kind,
            if cancelled {
                ErrorKind::Cancelled
            } else {
                ErrorKind::BudgetExhausted
            }
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean;
#[test]
fn native_helper_queries_record_two_and_keeps_volume_flags_separate() {
    use ntfs_clean::{name_value, nonresident, put, resident};
    use partmgr::fs_ntfs::{NtfsReadLimits, NtfsStreamLimits};
    use partmgr::fs_ntfs_logfile::inspect_ntfs_logfile_record;
    for dirty in [false, true] {
        let payload = [0x42; 1200];
        let (journal, query) = fixture(FIRST + 64, &payload);
        let mut bytes = ntfs_clean::ntfs_audit_seed();
        let data = nonresident(
            &[0x22, 0, 2, 0, 2, 0],
            512,
            LENGTH as u64,
            LENGTH as u64,
            false,
        );
        put(
            &mut bytes,
            2,
            &[resident(0x30, &name_value("$LogFile", 5), 2), data],
            false,
            1,
        );
        bytes[512 * 512..512 * 512 + LENGTH].copy_from_slice(&journal);
        if dirty {
            let flag =
                2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10;
            w(&mut bytes, flag, 1);
        }
        let mirror = bytes[2048..6144].to_vec();
        bytes[500 * 512..508 * 512].copy_from_slice(&mirror);
        let r = resources();
        let inspected = inspect_ntfs_logfile_record(
            Arc::new(Image::new(bytes)),
            NtfsReadLimits {
                attributes: 32,
                runs: 64,
                names: 8,
            },
            NtfsStreamLimits {
                extension_records: 8,
                list_entries: 64,
                list_bytes: 4096,
                attributes: 32,
                runs: 64,
                work: 1_000_000,
            },
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(inspected.owner.native.as_slice().try_into().unwrap()),
            2
        );
        assert_eq!(inspected.owner.generation, 7);
        assert_eq!(inspected.volume_flags, u16::from(dirty));
        assert!(
            inspected.report.complete(),
            "{:?}",
            inspected.report.stopping_error()
        );
        assert_eq!(inspected.report.payload(), Some(payload.as_slice()));
        assert!(!inspected.report.active_window_complete());
        assert!(!inspected.report.transaction_analysis_complete());
        drop(inspected);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn fixed_up_record_header_may_cross_a_transfer_sector_boundary() {
    let (bytes, query) = fixture(FIRST + 496, &[0x24; 32]);
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
    assert_eq!(report.header().unwrap().previous_lsn, 0x1122334455667788);
    assert_eq!(report.payload(), Some([0x24; 32].as_slice()));
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn near_full_ring_record_can_revisit_the_first_page_prefix_before_its_header() {
    let ordinary_pages = LENGTH / PAGE - 4;
    let data_bytes = PAGE - 64;
    // Eight unused data bytes separate the final payload suffix from its own
    // header. The record fits the ring, but starts so late that it visits the
    // first physical page twice rather than overlapping its header.
    let payload_len = ordinary_pages * data_bytes - 48 - 8;
    let payload: Vec<u8> = (0..payload_len)
        .map(|n| ((n * 17 + 9) % 251) as u8)
        .collect();
    let query = lsn(7, FIRST + 4000);
    let mut pages: Vec<Vec<u8>> = (0..ordinary_pages)
        .map(|_| ordinary(query + 8, query, 1, 1, 64))
        .collect();
    pages[0][4000..4048].copy_from_slice(&record_header(query, payload_len, 1));
    let mut copied = 0;
    for visit in 0..=ordinary_pages {
        let index = visit % ordinary_pages;
        let position = if visit == 0 { 4048 } else { 64 };
        let count = (payload_len - copied).min(PAGE - position);
        pages[index][position..position + count].copy_from_slice(&payload[copied..copied + count]);
        copied += count;
        if visit == ordinary_pages {
            assert_eq!(position + count, 3992);
        }
    }
    assert_eq!(copied, payload_len);
    let mut bytes = base();
    for (index, page) in pages.iter_mut().enumerate() {
        protect(page, 40, 0xe000 + index as u16);
        bytes[(index + 4) * PAGE..(index + 5) * PAGE].copy_from_slice(page);
    }
    for cap in [ordinary_pages, ordinary_pages + 1] {
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            NtfsLogRecordLimits {
                pages: cap,
                payload_bytes: payload_len,
                work: 1_000_000,
            },
            query,
            &r,
        )
        .unwrap();
        assert_eq!(report.pages().len(), cap);
        if cap == ordinary_pages {
            assert!(!report.complete());
            assert!(report.payload().is_none());
            assert_eq!(
                report.stopping_error().unwrap().kind,
                ErrorKind::BudgetExhausted
            );
        } else {
            assert!(report.complete(), "{:?}", report.stopping_error());
            assert_eq!(report.payload(), Some(payload.as_slice()));
            assert_eq!(report.pages()[0].offset(), FIRST as u64);
            assert_eq!(report.pages().last().unwrap().offset(), FIRST as u64);
            assert_eq!(
                report.pages()[0].raw(),
                report.pages().last().unwrap().raw()
            );
        }
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn opaque_page_bit_two_preserves_structural_record_without_flag_semantics_claim() {
    let payload = [0x63; 32];
    for flags in [1, 3, 5] {
        let (mut bytes, query) = fixture(FIRST + 64, &payload);
        d(&mut bytes, FIRST + 16, flags);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert_eq!(report.pages()[0].header().unwrap().flags, flags);
        if flags == 5 {
            assert!(!report.complete());
            assert!(report.payload().is_none());
            assert_eq!(
                report.stopping_error().unwrap().kind,
                ErrorKind::Unsupported
            );
            assert!(!report.page_flag_semantics_supported());
        } else {
            assert!(report.complete(), "{:?}", report.stopping_error());
            assert_eq!(report.payload(), Some(payload.as_slice()));
            assert_eq!(report.page_flag_semantics_supported(), flags == 1);
        }
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

fn version_two_record_fixture(start: usize, payload: &[u8]) -> (Vec<u8>, u64) {
    let (mut bytes, query) = fixture(start, payload);
    for offset in [0, PAGE] {
        w(&mut bytes, offset + 26, 0);
        w(&mut bytes, offset + 28, 2);
    }
    if start / PAGE == LENGTH / PAGE - 1 && payload.len() > PAGE - start % PAGE - 48 {
        let continuation = bytes[FIRST..FIRST + PAGE].to_vec();
        bytes[34 * PAGE..35 * PAGE].copy_from_slice(&continuation);
        bytes[FIRST..FIRST + PAGE].fill(0xff);
    }
    (bytes, query)
}
fn contextual_query(
    bytes: Vec<u8>,
    lsn: u64,
    copy: u8,
    r: &Resources,
) -> partmgr::fs_core::Result<partmgr::fs_ntfs_logfile::NtfsLogRecordReport> {
    use partmgr::fs_ntfs_logfile::{NtfsLogRecordQuery, inspect_logfile_record_in_restart};
    inspect_logfile_record_in_restart(
        Arc::new(Image::new(bytes)),
        restart_limits(),
        limits(),
        NtfsLogRecordQuery {
            lsn,
            restart_copy: copy,
        },
        r,
    )
}
#[test]
fn explicit_restart_contexts_assemble_divergent_copies_without_selecting_an_active_window() {
    for version in [1, 2] {
        let payload = [0x36; 32];
        let start = if version == 1 {
            FIRST + 64
        } else {
            34 * PAGE + 64
        };
        let (mut bytes, query) = if version == 1 {
            fixture(start, &payload)
        } else {
            version_two_record_fixture(start, &payload)
        };
        q(&mut bytes, PAGE + 56, lsn(9, start + 8));
        let r = resources();
        let strict = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(!strict.complete());
        assert!(strict.restart().copies_disagree());
        assert_eq!(strict.requested_restart_copy(), None);
        drop(strict);
        for copy in 0..2 {
            let report = contextual_query(bytes.clone(), query, copy, &r).unwrap();
            assert!(
                report.complete(),
                "version {version} copy {copy}: {:?}",
                report.stopping_error()
            );
            assert_eq!(report.payload(), Some(payload.as_slice()));
            assert!(report.stopping_error().is_none());
            assert_eq!(report.requested_restart_copy(), Some(copy));
            assert_eq!(
                report.restart_context().unwrap(),
                report.restart().copies()[usize::from(copy)].area().unwrap()
            );
            assert!(report.restart().copies_disagree());
            assert!(!report.active_window_complete());
            assert!(!report.transaction_analysis_complete());
            drop(report);
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn invalid_copy_index_and_selected_client_identity_cannot_borrow_the_other_context() {
    let (mut bytes, query) = fixture(FIRST + 64, &[0x44; 32]);
    w(&mut bytes, PAGE + 140, SEQUENCE + 1);
    let r = resources();
    let good = contextual_query(bytes.clone(), query, 0, &r).unwrap();
    assert!(good.complete());
    drop(good);
    for copy in [1, 2, u8::MAX] {
        let report = contextual_query(bytes.clone(), query, copy, &r).unwrap();
        assert!(!report.complete());
        assert!(report.payload().is_none());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::InvalidData
        );
        drop(report);
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn explicit_context_retains_unselected_format_failure_but_never_uses_a_bad_selected_copy() {
    for unsupported in [false, true] {
        let (mut bytes, query) = fixture(FIRST + 64, &[0x51; 32]);
        if unsupported {
            w(&mut bytes, PAGE + 28, 3);
        } else {
            bytes[PAGE + 510] ^= 1;
        }
        let r = resources();
        let report = contextual_query(bytes.clone(), query, 0, &r).unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        assert!(report.stopping_error().is_none());
        assert!(report.restart().copies()[1].area().is_err());
        assert!(report.restart_context().is_some());
        drop(report);
        let bad = contextual_query(bytes, query, 1, &r).unwrap();
        assert!(!bad.complete());
        assert!(bad.payload().is_none());
        assert!(bad.restart_context().is_none());
        assert_eq!(
            bad.stopping_error().unwrap().kind,
            if unsupported {
                ErrorKind::Unsupported
            } else {
                ErrorKind::InvalidData
            }
        );
        drop(bad);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn unselected_backend_io_still_prevents_complete_contextual_assembly() {
    use partmgr::fs_ntfs_logfile::{NtfsLogRecordQuery, inspect_logfile_record_in_restart};
    let (bytes, query) = fixture(FIRST + 64, &[0x51; 32]);
    let mut source = Image::new(bytes);
    source.fail = PAGE as u64;
    let r = resources();
    let report = inspect_logfile_record_in_restart(
        Arc::new(source),
        restart_limits(),
        limits(),
        NtfsLogRecordQuery {
            lsn: query,
            restart_copy: 0,
        },
        &r,
    )
    .unwrap();
    assert!(!report.complete());
    assert!(report.payload().is_none());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
    assert!(!report.restart().copies()[1].read_complete());
    assert!(report.pages().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn matching_two_zero_contexts_support_strict_ordinary_records_and_wrap_at_page_34() {
    for start in [34 * PAGE + 4000, LENGTH - PAGE + 4000] {
        let payload = [0x67; 1024];
        let (bytes, query) = version_two_record_fixture(start, &payload);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes.clone())),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        assert_eq!(report.payload(), Some(payload.as_slice()));
        assert_eq!(report.requested_restart_copy(), None);
        assert_eq!(report.restart_context().unwrap().version, (2, 0));
        assert!(
            report
                .pages()
                .iter()
                .all(|page| page.offset() >= 34 * PAGE as u64)
        );
        if start / PAGE == 63 {
            assert_eq!(report.pages()[1].offset(), 34 * PAGE as u64);
        }
        drop(report);
        for fast in [2 * PAGE, 4 * PAGE, 33 * PAGE] {
            let invalid = contextual_query(bytes.clone(), lsn(7, fast + 64), 0, &r).unwrap();
            assert!(!invalid.complete());
            assert!(invalid.pages().is_empty());
            assert_eq!(
                invalid.stopping_error().unwrap().kind,
                ErrorKind::InvalidData
            );
            drop(invalid);
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn contextual_queries_keep_page_limits_cancellation_and_stale_source_guards() {
    use partmgr::fs_ntfs_logfile::{NtfsLogRecordQuery, inspect_logfile_record_in_restart};
    for mode in 0..3 {
        let (bytes, query) = version_two_record_fixture(34 * PAGE + 4000, &[0x74; 1024]);
        let r = resources();
        let mut source = Image::new(bytes);
        match mode {
            1 => {
                source.cancel_at = 35 * PAGE as u64;
                source.cancellation = r.cancellation.clone();
            }
            2 => source.stale_at = 35 * PAGE as u64,
            _ => {}
        }
        let cap = if mode == 0 {
            NtfsLogRecordLimits {
                pages: 1,
                ..limits()
            }
        } else {
            limits()
        };
        let report = inspect_logfile_record_in_restart(
            Arc::new(source),
            restart_limits(),
            cap,
            NtfsLogRecordQuery {
                lsn: query,
                restart_copy: 1,
            },
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.payload().is_none());
        assert_eq!(report.requested_restart_copy(), Some(1));
        assert_eq!(
            report.stopping_error().unwrap().kind,
            match mode {
                0 => ErrorKind::BudgetExhausted,
                1 => ErrorKind::Cancelled,
                _ => ErrorKind::StalePlan,
            }
        );
        assert!(!report.active_window_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn opaque_lfs_envelope_bit_four_is_structural_without_interpreting_its_semantics() {
    for flags in [0, 1, 4, 5, 2, 8] {
        let payload = [0x23; 32];
        let (mut bytes, query) = fixture(FIRST + 64, &payload);
        w(&mut bytes, FIRST + 64 + 40, flags);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        assert_eq!(report.header().unwrap().flags, flags);
        if flags & !5 != 0 {
            assert!(!report.complete());
            assert_eq!(
                report.stopping_error().unwrap().kind,
                ErrorKind::Unsupported
            );
            assert!(report.payload().is_none());
            assert!(!report.envelope_flag_semantics_supported());
        } else {
            assert!(
                report.complete(),
                "flags {flags}: {:?}",
                report.stopping_error()
            );
            assert_eq!(report.payload(), Some(payload.as_slice()));
            assert_eq!(report.envelope_flag_semantics_supported(), flags & 4 == 0);
        }
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn opaque_lfs_flag_four_does_not_replace_the_required_multipage_bit() {
    for flags in [4, 5] {
        let payload = [0x35; 1024];
        let (mut bytes, query) = fixture(FIRST + 4000, &payload);
        w(&mut bytes, FIRST + 4000 + 40, flags);
        let r = resources();
        let report = inspect_logfile_record(
            Arc::new(Image::new(bytes)),
            restart_limits(),
            limits(),
            query,
            &r,
        )
        .unwrap();
        if flags == 4 {
            assert!(!report.complete());
            assert_eq!(
                report.stopping_error().unwrap().kind,
                ErrorKind::InvalidData
            );
            assert!(report.payload().is_none());
        } else {
            assert!(report.complete(), "{:?}", report.stopping_error());
            assert_eq!(report.payload(), Some(payload.as_slice()));
        }
        assert!(!report.envelope_flag_semantics_supported());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
