#![cfg(feature = "std")]
//! Independent source-owned dirty-page to open-attribute links.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogCheckpointDumpLimits, NtfsLogFileLimits, NtfsLogRecordLimits, NtfsLogRecordQuery,
        NtfsLogRestartTableLimits, inspect_logfile_checkpoint_dumps,
    },
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;
const PAGE: usize = 4096;
const LENGTH: usize = 64 * PAGE;
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn q(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn protect(b: &mut [u8], usa: usize, marker: u16) {
    w(b, usa, marker);
    for sector in 1..=8 {
        let at = sector * 512 - 2;
        let prior = u16::from_le_bytes([b[at], b[at + 1]]);
        w(b, usa + sector * 2, prior);
        w(b, at, marker);
    }
}
fn lsn(page: usize) -> u64 {
    (7 << 16) | ((page * PAGE + 64) as u64 / 8)
}
fn restart(version: u16, current: u64, marker: u16) -> Vec<u8> {
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"RSTR");
    w(&mut b, 4, 32);
    w(&mut b, 6, 9);
    d(&mut b, 16, PAGE as u32);
    d(&mut b, 20, PAGE as u32);
    w(&mut b, 24, 56);
    w(&mut b, 26, if version == 1 { 1 } else { 0 });
    w(&mut b, 28, version);
    q(&mut b, 56, current);
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
    w(&mut b, 140, 9);
    d(&mut b, 148, 8);
    b[152..160].copy_from_slice(b"N\0T\0F\0S\0");
    protect(&mut b, 32, marker);
    b
}
fn record_page(page: usize, kind: u32, payload: &[u8]) -> Vec<u8> {
    let query = lsn(page);
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"RCRD");
    w(&mut b, 4, 40);
    w(&mut b, 6, 9);
    q(&mut b, 8, query);
    d(&mut b, 16, 1);
    w(&mut b, 20, 1);
    w(&mut b, 22, 1);
    w(&mut b, 24, (112 + payload.len()).next_multiple_of(8) as u16);
    q(&mut b, 32, query);
    q(&mut b, 64, query);
    d(&mut b, 88, payload.len() as u32);
    w(&mut b, 92, 9);
    d(&mut b, 96, kind);
    b[112..112 + payload.len()].copy_from_slice(payload);
    protect(&mut b, 40, 0xc000 + page as u16);
    b
}
struct Image {
    bytes: Vec<u8>,
    length: AtomicU64,
    reads: AtomicU64,
    fail: u64,
    cancel_at: u64,
    stale_at: u64,
    change_context: bool,
    cancel: Cancellation,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            reads: AtomicU64::new(0),
            fail: u64::MAX,
            cancel_at: u64::MAX,
            stale_at: u64::MAX,
            change_context: false,
            cancel: Cancellation::default(),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let read_index = self.reads.fetch_add(1, Ordering::SeqCst);
        if offset == self.fail {
            return Err(io::Error::other("independent later dump failure"));
        }
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(at..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        if self.change_context && offset == PAGE as u64 && read_index >= 3 {
            out[300] ^= 1;
        }
        if offset == self.cancel_at {
            self.cancel.cancel();
        }
        if offset == self.stale_at {
            self.length.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsLogCheckpointDumpLimits {
    NtfsLogCheckpointDumpLimits {
        restart: NtfsLogFileLimits {
            restart_page_bytes: PAGE,
            clients: 1,
            work: 10000,
        },
        record: NtfsLogRecordLimits {
            pages: 8,
            payload_bytes: 4096,
            work: 10000,
        },
        table: NtfsLogRestartTableLimits {
            entries: 32,
            bytes: 4096,
            work: 10000,
        },
        queries: 5,
        pages: 64,
        payload_bytes: 32768,
        work: 100_000,
    }
}

fn open_slot() -> Vec<u8> {
    let mut b = vec![0x6a; 48];
    d(&mut b, 0, u32::MAX);
    d(&mut b, 4, 4096);
    d(&mut b, 8, 0x80);
    b[12..16].copy_from_slice(&[0x91, 0x82, 0x73, 0x64]);
    q(&mut b, 16, 0x1234000056780000);
    q(&mut b, 24, 0x8877665544332211);
    b[32..40].copy_from_slice(&[1, 3, 5, 7, 9, 11, 13, 15]);
    b
}
fn dirty_slot() -> Vec<u8> {
    let mut b = vec![0x7b; 56];
    d(&mut b, 0, u32::MAX);
    d(&mut b, 4, 24);
    d(&mut b, 8, 4096);
    d(&mut b, 12, 2);
    q(&mut b, 16, (-0x123456i64) as u64);
    q(&mut b, 24, 0x9988776655443322);
    q(&mut b, 32, (-1i64) as u64);
    q(&mut b, 40, (i64::MIN + 3) as u64);
    b
}
fn tx_slot(state: u8) -> Vec<u8> {
    let mut b = vec![0x8c; 48];
    d(&mut b, 0, u32::MAX);
    b[4] = state;
    b[5..8].copy_from_slice(&[0xa1, 0xb2, 0xc3]);
    q(&mut b, 8, 0x1001);
    q(&mut b, 16, 0x2002);
    q(&mut b, 24, 0x3003);
    d(&mut b, 32, 17);
    d(&mut b, 36, 4097);
    b
}
fn table_for(slot: &[u8], allocated: bool) -> Vec<u8> {
    let mut raw = vec![0; 24 + slot.len()];
    w(&mut raw, 0, slot.len() as u16);
    w(&mut raw, 2, 1);
    w(&mut raw, 4, u16::from(allocated));
    raw[24..].copy_from_slice(slot);
    if !allocated {
        d(&mut raw, 16, 24);
        d(&mut raw, 20, 24);
        d(&mut raw, 24, 0);
    }
    raw
}
fn fixture(
    version: u16,
    tables: [Vec<u8>; 4],
    client_version: (u32, u32),
) -> (Vec<u8>, NtfsLogRecordQuery, usize) {
    let first = if version == 1 { 4 } else { 34 };
    let mut bytes = vec![0xff; LENGTH];
    let mut cp = vec![0; 64];
    d(&mut cp, 0, client_version.0);
    d(&mut cp, 4, client_version.1);
    for (index, table) in tables.iter().enumerate() {
        q(&mut cp, 16 + index * 8, lsn(first + index + 1));
        d(&mut cp, 48 + index * 4, table.len() as u32);
    }
    bytes[..PAGE].copy_from_slice(&restart(version, lsn(first), 0xa001));
    bytes[PAGE..2 * PAGE].copy_from_slice(&restart(version, lsn(first) + 8, 0xa002));
    bytes[first * PAGE..(first + 1) * PAGE].copy_from_slice(&record_page(first, 2, &cp));
    for (index, table) in tables.into_iter().enumerate() {
        let mut payload = vec![0; 40 + table.len()];
        w(&mut payload, 0, 29 + index as u16);
        w(&mut payload, 4, 40);
        w(&mut payload, 6, table.len() as u16);
        payload[40..].copy_from_slice(&table);
        let page = first + index + 1;
        bytes[page * PAGE..(page + 1) * PAGE].copy_from_slice(&record_page(page, 1, &payload));
    }
    (
        bytes,
        NtfsLogRecordQuery {
            lsn: lsn(first),
            restart_copy: 1,
        },
        first,
    )
}
fn tables() -> [Vec<u8>; 4] {
    let mut names = vec![0; 24];
    w(&mut names, 0, 4);
    [
        table_for(&open_slot(), true),
        names,
        table_for(&dirty_slot(), true),
        table_for(&tx_slot(3), true),
    ]
}

#[test]
fn links_borrow_exact_allocated_slots_in_both_source_context_profiles() {
    for version in [1, 2] {
        let (bytes, query, _) = fixture(version, tables(), (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete());
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        let charged = r.memory.used();
        let link = report.dirty_page_open_attribute(0).unwrap().unwrap();
        assert_eq!(link.target_offset(), 24);
        assert_eq!(link.target_index(), 0);
        assert_eq!(link.dirty().raw(), dirty_slot());
        assert_eq!(link.open_attribute().raw(), open_slot());
        assert!(std::ptr::eq(
            link.open_attribute().raw().as_ptr(),
            report.dumps()[0].record().unwrap().payload().unwrap()[64..].as_ptr()
        ));
        assert!(std::ptr::eq(
            link.dirty().raw().as_ptr(),
            report.dumps()[2].record().unwrap().payload().unwrap()[64..].as_ptr()
        ));
        assert_eq!(link.dirty().lcn(0), Some(-1));
        assert_eq!(
            link.open_attribute().opaque_flags(),
            &[0x91, 0x82, 0x73, 0x64]
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn target_must_be_exact_allocated_slot_start_not_header_interior_or_extent_end() {
    for target in [0, 4, 23, 25, 32, 71, 72, 120, u32::MAX] {
        let mut ts = tables();
        d(&mut ts[2], 28, target);
        let (bytes, query, _) = fixture(2, ts, (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete());
        assert_eq!(
            report.dirty_page_open_attribute(0).unwrap_err().kind,
            ErrorKind::InvalidData,
            "target={target}"
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn free_or_short_open_slot_cannot_resolve_an_allocated_dirty_slot() {
    for open in [
        table_for(&open_slot(), false),
        table_for(&u32::MAX.to_le_bytes(), true),
    ] {
        let mut ts = tables();
        ts[0] = open;
        let (bytes, query, _) = fixture(1, ts, (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete());
        assert_eq!(
            report.dirty_page_open_attribute(0).unwrap_err().kind,
            ErrorKind::InvalidData
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn absent_free_and_out_of_range_dirty_slots_have_no_link() {
    for free in [false, true] {
        let mut ts = tables();
        if free {
            ts[2] = table_for(&dirty_slot(), false);
        }
        let (bytes, query, _) = fixture(2, ts, (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        if free {
            assert!(report.dirty_page_open_attribute(0).unwrap().is_none());
        }
        assert!(report.dirty_page_open_attribute(1).unwrap().is_none());
        assert!(
            report
                .dirty_page_open_attribute(usize::MAX)
                .unwrap()
                .is_none()
        );
    }
    let (mut bytes, query, first) = fixture(1, tables(), (1, 0));
    // Zero byte references are absent even when the original LSN is retained.
    d(&mut bytes, first * PAGE + 112 + 56, 0);
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(report.complete());
    assert!(report.dirty_page_open_attribute(0).unwrap().is_none());
}

#[test]
fn partial_reports_only_join_already_validated_tables() {
    for queries in [2, 4] {
        let (bytes, query, _) = fixture(2, tables(), (1, 0));
        let r = resources();
        let mut cap = limits();
        cap.queries = queries;
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), cap, query, &r).unwrap();
        assert!(!report.complete());
        if queries == 4 {
            assert!(report.dirty_page_open_attribute(0).unwrap().is_some());
        } else {
            assert_eq!(
                report.dirty_page_open_attribute(0).unwrap_err().kind,
                ErrorKind::InvalidData
            );
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    let mut ts = tables();
    // Generic allocated-count disagreement leaves the dirty record retained but unvalidated.
    w(&mut ts[2], 4, 0);
    let (bytes, query, _) = fixture(1, ts, (1, 0));
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(!report.complete());
    assert!(report.dumps()[2].record().is_some());
    assert_eq!(
        report.dirty_page_open_attribute(0).unwrap_err().kind,
        ErrorKind::InvalidData
    );
}

#[test]
fn missing_open_reference_does_not_borrow_a_foreign_report_or_mutated_observation() {
    let (bytes, query, _) = fixture(2, tables(), (1, 0));
    let r = resources();
    let good =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    let mut observed = good.dirty_page_entry(0).unwrap().unwrap();
    observed.target_attribute = u32::MAX;
    observed.lcn_count = u32::MAX;
    assert_eq!(observed.target_attribute, u32::MAX);
    assert_eq!(observed.lcn(usize::MAX), None);
    assert_eq!(
        good.dirty_page_open_attribute(0)
            .unwrap()
            .unwrap()
            .target_offset(),
        24
    );
    let (mut bytes, query, first) = fixture(2, tables(), (1, 0));
    d(&mut bytes, first * PAGE + 112 + 48, 0);
    let missing =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(missing.complete());
    assert_eq!(
        missing.dirty_page_open_attribute(0).unwrap_err().kind,
        ErrorKind::InvalidData
    );
    assert!(good.dirty_page_open_attribute(0).unwrap().is_some());
    drop(missing);
    drop(good);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn separate_restart_copy_reports_keep_their_own_open_bytes() {
    let r = resources();
    let mut reports = Vec::new();
    for copy in [0, 1] {
        let mut ts = tables();
        q(&mut ts[0], 24 + 16, 0x1000 + u64::from(copy));
        let (bytes, mut query, _) = fixture(2, ts, (1, 0));
        query.restart_copy = copy;
        reports.push(
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap(),
        );
    }
    for (index, report) in reports.iter().enumerate() {
        let link = report.dirty_page_open_attribute(0).unwrap().unwrap();
        assert_eq!(link.open_attribute().file_reference, 0x1000 + index as u64);
        assert_eq!(
            report.checkpoint().requested_restart_copy(),
            Some(index as u8)
        );
    }
    drop(reports);
    assert_eq!(r.memory.used(), 0);
}
