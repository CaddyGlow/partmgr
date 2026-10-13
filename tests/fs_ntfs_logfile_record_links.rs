#![cfg(feature = "std")]
//! Independent raw fixtures for source-owned native link observations.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogRecordLimits, NtfsLogRecordLinkKind, NtfsLogRecordLinkLimits,
        NtfsLogRecordLinkTermination, NtfsLogRecordQuery, inspect_logfile_record_links,
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
fn link_limits() -> NtfsLogRecordLinkLimits {
    NtfsLogRecordLinkLimits {
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
        records: 8,
        pages: 32,
        payload_bytes: 32768,
        work: 100000,
    }
}
fn chain(
    version: u16,
    kind: NtfsLogRecordLinkKind,
    targets: &[usize],
) -> (Vec<u8>, NtfsLogRecordQuery, usize) {
    let first = if version == 1 { 4 } else { 34 };
    let mut bytes = vec![0xff; LENGTH];
    bytes[..PAGE].copy_from_slice(&restart(version, lsn(first), 0xa001));
    bytes[PAGE..2 * PAGE].copy_from_slice(&restart(version, lsn(first) + 8, 0xa002));
    let query = NtfsLogRecordQuery {
        lsn: lsn(first),
        restart_copy: 1,
    };
    for index in 0..targets.len() {
        let payload = [0x40 + index as u8; 64];
        bytes[(first + index) * PAGE..(first + index + 1) * PAGE].copy_from_slice(&record_page(
            first + index,
            1,
            &payload,
        ));
    }
    let field = if kind == NtfsLogRecordLinkKind::Previous {
        8
    } else {
        16
    };
    for (index, &target) in targets.iter().enumerate() {
        let value = if target == usize::MAX {
            0
        } else {
            lsn(first + target)
        };
        q(&mut bytes, (first + index) * PAGE + 64 + field, value);
    }
    (bytes, query, first)
}
#[test]
fn zero_link_closure_is_source_owned_but_not_complete_history() {
    for version in [1, 2] {
        for kind in [
            NtfsLogRecordLinkKind::Previous,
            NtfsLogRecordLinkKind::UndoNext,
        ] {
            let (bytes, query, first) = chain(version, kind, &[1, 2, usize::MAX]);
            let r = resources();
            let source = Arc::new(Image::new(bytes));
            let report =
                inspect_logfile_record_links(source.clone(), link_limits(), query, kind, &r)
                    .unwrap();
            assert!(report.complete(), "{:?}", report.stopping_error());
            assert_eq!(report.termination(), NtfsLogRecordLinkTermination::ZeroLink);
            assert_eq!(report.kind(), kind);
            assert_eq!(report.records().len(), 3);
            assert_eq!(report.queries(), 3);
            assert_eq!(report.pages(), 9);
            assert_eq!(report.pending_next_lsn(), None);
            assert_eq!(source.reads.load(Ordering::SeqCst), 9);
            for (index, record) in report.records().iter().enumerate() {
                assert_eq!(record.header().unwrap().this_lsn, lsn(first + index));
                assert_eq!(record.payload().unwrap(), &[0x40 + index as u8; 64]);
            }
            assert!(!report.active_window_complete());
            assert!(!report.transaction_analysis_complete());
            let mut edited = *report.records()[0].header().unwrap();
            edited.previous_lsn = u64::MAX;
            assert_eq!(edited.previous_lsn, u64::MAX);
            assert_eq!(
                report.records()[1].header().unwrap().this_lsn,
                lsn(first + 1)
            );
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn self_and_multiple_record_cycles_stop_before_requery_and_retain_target() {
    for targets in [&[0][..], &[1, 0][..]] {
        let (bytes, query, _) = chain(1, NtfsLogRecordLinkKind::Previous, targets);
        let source = Arc::new(Image::new(bytes));
        let r = resources();
        let report = inspect_logfile_record_links(
            source.clone(),
            link_limits(),
            query,
            NtfsLogRecordLinkKind::Previous,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::InvalidData
        );
        assert_eq!(report.pending_next_lsn(), Some(query.lsn));
        assert_eq!(report.records().len(), targets.len());
        assert_eq!(
            source.reads.load(Ordering::SeqCst),
            3 * targets.len() as u64
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn later_io_identity_and_context_failures_retain_prior_and_failed_evidence() {
    for mode in 0..4 {
        let (mut bytes, query, first) = chain(2, NtfsLogRecordLinkKind::UndoNext, &[1, usize::MAX]);
        if mode == 1 {
            w(&mut bytes, (first + 1) * PAGE + 92, 10);
        }
        if mode == 2 {
            bytes[(first + 1) * PAGE + 510] ^= 1;
        }
        let mut source = Image::new(bytes);
        if mode == 0 {
            source.fail = ((first + 1) * PAGE) as u64;
        }
        if mode == 3 {
            source.change_context = true;
        }
        let r = resources();
        let report = inspect_logfile_record_links(
            Arc::new(source),
            link_limits(),
            query,
            NtfsLogRecordLinkKind::UndoNext,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert_eq!(report.records().len(), 2);
        assert!(report.records()[0].complete());
        assert_eq!(report.pending_next_lsn(), Some(lsn(first + 1)));
        assert!(report.stopping_error().is_some());
        if mode == 0 {
            assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
            assert!(report.stopping_error().unwrap().source.is_some());
        }
        if mode == 3 {
            assert!(report.records()[1].complete());
            assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn aggregate_ceilings_stop_with_unfollowed_link_and_refund_all_retained_leases() {
    for mode in 0..5 {
        let (bytes, query, first) = chain(1, NtfsLogRecordLinkKind::Previous, &[1, 2, usize::MAX]);
        let r = resources();
        let mut cap = link_limits();
        match mode {
            0 => cap.records = 1,
            1 => cap.pages = 3,
            2 => cap.payload_bytes = 64,
            3 => cap.record.pages = 0,
            _ => cap.record.work = 1,
        }
        let report = inspect_logfile_record_links(
            Arc::new(Image::new(bytes)),
            cap,
            query,
            NtfsLogRecordLinkKind::Previous,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.pending_next_lsn().is_some());
        if mode < 3 {
            assert_eq!(report.pending_next_lsn(), Some(lsn(first + 1)));
        }
        assert!(report.work() <= cap.work);
        assert!(report.pages() <= cap.pages);
        assert!(report.payload_bytes() <= cap.payload_bytes);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn cancellation_source_length_and_initial_ceilings_never_publish_closure() {
    for mode in 0..2 {
        let (bytes, query, first) = chain(2, NtfsLogRecordLinkKind::Previous, &[1, usize::MAX]);
        let r = resources();
        let mut source = Image::new(bytes);
        if mode == 0 {
            source.cancel_at = ((first + 1) * PAGE) as u64;
            source.cancel = r.cancellation.clone();
        } else {
            source.stale_at = ((first + 1) * PAGE) as u64;
        }
        let report = inspect_logfile_record_links(
            Arc::new(source),
            link_limits(),
            query,
            NtfsLogRecordLinkKind::Previous,
            &r,
        )
        .unwrap();
        assert!(!report.complete());
        assert!(report.source_error().is_some());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    for mode in 0..4 {
        let (bytes, query, _) = chain(1, NtfsLogRecordLinkKind::Previous, &[usize::MAX]);
        let r = resources();
        let mut cap = link_limits();
        match mode {
            0 => cap.records = 0,
            1 => cap.pages = 1,
            2 => cap.work = 0,
            _ => r.cancellation.cancel(),
        }
        let source = Arc::new(Image::new(bytes));
        assert!(
            inspect_logfile_record_links(
                source.clone(),
                cap,
                query,
                NtfsLogRecordLinkKind::Previous,
                &r
            )
            .is_err()
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn aggregate_work_charges_context_and_cycle_comparisons_and_rejects_invalid_target() {
    let r = resources();
    let (bytes, query, _) = chain(1, NtfsLogRecordLinkKind::Previous, &[usize::MAX]);
    let closed = inspect_logfile_record_links(
        Arc::new(Image::new(bytes)),
        link_limits(),
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    let work = closed.work();
    assert!(closed.complete());
    drop(closed);
    let (bytes, query, _) = chain(1, NtfsLogRecordLinkKind::Previous, &[0]);
    let cycle = inspect_logfile_record_links(
        Arc::new(Image::new(bytes)),
        link_limits(),
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert_eq!(cycle.work(), work + 1);
    drop(cycle);
    let (bytes, query, _) = chain(1, NtfsLogRecordLinkKind::Previous, &[usize::MAX]);
    let mut cap = link_limits();
    cap.work = work - 1;
    let partial = inspect_logfile_record_links(
        Arc::new(Image::new(bytes)),
        cap,
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert!(!partial.complete());
    assert!(partial.work() <= cap.work);
    drop(partial);
    let (mut bytes, query, first) = chain(1, NtfsLogRecordLinkKind::Previous, &[usize::MAX]);
    q(&mut bytes, first * PAGE + 72, 1);
    let partial = inspect_logfile_record_links(
        Arc::new(Image::new(bytes)),
        link_limits(),
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert!(!partial.complete());
    assert_eq!(partial.pending_next_lsn(), Some(1));
    assert_eq!(partial.records().len(), 2);
    assert!(partial.records()[1].pages().is_empty());
    assert_eq!(
        partial.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    drop(partial);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn single_anchor_closure_and_aggregate_work_do_not_infer_chronology_or_transaction_identity() {
    let r = resources();
    let (bytes, query, _) = chain(2, NtfsLogRecordLinkKind::Previous, &[usize::MAX]);
    let source = Arc::new(Image::new(bytes));
    let one = inspect_logfile_record_links(
        source.clone(),
        link_limits(),
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert!(one.complete());
    assert_eq!(one.queries(), 1);
    assert_eq!(source.reads.load(Ordering::SeqCst), 3);
    let first_work = one.work();
    drop(one);
    let (mut bytes, query, first) = chain(2, NtfsLogRecordLinkKind::Previous, &[1, usize::MAX]);
    d(&mut bytes, first * PAGE + 100, 0x1234);
    d(&mut bytes, (first + 1) * PAGE + 100, 0x5678);
    let source = Arc::new(Image::new(bytes.clone()));
    let full = inspect_logfile_record_links(
        source,
        link_limits(),
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert!(full.complete());
    assert!(full.records()[1].header().unwrap().this_lsn > query.lsn);
    assert_ne!(
        full.records()[0].header().unwrap().transaction_id,
        full.records()[1].header().unwrap().transaction_id
    );
    drop(full);
    let mut cap = link_limits();
    cap.work = first_work;
    let source = Arc::new(Image::new(bytes));
    let partial = inspect_logfile_record_links(
        source.clone(),
        cap,
        query,
        NtfsLogRecordLinkKind::Previous,
        &r,
    )
    .unwrap();
    assert!(!partial.complete());
    assert_eq!(partial.pending_next_lsn(), Some(lsn(first + 1)));
    assert_eq!(
        partial.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(partial.work() <= cap.work);
    assert_eq!(source.reads.load(Ordering::SeqCst), 3);
    drop(partial);
    assert_eq!(r.memory.used(), 0);
}
