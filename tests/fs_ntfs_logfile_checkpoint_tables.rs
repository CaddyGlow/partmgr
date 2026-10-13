#![cfg(feature = "std")]
//! Independent combined-source checkpoint and dump records, without native encoders.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogCheckpointDumpKind, NtfsLogCheckpointDumpLimits, NtfsLogFileLimits,
        NtfsLogRecordLimits, NtfsLogRecordQuery, NtfsLogRestartTableLimits,
        inspect_logfile_checkpoint_dumps, inspect_ntfs_log_client_record,
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
fn fixture(
    version: u16,
    declared: [u32; 4],
    ops: [u16; 4],
) -> (Vec<u8>, NtfsLogRecordQuery, usize) {
    let first = if version == 1 { 4 } else { 34 };
    let mut bytes = vec![0xff; LENGTH];
    let mut checkpoint = vec![0; 64];
    d(&mut checkpoint, 0, 1);
    q(&mut checkpoint, 8, lsn(first));
    for (index, declared_bytes) in declared.into_iter().enumerate() {
        q(&mut checkpoint, 16 + index * 8, lsn(first + index + 1));
        d(&mut checkpoint, 48 + index * 4, declared_bytes);
    }
    bytes[..PAGE].copy_from_slice(&restart(version, lsn(first), 0xa001));
    bytes[PAGE..2 * PAGE].copy_from_slice(&restart(version, lsn(first) + 8, 0xa002));
    bytes[first * PAGE..(first + 1) * PAGE].copy_from_slice(&record_page(first, 2, &checkpoint));
    for (index, op) in ops.into_iter().enumerate() {
        let mut payload = vec![0; 64];
        w(&mut payload, 0, op);
        w(&mut payload, 4, 40);
        w(&mut payload, 6, 24);
        w(&mut payload, 40, 4);
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

#[test]
fn all_dump_types_are_queried_from_the_same_source_and_explicit_restart_context() {
    for version in [1, 2] {
        let (bytes, query, first) = fixture(version, [24; 4], [29, 30, 31, 32]);
        let source = Arc::new(Image::new(bytes));
        let r = resources();
        let report = inspect_logfile_checkpoint_dumps(source, limits(), query, &r).unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        assert!(report.stopping_error().is_none());
        assert!(report.source_error().is_none());
        assert!(report.checkpoint().complete());
        assert!(report.references_available());
        assert_eq!(report.checkpoint().requested_restart_copy(), Some(1));
        assert!(report.checkpoint().restart().copies_disagree());
        for (index, dump) in report.dumps().iter().enumerate() {
            assert_eq!(
                dump.kind(),
                [
                    NtfsLogCheckpointDumpKind::OpenAttributes,
                    NtfsLogCheckpointDumpKind::AttributeNames,
                    NtfsLogCheckpointDumpKind::DirtyPages,
                    NtfsLogCheckpointDumpKind::Transactions
                ][index]
            );
            assert_eq!(dump.reference().lsn, lsn(first + index + 1));
            assert_eq!(dump.reference().bytes, 24);
            let record = dump.record().unwrap();
            assert!(record.complete());
            assert_eq!(record.requested_restart_copy(), Some(1));
            assert_eq!(
                record.restart_context(),
                report.checkpoint().restart_context()
            );
            assert_eq!(record.header().unwrap().this_lsn, lsn(first + index + 1));
            assert_eq!(
                inspect_ntfs_log_client_record(record)
                    .unwrap()
                    .redo_operation,
                [29, 30, 31, 32][index]
            );
            assert_eq!(dump.reference_bytes_match(), Some(true));
            assert_eq!(dump.table_validated(), index != 1);
        }
        assert_eq!(report.queries(), 5);
        assert_eq!(report.pages(), 15);
        assert_eq!(report.payload_bytes(), 320);
        assert!(report.work() > 0);
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn zero_byte_references_are_skipped_even_with_nonzero_unusable_lsns() {
    let (mut bytes, query, first) = fixture(2, [0; 4], [29, 30, 31, 32]);
    // Rewrite the fixed-up checkpoint before independently protecting it again.
    let mut payload = vec![0; 64];
    d(&mut payload, 0, 1);
    for index in 0..4 {
        q(&mut payload, 16 + index * 8, u64::MAX - index as u64);
    }
    bytes[first * PAGE..(first + 1) * PAGE].copy_from_slice(&record_page(first, 2, &payload));
    let mut image = Image::new(bytes);
    image.fail = ((first + 1) * PAGE) as u64;
    let source = Arc::new(image);
    let r = resources();
    let report = inspect_logfile_checkpoint_dumps(source.clone(), limits(), query, &r).unwrap();
    assert!(report.complete());
    assert!(report.references_available());
    assert_eq!(report.queries(), 1);
    assert_eq!(source.reads.load(Ordering::SeqCst), 3);
    for dump in report.dumps() {
        assert_eq!(dump.reference().bytes, 0);
        assert_ne!(dump.reference().lsn, 0);
        assert!(dump.record().is_none());
        assert_eq!(dump.reference_bytes_match(), None);
        assert!(!dump.table_validated());
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn reference_byte_count_mismatch_is_retained_as_observation_without_universal_corruption() {
    let (bytes, query, _) = fixture(2, [23, 25, 24, 24], [29, 30, 31, 32]);
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(report.complete(), "{:?}", report.stopping_error());
    assert_eq!(report.dumps()[0].reference_bytes_match(), Some(false));
    assert_eq!(report.dumps()[1].reference_bytes_match(), Some(false));
    assert!(
        report
            .dumps()
            .iter()
            .all(|dump| dump.record().unwrap().complete())
    );
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn a_later_wrong_operation_retains_checkpoint_and_prior_dump_records() {
    let (bytes, query, _) = fixture(2, [24; 4], [29, 30, 29, 32]);
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(!report.complete());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(report.checkpoint().complete());
    assert!(report.dumps()[0].record().unwrap().complete());
    assert!(report.dumps()[1].record().unwrap().complete());
    assert!(report.dumps()[2].record().is_some());
    assert!(report.dumps()[3].record().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn later_io_cancellation_and_source_change_preserve_earlier_source_owned_evidence() {
    for mode in 0..3 {
        let (bytes, query, first) = fixture(2, [24; 4], [29, 30, 31, 32]);
        let r = resources();
        let mut source = Image::new(bytes);
        let trigger = ((first + 3) * PAGE) as u64;
        match mode {
            0 => source.fail = trigger,
            1 => {
                source.cancel_at = trigger;
                source.cancel = r.cancellation.clone();
            }
            _ => source.stale_at = trigger,
        }
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(source), limits(), query, &r).unwrap();
        assert!(!report.complete());
        assert!(report.checkpoint().complete());
        assert!(report.references_available());
        assert!(report.dumps()[0].record().unwrap().complete());
        assert!(report.dumps()[1].record().unwrap().complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            match mode {
                0 => ErrorKind::Io,
                1 => ErrorKind::Cancelled,
                _ => ErrorKind::StalePlan,
            }
        );
        assert!(report.dumps()[3].record().is_none());
        if mode == 0 {
            assert!(
                report
                    .stopping_error()
                    .unwrap()
                    .source
                    .as_ref()
                    .unwrap()
                    .to_string()
                    .contains("independent later dump failure")
            );
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn aggregate_and_per_query_limits_fail_with_refunded_retained_evidence() {
    let (bytes, query, _) = fixture(2, [24; 4], [29, 30, 31, 32]);
    let mut per_payload = limits();
    per_payload.record.payload_bytes = 63;
    let mut per_pages = limits();
    per_pages.record.pages = 0;
    let mut per_work = limits();
    per_work.record.work = 0;
    for caps in [
        NtfsLogCheckpointDumpLimits {
            queries: 1,
            ..limits()
        },
        NtfsLogCheckpointDumpLimits {
            pages: 14,
            ..limits()
        },
        NtfsLogCheckpointDumpLimits {
            payload_bytes: 319,
            ..limits()
        },
        NtfsLogCheckpointDumpLimits {
            work: 0,
            ..limits()
        },
        per_payload,
        per_pages,
        per_work,
    ] {
        let r = resources();
        match inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes.clone())), caps, query, &r)
        {
            Ok(report) => {
                assert!(!report.complete());
                assert_eq!(
                    report.stopping_error().unwrap().kind,
                    ErrorKind::BudgetExhausted
                );
                drop(report);
            }
            Err(error) => assert_eq!(error.kind, ErrorKind::BudgetExhausted),
        }
        assert_eq!(r.memory.used(), 0);
    }
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn same_length_selected_restart_byte_change_is_a_stale_context_even_when_decoded_fields_match() {
    let (bytes, query, _) = fixture(2, [24; 4], [29, 30, 31, 32]);
    let mut source = Image::new(bytes);
    source.change_context = true;
    let r = resources();
    let report = inspect_logfile_checkpoint_dumps(Arc::new(source), limits(), query, &r).unwrap();
    assert!(!report.complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
    assert!(report.checkpoint().complete());
    assert!(
        report.dumps()[1..]
            .iter()
            .all(|dump| dump.record().is_none())
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_later_generic_table_keeps_its_record_and_prior_completed_dumps() {
    let (mut bytes, query, first) = fixture(2, [24; 4], [29, 30, 31, 32]);
    w(&mut bytes, (first + 3) * PAGE + 112 + 40 + 4, 1);
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(!report.complete());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(report.checkpoint().complete());
    assert!(report.dumps()[0].record().unwrap().complete());
    assert!(report.dumps()[1].record().unwrap().complete());
    assert!(report.dumps()[2].record().unwrap().complete());
    assert!(!report.dumps()[2].table_validated());
    assert!(report.dumps()[3].record().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean;
fn native_fixture(journal: &[u8], dirty: bool) -> Vec<u8> {
    use ntfs_clean::{name_value, nonresident, put, resident};
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
    bytes[512 * 512..512 * 512 + LENGTH].copy_from_slice(journal);
    if dirty {
        let flag =
            2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10;
        w(&mut bytes, flag, 1);
    }
    let mirror = bytes[2048..6144].to_vec();
    bytes[500 * 512..508 * 512].copy_from_slice(&mirror);
    bytes
}
#[test]
fn native_volume_helper_retains_system_owner_and_independent_volume_flags() {
    use partmgr::fs_ntfs::{NtfsReadLimits, NtfsStreamLimits};
    use partmgr::fs_ntfs_logfile::inspect_ntfs_logfile_checkpoint_dumps;
    for dirty in [false, true] {
        let (journal, query, _) = fixture(2, [24; 4], [29, 30, 31, 32]);
        let r = resources();
        let inspected = inspect_ntfs_logfile_checkpoint_dumps(
            Arc::new(Image::new(native_fixture(&journal, dirty))),
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
        assert_eq!(inspected.report.queries(), 5);
        assert!(
            inspected
                .report
                .dumps()
                .iter()
                .all(|dump| dump.record().unwrap().complete())
        );
        assert!(!inspected.report.transaction_analysis_complete());
        drop(inspected);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn final_volume_source_guard_rejects_a_length_change_beneath_the_fixed_length_log_mapping() {
    use partmgr::fs_ntfs::{NtfsReadLimits, NtfsStreamLimits};
    use partmgr::fs_ntfs_logfile::inspect_ntfs_logfile_checkpoint_dumps;
    let (journal, query, first) = fixture(2, [24; 4], [29, 30, 31, 32]);
    let mut source = Image::new(native_fixture(&journal, false));
    source.stale_at = (512 * 512 + (first + 4) * PAGE) as u64;
    let r = resources();
    let inspected = inspect_ntfs_logfile_checkpoint_dumps(
        Arc::new(source),
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
        limits(),
        query,
        &r,
    )
    .unwrap();
    assert!(!inspected.report.complete());
    assert_eq!(
        inspected.report.stopping_error().unwrap().kind,
        ErrorKind::StalePlan
    );
    assert!(inspected.report.source_error().is_some());
    assert!(inspected.report.checkpoint().complete());
    drop(inspected);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn unavailable_checkpoint_references_are_distinct_from_decoded_empty_references() {
    for payload in [vec![0; 63], vec![0; 64]] {
        let (mut bytes, query, first) = fixture(2, [0; 4], [29, 30, 31, 32]);
        bytes[first * PAGE..(first + 1) * PAGE].copy_from_slice(&record_page(first, 2, &payload));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.checkpoint().complete());
        assert!(!report.complete());
        assert!(!report.references_available());
        assert!(report.stopping_error().is_some());
        assert_eq!(report.queries(), 1);
        assert!(report.dumps().iter().all(|dump| dump.record().is_none()));
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
