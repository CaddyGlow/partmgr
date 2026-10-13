#![cfg(feature = "std")]
//! Independent typed restart-table entries retained by the source-owned loader.
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
    d(&mut b, 4, 0x11223344);
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
fn allocated_entry_bodies_are_borrowed_from_matching_source_owned_checkpoint_dumps() {
    for version in [1, 2] {
        let (bytes, query, _) = fixture(version, tables(), (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete(), "{:?}", report.stopping_error());
        let charged = r.memory.used();
        {
            let open = report.open_attribute_entry(0).unwrap().unwrap();
            assert_eq!(open.bytes_per_index, 4096);
            assert_eq!(open.attribute_type, 0x80);
            assert_eq!(open.file_reference, 0x1234000056780000);
            assert_eq!(open.open_record_lsn, 0x8877665544332211);
            let expected = open_slot();
            assert_eq!(open.raw(), expected);
            assert!(std::ptr::eq(
                open.raw().as_ptr(),
                report.dumps()[0].record().unwrap().payload().unwrap()[64..].as_ptr()
            ));
            assert_eq!(open.opaque_flags(), &expected[12..16]);
            assert_eq!(open.pointer_bytes(), &expected[32..40]);
            assert_eq!(open.trailing_bytes(), &expected[40..]);
            let dirty = report.dirty_page_entry(0).unwrap().unwrap();
            assert_eq!(dirty.target_attribute, 0x11223344);
            assert_eq!(dirty.transfer_bytes, 4096);
            assert_eq!(dirty.lcn_count, 2);
            assert_eq!(dirty.target_vcn, -0x123456);
            assert_eq!(dirty.oldest_lsn, 0x9988776655443322);
            assert_eq!(dirty.lcn(0), Some(-1));
            assert_eq!(dirty.lcn(1), Some(i64::MIN + 3));
            assert_eq!(dirty.lcn(2), None);
            assert_eq!(dirty.lcn(usize::MAX), None);
            let expected = dirty_slot();
            assert_eq!(dirty.raw(), expected);
            assert_eq!(dirty.lcn_bytes(), &expected[32..48]);
            assert_eq!(dirty.trailing_bytes(), &expected[48..]);
            let tx = report.transaction_entry(0).unwrap().unwrap();
            assert_eq!(tx.state, 3);
            assert_eq!(tx.first_lsn, 0x1001);
            assert_eq!(tx.previous_lsn, 0x2002);
            assert_eq!(tx.undo_next_lsn, 0x3003);
            assert_eq!(tx.undo_records, 17);
            assert_eq!(tx.undo_bytes, 4097);
            let expected = tx_slot(3);
            assert_eq!(tx.raw(), expected);
            assert_eq!(tx.reserved_bytes(), &expected[5..8]);
            assert_eq!(tx.trailing_bytes(), &expected[40..]);
            assert!(tx.state_semantics_supported());
            assert!(report.open_attribute_entry(1).unwrap().is_none());
            assert!(report.dirty_page_entry(usize::MAX).unwrap().is_none());
            assert!(report.transaction_entry(1).unwrap().is_none());
            assert_eq!(r.memory.used(), charged);
        }
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn dirty_entry_public_observation_edits_cannot_expand_original_lcn_bounds() {
    let (bytes, query, _) = fixture(2, tables(), (1, 0));
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    for count in [0, u32::MAX] {
        let mut entry = report.dirty_page_entry(0).unwrap().unwrap();
        entry.lcn_count = count;
        assert_eq!(entry.lcn_bytes(), &dirty_slot()[32..48]);
        assert_eq!(entry.lcn(0), Some(-1));
        assert_eq!(entry.lcn(1), Some(i64::MIN + 3));
        assert_eq!(entry.lcn(2), None);
        assert_eq!(entry.lcn(usize::MAX), None);
        assert_eq!(entry.trailing_bytes(), &dirty_slot()[48..]);
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn free_slots_are_absent_but_short_allocated_bodies_are_invalid_typed_views() {
    for allocated in [false, true] {
        let short = vec![0; 4];
        let mut variants = tables();
        variants[0] = table_for(&short, allocated);
        variants[2] = table_for(&short, allocated);
        variants[3] = table_for(&short, allocated);
        // Keep the generic allocated sentinel distinct from free-chain tail zero.
        if allocated {
            for index in [0, 2, 3] {
                d(&mut variants[index], 24, u32::MAX);
            }
        }
        let (bytes, query, _) = fixture(2, variants, (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete());
        if allocated {
            assert_eq!(
                report.open_attribute_entry(0).err().unwrap().kind,
                ErrorKind::InvalidData
            );
            assert_eq!(
                report.dirty_page_entry(0).err().unwrap().kind,
                ErrorKind::InvalidData
            );
            assert_eq!(
                report.transaction_entry(0).err().unwrap().kind,
                ErrorKind::InvalidData
            );
        } else {
            assert!(report.open_attribute_entry(0).unwrap().is_none());
            assert!(report.dirty_page_entry(0).unwrap().is_none());
            assert!(report.transaction_entry(0).unwrap().is_none());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn dirty_lcn_geometry_is_checked_without_guessing_signed_mapping_semantics() {
    for count in [4, u32::MAX] {
        let mut variants = tables();
        d(&mut variants[2], 24 + 12, count);
        let (bytes, query, _) = fixture(2, variants, (1, 0));
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        assert!(report.complete());
        let charged = r.memory.used();
        assert_eq!(
            report.dirty_page_entry(0).err().unwrap().kind,
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn unknown_transaction_state_is_retained_without_claiming_state_or_replay_support() {
    let mut variants = tables();
    variants[3] = table_for(&tx_slot(0xfe), true);
    let (bytes, query, _) = fixture(2, variants, (1, 0));
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    {
        let mut tx = report.transaction_entry(0).unwrap().unwrap();
        assert_eq!(tx.state, 0xfe);
        assert!(!tx.state_semantics_supported());
        tx.state = 3;
        assert!(!tx.state_semantics_supported());
        assert_eq!(tx.raw()[4], 0xfe);
    }
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn partial_loader_reports_only_expose_prior_validated_entries_and_retain_limits() {
    let (bytes, query, _) = fixture(2, tables(), (1, 0));
    let r = resources();
    let report = inspect_logfile_checkpoint_dumps(
        Arc::new(Image::new(bytes)),
        NtfsLogCheckpointDumpLimits {
            queries: 3,
            ..limits()
        },
        query,
        &r,
    )
    .unwrap();
    assert!(!report.complete());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(report.open_attribute_entry(0).unwrap().is_some());
    assert_eq!(
        report.dirty_page_entry(0).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert_eq!(
        report.transaction_entry(0).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn client_checkpoint_version_is_not_inferred_from_lfs_version_or_unloaded_slots() {
    let (bytes, query, _) = fixture(2, tables(), (1, 1));
    let r = resources();
    let report =
        inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r).unwrap();
    assert!(!report.complete());
    assert_eq!(
        report.open_attribute_entry(0).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        report.dirty_page_entry(0).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        report.transaction_entry(0).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn zero_byte_references_and_wrong_dump_kinds_never_fabricate_typed_entries() {
    for wrong_kind in [false, true] {
        let (mut bytes, query, first) = fixture(2, tables(), (1, 0));
        if wrong_kind {
            w(&mut bytes, (first + 3) * PAGE + 112, 29);
        } else {
            let mut cp = vec![0; 64];
            d(&mut cp, 0, 1);
            for index in 0..4 {
                q(&mut cp, 16 + index * 8, lsn(first + index + 1));
            }
            bytes[first * PAGE..(first + 1) * PAGE].copy_from_slice(&record_page(first, 2, &cp));
        }
        let r = resources();
        let report =
            inspect_logfile_checkpoint_dumps(Arc::new(Image::new(bytes)), limits(), query, &r)
                .unwrap();
        if wrong_kind {
            assert!(!report.complete());
            assert!(report.open_attribute_entry(0).unwrap().is_some());
            assert_eq!(
                report.dirty_page_entry(0).err().unwrap().kind,
                ErrorKind::InvalidData
            );
        } else {
            assert!(report.complete());
            assert!(report.open_attribute_entry(0).unwrap().is_none());
            assert!(report.dirty_page_entry(0).unwrap().is_none());
            assert!(report.transaction_entry(0).unwrap().is_none());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
