#![cfg(feature = "std")]
//! Independent native-byte checkpoint fixtures; no production encoder.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogRecordLimits, NtfsLogRecordReport, inspect_logfile_record,
        inspect_ntfs_client_restart,
    },
    io,
};
use std::sync::Arc;
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
        let original = u16::from_le_bytes([b[at], b[at + 1]]);
        w(b, usa + sector * 2, original);
        w(b, at, marker);
    }
}
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn fixture(payload: &[u8], lfs_major: u16, record_type: u32, torn: bool) -> (Vec<u8>, u64) {
    let ordinary_page = if lfs_major == 1 { 4 } else { 34 };
    let query = (7u64 << 16) | ((ordinary_page * PAGE + 64) as u64 / 8);
    let mut bytes = vec![0xff; LENGTH];
    for index in 0..2 {
        let mut page = vec![0; PAGE];
        page[..4].copy_from_slice(b"RSTR");
        w(&mut page, 4, 32);
        w(&mut page, 6, 9);
        d(&mut page, 16, PAGE as u32);
        d(&mut page, 20, PAGE as u32);
        w(&mut page, 24, 56);
        w(&mut page, 26, if lfs_major == 1 { 1 } else { 0 });
        w(&mut page, 28, lfs_major);
        q(&mut page, 56, query);
        w(&mut page, 64, 1);
        w(&mut page, 66, u16::MAX);
        w(&mut page, 68, 0);
        d(&mut page, 72, 48);
        w(&mut page, 76, 224);
        w(&mut page, 78, 64);
        q(&mut page, 80, LENGTH as u64);
        w(&mut page, 92, 48);
        w(&mut page, 94, 64);
        w(&mut page, 136, u16::MAX);
        w(&mut page, 138, u16::MAX);
        w(&mut page, 140, 9);
        d(&mut page, 148, 8);
        page[152..160].copy_from_slice(b"N\0T\0F\0S\0");
        protect(&mut page, 32, 0xab00 + index as u16);
        bytes[index * PAGE..(index + 1) * PAGE].copy_from_slice(&page);
    }
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    w(&mut page, 4, 40);
    w(&mut page, 6, 9);
    q(&mut page, 8, query);
    d(&mut page, 16, 1);
    w(&mut page, 20, 1);
    w(&mut page, 22, 1);
    w(
        &mut page,
        24,
        (112 + payload.len()).next_multiple_of(8) as u16,
    );
    q(&mut page, 32, query);
    q(&mut page, 64, query);
    d(&mut page, 88, payload.len() as u32);
    w(&mut page, 92, 9);
    w(&mut page, 94, 0);
    d(&mut page, 96, record_type);
    page[112..112 + payload.len()].copy_from_slice(payload);
    protect(&mut page, 40, 0xf1f2);
    if torn {
        page[510] ^= 1;
    }
    bytes[ordinary_page * PAGE..(ordinary_page + 1) * PAGE].copy_from_slice(&page);
    (bytes, query)
}
fn record(
    payload: &[u8],
    lfs_major: u16,
    record_type: u32,
    torn: bool,
    r: &Resources,
) -> NtfsLogRecordReport {
    let (bytes, lsn) = fixture(payload, lfs_major, record_type, torn);
    inspect_logfile_record(
        Arc::new(Image(bytes)),
        NtfsLogFileLimits {
            restart_page_bytes: PAGE,
            clients: 1,
            work: 10000,
        },
        NtfsLogRecordLimits {
            pages: 8,
            payload_bytes: 4096,
            work: 10000,
        },
        lsn,
        r,
    )
    .unwrap()
}
fn checkpoint_payload() -> Vec<u8> {
    let mut b = vec![0xd5; 120];
    d(&mut b, 0, 1);
    d(&mut b, 4, 0);
    for (at, value) in [
        (8, 0x1001),
        (16, 0x2002),
        (24, 0x3003),
        (32, 0x4004),
        (40, 0x5005),
    ] {
        q(&mut b, at, value);
    }
    for (at, value) in [(48, 8), (52, 16), (56, 24), (60, 32)] {
        d(&mut b, at, value);
    }
    q(&mut b, 64, (-0x12345678i64) as u64);
    q(&mut b, 72, 0x8877665544332211);
    d(&mut b, 80, 4096);
    b[84..88].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]);
    q(&mut b, 88, 0x1234000056780000);
    q(&mut b, 96, (i64::MIN + 17) as u64);
    q(&mut b, 104, 0x9988776655443322);
    b
}

#[test]
fn pinned_checkpoint_prefix_is_independent_of_lfs_restart_version_and_borrows_payload() {
    let payload = checkpoint_payload();
    for lfs in [1, 2] {
        let r = resources();
        let report = record(&payload[..64], lfs, 2, false, &r);
        assert!(report.complete());
        let charged = r.memory.used();
        {
            let view = inspect_ntfs_client_restart(&report).unwrap();
            assert_eq!(view.version, (1, 0));
            assert_eq!(view.checkpoint_start_lsn, 0x1001);
            for (table, lsn, bytes) in [
                (view.open_attribute_table, 0x2002, 8),
                (view.attribute_names, 0x3003, 16),
                (view.dirty_page_table, 0x4004, 24),
                (view.transaction_table, 0x5005, 32),
            ] {
                assert_eq!(table.lsn, lsn);
                assert_eq!(table.bytes, bytes);
            }
            assert_eq!(view.raw(), &payload[..64]);
            assert!(std::ptr::eq(
                view.raw().as_ptr(),
                report.payload().unwrap().as_ptr()
            ));
            assert!(view.extension_bytes().is_empty());
            assert!(view.reserved_bytes().is_none());
            assert!(view.trailing_bytes().is_empty());
            assert_eq!(r.memory.used(), charged);
            assert!(!report.active_window_complete());
            assert!(!report.transaction_analysis_complete());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn optional_checkpoint_fields_require_their_entire_native_length_and_keep_partial_bytes() {
    let payload = checkpoint_payload();
    for length in [
        64, 65, 71, 72, 73, 79, 80, 81, 83, 84, 85, 87, 88, 89, 95, 96, 97, 103, 104, 105, 111,
        112, 113, 120,
    ] {
        let r = resources();
        let report = record(&payload[..length], 2, 2, false, &r);
        let charged = r.memory.used();
        {
            let view = inspect_ntfs_client_restart(&report).unwrap();
            assert_eq!(
                view.usn_journal_restart_offset,
                (length >= 72).then_some(-0x12345678)
            );
            assert_eq!(view.last_lsn, (length >= 80).then_some(0x8877665544332211));
            assert_eq!(view.bytes_per_cluster, (length >= 84).then_some(4096));
            assert_eq!(
                view.reserved_bytes(),
                (length >= 88).then_some(&payload[84..88])
            );
            assert_eq!(
                view.usn_journal_reference,
                (length >= 96).then_some(0x1234000056780000)
            );
            assert_eq!(view.usn_base, (length >= 104).then_some(i64::MIN + 17));
            assert_eq!(
                view.oldest_lsn,
                (length >= 112).then_some(0x9988776655443322)
            );
            assert_eq!(view.raw(), &payload[..length]);
            assert_eq!(view.extension_bytes(), &payload[64..length]);
            assert_eq!(
                view.trailing_bytes(),
                if length > 112 {
                    &payload[112..length]
                } else {
                    &[]
                }
            );
            assert_eq!(r.memory.used(), charged);
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn short_checkpoint_and_unknown_client_versions_are_distinct_failures() {
    let original = checkpoint_payload();
    for length in [0, 1, 7, 8, 48, 63] {
        let r = resources();
        let report = record(&original[..length], 1, 2, false, &r);
        assert!(report.complete());
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_client_restart(&report).err().unwrap().kind,
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    for (major, minor) in [(0, 0), (1, 1), (2, 0), (u32::MAX, u32::MAX)] {
        let mut payload = original.clone();
        d(&mut payload, 0, major);
        d(&mut payload, 4, minor);
        let r = resources();
        let report = record(&payload, 2, 2, false, &r);
        assert!(report.complete());
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_client_restart(&report).err().unwrap().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn ordinary_client_record_and_incomplete_lfs_evidence_cannot_be_checkpoint_views() {
    let payload = checkpoint_payload();
    for (kind, torn) in [(1, false), (2, true)] {
        let r = resources();
        let report = record(&payload, 1, kind, torn, &r);
        let charged = r.memory.used();
        assert_eq!(report.complete(), !torn);
        let error = inspect_ntfs_client_restart(&report).err().unwrap();
        assert_eq!(
            error.kind,
            if torn {
                ErrorKind::InvalidData
            } else {
                ErrorKind::Unsupported
            }
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn zero_table_references_and_lengths_are_observations_without_invented_table_resolution() {
    let mut payload = vec![0; 64];
    d(&mut payload, 0, 1);
    let r = resources();
    let report = record(&payload, 2, 2, false, &r);
    {
        let view = inspect_ntfs_client_restart(&report).unwrap();
        assert_eq!(view.checkpoint_start_lsn, 0);
        for table in [
            view.open_attribute_table,
            view.attribute_names,
            view.dirty_page_table,
            view.transaction_table,
        ] {
            assert_eq!(table.lsn, 0);
            assert_eq!(table.bytes, 0);
        }
        assert!(view.usn_journal_restart_offset.is_none());
        assert!(view.oldest_lsn.is_none());
    }
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
