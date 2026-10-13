#![cfg(feature = "std")]
//! Independent NTFS client-record bytes within source-bound LFS envelopes.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogRecordLimits, NtfsLogRecordReport, inspect_logfile_record,
        inspect_ntfs_log_client_record,
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

fn client_payload() -> Vec<u8> {
    let mut b = vec![0xd7; 96];
    w(&mut b, 0, 0xf00d);
    w(&mut b, 2, 0xbeef);
    w(&mut b, 4, 64);
    w(&mut b, 6, 8);
    w(&mut b, 8, 72);
    w(&mut b, 10, 8);
    w(&mut b, 12, 0x1234);
    w(&mut b, 14, 2);
    w(&mut b, 16, 0x2233);
    w(&mut b, 18, 0x4455);
    w(&mut b, 20, 0x6677);
    w(&mut b, 22, 0x8899);
    q(&mut b, 24, (-0x123456i64) as u64);
    q(&mut b, 32, (-1i64) as u64);
    q(&mut b, 40, (i64::MIN + 33) as u64);
    b[64..72].copy_from_slice(b"REDOdata");
    b[72..80].copy_from_slice(b"UNDOdata");
    b
}
#[test]
fn client_header_lcns_and_opaque_operations_borrow_exact_native_bytes() {
    let payload = client_payload();
    for lfs in [1, 2] {
        let r = resources();
        let report = record(&payload, lfs, 1, false, &r);
        assert!(report.complete());
        let charged = r.memory.used();
        {
            let view = inspect_ntfs_log_client_record(&report).unwrap();
            assert_eq!(view.redo_operation, 0xf00d);
            assert_eq!(view.undo_operation, 0xbeef);
            assert_eq!(view.target_attribute, 0x1234);
            assert_eq!(view.lcn_count, 2);
            assert_eq!(view.record_offset, 0x2233);
            assert_eq!(view.attribute_offset, 0x4455);
            assert_eq!(view.cluster_offset, 0x6677);
            assert_eq!(view.reserved, 0x8899);
            assert_eq!(view.target_vcn, -0x123456);
            assert_eq!(view.lcn(0), Some(-1));
            assert_eq!(view.lcn(1), Some(i64::MIN + 33));
            assert_eq!(view.lcn(2), None);
            assert_eq!(view.lcn(usize::MAX), None);
            assert_eq!(view.raw(), payload);
            assert_eq!(view.header_bytes(), &payload[..48]);
            assert_eq!(view.lcn_bytes(), &payload[32..48]);
            assert_eq!(view.padding_bytes(), &payload[48..64]);
            assert_eq!(view.redo(), b"REDOdata");
            assert_eq!(view.undo(), b"UNDOdata");
            assert!(std::ptr::eq(
                view.raw().as_ptr(),
                report.payload().unwrap().as_ptr()
            ));
            assert!(std::ptr::eq(
                view.redo().as_ptr(),
                report.payload().unwrap()[64..].as_ptr()
            ));
            assert!(!view.operation_semantics_supported());
            assert_eq!(r.memory.used(), charged);
        }
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn linux_profile_retains_one_unused_lcn_slot_even_when_the_declared_count_is_zero() {
    let mut payload = client_payload();
    w(&mut payload, 14, 0);
    w(&mut payload, 4, 0);
    w(&mut payload, 6, 0);
    w(&mut payload, 8, 0);
    w(&mut payload, 10, 0);
    for length in [32, 39, 40] {
        let r = resources();
        let report = record(&payload[..length], 1, 1, false, &r);
        if length < 40 {
            assert_eq!(
                inspect_ntfs_log_client_record(&report).err().unwrap().kind,
                ErrorKind::InvalidData
            );
        } else {
            let view = inspect_ntfs_log_client_record(&report).unwrap();
            assert_eq!(view.header_bytes(), &payload[..40]);
            assert!(view.lcn_bytes().is_empty());
            assert_eq!(view.lcn(0), None);
            assert_eq!(&view.header_bytes()[32..40], &payload[32..40]);
            assert!(view.redo().is_empty());
            assert!(view.undo().is_empty());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn declared_lcn_count_is_checked_before_any_lazy_element_access() {
    for count in [9, u16::MAX] {
        let mut payload = client_payload();
        w(&mut payload, 14, count);
        let r = resources();
        let report = record(&payload, 2, 1, false, &r);
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_log_client_record(&report).err().unwrap().kind,
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn redo_and_undo_ranges_obey_native_alignment_header_exclusion_and_end_bounds() {
    for (offset_at, length_at) in [(4, 6), (8, 10)] {
        for (offset, length) in [
            (0, 1),
            (32, 8),
            (40, 8),
            (49, 8),
            (88, 9),
            (96, 1),
            (104, 0),
            (95, 0),
            (u16::MAX, 1),
        ] {
            let mut payload = client_payload();
            w(&mut payload, offset_at, offset);
            w(&mut payload, length_at, length);
            let r = resources();
            let report = record(&payload, 1, 1, false, &r);
            assert!(report.complete());
            let charged = r.memory.used();
            assert_eq!(
                inspect_ntfs_log_client_record(&report).err().unwrap().kind,
                ErrorKind::InvalidData,
                "offset {offset} length {length}"
            );
            assert_eq!(r.memory.used(), charged);
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn zero_length_eof_and_shared_or_overlapping_data_ranges_preserve_raw_bytes() {
    for (redo, redo_len, undo, undo_len) in [
        (0, 0, 96, 0),
        (96, 0, 0, 0),
        (64, 16, 64, 16),
        (64, 16, 72, 16),
        (88, 8, 96, 0),
    ] {
        let mut payload = client_payload();
        w(&mut payload, 4, redo);
        w(&mut payload, 6, redo_len);
        w(&mut payload, 8, undo);
        w(&mut payload, 10, undo_len);
        let r = resources();
        let report = record(&payload, 2, 1, false, &r);
        {
            let view = inspect_ntfs_log_client_record(&report).unwrap();
            assert_eq!(
                view.redo(),
                &payload[usize::from(redo)..usize::from(redo + redo_len)]
            );
            assert_eq!(
                view.undo(),
                &payload[usize::from(undo)..usize::from(undo + undo_len)]
            );
            assert_eq!(view.raw(), payload);
            assert_eq!(
                view.padding_bytes(),
                if redo_len == 0 && undo_len == 0 {
                    &payload[48..]
                } else {
                    &payload[48..usize::from(if redo_len == 0 {
                        undo
                    } else if undo_len == 0 {
                        redo
                    } else {
                        redo.min(undo)
                    })]
                }
            );
            if redo == undo {
                assert!(std::ptr::eq(view.redo().as_ptr(), view.undo().as_ptr()));
            }
            assert!(!view.operation_semantics_supported());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn only_complete_type_one_records_with_validated_client_identity_admit_client_views() {
    let payload = client_payload();
    for (kind, torn, bad_client) in [(2, false, false), (1, true, false), (1, false, true)] {
        let (mut bytes, query) = fixture(&payload, 2, kind, torn);
        if bad_client {
            w(&mut bytes, 34 * PAGE + 92, 10);
        }
        let r = resources();
        let report = inspect_logfile_record(
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
            query,
            &r,
        )
        .unwrap();
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_log_client_record(&report).err().unwrap().kind,
            if kind == 2 {
                ErrorKind::Unsupported
            } else {
                ErrorKind::InvalidData
            }
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn redo_bytes_crossing_a_protected_sector_trailer_are_restored_before_borrowing() {
    let mut payload = vec![0; 512];
    w(&mut payload, 4, 392);
    w(&mut payload, 6, 24);
    w(&mut payload, 8, 512);
    w(&mut payload, 10, 0);
    for (index, byte) in payload[392..416].iter_mut().enumerate() {
        *byte = 0x80 + index as u8;
    }
    let r = resources();
    let report = record(&payload, 2, 1, false, &r);
    {
        let view = inspect_ntfs_log_client_record(&report).unwrap();
        assert_eq!(view.redo(), &payload[392..416]);
        assert!(view.undo().is_empty());
        assert_eq!(view.raw(), payload);
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn editing_public_lcn_observations_does_not_change_private_validated_slice_bounds() {
    let payload = client_payload();
    let r = resources();
    let report = record(&payload, 2, 1, false, &r);
    for edited in [0, u16::MAX] {
        let mut view = inspect_ntfs_log_client_record(&report).unwrap();
        view.lcn_count = edited;
        assert_eq!(view.lcn_bytes(), &payload[32..48]);
        assert_eq!(view.lcn(0), Some(-1));
        assert_eq!(view.lcn(1), Some(i64::MIN + 33));
        assert_eq!(view.lcn(2), None);
        assert_eq!(view.lcn(usize::MAX), None);
        assert_eq!(view.header_bytes(), &payload[..48]);
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
