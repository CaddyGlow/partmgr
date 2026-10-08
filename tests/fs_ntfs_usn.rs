#![cfg(feature = "std")]

use partmgr::fs_ntfs_usn::*;

#[test]
fn shared_resources_cancel_before_decoding_without_retaining_memory() {
    let resources = partmgr::fs_core::Resources {
        memory: partmgr::fs_core::Budget::new(0),
        cancellation: partmgr::fs_core::Cancellation::default(),
    };
    let bytes = include_bytes!("fixtures/ntfs_usn_mixed.bin");
    let mut records = Records::new(
        bytes,
        provenance(0),
        StreamLimits {
            record: limits(),
            records: 1024,
            bytes: bytes.len(),
        },
    );
    assert!(
        records
            .next_record(|| resources.cancellation.check().is_err())
            .unwrap()
            .is_some()
    );
    resources.cancellation.cancel();
    assert_eq!(
        records
            .next_record(|| resources.cancellation.check().is_err())
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(records.decoded_records(), 1);
    assert_eq!(resources.memory.used(), 0);
}
fn provenance(offset: u64) -> Provenance {
    Provenance {
        evidence_id: [0x59; 32],
        offset,
    }
}
fn limits() -> RecordLimits {
    RecordLimits {
        record_bytes: 4096,
        name_units: 1024,
    }
}
// Fixtures are assembled from documented field offsets, without decoder builders.
fn fixture(major: u16, minor: u16, extension: usize, name: &[u16]) -> Vec<u8> {
    let (header, common) = if major == 2 { (60, 24) } else { (76, 40) };
    let name_at = header + extension;
    let length = (name_at + name.len() * 2).div_ceil(8) * 8;
    let mut b = vec![0xa5; length];
    b[..4].copy_from_slice(&(length as u32).to_le_bytes());
    b[4..6].copy_from_slice(&major.to_le_bytes());
    b[6..8].copy_from_slice(&minor.to_le_bytes());
    if major == 2 {
        b[8..16].copy_from_slice(&0xabcd_0000_0000_1234u64.to_le_bytes());
        b[16..24].copy_from_slice(&0x9876_0000_0000_0005u64.to_le_bytes());
    } else {
        b[8..24].copy_from_slice(&[0x83; 16]);
        b[24..40].copy_from_slice(&[0x37; 16]);
    }
    b[common..common + 8].copy_from_slice(&123456i64.to_le_bytes());
    b[common + 8..common + 16].copy_from_slice(&132_537_600_123_456_789i64.to_le_bytes());
    b[common + 16..common + 20].copy_from_slice(&0x8100_2100u32.to_le_bytes());
    b[common + 20..common + 24].copy_from_slice(&0x8000_0009u32.to_le_bytes());
    b[common + 24..common + 28].copy_from_slice(&42u32.to_le_bytes());
    b[common + 28..common + 32].copy_from_slice(&0x8000_0020u32.to_le_bytes());
    b[common + 32..common + 34].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
    b[common + 34..common + 36].copy_from_slice(&(name_at as u16).to_le_bytes());
    for (at, unit) in name.iter().enumerate() {
        b[name_at + at * 2..name_at + at * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    b
}
#[test]
fn independent_v2_exact_fields_provenance_and_native_name() {
    let name = [0x0061, 0, 0xd800, 0xdcff, 0xffff];
    let b = fixture(2, 0, 0, &name);
    let r = decode_record(&b, provenance(0x1230), limits()).unwrap();
    assert_eq!(r.raw(), b);
    assert_eq!(r.provenance, provenance(0x1230));
    assert_eq!(r.file.ntfs_v2_parts(), Some((0x1234, 0xabcd)));
    assert_eq!(r.parent.ntfs_v2_parts(), Some((5, 0x9876)));
    assert_eq!(r.usn, 123456);
    assert_eq!(r.timestamp_ticks, 132_537_600_123_456_789);
    assert_eq!(r.security_id, 42);
    assert_eq!(r.file_attributes, 0x8000_0020);
    assert_eq!(r.reason.raw, 0x8100_2100);
    assert_eq!(r.reason.unknown(), 0x0100_0000);
    assert_eq!(r.source.recognized(), 9);
    assert_eq!(r.source.unknown(), 0x8000_0000);
    assert_eq!(r.name.units().collect::<Vec<_>>(), name);
    assert!(r.trailing().iter().all(|b| *b == 0xa5));
}
#[test]
fn independent_v3_opaque_ids_and_minor_extension() {
    let b = fixture(3, 17, 12, &[0xdfff, 0x007a]);
    let r = decode_record(&b, provenance(99), limits()).unwrap();
    assert_eq!(r.major, 3);
    assert_eq!(r.minor, 17);
    assert_eq!(r.file, FileReference::V3([0x83; 16]));
    assert_eq!(r.parent, FileReference::V3([0x37; 16]));
    assert_eq!(r.file.ntfs_v2_parts(), None);
    assert_eq!(r.header_extension(), [0xa5; 12]);
    assert_eq!(r.name.units().collect::<Vec<_>>(), [0xdfff, 0x007a]);
}
#[test]
fn empty_name_and_native_zero_or_negative_timestamp_preserved() {
    for ticks in [0i64, -1, i64::MAX, i64::MIN] {
        let mut b = fixture(2, 0, 0, &[]);
        b[32..40].copy_from_slice(&ticks.to_le_bytes());
        let r = decode_record(&b, provenance(0), limits()).unwrap();
        assert_eq!(r.timestamp_ticks, ticks);
        assert_eq!(r.name.units().len(), 0);
    }
}
#[test]
fn every_truncation_rejected_and_no_panics_on_small_framing_mutations() {
    for major in [2, 3] {
        let b = fixture(major, 0, 0, &[0x61, 0x62]);
        for end in 0..b.len() {
            assert!(decode_record(&b[..end], provenance(0), limits()).is_err());
        }
        for at in 0..b.len() {
            for value in [0, 1, 0x7f, 0xff] {
                let mut changed = b.clone();
                changed[at] = value;
                let _ = decode_record(&changed, provenance(0), limits());
            }
        }
    }
}
#[test]
fn malformed_length_versions_name_ranges_and_negative_usn() {
    for major in [2, 3] {
        let original = fixture(major, 0, 0, &[0x61, 0x62]);
        let common = if major == 2 { 24 } else { 40 };
        for length in [0u32, 7, 8, 15, 32, u32::MAX] {
            let mut b = original.clone();
            b[..4].copy_from_slice(&length.to_le_bytes());
            assert!(decode_record(&b, provenance(0), limits()).is_err());
        }
        for (field, value) in [
            (common + 32, 3),
            (common + 32, u16::MAX),
            (common + 34, 0),
            (common + 34, 59),
            (common + 34, u16::MAX),
        ] {
            let mut b = original.clone();
            b[field..field + 2].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                decode_record(&b, provenance(0), limits()).unwrap_err().kind,
                ErrorKind::InvalidFraming
            );
        }
        let mut b = original.clone();
        b[common..common + 8].copy_from_slice(&(-1i64).to_le_bytes());
        assert_eq!(
            decode_record(&b, provenance(0), limits())
                .unwrap_err()
                .field_offset,
            common
        );
        let mut b = original;
        b[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(
            decode_record(&b, provenance(0), limits()).unwrap_err().kind,
            ErrorKind::UnsupportedVersion
        );
    }
}
#[test]
fn record_budgets_and_provenance_overflow() {
    let b = fixture(2, 0, 0, &[0x61, 0x62]);
    for bound in [
        RecordLimits {
            record_bytes: b.len() - 1,
            name_units: 2,
        },
        RecordLimits {
            record_bytes: 4096,
            name_units: 1,
        },
    ] {
        assert_eq!(
            decode_record(&b, provenance(0), bound).unwrap_err().kind,
            ErrorKind::BudgetExhausted
        );
    }
    assert_eq!(
        decode_record(&b, provenance(u64::MAX - 3), limits())
            .unwrap_err()
            .kind,
        ErrorKind::OffsetOverflow
    );
}
#[test]
fn contiguous_cursor_offsets_budgets_cancel_and_terminal_error() {
    let first = fixture(2, 0, 0, &[0x61]);
    let second = fixture(3, 0, 0, &[0x62]);
    let bytes = [first.as_slice(), second.as_slice()].concat();
    let stream = StreamLimits {
        record: limits(),
        records: 2,
        bytes: bytes.len(),
    };
    let mut c = Records::new(&bytes, provenance(128), stream);
    assert_eq!(
        c.next_record(|| false).unwrap().unwrap().provenance.offset,
        128
    );
    assert_eq!(
        c.next_record(|| false).unwrap().unwrap().provenance.offset,
        128 + first.len() as u64
    );
    assert_eq!(c.consumed_bytes(), bytes.len());
    assert_eq!(c.decoded_records(), 2);
    assert!(c.next_record(|| false).unwrap().is_none());
    for restricted in [
        StreamLimits {
            records: 1,
            ..stream
        },
        StreamLimits {
            bytes: bytes.len() - 1,
            ..stream
        },
    ] {
        let mut c = Records::new(&bytes, provenance(128), restricted);
        c.next_record(|| false).unwrap();
        let e = c.next_record(|| false).unwrap_err();
        assert_eq!(e.kind, ErrorKind::BudgetExhausted);
        assert_eq!(e.provenance.offset, 128 + first.len() as u64);
        assert_eq!(c.consumed_bytes(), first.len());
        assert!(c.next_record(|| false).unwrap().is_none());
    }
    let mut c = Records::new(&bytes, provenance(128), stream);
    assert_eq!(
        c.next_record(|| true).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(c.consumed_bytes(), 0);
    assert!(c.next_record(|| false).unwrap().is_none());
}
#[test]
fn no_implicit_sparse_hole_skip_or_ioctl_prefix_interpretation() {
    let b = fixture(2, 0, 0, &[0x61]);
    for prefix in [vec![0; 8], 123456u64.to_le_bytes().to_vec()] {
        let bytes = [prefix, b.clone()].concat();
        let mut c = Records::new(
            &bytes,
            provenance(0),
            StreamLimits {
                record: limits(),
                records: 2,
                bytes: 1024,
            },
        );
        assert!(c.next_record(|| false).is_err());
        assert_eq!(c.consumed_bytes(), 0);
    }
}
#[test]
fn independently_assembled_large_mixed_stream_exact_fields_and_offsets() {
    let bytes = include_bytes!("fixtures/ntfs_usn_mixed.bin");
    assert!(bytes.len() > 65536);
    let mut cursor = Records::new(
        bytes,
        provenance(4096),
        StreamLimits {
            record: limits(),
            records: 1024,
            bytes: bytes.len(),
        },
    );
    let mut offset = 4096;
    for i in 0..1024 {
        let r = cursor.next_record(|| false).unwrap().unwrap();
        assert_eq!(r.provenance.offset, offset);
        assert_eq!(r.major, if i % 2 == 0 { 2 } else { 3 });
        assert_eq!(r.usn, i * 4096);
        assert_eq!(r.timestamp_ticks, 132_537_600_123_456_789 + i);
        assert_eq!(r.reason.unknown(), 0x0100_0000);
        assert_eq!(
            r.name.units().collect::<Vec<_>>(),
            [0x61, 0xd800, i as u16, 0, 0xffff]
        );
        assert_eq!(r.header_extension().len(), if i % 3 == 0 { 8 } else { 0 });
        if i % 2 == 0 {
            assert_eq!(r.file.ntfs_v2_parts(), Some((i as u64, (i + 1) as u16)));
        } else {
            assert_eq!(r.file, FileReference::V3((i as u128).to_le_bytes()));
        }
        offset += r.raw().len() as u64;
    }
    assert_eq!(offset, 4096 + bytes.len() as u64);
    assert!(cursor.next_record(|| false).unwrap().is_none());
}
