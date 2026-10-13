#![cfg(all(feature = "std", feature = "forensics"))]
#[path = "fixtures/ntfs_clean.rs"]
mod fixture;
use partmgr::{
    forensics::*,
    forensics_journal::*,
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsStreamLimits},
    fs_ntfs_usn::RecordLimits,
    fs_ntfs_usn_extract::JournalLimits,
    io::{self, ReadAt},
};
use std::sync::Arc;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.0
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn source(bytes: Vec<u8>) -> ForensicSource {
    let length = bytes.len() as u64;
    ForensicSource::new(
        Arc::new(Bytes(bytes)),
        SourceIdentity {
            acquisition: "independent fixture".into(),
            source: "bytes".into(),
            stability_provider: "immutable owned bytes".into(),
        },
        Arc::new(AcquisitionLease::default()),
        ByteRange { offset: 0, length },
        vec![],
    )
    .unwrap()
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn read() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn streams() -> NtfsStreamLimits {
    NtfsStreamLimits {
        extension_records: 8,
        list_entries: 32,
        list_bytes: 8192,
        attributes: 128,
        runs: 128,
        work: 65536,
    }
}
fn directories() -> NtfsDirectoryLimits {
    NtfsDirectoryLimits {
        blocks: 32,
        entries: 128,
        depth: 8,
    }
}
fn journal() -> JournalLimits {
    JournalLimits {
        record: RecordLimits {
            record_bytes: 1024,
            name_units: 128,
        },
        records: 32,
        extents: 16,
        read_bytes: 8192,
        work: 4096,
    }
}
fn named(name: &[u16], value: &[u8], id: u16) -> Vec<u8> {
    let at = (24 + name.len() * 2).next_multiple_of(8);
    let mut b = vec![0; (at + value.len()).next_multiple_of(8)];
    let len = b.len();
    fixture::d(&mut b, 0, 0x80);
    fixture::d(&mut b, 4, len as u32);
    b[9] = name.len() as u8;
    fixture::w(&mut b, 10, 24);
    fixture::w(&mut b, 14, id);
    fixture::d(&mut b, 16, value.len() as u32);
    fixture::w(&mut b, 20, at as u16);
    for (n, v) in name.iter().enumerate() {
        fixture::w(&mut b, 24 + n * 2, *v);
    }
    b[at..at + value.len()].copy_from_slice(value);
    b
}
fn journal_seed(max: &[u8]) -> Vec<u8> {
    let native = include_bytes!("fixtures/ntfs_usn_mixed.bin");
    let count = u32::from_le_bytes(native[..4].try_into().unwrap()) as usize;
    let mut payload = vec![0; 8];
    payload.extend_from_slice(&native[..count]);
    journal_seed_payload(max, &payload)
}
fn journal_seed_payload(max: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = fixture::ntfs_audit_seed();
    // Replace the complete root index when reusing inode24 for the journal;
    // retaining the seed's alpha/beta links would create unrelated stale entries.
    let mut extend_entry = fixture::index_entry(11, "$Extend", None);
    fixture::d(&mut extend_entry, 16 + 56, 0x10000000);
    let mut root_index = fixture::root_attribute(&[extend_entry, fixture::terminal(None)], false);
    fixture::d(&mut root_index, 40, 2048);
    root_index[44] = 4;
    fixture::put(
        &mut bytes,
        5,
        &[
            fixture::resident(0x30, &fixture::name_value(".", 5), 2),
            root_index,
        ],
        true,
        1,
    );
    let mut entry = fixture::index_entry(24, "$UsnJrnl", None);
    fixture::q(&mut entry, 16, 11 | (7 << 48));
    let mut root = fixture::root_attribute(&[entry, fixture::terminal(None)], false);
    fixture::d(&mut root, 40, 2048);
    root[44] = 4;
    fixture::put(
        &mut bytes,
        11,
        &[
            fixture::resident(0x30, &fixture::name_value("$Extend", 5), 2),
            root,
        ],
        true,
        1,
    );
    fixture::put(
        &mut bytes,
        24,
        &[
            fixture::resident(0x30, &fixture::name_value("$UsnJrnl", 11), 2),
            named(&[36, 74], payload, 3),
            named(&[36, 77, 97, 120], max, 4),
        ],
        false,
        1,
    );
    bytes
}
#[test]
fn namespace_max_native_records_and_gaps_are_independent_observations() {
    let mut max = [0; 32];
    fixture::q(&mut max, 0, 8192);
    fixture::q(&mut max, 8, 4096);
    fixture::q(&mut max, 16, 99);
    fixture::q(&mut max, 24, 8);
    let r = resources();
    let mut namespace = false;
    let mut record = false;
    let mut gap = false;
    let mut retention = false;
    let out = inspect_usn(
        &source(journal_seed(&max)),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |event| {
            match event {
                UsnObservation::Namespace { journal, .. } => {
                    namespace = true;
                    assert_eq!(journal.native, 24u64.to_le_bytes());
                }
                UsnObservation::Max(m) => assert_eq!(m.decoded.unwrap().journal_id, 99),
                UsnObservation::Gap { range, .. } => {
                    gap = true;
                    assert_eq!(
                        range,
                        ByteRange {
                            offset: 0,
                            length: 8
                        }
                    );
                }
                UsnObservation::Record { record: r, .. } => {
                    record = true;
                    assert_eq!(r.provenance.offset, 8);
                }
                UsnObservation::Retention {
                    lowest_valid_usn, ..
                } => {
                    retention = true;
                    assert_eq!(lowest_valid_usn, 8);
                }
                _ => {}
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert_eq!(out.coordinate_space, CoordinateSpace::LogicalStreamBytes);
    assert!(namespace && record && gap && retention);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unavailable_namespace_and_truncated_max_do_not_become_empty_success() {
    let r = resources();
    let absent = inspect_usn(
        &source(fixture::ntfs_audit_seed()),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |_| panic!("no validated journal"),
    );
    assert!(matches!(
        absent.stop_reason,
        StopReason::InvalidBootstrap(_)
    ));
    assert_eq!(absent.observations, 0);
    let mut bad = false;
    let out = inspect_usn(
        &source(journal_seed(&[0; 16])),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |event| {
            if let UsnObservation::Max(m) = event {
                bad = m.decoded.is_err();
            }
            Ok(true)
        },
    );
    assert!(bad);
    assert!(!out.is_complete());
    assert!(out.unvisited.length > 0);
    let out = inspect_usn(
        &source(journal_seed(&[0; 32])),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits {
            read_bytes: 0,
            ..ScanLimits::default()
        },
        &NeverCancel,
        &r,
        |_| panic!("no delivery"),
    );
    assert!(matches!(
        out.stop_reason,
        StopReason::ResourceCause {
            ceiling: "read_bytes",
            ..
        }
    ));
}
#[test]
fn output_failure_and_caller_stop_preserve_terminal_outcomes() {
    let src = source(journal_seed(&[0; 32]));
    let r = resources();
    let out = inspect_usn(
        &src,
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |_| Err(io::Error::other("output failed")),
    );
    assert!(matches!(out.stop_reason, StopReason::DeliveryFailed(_)));
    assert_eq!(out.observations, 0);
    let out = inspect_usn(
        &src,
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |_| Ok(false),
    );
    assert!(matches!(out.stop_reason, StopReason::CallerStop));
    assert_eq!(out.observations, 1);
    assert!(!out.is_complete());
}

// Hand-authored LFS restart fields from the existing independent modeled native
// layout. No production encoder constructs the expected restart bytes.
fn restart_page(sequence: u16) -> Vec<u8> {
    let mut b = vec![0; 4096];
    b[..4].copy_from_slice(b"RSTR");
    fixture::w(&mut b, 4, 32);
    fixture::w(&mut b, 6, 9);
    fixture::d(&mut b, 16, 4096);
    fixture::d(&mut b, 20, 4096);
    fixture::w(&mut b, 24, 56);
    fixture::w(&mut b, 26, 1);
    fixture::w(&mut b, 28, 1);
    fixture::w(&mut b, 64, 1);
    fixture::w(&mut b, 66, u16::MAX);
    fixture::w(&mut b, 68, 0);
    fixture::w(&mut b, 70, 2);
    fixture::d(&mut b, 72, 49);
    fixture::w(&mut b, 76, 224);
    fixture::w(&mut b, 78, 64);
    fixture::q(&mut b, 80, 400 * 512);
    fixture::w(&mut b, 92, 48);
    fixture::w(&mut b, 94, 64);
    fixture::d(&mut b, 96, 17);
    fixture::w(&mut b, 136, u16::MAX);
    fixture::w(&mut b, 138, u16::MAX);
    fixture::d(&mut b, 148, 8);
    for (n, v) in "NTFS".encode_utf16().enumerate() {
        fixture::w(&mut b, 152 + n * 2, v);
    }
    fixture::w(&mut b, 32, sequence);
    for n in 1..=8 {
        fixture::w(&mut b, 32 + n * 2, 0);
        fixture::w(&mut b, n * 512 - 2, sequence);
    }
    b
}
fn log_seed() -> Vec<u8> {
    let mut disk = fixture::ntfs_audit_seed();
    fixture::put(
        &mut disk,
        2,
        &[
            fixture::resident(0x30, &fixture::name_value("$LogFile", 5), 2),
            fixture::nonresident(&[0x22, 0x90, 1, 0, 2, 0], 400, 400 * 512, 400 * 512, false),
        ],
        false,
        1,
    );
    disk[512 * 512..512 * 512 + 4096].copy_from_slice(&restart_page(0xa55a));
    disk[512 * 512 + 4096..512 * 512 + 8192].copy_from_slice(&restart_page(0x7e21));
    disk
}
#[test]
fn logfile_restart_observations_are_separate_from_usn_and_never_claim_replay() {
    let src = source(log_seed());
    let r = resources();
    let mut seen = false;
    let out = inspect_logfile(
        &src,
        read(),
        streams(),
        partmgr::fs_ntfs_logfile::NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 16,
            work: 10000,
        },
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |event| {
            if let LogObservation::Restart(report) = event {
                seen = true;
                assert_eq!(
                    report.report.state(),
                    partmgr::fs_ntfs_logfile::NtfsLogFileState::CleanFlagObserved
                );
                assert!(!report.report.transaction_analysis_complete());
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(seen);
    assert_eq!(out.coverage_events, 2);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn logfile_missing_copy_keeps_causal_error_and_unvisited_gap() {
    let bytes = log_seed();
    let length = bytes.len() as u64;
    let src = ForensicSource::new(
        Arc::new(Bytes(bytes)),
        SourceIdentity {
            acquisition: "gapped log capture".into(),
            source: "bytes".into(),
            stability_provider: "immutable".into(),
        },
        Arc::new(AcquisitionLease::default()),
        ByteRange { offset: 0, length },
        vec![ByteRange {
            offset: 512 * 512 + 4096,
            length: 4096,
        }],
    )
    .unwrap();
    let mut unreadable = 0;
    let mut serialized = Vec::new();
    let out = inspect_logfile(
        &src,
        read(),
        streams(),
        partmgr::fs_ntfs_logfile::NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 16,
            work: 10000,
        },
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            write_log_json(&mut serialized, &event).unwrap();
            if let LogObservation::Coverage(e) = event
                && e.kind == CoverageKind::Unreadable
            {
                unreadable += 1;
            }
            Ok(true)
        },
    );
    assert!(matches!(out.stop_reason, StopReason::Io(_)));
    assert_eq!(unreadable, 1);
    assert!(
        String::from_utf8(serialized)
            .unwrap()
            .contains("\"read_complete\":false,\"raw_hex\":null")
    );
    assert_eq!(
        out.unvisited,
        ByteRange {
            offset: 4096,
            length: 4096
        }
    );
    assert!(!out.is_complete());
}

#[test]
fn configured_decoder_ceilings_retain_cause_and_delivered_prefix() {
    let source = source(journal_seed(&[0; 32]));
    for (entries, work, expected, delivered) in
        [(0, 4096, "directory_entries", 0), (128, 0, "work", 2)]
    {
        let mut directory = directories();
        directory.entries = entries;
        let mut journal = journal();
        journal.work = work;
        let out = inspect_usn(
            &source,
            read(),
            streams(),
            directory,
            journal,
            ScanLimits::default(),
            &NeverCancel,
            &resources(),
            |_| Ok(true),
        );
        match out.stop_reason {
            StopReason::ResourceCause { ceiling, cause } => {
                assert_eq!(ceiling, expected);
                assert!(cause.get_ref().is_some());
                assert!(cause.to_string().contains(if entries == 0 {
                    "directory entry limit"
                } else {
                    "USN extraction work"
                }));
            }
            reason => panic!("unexpected stop: {reason:?}"),
        }
        assert_eq!(out.observations, delivered);
        assert!(out.unvisited.length > 0);
    }
}

#[test]
fn usn_timestamp_json_retains_integer_ticks_as_decimal_string() {
    let mut json = Vec::new();
    let out = inspect_usn(
        &source(journal_seed(&[0; 32])),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let UsnObservation::Record { record, .. } = &event {
                write_usn_json(&mut json, &event).unwrap();
                assert!(String::from_utf8_lossy(&json).contains(&format!(
                    "\"timestamp_ticks\":\"{}\"",
                    record.timestamp_ticks
                )));
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(!json.is_empty());
}

#[test]
fn journal_record_size_and_count_ceilings_have_distinct_causal_outcomes() {
    let source = source(journal_seed(&[0; 32]));
    for (bytes, records, expected) in [
        (8, 128, "journal_record_bytes"),
        (1024, 0, "journal_records"),
    ] {
        let mut native_limits = journal();
        native_limits.record.record_bytes = bytes;
        native_limits.records = records;
        let out = inspect_usn(
            &source,
            read(),
            streams(),
            directories(),
            native_limits,
            ScanLimits::default(),
            &NeverCancel,
            &resources(),
            |_| Ok(true),
        );
        assert_eq!(out.source_id, Some(source.id()));
        assert!(out.observations >= 2);
        match out.stop_reason {
            StopReason::ResourceCause { ceiling, cause } => {
                assert_eq!(ceiling, expected);
                assert!(cause.get_ref().is_some());
            }
            other => panic!("unexpected stop: {other:?}"),
        }
    }
}

#[test]
fn stale_sequences_ambiguous_parents_and_unpaired_rename_events_survive_export() {
    // Independent old-name events with one reused slot and two parent identities.
    // No new-name partner exists; resolving against current MFT would lose history.
    let mut payload = Vec::new();
    for (sequence, parent) in [(1u64, 5u64), (2, 11)] {
        let mut record = vec![0; 64];
        fixture::d(&mut record, 0, 64);
        fixture::w(&mut record, 4, 2);
        fixture::q(&mut record, 8, 25 | (sequence << 48));
        fixture::q(&mut record, 16, parent | (99 << 48));
        fixture::q(&mut record, 24, payload.len() as u64);
        fixture::q(&mut record, 32, 132_000_000_000_000_001);
        fixture::d(&mut record, 40, 0x1000); // RENAME_OLD_NAME, unmatched.
        fixture::w(&mut record, 56, 2);
        fixture::w(&mut record, 58, 60);
        fixture::w(&mut record, 60, 0xd800); // Preserve an unpaired native surrogate.
        payload.extend_from_slice(&record);
    }
    let mut records = Vec::new();
    let out = inspect_usn(
        &source(journal_seed_payload(&[0; 32], &payload)),
        read(),
        streams(),
        directories(),
        journal(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let UsnObservation::Record { record, .. } = &event {
                let mut json = Vec::new();
                write_usn_json(&mut json, &event).unwrap();
                records.push((
                    record.file.ntfs_v2_parts(),
                    record.parent.ntfs_v2_parts(),
                    record.reason.raw,
                    String::from_utf8(json).unwrap(),
                ));
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert_eq!(records.len(), 2);
    for (index, (file, parent, reason, json)) in records.iter().enumerate() {
        assert_eq!(*file, Some((25, index as u16 + 1)));
        assert_eq!(*parent, Some((if index == 0 { 5 } else { 11 }, 99)));
        assert_eq!(*reason, 0x1000);
        assert!(json.contains("\"name_utf16\":[55296]"));
        assert!(json.contains("\"reason\":4096"));
        assert!(json.contains(&format!("\"sequence\":{}", index + 1)));
        assert!(json.contains("\"sequence\":99"));
        assert!(!json.contains("resolved_path"));
        assert!(!json.contains("rename_partner"));
    }
}
