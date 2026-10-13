#![cfg(all(feature = "std", feature = "forensics"))]
#[path = "fixtures/ntfs_clean.rs"]
mod clean;
use partmgr::{
    forensics::*,
    forensics_ntfs::*,
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
    io::{self, ReadAt},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let at = offset as usize;
        buf.copy_from_slice(
            self.0
                .get(at..at + buf.len())
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
            acquisition: "fixture".into(),
            source: "hand-authored".into(),
            stability_provider: "owned immutable bytes".into(),
        },
        Arc::new(AcquisitionLease::default()),
        ByteRange { offset: 0, length },
        vec![],
    )
    .unwrap()
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
        extension_records: 16,
        list_entries: 128,
        list_bytes: 8192,
        attributes: 128,
        runs: 128,
        work: 100000,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn inventory_preserves_bad_fixups_and_separate_bitmap_bits() {
    let mut bytes = clean::ntfs_audit_seed();
    // Independent fixture's allocated record 24 deliberately retains a torn trailer.
    bytes[2048 + 24 * 1024 + 1022] ^= 1;
    let r = resources();
    let mut bad = false;
    let mut covered = 0;
    let out = inventory(
        &source(bytes),
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |event| {
            match event {
                InventoryEvent::Slot(slot) if slot.slot == 24 => {
                    bad = slot.decoded.is_err();
                    assert_eq!(slot.allocated.unwrap(), Some(true));
                    assert_eq!(&slot.raw[..4], b"FILE");
                }
                InventoryEvent::Coverage(_) => covered += 1,
                _ => {}
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(bad);
    assert_eq!(covered, 32);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn bitmap_and_owners_have_independent_complete_coverage() {
    let src = source(clean::ntfs_audit_seed());
    let r = resources();
    let mut allocated = 0;
    let bitmap = volume_bitmap(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |e| {
            if let BitmapEvent::Page(p) = e {
                assert_eq!(p.source_id, src.id());
                allocated += p.bytes.iter().map(|b| b.count_ones()).sum::<u32>();
            }
            Ok(true)
        },
    );
    assert_eq!(bitmap.source_id, Some(src.id()));
    assert!(bitmap.is_complete(), "{:?}", bitmap.stop_reason);
    assert_eq!(allocated, 335);
    assert!(bitmap.coverage_events > 0);
    let mut claims = 0;
    let owners = current_owners(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |e| {
            if let OwnershipEvent::Claim(claim) = e {
                assert_eq!(claim.source_id, src.id());
                claims += 1;
            }
            Ok(true)
        },
    );
    assert_eq!(owners.source_id, Some(src.id()));
    assert!(owners.is_complete(), "{:?}", owners.stop_reason);
    assert!(claims > 0);
    assert_eq!(owners.coverage_events, 32);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn cancellation_limits_and_output_failures_never_complete() {
    let src = source(clean::ntfs_audit_seed());
    let r = resources();
    let exhausted = inventory(
        &src,
        read(),
        streams(),
        ScanLimits {
            read_bytes: 0,
            ..ScanLimits::default()
        },
        &NeverCancel,
        &r,
        |_| panic!("no delivery"),
    );
    assert!(matches!(
        exhausted.stop_reason,
        StopReason::ResourceCause {
            ceiling: "read_bytes",
            ..
        }
    ));
    assert_eq!(exhausted.observations, 0);
    let exhausted = inventory(
        &src,
        read(),
        streams(),
        ScanLimits {
            memory_bytes: 0,
            ..ScanLimits::default()
        },
        &NeverCancel,
        &r,
        |_| panic!("no delivery"),
    );
    assert!(matches!(
        exhausted.stop_reason,
        StopReason::ResourceCause {
            ceiling: "memory_bytes",
            ..
        }
    ));
    let control = AtomicBool::new(false);
    let cancelled = inventory(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &control,
        &r,
        |event| {
            if matches!(event, InventoryEvent::Coverage(_)) {
                control.store(true, Ordering::Relaxed);
            }
            Ok(true)
        },
    );
    assert!(matches!(cancelled.stop_reason, StopReason::Cancelled));
    assert_eq!(cancelled.coverage_events, 1);
    assert!(cancelled.unvisited.length > 0);
    let failure = current_owners(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |_| Err(io::Error::other("output failed")),
    );
    assert!(matches!(failure.stop_reason, StopReason::DeliveryFailed(_)));
    assert_eq!(failure.observations, 0);
    assert!(!failure.is_complete());
}

#[path = "fixtures/ntfs_basic.rs"]
mod basic;
use partmgr::{
    forensics_ntfs_extract::{StreamExtractionEvent, extract_live_stream},
    fs_ntfs::NtfsCompressionLimits,
};
use sha2::{Digest, Sha256};
fn export(
    bytes: Vec<u8>,
    name: &[u16],
    compression: Option<NtfsCompressionLimits>,
) -> (partmgr::forensics_extract::ExtractionOutcome, Vec<u8>) {
    let mut output = Vec::new();
    let out = extract_live_stream(
        &source(bytes),
        24,
        name,
        read(),
        streams(),
        compression,
        ScanLimits::default(),
        &resources(),
        &NeverCancel,
        |event| {
            if let StreamExtractionEvent::Bytes { bytes, .. } = event {
                output.extend_from_slice(bytes);
            }
            Ok(())
        },
    );
    (out, output)
}
#[test]
fn resident_and_named_stream_exports_preserve_logical_hashes() {
    let (out, bytes) = export(basic::fixture(), &[], None);
    assert!(out.scan.is_complete(), "{:?}", out.scan.stop_reason);
    assert_eq!(&bytes, b"hello");
    assert_eq!(
        out.prefix_sha256,
        <[u8; 32]>::from(Sha256::digest(b"hello"))
    );
    let mut disk = basic::fixture();
    let mut attr = vec![0; 40];
    basic::d(&mut attr, 0, 0x80);
    basic::d(&mut attr, 4, 40);
    attr[9] = 1;
    basic::w(&mut attr, 10, 24);
    basic::w(&mut attr, 14, 3);
    basic::d(&mut attr, 16, 5);
    basic::w(&mut attr, 20, 32);
    basic::w(&mut attr, 24, 0xd800);
    attr[32..37].copy_from_slice(b"named");
    disk[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&basic::record(24, &[attr]));
    let (out, bytes) = export(disk, &[0xd800], None);
    assert!(out.scan.is_complete(), "{:?}", out.scan.stop_reason);
    assert_eq!(&bytes, b"named");
}
#[test]
fn lznt1_export_hashes_decoded_bytes_and_output_limit_hashes_prefix() {
    let mut disk = basic::fixture();
    let mut attr = vec![0; 80];
    basic::d(&mut attr, 0, 0x80);
    basic::d(&mut attr, 4, 80);
    attr[8] = 1;
    basic::w(&mut attr, 12, 1);
    basic::w(&mut attr, 14, 3);
    basic::q(&mut attr, 24, 15);
    basic::w(&mut attr, 32, 72);
    basic::w(&mut attr, 34, 4);
    basic::q(&mut attr, 40, 8192);
    basic::q(&mut attr, 48, 8192);
    basic::q(&mut attr, 56, 8192);
    basic::q(&mut attr, 64, 512);
    attr[72..78].copy_from_slice(&[0x11, 1, 90, 1, 15, 0]);
    disk[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&basic::record(24, &[attr]));
    disk[90 * 512..91 * 512].fill(0);
    disk[90 * 512..90 * 512 + 12]
        .copy_from_slice(&[3, 0xb0, 2, b'A', 0xfc, 0x0f, 3, 0xb0, 2, b'A', 0xfc, 0x0f]);
    let (out, bytes) = export(
        disk,
        &[],
        Some(NtfsCompressionLimits {
            max_unit_bytes: 65536,
            max_units_per_read: 32,
            max_work: 10000,
        }),
    );
    assert!(out.scan.is_complete(), "{:?}", out.scan.stop_reason);
    assert_eq!(bytes, vec![b'A'; 8192]);
    assert_eq!(out.prefix_sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
    let mut prefix = Vec::new();
    let limited = extract_live_stream(
        &source(basic::fixture()),
        24,
        &[],
        read(),
        streams(),
        None,
        ScanLimits {
            output_bytes: 2,
            ..ScanLimits::default()
        },
        &resources(),
        &NeverCancel,
        |event| {
            if let StreamExtractionEvent::Bytes { bytes, .. } = event {
                prefix.extend_from_slice(bytes);
            }
            Ok(())
        },
    );
    assert!(matches!(
        limited.scan.stop_reason,
        StopReason::ResourceLimit(_)
    ));
    assert_eq!(&prefix, b"he");
    assert_eq!(limited.output_bytes, 2);
    assert!(!limited.scan.is_complete());
}

fn deleted_seed(cluster: u8) -> Vec<u8> {
    let mut disk = clean::ntfs_audit_seed();
    clean::put(
        &mut disk,
        24,
        &[clean::nonresident(
            &[0x11, 1, cluster, 0],
            1,
            100,
            100,
            false,
        )],
        false,
        1,
    );
    clean::w(&mut disk, 2048 + 24 * 1024 + 22, 0);
    let bitmap = 2048
        + 56
        + clean::resident(0x30, &clean::name_value("$MFT", 5), 2).len()
        + clean::nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    disk[bitmap + 3] &= !1;
    disk
}
#[test]
fn candidate_checks_current_owner_conflicts_and_preserves_incomplete_unknown() {
    // Deleted candidate points at the independently owned physical cluster 90.
    let src = source(deleted_seed(90));
    let r = resources();
    let candidate = deleted_stream_candidate(&src, 24, &[], read(), streams(), &r).unwrap();
    assert_eq!(
        candidate.ranges[0].reuse,
        partmgr::forensics_extract::ReuseEvidence::Unknown
    );
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert_eq!(assessment.allocation, RangeAllocation::Allocated);
    assert_eq!(assessment.conflicting_owner.unwrap().owner, 25);
    assert!(assessment.ownership_outcome.is_complete());
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::ConflictingOwner
    );
    // Cluster 92 is currently free, while an interrupted owner scan remains unknown.
    let src = source(deleted_seed(92));
    let candidate = deleted_stream_candidate(&src, 24, &[], read(), streams(), &r).unwrap();
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits {
            records: 1,
            ..ScanLimits::default()
        },
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert_eq!(assessment.allocation, RangeAllocation::Free);
    assert!(!assessment.ownership_outcome.is_complete());
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::Unknown
    );
}
#[test]
fn dirty_volume_and_mirror_disagreement_are_observations() {
    let mut disk = clean::ntfs_audit_seed();
    let flags = 2048
        + 3 * 1024
        + 56
        + clean::resident(0x30, &clean::name_value("$Volume", 5), 2).len()
        + 24
        + 10;
    disk[flags] = 1;
    disk[500 * 512 + 1000] ^= 1;
    let src = source(disk);
    let r = resources();
    let mut disagreement = false;
    let out = inventory(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
        |event| {
            if let InventoryEvent::Slot(slot) = event
                && slot.slot == 0
            {
                disagreement = slot.mirror_agrees.unwrap() == Some(false);
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(disagreement);
    assert!(partmgr::fs_ntfs::NtfsVolume::open(Arc::new(src), read(), &r).is_err());
}

#[test]
fn live_stream_detects_stability_loss_in_final_output_callback() {
    let disk = basic::fixture();
    let length = disk.len() as u64;
    let lease = Arc::new(AcquisitionLease::default());
    let src = ForensicSource::new(
        Arc::new(Bytes(disk)),
        SourceIdentity {
            acquisition: "fixture".into(),
            source: "bytes".into(),
            stability_provider: "revocable lease".into(),
        },
        lease.clone(),
        ByteRange { offset: 0, length },
        vec![],
    )
    .unwrap();
    let out = extract_live_stream(
        &src,
        24,
        &[],
        read(),
        streams(),
        None,
        ScanLimits::default(),
        &resources(),
        &NeverCancel,
        |event| {
            if matches!(event, StreamExtractionEvent::Coverage(_)) {
                lease.invalidate();
            }
            Ok(())
        },
    );
    assert!(matches!(
        out.scan.stop_reason,
        StopReason::SourceStability(_)
    ));
    assert_eq!(out.output_bytes, 5);
    assert!(!out.scan.is_complete());
}

#[test]
fn missing_volume_bitmap_stays_unknown_independently_of_owner_coverage() {
    let mut disk = deleted_seed(92);
    clean::put(
        &mut disk,
        6,
        &[clean::resident(0x30, &clean::name_value("$Bitmap", 5), 2)],
        false,
        1,
    );
    let r = resources();
    let candidate =
        deleted_stream_candidate(&source(disk), 24, &[], read(), streams(), &r).unwrap();
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert_eq!(assessment.allocation, RangeAllocation::Unknown);
    assert!(!assessment.bitmap_outcome.is_complete());
    assert!(assessment.ownership_outcome.is_complete());
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::Unknown
    );
}

#[test]
fn truncated_volume_bitmap_never_establishes_a_free_candidate_range() {
    let mut disk = deleted_seed(92);
    // The volume requires 128 bitmap bytes. A present but short stream is
    // different evidence from a missing attribute, even when its bits are zero.
    clean::put(
        &mut disk,
        6,
        &[
            clean::resident(0x30, &clean::name_value("$Bitmap", 5), 2),
            clean::resident(0x80, &[0; 8], 3),
        ],
        false,
        1,
    );
    let src = source(disk);
    let r = resources();
    let candidate = deleted_stream_candidate(&src, 24, &[], read(), streams(), &r).unwrap();
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert_eq!(assessment.allocation, RangeAllocation::Unknown);
    assert!(!assessment.bitmap_outcome.is_complete());
    assert_eq!(assessment.bitmap_outcome.source_id, Some(src.id()));
    assert_eq!(
        assessment.bitmap_outcome.unvisited,
        ByteRange {
            offset: 0,
            length: 128
        }
    );
    assert!(assessment.ownership_outcome.is_complete());
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::Unknown
    );
}

#[test]
fn mft_bitmap_flag_disagreement_is_retained_and_stops_owner_completeness() {
    let mut disk = clean::ntfs_audit_seed();
    // FILE 24 still has its in-use flag, but the independent allocation bitmap
    // says free. Preserve both rather than choosing either as authority.
    let bitmap = 2048
        + 56
        + clean::resident(0x30, &clean::name_value("$MFT", 5), 2).len()
        + clean::nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    disk[bitmap + 3] &= !1;
    let src = source(disk);
    let mut observed = false;
    let out = inventory(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let InventoryEvent::Slot(slot) = event
                && slot.slot == 24
            {
                observed = true;
                assert_eq!(slot.allocated.unwrap(), Some(false));
                assert!(slot.decoded.unwrap().unwrap().in_use);
            }
            Ok(true)
        },
    );
    assert!(out.is_complete());
    assert!(observed);
    let owners = current_owners(
        &src,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |_| Ok(true),
    );
    assert!(!owners.is_complete());
    assert_eq!(owners.unvisited.offset, 24 * 1024);
    assert_eq!(owners.source_id, Some(src.id()));
}

#[test]
fn observed_owner_conflict_survives_a_later_scan_limit() {
    let src = source(deleted_seed(90));
    let r = resources();
    let candidate = deleted_stream_candidate(&src, 24, &[], read(), streams(), &r).unwrap();
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits {
            records: 26,
            ..ScanLimits::default()
        },
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert!(assessment.bitmap_outcome.is_complete());
    assert!(!assessment.ownership_outcome.is_complete());
    assert_eq!(assessment.ownership_outcome.unvisited.offset, 26 * 1024);
    assert_eq!(assessment.conflicting_owner.unwrap().owner, 25);
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::ConflictingOwner
    );
}

#[test]
fn allocated_cluster_without_a_resolved_owner_remains_owner_unknown() {
    let mut disk = deleted_seed(92);
    let mut bits = vec![0; 128];
    for cluster in [0usize]
        .into_iter()
        .chain(4..68)
        .chain(128..384)
        .chain(400..404)
        .chain(500..508)
        .chain(90..93)
    {
        bits[cluster / 8] |= 1 << (cluster % 8);
    }
    // Allocation now includes cluster 92, but no allocated FILE stream owns it.
    clean::put(
        &mut disk,
        6,
        &[
            clean::resident(0x30, &clean::name_value("$Bitmap", 5), 2),
            clean::resident(0x80, &bits, 3),
        ],
        false,
        1,
    );
    let src = source(disk);
    let r = resources();
    let candidate = deleted_stream_candidate(&src, 24, &[], read(), streams(), &r).unwrap();
    let assessment = assess_candidate_range(
        &candidate,
        0,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &r,
    )
    .unwrap();
    assert!(assessment.bitmap_outcome.is_complete());
    assert!(assessment.ownership_outcome.is_complete());
    assert_eq!(assessment.allocation, RangeAllocation::Allocated);
    assert!(assessment.conflicting_owner.is_none());
    assert_eq!(
        assessment.reuse_evidence(),
        partmgr::forensics_extract::ReuseEvidence::AllocatedOwnerUnknown
    );
}
#[test]
fn unavailable_live_payload_emits_gap_and_never_delivers_placeholder_zeros() {
    let bytes = basic::fixture();
    let length = bytes.len() as u64;
    let source = ForensicSource::new(
        Arc::new(Bytes(bytes)),
        SourceIdentity {
            acquisition: "gapped capture".into(),
            source: "bytes".into(),
            stability_provider: "immutable".into(),
        },
        Arc::new(AcquisitionLease::default()),
        ByteRange { offset: 0, length },
        vec![ByteRange {
            offset: 90 * 512,
            length: 512,
        }],
    )
    .unwrap();
    let mut gaps = 0;
    let mut delivered = 0;
    let out = extract_live_stream(
        &source,
        25,
        &[],
        read(),
        streams(),
        None,
        ScanLimits::default(),
        &resources(),
        &NeverCancel,
        |event| {
            match event {
                StreamExtractionEvent::Coverage(e) if e.kind == CoverageKind::Unreadable => {
                    gaps += 1;
                    assert_eq!(
                        e.range,
                        ByteRange {
                            offset: 0,
                            length: 512
                        }
                    );
                }
                StreamExtractionEvent::Bytes { bytes, .. } => delivered += bytes.len(),
                _ => {}
            }
            Ok(())
        },
    );
    assert!(matches!(out.scan.stop_reason, StopReason::Io(_)));
    assert_eq!(gaps, 1);
    assert_eq!(delivered, 0);
    assert_eq!(out.scan.unvisited.offset, 0);
}

#[test]
fn resident_deleted_candidate_extracts_usa_replacement_bytes_not_markers() {
    let mut disk = deleted_seed(92);
    let payload = (0..600).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    clean::put(
        &mut disk,
        24,
        &[clean::resident(0x80, &payload, 3)],
        false,
        1,
    );
    clean::w(&mut disk, 2048 + 24 * 1024 + 22, 0);
    let r = resources();
    let candidate =
        deleted_stream_candidate(&source(disk), 24, &[], read(), streams(), &r).unwrap();
    assert_eq!(candidate.length, 600);
    assert!(candidate.ranges.len() > 1);
    let mut bytes = Vec::new();
    let out = partmgr::forensics_extract::extract_ranges(
        candidate.source(),
        candidate.length,
        &candidate.ranges,
        ScanLimits::default(),
        &r,
        &NeverCancel,
        &mut |event| {
            if let partmgr::forensics_extract::ExtractionEvent::Bytes { bytes: b, .. } = event {
                bytes.extend_from_slice(b);
            }
            Ok(())
        },
    );
    assert!(out.scan.is_complete(), "{:?}", out.scan.stop_reason);
    assert_eq!(bytes, payload);
    assert_eq!(
        out.prefix_sha256,
        <[u8; 32]>::from(Sha256::digest(&payload))
    );
}

#[test]
fn fragmented_mft_inventory_uses_proven_ranges_and_retains_bitmap_bits() {
    let mut disk = clean::ntfs_audit_seed();
    let moved = disk[2048 + 16 * 1024..2048 + 32 * 1024].to_vec();
    disk[600 * 512..600 * 512 + moved.len()].copy_from_slice(&moved);
    clean::put(
        &mut disk,
        0,
        &[
            clean::resident(0x30, &clean::name_value("$MFT", 5), 2),
            clean::nonresident(
                &[0x11, 32, 4, 0x21, 32, 0x54, 2, 0],
                64,
                32768,
                32768,
                false,
            ),
            clean::resident(0xb0, &0x0300ffffu64.to_le_bytes(), 4),
        ],
        false,
        1,
    );
    let mirror = disk[2048..6144].to_vec();
    disk[500 * 512..508 * 512].copy_from_slice(&mirror);
    let mut seen = false;
    let out = inventory(
        &source(disk),
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let InventoryEvent::Slot(slot) = event
                && slot.slot == 24
            {
                seen = true;
                assert_eq!(slot.allocated.unwrap(), Some(true));
                assert_eq!(
                    slot.volume_ranges,
                    &[ByteRange {
                        offset: 600 * 512 + 8 * 1024,
                        length: 1024
                    }]
                );
                assert!(slot.decoded.is_ok());
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(seen);
}
fn attr_list_entry(kind: u32, name: &str, low: u64, carrier: u64, instance: u16) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let mut b = vec![0; (26 + units.len() * 2).next_multiple_of(8)];
    let length = b.len();
    clean::d(&mut b, 0, kind);
    clean::w(&mut b, 4, length as u16);
    b[6] = units.len() as u8;
    b[7] = if units.is_empty() { 0 } else { 26 };
    clean::q(&mut b, 8, low);
    clean::q(&mut b, 16, carrier | (7 << 48));
    clean::w(&mut b, 24, instance);
    for (n, v) in units.into_iter().enumerate() {
        clean::w(&mut b, 26 + n * 2, v);
    }
    b
}
#[test]
fn ownership_resolves_ads_extensions_and_allocated_tails() {
    let mut disk = clean::ntfs_audit_seed();
    let mut first = clean::named_allocation(
        clean::nonresident(&[0x11, 1, 92, 0], 1, 700, 700, false),
        0x80,
        "aux",
        8,
    );
    clean::q(&mut first, 40, 1024);
    let mut second = clean::named_allocation(
        clean::nonresident(&[0x11, 1, 93, 0], 1, 0, 0, false),
        0x80,
        "aux",
        8,
    );
    clean::q(&mut second, 16, 1);
    clean::q(&mut second, 24, 1);
    clean::q(&mut second, 40, 0);
    let list = [
        attr_list_entry(0x30, "", 0, 25, 2),
        attr_list_entry(0x80, "", 0, 25, 3),
        attr_list_entry(0x80, "aux", 0, 25, 8),
        attr_list_entry(0x80, "aux", 1, 26, 8),
    ]
    .concat();
    clean::put(
        &mut disk,
        25,
        &[
            clean::resident(0x20, &list, 9),
            clean::resident(0x30, &clean::name_value("gamma", 5), 2),
            clean::nonresident(&[0x11, 1, 90, 1, 1, 0x11, 1, 1, 0], 3, 1000, 256, true),
            first,
        ],
        false,
        1,
    );
    let mut extension = clean::record(26, &[second]);
    clean::q(&mut extension, 32, 25 | (7 << 48));
    clean::w(&mut extension, 18, 0);
    disk[2048 + 26 * 1024..2048 + 27 * 1024].copy_from_slice(&extension);
    let bitmap = 2048
        + 56
        + clean::resident(0x30, &clean::name_value("$MFT", 5), 2).len()
        + clean::nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    disk[bitmap + 3] |= 4;
    let mut observed = false;
    let out = current_owners(
        &source(disk),
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let OwnershipEvent::Claim(owner) = event
                && owner.carrier == 26
            {
                observed = true;
                assert_eq!(owner.owner, 25);
                assert_eq!(
                    owner.range,
                    ByteRange {
                        offset: 93 * 512,
                        length: 512
                    }
                );
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert!(observed);
}

#[test]
fn native_sparse_unit_four_is_explicit_forensic_profile_only() {
    let mut disk = basic::fixture();
    let mut sparse = basic::nonresident(&[0x11, 1, 90, 1, 1, 0x11, 1, 1, 0], 3, 1536, 1280, true);
    basic::w(&mut sparse, 34, 4);
    disk[2048 + 25 * 1024..2048 + 26 * 1024].copy_from_slice(&basic::record(25, &[sparse]));
    let src = source(disk);
    let r = resources();
    let strict = partmgr::fs_ntfs::NtfsVolume::open(Arc::new(src.clone()), read(), &r).unwrap();
    assert!(strict.open_file(25, &r).is_err());
    let mut bytes = Vec::new();
    let out = extract_live_stream(
        &src,
        25,
        &[],
        read(),
        streams(),
        None,
        ScanLimits::default(),
        &r,
        &NeverCancel,
        |event| {
            if let StreamExtractionEvent::Bytes { bytes: b, .. } = event {
                bytes.extend_from_slice(b);
            }
            Ok(())
        },
    );
    assert!(out.scan.is_complete(), "{:?}", out.scan.stop_reason);
    assert_eq!(&bytes[..512], &vec![0x31; 512]);
    assert_eq!(&bytes[512..1024], &vec![0; 512]);
    assert_eq!(&bytes[1024..1280], &vec![0x72; 256]);
    assert_eq!(&bytes[1280..], &vec![0; 256]);
}

#[test]
fn missing_mft_bitmap_retains_causal_unknown_for_every_slot() {
    let mut bytes = clean::ntfs_audit_seed();
    let record = &mut bytes[2048..3072];
    let mut at = u16::from_le_bytes(record[20..22].try_into().unwrap()) as usize;
    loop {
        let kind = u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
        assert_ne!(kind, u32::MAX);
        if kind == 0xb0 {
            record[at..at + 4].copy_from_slice(&0xc0u32.to_le_bytes());
            break;
        }
        at += u32::from_le_bytes(record[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    let mut unknown = 0;
    let out = inventory(
        &source(bytes),
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let InventoryEvent::Slot(slot) = event {
                let error = slot.allocated.as_ref().unwrap_err();
                assert!(std::error::Error::source(error).is_some());
                unknown += 1;
            }
            Ok(true)
        },
    );
    assert!(out.is_complete(), "{:?}", out.stop_reason);
    assert_eq!(unknown, 32);
}

#[test]
fn decoder_attribute_ceiling_retains_cause_and_source_before_inventory() {
    let src = source(clean::ntfs_audit_seed());
    let mut decoder = read();
    decoder.attributes = 0;
    let out = inventory(
        &src,
        decoder,
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |_| panic!("bootstrap must stop before observation"),
    );
    assert_eq!(out.source_id, Some(src.id()));
    assert_eq!(out.observations, 0);
    match out.stop_reason {
        StopReason::ResourceCause { ceiling, cause } => {
            assert_eq!(ceiling, "attributes");
            assert!(cause.get_ref().is_some());
            assert!(cause.to_string().contains("attribute"));
        }
        other => panic!("unexpected stop: {other:?}"),
    }
}

#[test]
fn inventory_observation_and_early_stop_bind_exact_view_despite_identical_labels() {
    let first = source(clean::ntfs_audit_seed());
    let second = source(clean::ntfs_audit_seed());
    assert_eq!(first.identity(), second.identity());
    assert_ne!(first.id(), second.id());
    let mut delivered = false;
    let out = inventory(
        &second,
        read(),
        streams(),
        ScanLimits::default(),
        &NeverCancel,
        &resources(),
        |event| {
            if let InventoryEvent::Slot(slot) = event {
                assert_eq!(slot.source_id, Some(second.id()));
                assert_ne!(slot.source_id, Some(first.id()));
                delivered = true;
                return Ok(false);
            }
            Ok(true)
        },
    );
    assert!(delivered);
    assert_eq!(out.source_id, Some(second.id()));
    assert!(matches!(out.stop_reason, StopReason::CallerStop));
}
