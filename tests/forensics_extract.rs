#![cfg(all(feature = "std", feature = "forensics"))]

use partmgr::{
    forensics::{
        AcquisitionLease, ByteRange, ForensicSource, NeverCancel, ScanLimits, SourceIdentity,
        StopReason,
    },
    forensics_extract::{
        ExtractionEvent, ExtractionKind, ExtractionRange, ReuseEvidence, extract_ranges,
    },
    fs_core::{Budget, Cancellation, Resources},
    io::{self, ReadAt},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn source() -> (ForensicSource, Arc<AcquisitionLease>, Resources) {
    let lease = Arc::new(AcquisitionLease::default());
    let source = ForensicSource::new(
        Arc::new(Bytes(b"abcdef".to_vec())),
        SourceIdentity {
            acquisition: "test acquisition".into(),
            source: "literal".into(),
            stability_provider: "test owner".into(),
        },
        lease.clone(),
        ByteRange {
            offset: 0,
            length: 6,
        },
        vec![],
    )
    .unwrap();
    (
        source,
        lease,
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        },
    )
}
fn range(offset: u64, length: u64, kind: ExtractionKind) -> ExtractionRange {
    ExtractionRange {
        logical: ByteRange { offset, length },
        kind,
        reuse: ReuseEvidence::Unknown,
    }
}

#[test]
fn fragmented_data_and_logical_zero_kinds_have_exact_hash_and_manifest() {
    let (source, _, resources) = source();
    let map = [
        range(0, 2, ExtractionKind::Data(4)),
        range(2, 2, ExtractionKind::Sparse),
        range(4, 1, ExtractionKind::Unwritten),
        range(5, 2, ExtractionKind::Data(0)),
    ];
    let mut bytes = Vec::new();
    let mut metadata = Vec::new();
    let result = extract_ranges(
        &source,
        7,
        &map,
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |event| {
            match event {
                ExtractionEvent::Bytes { bytes: chunk, .. } => bytes.extend_from_slice(chunk),
                ExtractionEvent::Range(range) => metadata.push(range),
                _ => {}
            }
            Ok(())
        },
    );
    assert_eq!(bytes, b"ef\0\0\0ab");
    assert_eq!(
        result.prefix_sha256.as_slice(),
        Sha256::digest(&bytes).as_slice()
    );
    assert!(result.scan.is_complete());
    assert_eq!(metadata, map);
    assert_eq!(resources.memory.used(), 0);
}

#[test]
fn unavailable_range_never_concatenates_or_zero_fills() {
    let (source, _, resources) = source();
    let map = [
        range(0, 2, ExtractionKind::Data(0)),
        range(2, 2, ExtractionKind::Unavailable),
        range(4, 2, ExtractionKind::Data(4)),
    ];
    let mut bytes = Vec::new();
    let result = extract_ranges(
        &source,
        6,
        &map,
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |event| {
            if let ExtractionEvent::Bytes { bytes: chunk, .. } = event {
                bytes.extend_from_slice(chunk);
            }
            Ok(())
        },
    );
    assert_eq!(bytes, b"ab");
    assert!(matches!(result.scan.stop_reason, StopReason::Io(_)));
    assert_eq!(
        result.scan.unvisited,
        ByteRange {
            offset: 2,
            length: 4
        }
    );
}

#[test]
fn cancellation_and_invalid_maps_fail_before_output() {
    let (source, _, resources) = source();
    let map = [range(1, 2, ExtractionKind::Data(0))];
    let result = extract_ranges(
        &source,
        2,
        &map,
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |_| panic!("invalid map delivered output"),
    );
    assert!(matches!(
        result.scan.stop_reason,
        StopReason::InvalidBootstrap(_)
    ));
    resources.cancellation.cancel();
    let result = extract_ranges(
        &source,
        0,
        &[],
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |_| panic!("cancelled scan delivered output"),
    );
    assert!(matches!(result.scan.stop_reason, StopReason::Cancelled));
    assert!(!result.scan.is_complete());
}

#[test]
fn each_ceiling_is_independent_and_shared_memory_is_refunded() {
    for (limits, expected) in [
        (
            ScanLimits {
                records: 0,
                ..ScanLimits::default()
            },
            "records",
        ),
        (
            ScanLimits {
                read_bytes: 0,
                ..ScanLimits::default()
            },
            "read_bytes",
        ),
        (
            ScanLimits {
                output_bytes: 0,
                ..ScanLimits::default()
            },
            "output_bytes",
        ),
        (
            ScanLimits {
                memory_bytes: 0,
                ..ScanLimits::default()
            },
            "memory_bytes",
        ),
    ] {
        let (source, _, resources) = source();
        let result = extract_ranges(
            &source,
            6,
            &[range(0, 6, ExtractionKind::Data(0))],
            limits,
            &resources,
            &NeverCancel,
            &mut |_| Ok(()),
        );
        assert!(
            matches!(result.scan.stop_reason, StopReason::ResourceLimit(name) if name == expected)
        );
        assert_eq!(result.output_bytes, 0);
        assert_eq!(resources.memory.used(), 0);
    }
}

#[test]
fn output_failure_and_revocation_retain_incomplete_terminal_state() {
    let (source, lease, resources) = source();
    let map = [range(0, 6, ExtractionKind::Data(0))];
    let result = extract_ranges(
        &source,
        6,
        &map,
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |event| {
            if matches!(event, ExtractionEvent::Bytes { .. }) {
                return Err(io::Error::other("sink failed"));
            }
            Ok(())
        },
    );
    assert!(matches!(
        result.scan.stop_reason,
        StopReason::DeliveryFailed(_)
    ));
    assert_eq!(result.output_bytes, 0);
    let result = extract_ranges(
        &source,
        6,
        &map,
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |event| {
            if matches!(event, ExtractionEvent::Range(_)) {
                lease.invalidate();
            }
            Ok(())
        },
    );
    assert!(matches!(
        result.scan.stop_reason,
        StopReason::SourceStability(_)
    ));
    assert_eq!(result.output_bytes, 0);
}

#[test]
fn empty_success_is_distinct_from_failure_before_first_finding() {
    let (source, _, resources) = source();
    let result = extract_ranges(
        &source,
        0,
        &[],
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |_| panic!("empty export"),
    );
    assert!(result.scan.is_complete());
    assert_eq!(result.output_bytes, 0);
    assert_eq!(
        result.prefix_sha256.as_slice(),
        Sha256::digest([]).as_slice()
    );
}

#[test]
fn failed_coverage_delivery_keeps_prefix_hash_but_not_completed_coverage() {
    let (source, _, resources) = source();
    let result = extract_ranges(
        &source,
        6,
        &[range(0, 6, ExtractionKind::Data(0))],
        ScanLimits::default(),
        &resources,
        &NeverCancel,
        &mut |event| {
            if matches!(event, ExtractionEvent::Coverage(_)) {
                return Err(io::Error::other("coverage sink failed"));
            }
            Ok(())
        },
    );
    assert_eq!(result.output_bytes, 6);
    assert_eq!(
        result.prefix_sha256.as_slice(),
        Sha256::digest(b"abcdef").as_slice()
    );
    assert!(matches!(
        result.scan.stop_reason,
        StopReason::DeliveryFailed(_)
    ));
    assert_eq!(result.scan.last_delivered, None);
    assert_eq!(
        result.scan.unvisited,
        ByteRange {
            offset: 0,
            length: 6
        }
    );
    assert!(!result.scan.is_complete());
}
