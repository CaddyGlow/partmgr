#![cfg(all(feature = "std", feature = "forensics"))]
#[path = "fixtures/ntfs_clean.rs"]
mod clean;
use partmgr::{
    forensics::{
        AcquisitionLease, ByteRange, ForensicSource, NeverCancel, ScanLimits, SourceIdentity,
    },
    forensics_export::{NtfsStreamExportRequest, export_ntfs_candidate, export_ntfs_live_stream},
    forensics_ntfs::{assess_candidate_range, bounded_deleted_stream_candidate},
    fs_core::{Budget, Cancellation, NativeName, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
    io::{self, ReadAt},
};
use std::sync::Arc;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        let range = self
            .0
            .get(offset as usize..offset as usize + buffer.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buffer.copy_from_slice(range);
        Ok(())
    }
}
fn source(bytes: Vec<u8>) -> ForensicSource {
    let length = bytes.len() as u64;
    ForensicSource::new(
        Arc::new(Bytes(bytes)),
        SourceIdentity {
            acquisition: "independent-fixture".into(),
            source: "native-ntfs-layout".into(),
            stability_provider: "owned immutable bytes".into(),
        },
        Arc::new(AcquisitionLease::default()),
        ByteRange { offset: 0, length },
        vec![],
    )
    .unwrap()
}
fn profiles() -> (NtfsReadLimits, NtfsStreamLimits) {
    (
        NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        NtfsStreamLimits {
            extension_records: 16,
            list_entries: 128,
            list_bytes: 8192,
            attributes: 128,
            runs: 128,
            work: 100_000,
        },
    )
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn live_resident_stream_exports_exact_content_and_logical_provenance() {
    let source = source(clean::ntfs_audit_seed());
    let root = tempfile::tempdir().unwrap();
    let r = resources();
    let (read, streams) = profiles();
    let name = NativeName::Utf16(vec![]);
    let result = export_ntfs_live_stream(
        root.path(),
        &source,
        NtfsStreamExportRequest {
            record: 24,
            name: &name,
            read,
            streams,
            compression: None,
            limits: ScanLimits::default(),
        },
        &r,
        &NeverCancel,
    )
    .unwrap();
    assert!(
        result.outcome.scan.is_complete(),
        "{:?}",
        result.outcome.scan.stop_reason
    );
    assert_eq!(std::fs::read(result.output).unwrap(), b"hello");
    let manifest = std::fs::read_to_string(result.manifest).unwrap();
    assert!(manifest.contains("\"type\":\"ntfs_stream_selection\",\"record\":24"));
    assert!(manifest.contains("\"stream_range\":{\"offset\":0,\"length\":5}"));
    assert!(manifest.contains("\"physical_mapping\":null"));
    assert!(manifest.contains("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn missing_bitmap_remains_unknown_in_standalone_recovery_manifest() {
    let mut bytes = clean::ntfs_audit_seed();
    clean::put(
        &mut bytes,
        24,
        &[clean::nonresident(&[0x11, 1, 92, 0], 1, 100, 100, false)],
        false,
        1,
    );
    clean::w(&mut bytes, 2048 + 24 * 1024 + 22, 0);
    let bitmap = 2048
        + 56
        + clean::resident(0x30, &clean::name_value("$MFT", 5), 2).len()
        + clean::nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    bytes[bitmap + 3] &= !1;
    bytes[92 * 512..92 * 512 + 100].fill(b'D');
    clean::put(
        &mut bytes,
        6,
        &[clean::resident(0x30, &clean::name_value("$Bitmap", 5), 2)],
        false,
        1,
    );
    let source = source(bytes);
    let root = tempfile::tempdir().unwrap();
    let r = resources();
    let (read, streams) = profiles();
    let limits = ScanLimits::default();
    let candidate =
        bounded_deleted_stream_candidate(&source, 24, &[], read, streams, limits, &r).unwrap();
    let mut assessment =
        assess_candidate_range(&candidate, 0, read, streams, limits, &NeverCancel, &r).unwrap();
    assert!(!assessment.bitmap_outcome.is_complete());
    assert!(assessment.ownership_outcome.is_complete());
    let sibling = source
        .select_region(ByteRange {
            offset: 0,
            length: source.len(),
        })
        .unwrap();
    assessment.bitmap_outcome.source_id = Some(sibling.id());
    let mut assessments = [Some(assessment)];
    let failure = match export_ntfs_candidate(
        root.path(),
        &candidate,
        &assessments,
        limits,
        &r,
        &NeverCancel,
    ) {
        Ok(_) => panic!("foreign view assessment was accepted"),
        Err(failure) => failure,
    };
    assert!(failure.output.is_none());
    assert!(failure.manifest.is_none());
    assert!(failure.cause.to_string().contains("source view mismatch"));
    assessments[0].as_mut().unwrap().bitmap_outcome.source_id = Some(source.id());
    let result = export_ntfs_candidate(
        root.path(),
        &candidate,
        &assessments,
        limits,
        &r,
        &NeverCancel,
    )
    .unwrap();
    assert!(result.outcome.scan.is_complete());
    assert_eq!(std::fs::read(result.output).unwrap(), [b'D'; 100]);
    let manifest = std::fs::read_to_string(result.manifest).unwrap();
    assert!(manifest.contains("\"raw_record_hex\":\"46494c45"));
    assert!(manifest.contains("\"allocation\":\"unknown\""));
    assert!(manifest.contains("\"current_reuse_evidence\":\"unknown\""));
    assert!(manifest.contains("\"historical_authenticity\":\"unproven\""));
    assert!(manifest.contains("\"profile\":\"ntfs-volume-bitmap/logical-stream\""));
    assert!(manifest.contains("\"complete\":false"));
    assert!(manifest.contains("\"profile\":\"candidate-extraction-v1\""));
}
