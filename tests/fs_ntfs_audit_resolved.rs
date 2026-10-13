#![cfg(feature = "std")]

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean;
use ntfs_clean::*;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
    fs_ntfs_audit::{
        NtfsAuditFinding, NtfsAuditLimits, audit_ntfs_resolved, audit_ntfs_resolved_detailed,
    },
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;

struct Image {
    bytes: Vec<u8>,
    reads: AtomicU64,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reads: AtomicU64::new(0),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let offset = usize::try_from(offset).map_err(io::Error::other)?;
        bytes.copy_from_slice(
            self.bytes
                .get(offset..offset + bytes.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn read_limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn stream_limits() -> NtfsStreamLimits {
    NtfsStreamLimits {
        extension_records: 8,
        list_entries: 64,
        list_bytes: 4096,
        attributes: 32,
        runs: 64,
        work: 10_000_000,
    }
}
fn audit_limits() -> NtfsAuditLimits {
    NtfsAuditLimits {
        clusters: 2048,
        records: 128,
        attributes: 2048,
        ranges: 512,
        entries: 128,
        index_blocks: 32,
        depth: 8,
        work: 10_000_000,
        findings: 64,
        free_ranges: 64,
    }
}
fn bitmap_offset() -> usize {
    2048 + 6 * 1024 + 56 + resident(0x30, &name_value("$Bitmap", 5), 2).len() + 24
}
fn mft_bitmap_offset() -> usize {
    2048 + 56
        + resident(0x30, &name_value("$MFT", 5), 2).len()
        + nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24
}
fn sync_mirror(bytes: &mut [u8]) {
    let mirror = bytes[2048..6144].to_vec();
    bytes[500 * 512..508 * 512].copy_from_slice(&mirror);
}
fn list_entry(kind: u32, name: &str, low: u64, number: u64, instance: u16) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut entry = vec![0; (26 + units.len() * 2).next_multiple_of(8)];
    let length = entry.len();
    d(&mut entry, 0, kind);
    w(&mut entry, 4, length as u16);
    entry[6] = units.len() as u8;
    entry[7] = if units.is_empty() { 0 } else { 26 };
    q(&mut entry, 8, low);
    q(&mut entry, 16, number | (7 << 48));
    w(&mut entry, 24, instance);
    for (i, unit) in units.iter().enumerate() {
        w(&mut entry, 26 + i * 2, *unit);
    }
    entry
}
fn fixture() -> Vec<u8> {
    fixture_variant(false)
}
fn fixture_variant(sparse: bool) -> Vec<u8> {
    let mut bytes = ntfs_audit_seed();
    // Explicit sparse encoding for the reserved all-hole $BadClus stream.
    let mut bad = nonresident(&[0x02, 0, 4, 0], 1024, 1024 * 512, 0, true);
    q(&mut bad, 64, 0);
    put(
        &mut bytes,
        8,
        &[
            resident(0x30, &name_value("$BadClus", 5), 2),
            resident(0x80, &[], 3),
            named_allocation(bad, 0x80, "$Bad", 4),
        ],
        false,
        1,
    );
    let mut first = named_allocation(
        nonresident(
            if sparse {
                &[0x11, 1, 92, 1, 1, 0]
            } else {
                &[0x11, 1, 92, 0]
            },
            if sparse { 2 } else { 1 },
            700,
            128,
            sparse,
        ),
        0x80,
        "aux",
        8,
    );
    q(&mut first, 40, if sparse { 1536 } else { 1024 });
    if sparse {
        q(&mut first, 64, 1024);
    }
    let mut second = named_allocation(
        nonresident(&[0x11, 1, 93, 0], 1, 0, 0, sparse),
        0x80,
        "aux",
        8,
    );
    q(&mut second, 16, if sparse { 2 } else { 1 });
    q(&mut second, 24, if sparse { 2 } else { 1 });
    q(&mut second, 40, 0);
    let list = [
        list_entry(0x30, "", 0, 25, 2),
        list_entry(0x80, "", 0, 25, 3),
        list_entry(0x80, "aux", 0, 25, 8),
        list_entry(0x80, "aux", if sparse { 2 } else { 1 }, 26, 8),
        list_entry(0x80, "$I30", 0, 26, 10),
    ]
    .concat();
    put(
        &mut bytes,
        25,
        &[
            resident(0x20, &list, 9),
            resident(0x30, &name_value("gamma", 5), 2),
            nonresident(&[0x11, 1, 90, 1, 1, 0x11, 1, 1, 0], 3, 1000, 256, true),
            first,
        ],
        false,
        1,
    );
    let mut extension = record(26, &[second, named_resident(0x80, b"resident ADS", 10)]);
    q(&mut extension, 32, 25 | (7 << 48));
    w(&mut extension, 18, 0);
    bytes[2048 + 26 * 1024..2048 + 27 * 1024].copy_from_slice(&extension);
    bytes[mft_bitmap_offset() + 3] |= 4;
    for cluster in [92, 93] {
        bytes[bitmap_offset() + cluster / 8] |= 1 << (cluster % 8);
    }
    sync_mirror(&mut bytes);
    bytes
}
#[test]
fn whole_volume_resolves_extensions_and_counts_allocated_tails_once() {
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(fixture())),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert!(report.is_complete());
    assert_eq!(report.allocated_records(), 19);
    assert_eq!(report.allocated_clusters(), 337);
    assert_eq!(report.owned_clusters(), 337);
    assert_eq!(
        report.free_ranges().iter().map(|e| e.length).sum::<u64>(),
        (1024 - 337) * 512
    );
    assert!(
        !report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::UnreachableRecord { record: 26 }))
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn continuation_allocation_is_checked_against_global_bitmap() {
    let mut bytes = fixture();
    bytes[bitmap_offset() + 93 / 8] &= !(1 << (93 % 8));
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::ReferencedFree { cluster: 93 })),
        "{:?}",
        report.findings()
    );
    assert!(report.findings().iter().any(|f|matches!(f,NtfsAuditFinding::ReferencedFreeOwner{cluster:93,owner} if owner.record==25 && owner.carrier_record==26 && owner.lowest_vcn==1)),"{:?}",report.findings());
    assert!(report.free_ranges().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn cross_stream_overlap_in_continuation_is_not_deduplicated() {
    let mut bytes = fixture();
    // The continuation is native nonresident header + aligned six-byte name.
    let offset = 2048 + 26 * 1024 + 56 + 72;
    assert_eq!(&bytes[offset..offset + 4], &[0x11, 1, 93, 0]);
    bytes[offset + 2] = 90;
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f, NtfsAuditFinding::CrossLink { cluster: 90, .. })),
        "{:?}",
        report.findings()
    );
    assert!(report.free_ranges().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_list_relationships_never_grant_complete_free_space() {
    for mutation in 0..5 {
        let mut bytes = fixture();
        let extension = 2048 + 26 * 1024;
        let list = 2048 + 25 * 1024 + 56 + 24;
        match mutation {
            0 => q(&mut bytes, extension + 32, 24 | (7 << 48)), // wrong base
            1 => w(&mut bytes, extension + 16, 8),              // stale target sequence
            2 => q(&mut bytes, extension + 32, 25 | (8 << 48)), // stale owner sequence
            3 => {
                let duplicate = bytes[list + 64..list + 96].to_vec();
                bytes[list + 96..list + 128].copy_from_slice(&duplicate);
            }
            _ => {
                // Remove the extension's resident attribute from the list, retaining the live occurrence.
                let at = list + 128;
                d(&mut bytes, at, 0x80);
                w(&mut bytes, at + 24, 11);
            }
        }
        let r = resources();
        match audit_ntfs_resolved_detailed(
            Arc::new(Image::new(bytes)),
            read_limits(),
            stream_limits(),
            audit_limits(),
            &r,
        ) {
            Ok(report) => {
                assert!(
                    !report.is_complete() || !report.is_clean(),
                    "mutation {mutation}"
                );
                assert!(report.free_ranges().is_empty());
            }
            Err(failure) => {
                assert!(
                    matches!(
                        failure.error().kind,
                        ErrorKind::InvalidData | ErrorKind::Unsupported | ErrorKind::StalePlan
                    ),
                    "mutation {mutation}: {:?}",
                    failure.error()
                );
                if let Some(report) = failure.report() {
                    assert!(!report.is_complete());
                    assert!(report.free_ranges().is_empty());
                }
            }
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn cancellation_and_resolution_budgets_release_all_reservations() {
    let source = Arc::new(Image::new(fixture()));
    let r = resources();
    r.cancellation.cancel();
    let failure = audit_ntfs_resolved_detailed(
        source.clone(),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .err()
    .unwrap();
    assert_eq!(failure.error().kind, ErrorKind::Cancelled);
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    drop(failure);
    assert_eq!(r.memory.used(), 0);
    for mutation in 0..4 {
        let r = resources();
        let mut limits = stream_limits();
        match mutation {
            0 => limits.extension_records = 0,
            1 => limits.list_entries = 0,
            2 => limits.list_bytes = 0,
            _ => limits.work = 0,
        };
        let failure =
            audit_ntfs_resolved_detailed(source.clone(), read_limits(), limits, audit_limits(), &r)
                .err()
                .unwrap();
        assert_eq!(
            failure.error().kind,
            ErrorKind::BudgetExhausted,
            "case {mutation}"
        );
        if let Some(report) = failure.report() {
            assert!(!report.is_complete());
            assert!(report.free_ranges().is_empty());
        }
        drop(failure);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn orphan_extension_is_not_a_namespace_object_or_free_space_authority() {
    let mut bytes = fixture();
    let mut extension = record(27, &[resident(0x80, b"unlisted", 3)]);
    q(&mut extension, 32, 25 | (7 << 48));
    w(&mut extension, 18, 0);
    bytes[2048 + 27 * 1024..2048 + 28 * 1024].copy_from_slice(&extension);
    bytes[mft_bitmap_offset() + 3] |= 8;
    sync_mirror(&mut bytes);
    let r = resources();
    match audit_ntfs_resolved_detailed(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    ) {
        Ok(report) => {
            assert!(!report.is_clean());
            assert!(
                report.findings().iter().any(|f| matches!(
                    f,
                    NtfsAuditFinding::ExtensionParticipation {
                        record: 27,
                        participants: 0,
                        ..
                    }
                )),
                "{:?}",
                report.findings()
            );
            assert!(report.free_ranges().is_empty());
            assert!(
                !report
                    .findings()
                    .iter()
                    .any(|f| matches!(f, NtfsAuditFinding::UnreachableRecord { record: 27 }))
            );
        }
        Err(failure) => {
            if let Some(report) = failure.report() {
                assert!(!report.is_complete());
                assert!(report.free_ranges().is_empty());
            }
        }
    }
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn sparse_continuation_beyond_eof_still_owns_native_physical_runs() {
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(fixture_variant(true))),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.owned_clusters(), 337);
    assert_eq!(report.allocated_clusters(), 337);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

struct PayloadTrap(Image);
impl ReadAt for PayloadTrap {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        if offset < 94 * 512 && offset + bytes.len() as u64 > 90 * 512 {
            return Err(io::Error::other("audit read file payload"));
        }
        self.0.read_exact_at(offset, bytes)
    }
}
#[test]
fn resolved_audit_never_prefetches_stream_payload() {
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(PayloadTrap(Image::new(fixture()))),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

struct CancelOnExtension {
    image: Image,
    cancellation: Cancellation,
}
impl ReadAt for CancelOnExtension {
    fn len(&self) -> u64 {
        self.image.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.image.read_exact_at(offset, bytes)?;
        if offset == 2048 + 26 * 1024 {
            self.cancellation.cancel();
        }
        Ok(())
    }
}
#[test]
fn cancellation_during_extension_io_retains_incomplete_evidence() {
    let r = resources();
    let source = Arc::new(CancelOnExtension {
        image: Image::new(fixture()),
        cancellation: r.cancellation.clone(),
    });
    let failure =
        audit_ntfs_resolved_detailed(source, read_limits(), stream_limits(), audit_limits(), &r)
            .err()
            .unwrap();
    assert_eq!(failure.error().kind, ErrorKind::Cancelled);
    let report = failure.report().expect("scan started");
    assert!(!report.is_complete());
    assert!(report.free_ranges().is_empty());
    drop(failure);
    assert_eq!(r.memory.used(), 0);
}

fn nonresident_directory_bitmap_fixture(mode: usize) -> Vec<u8> {
    let mut bytes = fixture();
    let mut root = root_attribute(&[terminal(Some(0))], true);
    d(&mut root, 40, 2048);
    root[44] = 4;
    let allocation = named_allocation(
        nonresident(&[0x21, 4, 0x90, 1, 0], 4, 2048, 2048, false),
        0xa0,
        "$I30",
        5,
    );
    let bitmap = named_allocation(
        nonresident(
            &[0x11, 1, 94, 0],
            1,
            8,
            if mode == 1 { 0 } else { 8 },
            mode == 2,
        ),
        0xb0,
        "$I30",
        6,
    );
    // Sparse native physical allocation count is one cluster for this test.
    let mut bitmap = bitmap;
    if mode == 2 {
        q(&mut bitmap, 64, 512);
    }
    put(
        &mut bytes,
        5,
        &[
            resident(0x30, &name_value(".", 5), 2),
            root,
            allocation,
            bitmap,
        ],
        true,
        1,
    );
    bytes[94 * 512] = if mode == 3 { 3 } else { 1 };
    bytes[bitmap_offset() + 94 / 8] |= 1 << (94 % 8);
    bytes
}
#[test]
fn resolved_nonresident_directory_bitmap_preserves_index_validation() {
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(nonresident_directory_bitmap_fixture(0))),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.owned_clusters(), 338);
    drop(report);
    assert_eq!(r.memory.used(), 0);
    for mode in 1..4 {
        let r = resources();
        match audit_ntfs_resolved_detailed(
            Arc::new(Image::new(nonresident_directory_bitmap_fixture(mode))),
            read_limits(),
            stream_limits(),
            audit_limits(),
            &r,
        ) {
            Ok(report) => {
                assert!(!report.is_clean(), "bitmap mode {mode}");
                assert!(report.free_ranges().is_empty());
            }
            Err(failure) => {
                assert!(
                    matches!(
                        failure.error().kind,
                        ErrorKind::InvalidData | ErrorKind::Unsupported
                    ),
                    "bitmap mode {mode}: {:?}",
                    failure.error()
                );
                if let Some(report) = failure.report() {
                    assert!(!report.is_complete());
                    assert!(report.free_ranges().is_empty());
                }
            }
        }
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn cross_owner_continuation_conflict_retains_exact_carrier_provenance() {
    let mut bytes = fixture();
    put(
        &mut bytes,
        24,
        &[
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
            nonresident(&[0x11, 1, 93, 0], 1, 100, 100, false),
        ],
        false,
        2,
    );
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    let conflict = report
        .findings()
        .iter()
        .find_map(|f| match f {
            NtfsAuditFinding::CrossLink {
                cluster: 93,
                first,
                second,
                ..
            } => Some((*first, *second)),
            _ => None,
        })
        .expect("cross-owner continuation overlap");
    let extension = if conflict.0.carrier_record == 26 {
        conflict.0
    } else {
        conflict.1
    };
    assert_eq!(extension.record, 25);
    assert_eq!(extension.carrier_record, 26);
    assert_eq!(extension.carrier_sequence, 7);
    assert_eq!(extension.attribute, 8);
    assert_eq!(extension.kind, 0x80);
    assert_eq!(extension.lowest_vcn, 1);
    assert_eq!(extension.highest_vcn, 1);
    assert_eq!(extension.offset, 56);
    let other = if conflict.0.carrier_record == 24 {
        conflict.0
    } else {
        conflict.1
    };
    assert_eq!(other.record, 24);
    assert_eq!(other.attribute, 3);
    assert!(report.free_ranges().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn binding() -> partmgr::fs_maintenance::PlanBinding {
    partmgr::fs_maintenance::PlanBinding {
        source: partmgr::fs_core::ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        backend: [0; 32],
        region_start: 0,
        region_bytes: 1024 * 512 + 512,
        filesystem_bytes: 1024 * 512,
        allocation_unit: 512,
        sectors: partmgr::fs_storage::SectorGeometry {
            logical: Some(512),
            physical: None,
        },
        features: [0; 32],
        metadata: [0; 32],
    }
}
#[test]
fn resolved_maintenance_adapter_exposes_partial_scope_and_native_cleanliness() {
    use partmgr::{
        fs_maintenance::{CheckCompletion, CheckOutcome},
        fs_maintenance_audit::check_ntfs_resolved,
    };
    let r = resources();
    let binding = binding();
    let checked = check_ntfs_resolved(
        Arc::new(Image::new(fixture())),
        &binding,
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    );
    assert!(checked.audit().unwrap().is_clean());
    assert!(checked.audit().unwrap().is_complete());
    assert_eq!(checked.report().completion, CheckCompletion::Complete);
    assert_eq!(checked.report().outcome(), CheckOutcome::Incomplete);
    assert!(!checked.report().skipped.is_empty());
    assert!(checked.error().is_none());
    drop(checked);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn resolved_maintenance_adapter_retains_dirty_marker_and_later_error() {
    use partmgr::{
        fs_maintenance::{CheckCompletion, CheckOutcome},
        fs_maintenance_audit::check_ntfs_resolved,
    };
    let r = resources();
    let binding = binding();
    let mut bytes = fixture();
    let flags = 2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10;
    w(&mut bytes, flags, 1);
    sync_mirror(&mut bytes);
    q(&mut bytes, 2048 + 26 * 1024 + 32, 24 | (7 << 48));
    let caps = audit_limits();
    let checked = check_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        &binding,
        read_limits(),
        stream_limits(),
        caps,
        &r,
    );
    assert_eq!(checked.error().unwrap().kind, ErrorKind::InvalidData);
    assert_eq!(checked.report().completion, CheckCompletion::Incomplete);
    assert_eq!(checked.report().outcome(), CheckOutcome::Incomplete);
    assert!(checked.report().recovery_required);
    let audit = checked.audit().unwrap();
    assert!(audit.findings().contains(&NtfsAuditFinding::Dirty));
    assert!(!audit.is_complete());
    assert!(audit.free_ranges().is_empty());
    drop(checked);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn reserved_unflagged_badclus_holes_remain_valid_native_ownership() {
    let mut bytes = fixture();
    put(
        &mut bytes,
        8,
        &[
            resident(0x30, &name_value("$BadClus", 5), 2),
            resident(0x80, &[], 3),
            named_allocation(
                nonresident(&[0x02, 0, 4, 0], 1024, 1024 * 512, 0, false),
                0x80,
                "$Bad",
                4,
            ),
        ],
        false,
        1,
    );
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.owned_clusters(), 337);
    assert_eq!(report.bad_clusters(), 0);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn repeated_filename_occurrences_in_extension_belong_to_one_base_hardlink_owner() {
    let mut bytes = fixture();
    let list = [
        list_entry(0x30, "", 0, 27, 1),
        list_entry(0x30, "", 0, 27, 2),
        list_entry(0x80, "", 0, 24, 3),
    ]
    .concat();
    put(
        &mut bytes,
        24,
        &[resident(0x20, &list, 4), resident(0x80, b"hello", 3)],
        false,
        2,
    );
    let mut extension = record(
        27,
        &[
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
        ],
    );
    q(&mut extension, 32, 24 | (7 << 48));
    w(&mut extension, 18, 0);
    bytes[2048 + 27 * 1024..2048 + 28 * 1024].copy_from_slice(&extension);
    bytes[mft_bitmap_offset() + 3] |= 8;
    sync_mirror(&mut bytes);
    let r = resources();
    let report = audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_records(), 20);
    assert_eq!(report.owned_clusters(), 337);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unused_framed_slots_ignore_stale_number_and_owner_but_live_slots_validate_number() {
    for stale in [0, u32::MAX] {
        let mut bytes = fixture();
        let mut unused = record(17, &[]);
        w(&mut unused, 22, 0);
        d(&mut unused, 44, stale);
        q(&mut unused, 32, u64::MAX);
        bytes[2048 + 17 * 1024..2048 + 18 * 1024].copy_from_slice(&unused);
        let r = resources();
        let report = audit_ntfs_resolved(
            Arc::new(Image::new(bytes)),
            read_limits(),
            stream_limits(),
            audit_limits(),
            &r,
        )
        .unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    let mut bytes = fixture();
    d(&mut bytes, 2048 + 26 * 1024 + 44, 0);
    let r = resources();
    let failure = audit_ntfs_resolved_detailed(
        Arc::new(Image::new(bytes)),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .err()
    .unwrap();
    assert_eq!(failure.error().kind, ErrorKind::InvalidData);
    if let Some(report) = failure.report() {
        assert!(!report.is_complete());
        assert!(report.free_ranges().is_empty());
    }
    drop(failure);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn volume_information_in_extension_is_resolved_during_audit_bootstrap() {
    let mut bytes = fixture();
    let list = [
        list_entry(0x30, "", 0, 3, 2),
        list_entry(0x70, "", 0, 28, 3),
    ]
    .concat();
    put(
        &mut bytes,
        3,
        &[
            resident(0x20, &list, 4),
            resident(0x30, &name_value("$Volume", 5), 2),
        ],
        false,
        1,
    );
    let mut information = vec![0; 12];
    information[8] = 3;
    information[9] = 1;
    let mut extension = record(28, &[resident(0x70, &information, 3)]);
    q(&mut extension, 32, 3 | (7 << 48));
    w(&mut extension, 18, 0);
    bytes[2048 + 28 * 1024..2048 + 29 * 1024].copy_from_slice(&extension);
    bytes[mft_bitmap_offset() + 3] |= 16;
    sync_mirror(&mut bytes);
    let source = Arc::new(Image::new(bytes));
    let r = resources();
    let report = audit_ntfs_resolved(
        source.clone(),
        read_limits(),
        stream_limits(),
        audit_limits(),
        &r,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_records(), 20);
    assert_eq!(report.owned_clusters(), 337);
    drop(report);
    assert_eq!(r.memory.used(), 0);
    let error = partmgr::fs_ntfs_audit::audit_ntfs(source, read_limits(), audit_limits(), &r)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(r.memory.used(), 0);
}
