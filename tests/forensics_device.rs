#![cfg(all(
    feature = "std",
    feature = "forensics",
    any(target_os = "linux", target_os = "windows")
))]
//! Native disposable-device qualification. Missing provisioning is a failure.
use partmgr::{
    forensics::{
        AcquisitionLease, ByteRange, NeverCancel, ScanLimits, SourceIdentity, StabilityProvider,
        StopReason,
    },
    forensics_fat::{FatForensics, FatOwnershipObservation, FatSlotKind},
    forensics_host::{self, HostSource},
    fs_core::{Budget, Cancellation, Resources},
    io::{self, ReadAt},
    partition::PartitionTable,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug)]
struct NativeLeaseRevoked;
impl std::fmt::Display for NativeLeaseRevoked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native disposable acquisition revoked after equivalence")
    }
}
impl std::error::Error for NativeLeaseRevoked {}

#[derive(Default)]
struct NativeDeviceLease(AtomicBool);
impl NativeDeviceLease {
    fn invalidate(&self) {
        self.0.store(true, Ordering::Release);
    }
}
impl StabilityProvider for NativeDeviceLease {
    fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                NativeLeaseRevoked,
            ))
        } else {
            Ok(())
        }
    }
}

fn assert_native_revocation_cause(error: &io::Error) {
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        if current.downcast_ref::<NativeLeaseRevoked>().is_some() {
            return;
        }
        if current.downcast_ref::<io::Error>().is_some_and(|error| {
            error
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<NativeLeaseRevoked>().is_some())
        }) {
            return;
        }
        cause = current.source();
    }
    panic!("native revocation sentinel missing from causal chain: {error}");
}

#[test]
#[ignore = "requires isolated native disposable device; use integration/forensics/native-*.{py,ps1}"]
fn native_fat_partition_equivalence_for_disposable_device() {
    let device = PathBuf::from(
        std::env::var_os("PARTMGR_TEST_DEVICE").expect("native disposable device required"),
    );
    let fixture = PathBuf::from(
        std::env::var_os("PARTMGR_TEST_RAW").expect("immutable raw fixture required"),
    );
    let sector: u32 = std::env::var("PARTMGR_TEST_SECTOR_SIZE")
        .expect("logical sector required")
        .parse()
        .unwrap();
    assert!([512, 4096].contains(&sector));
    let lease = Arc::new(AcquisitionLease::default());
    let physical_lease = Arc::new(NativeDeviceLease::default());
    let identity = |source: &str| SourceIdentity {
        acquisition: "private-disposable-closed-fixture".into(),
        source: source.into(),
        stability_provider: "private-directory-closed-file-readonly-device".into(),
    };
    let raw = forensics_host::open(
        HostSource::Raw(&fixture),
        identity("raw-artifact"),
        lease,
        Some(sector),
        None,
        vec![],
    )
    .unwrap();
    let physical = forensics_host::open(
        HostSource::Physical(&device),
        identity("native-device"),
        physical_lease.clone(),
        Some(sector),
        None,
        vec![],
    )
    .unwrap();
    assert_eq!(physical.logical_sector_size, sector);
    assert_eq!(physical.source.len(), 8 << 20);
    let raw_table = PartitionTable::read(Arc::new(raw.source.clone()), sector).unwrap();
    let device_table = PartitionTable::read(Arc::new(physical.source.clone()), sector).unwrap();
    assert_eq!(raw_table.partitions(), device_table.partitions());
    assert_eq!(raw_table.partitions()[0].first_lba, 8);
    assert_eq!(
        raw_table.partitions()[0].sectors * u64::from(sector),
        2880 * 512
    );
    let raw = raw.select_partition(1).unwrap();
    let physical = physical.select_partition(1).unwrap();
    assert_ne!(raw.source.identity(), physical.source.identity());
    assert_eq!(
        physical
            .source
            .translate_range(ByteRange {
                offset: 19 * 512,
                length: 32
            })
            .unwrap()
            .offset,
        8 * u64::from(sector) + 19 * 512
    );
    let raw_fat = FatForensics::open(raw.source).unwrap();
    let device_fat = FatForensics::open(physical.source).unwrap();
    assert_eq!(raw_fat.boot_sector(), device_fat.boot_sector());
    assert_eq!(device_fat.geometry().bytes_per_sector(), 512);
    let mut slot_sets = Vec::new();
    let mut allocation_sets = Vec::new();
    let mut owner_sets = Vec::new();
    for fat in [&raw_fat, &device_fat] {
        let mut slots = Vec::new();
        let outcome = fat
            .scan_directory_region(
                ByteRange {
                    offset: 19 * 512,
                    length: 160,
                },
                ScanLimits::default(),
                &NeverCancel,
                &mut |slot| {
                    slots.push(slot);
                    Ok(true)
                },
                &mut |_| Ok(()),
            )
            .with_coordinate_space(partmgr::forensics::CoordinateSpace::VolumeBytes);
        assert!(outcome.is_complete());
        assert_eq!(outcome.observations, 5);
        assert_eq!(slots[0].kind, FatSlotKind::File);
        assert_eq!(slots[1].kind, FatSlotKind::DeletedAlias);
        assert_eq!(slots[2].kind, FatSlotKind::Terminator);
        assert!(slots[3].post_terminator);
        assert!(slots[4].post_terminator);
        slot_sets.push(slots);
        let mut allocation = Vec::new();
        let outcome = fat.scan_allocation(
            ScanLimits::default(),
            &NeverCancel,
            &mut |entry| {
                allocation.push(entry);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(outcome.is_complete());
        allocation_sets.push(allocation);
        let resources = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let mut owners = Vec::new();
        let outcome = fat.scan_ownership(
            ScanLimits::default(),
            &resources,
            &NeverCancel,
            &mut |owner| {
                owners.push(owner);
                Ok(true)
            },
            &mut |_| Ok(()),
        );
        assert!(
            outcome.scan.is_complete() && outcome.namespace_complete && outcome.allocation_complete
        );
        assert!(
            owners
                .iter()
                .any(|owner| matches!(owner, FatOwnershipObservation::Owner { cluster: 2, .. }))
        );
        assert!(
            owners
                .iter()
                .any(|owner| matches!(owner, FatOwnershipObservation::Orphan { cluster: 4, .. }))
        );
        assert!(
            !owners.iter().any(|owner| matches!(
                owner,
                FatOwnershipObservation::Owner { cluster: 3 | 4, .. }
            ))
        );
        owner_sets.push(owners);
        let mut content = [0; 4];
        fat.source().read_exact_at(33 * 512, &mut content).unwrap();
        assert_eq!(&content, b"FAT!");
        let mut unaligned = [0; 513];
        fat.source()
            .read_exact_at(33 * 512 + 1, &mut unaligned)
            .unwrap();
        assert_eq!(&unaligned[..3], b"AT!");
        let mut untouched = [0xa5; 2];
        assert!(
            fat.source()
                .read_exact_at(fat.source().len() - 1, &mut untouched)
                .is_err()
        );
        assert_eq!(untouched, [0xa5; 2]);
    }
    // Source IDs identify backend views, so compare facts after explicitly
    // normalizing the comparison observation sets while retaining original identities.
    assert_ne!(slot_sets[0][0].source_id, slot_sets[1][0].source_id);
    assert_ne!(
        allocation_sets[0][0].source_id,
        allocation_sets[1][0].source_id
    );
    let baseline = raw_fat.source().id();
    for slots in &mut slot_sets {
        for slot in slots {
            slot.source_id = Some(baseline);
        }
    }
    for entries in &mut allocation_sets {
        for entry in entries {
            entry.source_id = baseline;
        }
    }
    for owners in &mut owner_sets {
        for owner in owners {
            match owner {
                FatOwnershipObservation::LiveAlias { source_id, .. }
                | FatOwnershipObservation::Owner { source_id, .. }
                | FatOwnershipObservation::CrossLink { source_id, .. }
                | FatOwnershipObservation::Orphan { source_id, .. }
                | FatOwnershipObservation::LengthMismatch { source_id, .. }
                | FatOwnershipObservation::InvalidChain { source_id, .. }
                | FatOwnershipObservation::MirrorDisagreement { source_id, .. } => {
                    *source_id = baseline
                }
            }
        }
    }
    assert_eq!(slot_sets[0], slot_sets[1]);
    assert_eq!(allocation_sets[0], allocation_sets[1]);
    assert_eq!(owner_sets[0], owner_sets[1]);
    // Keep the already acquired device source and its deferred clone alive.
    // Revocation must stop both direct reads and scans without reopening anything.
    let deferred = device_fat.source().clone();
    physical_lease.invalidate();
    let mut untouched = [0xa5; 4];
    let error = deferred
        .read_exact_at(33 * 512, &mut untouched)
        .unwrap_err();
    assert_native_revocation_cause(&error);
    assert_eq!(untouched, [0xa5; 4]);
    let requested = ByteRange {
        offset: 19 * 512,
        length: 160,
    };
    let mut failure_coverage = Vec::new();
    let outcome = device_fat.scan_directory_region(
        requested,
        ScanLimits::default(),
        &NeverCancel,
        &mut |_| panic!("revoked native source delivered an observation"),
        &mut |event| {
            failure_coverage.push(event);
            Ok(())
        },
    );
    assert_eq!(outcome.observations, 0);
    assert_eq!(outcome.coverage_events, 1);
    assert_eq!(failure_coverage.len(), 1);
    assert_eq!(
        failure_coverage[0].range,
        ByteRange {
            offset: requested.offset,
            length: 32
        }
    );
    assert!(matches!(
        failure_coverage[0].kind,
        partmgr::forensics::CoverageKind::Unreadable
    ));
    assert_eq!(outcome.unvisited, requested);
    assert_eq!(outcome.source_id, Some(deferred.id()));
    let StopReason::SourceStability(error) = outcome.stop_reason else {
        panic!("revoked native scan did not retain typed stability outcome");
    };
    assert_native_revocation_cause(&error);
    println!(
        "native FAT/partition equivalence passed: logical_sector={sector}; backends=raw,native-device; partition_lba=8; slots=5; FAT_copies=2; allocation_entries={}; owners={}; deferred_lease_revocation=typed-cause-preserved",
        allocation_sets[0].len(),
        owner_sets[0].len()
    );
}
