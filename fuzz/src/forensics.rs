use partmgr::{
    forensics::{
        AcquisitionLease, ByteRange, ForensicSource, NeverCancel, ScanLimits, SourceIdentity,
    },
    forensics_fat::FatForensics,
    forensics_ntfs, forensics_time,
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
};
use std::sync::Arc;

#[derive(Default, Debug, Clone, Copy)]
pub struct ObservedProfiles {
    pub fat_slots: u64,
    pub fat_entries: u64,
    pub mft_slots: u64,
    pub file_records: u64,
    pub usn_records: u64,
}

pub fn run(data: &[u8]) -> ObservedProfiles {
    let mut observed = ObservedProfiles::default();
    if data.len() > 1 << 20 {
        return observed;
    }
    let resources = Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = ScanLimits {
        records: 16,
        read_bytes: 128 << 10,
        output_bytes: 128 << 10,
        memory_bytes: 1 << 20,
    };
    {
        let source = ForensicSource::new(
            Arc::new(super::Bytes(data.to_vec())),
            SourceIdentity {
                acquisition: "fuzz owned immutable bytes".into(),
                source: "input".into(),
                stability_provider: "owned allocation".into(),
            },
            Arc::new(AcquisitionLease::default()),
            ByteRange {
                offset: 0,
                length: data.len() as u64,
            },
            vec![],
        )
        .unwrap();
        if let Ok(fat) = FatForensics::open(source.clone()) {
            let _ = fat.scan_fat_copy_differences(
                limits,
                &resources,
                &NeverCancel,
                &mut |_| Ok(true),
                &mut |_| Ok(()),
            );
            let _ = fat.scan_fat_copy_chains(
                2,
                16,
                limits,
                &resources,
                &NeverCancel,
                &mut |_| Ok(true),
                &mut |_| Ok(()),
            );
            let _ = fat.scan_allocation(
                limits,
                &NeverCancel,
                &mut |_| {
                    observed.fat_entries += 1;
                    Ok(true)
                },
                &mut |_| Ok(()),
            );
            let offset = fat.geometry().root_offset().unwrap_or(0);
            let length = fat.geometry().root_bytes().min(16 * 32);
            let _ = fat.scan_directory_region(
                ByteRange { offset, length },
                limits,
                &NeverCancel,
                &mut |_| {
                    observed.fat_slots += 1;
                    Ok(true)
                },
                &mut |_| Ok(()),
            );
        }
        let inventory = forensics_ntfs::inventory(
            &source,
            NtfsReadLimits {
                attributes: 16,
                runs: 16,
                names: 8,
            },
            NtfsStreamLimits {
                extension_records: 8,
                list_entries: 32,
                list_bytes: 4096,
                attributes: 32,
                runs: 32,
                work: 8192,
            },
            limits,
            &NeverCancel,
            &resources,
            |_| Ok(true),
        );
        observed.mft_slots = inventory.observations;
        if data.len() >= 512 {
            let mut raw = data[..data.len().min(4096) / 512 * 512].to_vec();
            if matches!(
                forensics_ntfs::decode_record(&mut raw, 16, &resources),
                Ok(Some(_))
            ) {
                observed.file_records += 1;
            }
        }
        let usn_limits = partmgr::fs_ntfs_usn::RecordLimits {
            record_bytes: 4096,
            name_units: 64,
        };
        if partmgr::fs_ntfs_usn::decode_record(
            data,
            partmgr::fs_ntfs_usn::Provenance {
                evidence_id: [0; 32],
                offset: 0,
            },
            usn_limits,
        )
        .is_ok()
        {
            observed.usn_records += 1;
        }
        let _ = partmgr::forensics_journal::decode_max(data);
        if let Some(raw) = data.get(..8) {
            let _ = forensics_time::filetime(raw.try_into().unwrap());
        }
        if let Some(raw) = data.get(..5) {
            let _ = forensics_time::fat_created(raw.try_into().unwrap(), None);
        }
        if let Some(raw) = data.get(..4) {
            let _ = forensics_time::fat_modified(raw.try_into().unwrap(), Some(3600));
        }
        if let Some(raw) = data.get(..2) {
            let _ = forensics_time::fat_accessed(raw.try_into().unwrap(), Some(0));
        }
    }
    assert_eq!(resources.memory.used(), 0);
    observed
}

#[cfg(test)]
mod tests {
    #[test]
    fn independent_seeds_and_truncations_refund_resources() {
        let mut profiles = super::ObservedProfiles::default();
        for data in crate::seeds("forensics") {
            let seen = super::run(&data);
            profiles.fat_slots += seen.fat_slots;
            profiles.fat_entries += seen.fat_entries;
            profiles.mft_slots += seen.mft_slots;
            profiles.file_records += seen.file_records;
            profiles.usn_records += seen.usn_records;
            for length in [0, 31, 511, 1023] {
                super::run(&data[..data.len().min(length)]);
            }
        }
        assert!(
            profiles.fat_slots > 0 && profiles.fat_entries > 0,
            "{profiles:?}"
        );
        assert!(
            profiles.mft_slots > 0 && profiles.file_records > 0,
            "{profiles:?}"
        );
        assert!(profiles.usn_records > 0, "{profiles:?}");
    }
}
