//! Opt-in interoperability gate for a quiescent Windows-created raw disk.
#![cfg(all(feature = "bitlocker", feature = "std", unix))]

use partmgr::{
    bitlocker::{BitLockerVolume, ErrorKind, Limits, MetadataSelection, RecoveryPassword},
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
    io::{self, DiskView, ReadAt},
};
use sha2::{Digest, Sha256};
use std::{fs::File, os::unix::fs::FileExt, sync::Arc};
use zeroize::Zeroizing;

struct RawDisk(File, u64);
impl ReadAt for RawDisk {
    fn len(&self) -> u64 {
        self.0.metadata().map_or(self.1, |m| m.len())
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        Ok(self.0.read_exact_at(out, offset)?)
    }
}
fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing native fixture setting {name}"))
}

#[test]
#[ignore = "requires quiescent Windows-created raw disk and private recovery credential"]
fn windows_recovery_unlock_and_native_file_hash() {
    let disk = File::open(setting("PARTMGR_BITLOCKER_DISK")).unwrap();
    let length = disk.metadata().unwrap().len();
    let offset: u64 = setting("PARTMGR_BITLOCKER_OFFSET").parse().unwrap();
    let volume_length: u64 = setting("PARTMGR_BITLOCKER_LENGTH").parse().unwrap();
    let source =
        Arc::new(DiskView::new(Arc::new(RawDisk(disk, length)), offset, volume_length).unwrap());
    let resources = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let inspected = BitLockerVolume::inspect(
        source,
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &resources,
    )
    .unwrap();
    let protectors: Vec<_> = inspected
        .protectors()
        .filter(|p| p.protection_type == 0x0800)
        .collect();
    assert_eq!(
        protectors.len(),
        1,
        "fixture must select exactly one recovery protector"
    );
    let secret = Zeroizing::new(
        std::fs::read_to_string(setting("PARTMGR_BITLOCKER_PASSWORD_FILE")).unwrap(),
    );
    let password = RecoveryPassword::parse(secret.trim()).unwrap();
    let reader = inspected
        .unlock_recovery(protectors[0].identifier, &password)
        .unwrap();
    let wrong =
        RecoveryPassword::parse("000000-000000-000000-000000-000000-000000-000000-000000").unwrap();
    match inspected.unlock_recovery(protectors[0].identifier, &wrong) {
        Err(error) => assert_eq!(error.kind, ErrorKind::AuthenticationFailed),
        Ok(_) => panic!("wrong recovery password unlocked native fixture"),
    }
    // Native reserved-area reads are invariant across the documented remount;
    // compare only boot relocation bytes and reserved spans, not changing MFT data.
    if let Ok(directory) = std::env::var("PARTMGR_BITLOCKER_SECTORS_DIR") {
        let provenance = reader.provenance();
        let mut spans = vec![(0, provenance.relocated_boot_length)];
        spans.extend(provenance.metadata_offsets.map(|offset| (offset, 65536)));
        spans.push((
            provenance.relocated_boot_offset,
            provenance.relocated_boot_length,
        ));
        if let Some(region) = provenance.additional_reserved_region {
            spans.push(region);
        }
        for (offset, length) in spans {
            assert!(length <= 65536, "bounded native sample");
            let expected =
                std::fs::read(std::path::Path::new(&directory).join(format!("{offset}.bin")))
                    .unwrap();
            let mut actual = Zeroizing::new(vec![0; length as usize]);
            reader.read_exact_at(offset, &mut actual).unwrap();
            assert_eq!(
                actual.as_slice(),
                &expected[..length as usize],
                "native mapped range {offset}"
            );
        }
    }
    let ntfs = NtfsVolume::open(
        Arc::new(reader),
        NtfsReadLimits {
            attributes: 128,
            runs: 4096,
            names: 16,
        },
        &resources,
    )
    .unwrap();
    let root = ntfs.root_identity(&resources).unwrap();
    let directory = ntfs
        .directory(
            &root,
            NtfsDirectoryLimits {
                blocks: 1024,
                entries: 4096,
                depth: 32,
            },
            &resources,
        )
        .unwrap();
    let name = NativeName::Utf16(setting("PARTMGR_BITLOCKER_FILE").encode_utf16().collect());
    let entry = directory
        .entries()
        .iter()
        .find(|e| e.name == name)
        .expect("native oracle file in root directory");
    let file = ntfs.open_object(&entry.identity, &resources).unwrap();
    let mut hasher = Sha256::new();
    let mut scratch = Zeroizing::new(vec![0u8; 65536]);
    let mut position = 0;
    while position < file.len() {
        let n = file.read_at(position, &mut scratch, &resources).unwrap();
        assert_ne!(n, 0);
        hasher.update(&scratch[..n]);
        position += n as u64;
    }
    let actual = format!("{:x}", hasher.finalize());
    assert_eq!(
        actual,
        setting("PARTMGR_BITLOCKER_SHA256").to_ascii_lowercase()
    );
}
