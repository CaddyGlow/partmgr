//! Opt-in ciphertext-write gate on a fresh copy of a quiescent fixed VHD.
//!
//! In addition to the settings documented by `bitlocker_native.rs`, supply:
//! - `PARTMGR_BITLOCKER_WRITE_OUTPUT`: a nonexistent output VHD path.
//! - `PARTMGR_BITLOCKER_WRITE_OFFSET`: decimal volume-relative logical byte
//!   offset corresponding to byte 123 of the oracle file, established independently
//!   with Windows `fsutil file queryextents` and filesystem cluster geometry.
//!
//! The test writes 32 bytes of 0xA7 and prints the expected modified file SHA-256.
//! It creates `<output>.undo` independently with create-new semantics. The original
//! VHD is opened read-only. Windows must independently mount/unlock the resulting
//! VHD, compare the printed file hash and run its consistency checks; this host
//! test alone does not establish native write qualification.
#![cfg(all(feature = "bitlocker-write", feature = "std", unix))]

use partmgr::{
    bitlocker::{BitLockerVolume, Limits, MetadataSelection, RecoveryPassword},
    bitlocker_write::{BitLockerSession, SessionOptions},
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
    fs_undo::{UndoLimits, UndoState},
    io::{self, DiskView, ReadAt},
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const FILE_OFFSET: u64 = 123;
const PATCH: [u8; 32] = [0xa7; 32];

struct RawDisk(File, u64);
impl ReadAt for RawDisk {
    fn len(&self) -> u64 {
        self.0.metadata().map_or(self.1, |metadata| metadata.len())
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        Ok(self.0.read_exact_at(bytes, offset)?)
    }
}

struct OwnedFile {
    file: File,
    start: u64,
    length: u64,
    container_length: u64,
}
impl OwnedFile {
    fn position(&self, offset: u64, count: usize) -> io::Result<u64> {
        if self.file.metadata()?.len() != self.container_length
            || offset
                .checked_add(count as u64)
                .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.start
            .checked_add(offset)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
}
impl Storage for OwnedFile {
    fn len(&self) -> io::Result<u64> {
        self.position(0, 0)?;
        Ok(self.length)
    }
    fn read_exact_at(&self, at: u64, bytes: &mut [u8]) -> io::Result<()> {
        Ok(self
            .file
            .read_exact_at(bytes, self.position(at, bytes.len())?)?)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        Ok(self.file.write_at(bytes, self.position(at, bytes.len())?)?)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(self.file.sync_all()?)
    }
}
fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing native fixture setting {name}"))
}

#[test]
#[ignore = "requires Windows extent evidence and a fresh fixed-VHD output path"]
fn windows_oracle_ciphertext_replacement_on_exclusive_copy() {
    let input = PathBuf::from(setting("PARTMGR_BITLOCKER_DISK"));
    let output = PathBuf::from(setting("PARTMGR_BITLOCKER_WRITE_OUTPUT"));
    assert_ne!(input, output);
    let start: u64 = setting("PARTMGR_BITLOCKER_OFFSET").parse().unwrap();
    let length: u64 = setting("PARTMGR_BITLOCKER_LENGTH").parse().unwrap();
    let patch_at: u64 = setting("PARTMGR_BITLOCKER_WRITE_OFFSET").parse().unwrap();
    let resources = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let secret = Zeroizing::new(
        std::fs::read_to_string(setting("PARTMGR_BITLOCKER_PASSWORD_FILE")).unwrap(),
    );
    let password = RecoveryPassword::parse(secret.trim()).unwrap();
    let disk = File::open(&input).unwrap();
    let container_length = disk.metadata().unwrap().len();
    assert!(container_length >= 512, "truncated fixed VHD");
    assert!(
        start
            .checked_add(length)
            .is_some_and(|end| end <= container_length - 512)
    );
    let mut footer = [0; 512];
    disk.read_exact_at(&mut footer, container_length - 512)
        .unwrap();
    assert_eq!(
        &footer[..8],
        b"conectix",
        "native write gate requires a fixed VHD"
    );
    assert_eq!(
        u32::from_be_bytes(footer[60..64].try_into().unwrap()),
        2,
        "dynamic VHD is not a raw fixed mapping"
    );
    let source =
        Arc::new(DiskView::new(Arc::new(RawDisk(disk, container_length)), start, length).unwrap());
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
    assert_eq!(protectors.len(), 1);
    let protector = protectors[0].identifier;
    let reader = Arc::new(inspected.unlock_recovery(protector, &password).unwrap());
    let mut volume_bytes = Zeroizing::new([0; 32]);
    reader
        .read_exact_at(patch_at, &mut volume_bytes[..])
        .unwrap();
    let ntfs = NtfsVolume::open(
        reader,
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
        .find(|entry| entry.name == name)
        .expect("native oracle file");
    let file = ntfs.open_object(&entry.identity, &resources).unwrap();
    assert!(file.len() >= FILE_OFFSET + PATCH.len() as u64);
    let mut original = Sha256::new();
    let mut expected = Sha256::new();
    let mut scratch = Zeroizing::new(vec![0; 65536]);
    let mut position = 0;
    let mut extent_bytes = Zeroizing::new([0u8; 32]);
    while position < file.len() {
        let n = file.read_at(position, &mut scratch, &resources).unwrap();
        assert_ne!(n, 0);
        original.update(&scratch[..n]);
        let lo = position.max(FILE_OFFSET);
        let hi = (position + n as u64).min(FILE_OFFSET + PATCH.len() as u64);
        if lo < hi {
            let chunk = (lo - position) as usize..(hi - position) as usize;
            let patch = (lo - FILE_OFFSET) as usize..(hi - FILE_OFFSET) as usize;
            extent_bytes[patch.clone()].copy_from_slice(&scratch[chunk.clone()]);
            scratch[chunk].copy_from_slice(&PATCH[patch]);
        }
        expected.update(&scratch[..n]);
        position += n as u64;
    }
    assert_eq!(
        format!("{:x}", original.finalize()),
        setting("PARTMGR_BITLOCKER_SHA256").to_ascii_lowercase()
    );
    assert_eq!(
        *volume_bytes, *extent_bytes,
        "Windows extent offset disagrees with oracle file byte 123"
    );
    let expected_hash = format!("{:x}", expected.finalize());
    drop(file);
    drop(directory);
    drop(ntfs);
    drop(inspected);

    // create_new prevents replacement of either the original or earlier evidence.
    let mut target_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    let mut input_file = File::open(&input).unwrap();
    assert_eq!(
        std::io::copy(&mut input_file, &mut target_file).unwrap(),
        container_length
    );
    target_file.sync_all().unwrap();
    let mut journal_path = output.as_os_str().to_os_string();
    journal_path.push(".undo");
    let journal_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&journal_path)
        .unwrap();
    journal_file.set_len(1 << 20).unwrap();
    journal_file.sync_all().unwrap();
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent).unwrap().sync_all().unwrap();
    let target = OwnedFile {
        file: target_file,
        start,
        length,
        container_length,
    };
    let journal = OwnedFile {
        file: journal_file,
        start: 0,
        length: 1 << 20,
        container_length: 1 << 20,
    };
    let mut identity = Sha256::new();
    identity.update(b"partmgr native write isolated output v1");
    identity.update(output.as_os_str().as_encoded_bytes());
    identity.update(start.to_le_bytes());
    identity.update(length.to_le_bytes());
    let options = SessionOptions {
        selection: MetadataSelection::RequireAgreement,
        limits: Limits::default(),
        undo_limits: UndoLimits::default(),
        volume: identity.finalize().into(),
        generation: 1,
    };
    let mut session =
        BitLockerSession::open_recovery(target, journal, options, protector, &password, &resources)
            .unwrap();
    let plan = session.plan_replace(patch_at, &PATCH, [1; 16]).unwrap();
    assert_eq!(session.commit(plan).unwrap().state, UndoState::Committed);
    let (target, journal) = session.into_parts();
    let mut footer_after = [0; 512];
    target
        .file
        .read_exact_at(&mut footer_after, container_length - 512)
        .unwrap();
    assert_eq!(footer_after, footer);
    target.file.sync_all().unwrap();
    journal.file.sync_all().unwrap();
    println!("PARTMGR_BITLOCKER_WRITE_EXPECTED_SHA256={expected_hash}");
    println!("PARTMGR_BITLOCKER_WRITE_FILE_OFFSET={FILE_OFFSET}");
    println!("PARTMGR_BITLOCKER_WRITE_OFFSET={patch_at}");
    println!("PARTMGR_BITLOCKER_WRITE_BYTES={}", PATCH.len());
    println!("PARTMGR_BITLOCKER_WRITE_OUTPUT={}", output.display());
}
