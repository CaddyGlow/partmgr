#![cfg(feature = "bitlocker")]

use partmgr::{
    bitlocker::{
        self, BitLockerVolume, Candidate, CopyStatus, ErrorKind, KeyEvidence, Limits,
        MetadataSelection, RecoveryPassword,
    },
    fs_core::{Budget, Cancellation, Resources},
    io::{self, ReadAt},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_fixture;
#[path = "fixtures/bitlocker_vectors.rs"]
mod vectors;

const LENGTH: usize = 1 << 20;
const OFFSETS: [usize; 3] = [0x50000, 0x60000, 0x70000];
const BOOT: usize = 0x40000;
const RECOVERY_ID: [u8; 16] = [0x11; 16];
const CLEAR_ID: [u8; 16] = [0x22; 16];
const PASSWORD: &str = "110000-110011-110022-110033-110044-110055-110066-110077";
const FULL_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 1,
];

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn w(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn q(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn crc(b: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &v in b {
        crc ^= u32::from(v);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
fn entry(kind: u16, value: u16, body: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 8 + body.len()];
    let n = b.len();
    w(&mut b, 0, n as u16);
    w(&mut b, 2, kind);
    w(&mut b, 4, value);
    w(&mut b, 6, 1);
    b[8..].copy_from_slice(body);
    b
}
fn protector(id: [u8; 16], kind: u16, properties: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 28];
    b[..16].copy_from_slice(&id);
    w(&mut b, 26, kind);
    for p in properties {
        b.extend_from_slice(p);
    }
    entry(2, 8, &b)
}
fn fixture(method: u16, sector_size: u16) -> Vec<u8> {
    let mut stretch = vec![0; 20];
    d(&mut stretch, 0, 0x1000);
    stretch[4..].copy_from_slice(&(16..32).collect::<Vec<u8>>());
    let mut clear = vec![0; 36];
    d(&mut clear, 0, 0x2000);
    clear[4..].copy_from_slice(&(64..96).collect::<Vec<u8>>());
    let mut entries = protector(
        RECOVERY_ID,
        0x0800,
        &[
            entry(0, 3, &stretch),
            entry(0, 5, &hex(vectors::RECOVERY_VMK)),
        ],
    );
    entries.extend(protector(
        CLEAR_ID,
        0,
        &[entry(0, 1, &clear), entry(0, 5, &hex(vectors::CLEAR_VMK))],
    ));
    let fvek = if method == 0x8004 {
        vectors::XTS128_FVEK
    } else {
        vectors::XTS256_FVEK
    };
    entries.extend(entry(3, 5, &hex(fvek)));
    let dataset_size = 48 + entries.len();
    let block_size = (64 + dataset_size).next_multiple_of(16);
    let mut metadata = vec![0; block_size + 8];
    metadata[..8].copy_from_slice(b"-FVE-FS-");
    w(&mut metadata, 8, (block_size / 16) as u16);
    w(&mut metadata, 10, 2);
    w(&mut metadata, 12, 4);
    w(&mut metadata, 14, 4);
    q(&mut metadata, 16, LENGTH as u64);
    d(&mut metadata, 28, 1);
    for (i, &at) in OFFSETS.iter().enumerate() {
        q(&mut metadata, 32 + 8 * i, at as u64);
    }
    q(&mut metadata, 56, BOOT as u64);
    d(&mut metadata, 64, dataset_size as u32);
    d(&mut metadata, 68, 1);
    d(&mut metadata, 72, 48);
    d(&mut metadata, 76, dataset_size as u32);
    metadata[80..96].fill(0x33);
    d(&mut metadata, 100, u32::from(method));
    metadata[112..112 + entries.len()].copy_from_slice(&entries);
    w(&mut metadata, block_size, 8);
    w(&mut metadata, block_size + 2, 1);
    let checksum = crc(&metadata[..block_size]);
    d(&mut metadata, block_size + 4, checksum);
    let mut image = vec![0; LENGTH];
    image[3..11].copy_from_slice(b"-FVE-FS-");
    w(&mut image, 11, sector_size);
    image[160..176].copy_from_slice(&FULL_GUID);
    for (i, &at) in OFFSETS.iter().enumerate() {
        q(&mut image, 176 + 8 * i, at as u64);
        image[at..at + metadata.len()].copy_from_slice(&metadata);
    }
    w(&mut image, 510, 0xaa55);
    let (boot, data) = match (method, sector_size) {
        (0x8004, 512) => (vectors::XTS128_512_BOOT, vectors::XTS128_512_DATA),
        (0x8005, 512) => (vectors::XTS256_512_BOOT, vectors::XTS256_512_DATA),
        (0x8004, 4096) => (vectors::XTS128_4096_BOOT, vectors::XTS128_4096_DATA),
        (0x8005, 4096) => (vectors::XTS256_4096_BOOT, vectors::XTS256_4096_DATA),
        _ => unreachable!(),
    };
    image[BOOT..BOOT + usize::from(sector_size)].copy_from_slice(&hex(boot));
    image[0x2000..0x2000 + usize::from(sector_size)].copy_from_slice(&hex(data));
    image
}
fn mutate(image: &mut [u8], copy: usize, f: impl FnOnce(&mut [u8])) {
    let at = OFFSETS[copy];
    let size = usize::from(word(image, at + 8)) * 16;
    f(&mut image[at..at + size]);
    let checksum = crc(&image[at..at + size]);
    d(image, at + size + 4, checksum);
}
struct Image {
    data: Vec<u8>,
    length: AtomicU64,
    failure: AtomicU64,
    calls: AtomicU64,
}
impl Image {
    fn new(data: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(data.len() as u64),
            data,
            failure: AtomicU64::new(u64::MAX),
            calls: AtomicU64::new(0),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if at >= self.failure.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected failure"));
        }
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.data
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn inspect(image: Vec<u8>, r: &Resources) -> BitLockerVolume {
    BitLockerVolume::inspect(
        Arc::new(Image::new(image)),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        r,
    )
    .unwrap()
}
fn kind<T>(r: bitlocker::Result<T>) -> ErrorKind {
    match r {
        Err(e) => e.kind,
        Ok(_) => panic!("expected failure"),
    }
}
fn plaintext(size: usize, boot: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
    if boot {
        bytes[3..11].copy_from_slice(b"NTFS    ");
        w(&mut bytes, 11, size as u16);
        w(&mut bytes, 510, 0xaa55);
    }
    bytes
}

#[test]
fn numerical_password_checks_groups_before_derivation() {
    assert!(RecoveryPassword::parse(PASSWORD).is_ok());
    for password in [
        "",
        "000000-000000",
        "110001-110011-110022-110033-110044-110055-110066-110077",
        "999999-110011-110022-110033-110044-110055-110066-110077",
        "110000 110011-110022-110033-110044-110055-110066-110077",
    ] {
        assert_eq!(
            kind(RecoveryPassword::parse(password)),
            ErrorKind::InvalidCredential
        );
    }
}

#[test]
fn recovery_unlock_matches_independent_key_chain_and_sector_vectors() {
    let r = resources();
    let volume = inspect(fixture(0x8004, 512), &r);
    assert_eq!(volume.protectors().count(), 2);
    let reader = volume
        .unlock_recovery(RECOVERY_ID, &RecoveryPassword::parse(PASSWORD).unwrap())
        .unwrap();
    assert_eq!(reader.key_evidence(), KeyEvidence::AuthenticatedKeyRecord);
    drop(volume);
    let mut boot = [0; 512];
    reader.read_exact_at(0, &mut boot).unwrap();
    assert_eq!(boot.as_slice(), plaintext(512, true));
    assert!(r.memory.used() > 0);
    drop(reader);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn clear_and_supplied_keys_read_both_xts_methods_and_sector_sizes() {
    for method in [0x8004, 0x8005] {
        for size in [512, 4096] {
            let r = resources();
            let volume = inspect(fixture(method, size), &r);
            let clear = volume.unlock_clear(CLEAR_ID).unwrap();
            let vmk = volume.unlock_vmk(&(160..192).collect::<Vec<u8>>()).unwrap();
            let raw = volume
                .unlock_fvek(&(0..if method == 0x8004 { 32 } else { 64 }).collect::<Vec<u8>>())
                .unwrap();
            assert_eq!(raw.key_evidence(), KeyEvidence::CallerSupplied);
            for reader in [&clear, &vmk, &raw] {
                for (at, expected) in [
                    (0, plaintext(size.into(), true)),
                    (0x2000, plaintext(size.into(), false)),
                ] {
                    let mut out = vec![0; size.into()];
                    reader.read_exact_at(at, &mut out).unwrap();
                    assert_eq!(out, expected);
                    let mut slice = [0; 31];
                    reader.read_exact_at(at + 17, &mut slice).unwrap();
                    assert_eq!(slice.as_slice(), &expected[17..48]);
                }
            }
            assert_eq!(bitlocker::probe(&raw, &r).unwrap(), Candidate::Unrecognized);
        }
    }
}

#[test]
fn mapping_zeros_reserved_regions_and_handles_cross_sector_reads() {
    let volume = inspect(fixture(0x8004, 512), &resources());
    let reader = volume.unlock_clear(CLEAR_ID).unwrap();
    for at in [
        BOOT,
        OFFSETS[0],
        OFFSETS[1],
        OFFSETS[2],
        OFFSETS[2] + 65_536 - 512,
    ] {
        let mut out = [0xff; 512];
        reader.read_exact_at(at as u64, &mut out).unwrap();
        assert_eq!(out, [0; 512]);
    }
    let mut out = [0xff; 64];
    reader
        .read_exact_at((OFFSETS[0] + 65_536 - 32) as u64, &mut out)
        .unwrap();
    assert_eq!(&out[..32], &[0; 32]);
    assert_eq!(&out[32..], &[0; 32]); // Adjacent second metadata region.
    reader.read_exact_at(LENGTH as u64, &mut []).unwrap();
    assert_eq!(
        reader
            .read_exact_at(LENGTH as u64 + 1, &mut [])
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        reader.read_exact_at(u64::MAX, &mut [0]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        reader
            .read_exact_at(LENGTH as u64 - 1, &mut [0; 2])
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn wrapper_uses_volume_relative_tweaks_at_nonzero_partition_start() {
    let prefix = 12_345;
    let mut disk = vec![0; prefix];
    disk.extend(fixture(0x8005, 512));
    disk.extend([0; 1024]);
    let view = partmgr::io::DiskView::new(Arc::new(Image::new(disk)), prefix as u64, LENGTH as u64)
        .unwrap();
    let volume = BitLockerVolume::inspect(
        Arc::new(view),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &resources(),
    )
    .unwrap();
    let reader = volume.unlock_clear(CLEAR_ID).unwrap();
    let mut out = [0; 512];
    reader.read_exact_at(0, &mut out).unwrap();
    assert_eq!(out.as_slice(), plaintext(512, true));
}

#[test]
fn metadata_conflict_requires_explicit_copy_selection() {
    let mut bytes = fixture(0x8004, 512);
    mutate(&mut bytes, 1, |b| b[80] ^= 1);
    assert_eq!(
        kind(BitLockerVolume::inspect(
            Arc::new(Image::new(bytes.clone())),
            MetadataSelection::RequireAgreement,
            Limits::default(),
            &resources()
        )),
        ErrorKind::AmbiguousMetadata
    );
    let volume = BitLockerVolume::inspect(
        Arc::new(Image::new(bytes)),
        MetadataSelection::Copy(1),
        Limits::default(),
        &resources(),
    )
    .unwrap();
    assert_eq!(volume.info().selected_copy, 1);
    assert_eq!(volume.info().identifier[0], 0x32);
}

#[test]
fn crc_invalid_copy_is_reported_and_cannot_be_explicitly_selected() {
    let mut bytes = fixture(0x8004, 512);
    bytes[OFFSETS[0] + 100] ^= 1;
    let volume = inspect(bytes.clone(), &resources());
    assert_eq!(
        volume.info().copies[0],
        CopyStatus::Rejected(ErrorKind::InvalidData)
    );
    assert_eq!(volume.info().selected_copy, 1);
    assert_eq!(
        kind(BitLockerVolume::inspect(
            Arc::new(Image::new(bytes)),
            MetadataSelection::Copy(0),
            Limits::default(),
            &resources()
        )),
        ErrorKind::InvalidData
    );
}

#[test]
fn malformed_and_unsupported_metadata_never_create_reader() {
    for edit in [
        |b: &mut [u8]| w(b, 112, 7),
        |b: &mut [u8]| d(b, 64, u32::MAX),
        |b: &mut [u8]| q(b, 32, 0),
    ] {
        let mut bytes = fixture(0x8004, 512);
        mutate(&mut bytes, 0, edit);
        let r = resources();
        assert_eq!(
            kind(BitLockerVolume::inspect(
                Arc::new(Image::new(bytes)),
                MetadataSelection::Copy(0),
                Limits::default(),
                &r
            )),
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), 0);
    }
    for (state, method) in [(2, 0x8004), (5, 0x8004), (4, 0x8000)] {
        let mut bytes = fixture(0x8004, 512);
        for i in 0..3 {
            mutate(&mut bytes, i, |b| {
                w(b, 12, state);
                w(b, 100, method);
            });
        }
        let volume = inspect(bytes, &resources());
        assert_eq!(kind(volume.unlock_clear(CLEAR_ID)), ErrorKind::Unsupported);
    }
    let mut bytes = fixture(0x8004, 512);
    bytes[160..176].copy_from_slice(&[
        0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae,
        0xd8,
    ]);
    assert_eq!(
        kind(inspect(bytes, &resources()).unlock_clear(CLEAR_ID)),
        ErrorKind::Unsupported
    );
}

#[test]
fn key_authentication_refuses_wrong_vmk_and_altered_fvek() {
    let volume = inspect(fixture(0x8004, 512), &resources());
    assert_eq!(
        kind(volume.unlock_vmk(&[0; 32])),
        ErrorKind::AuthenticationFailed
    );
    assert_eq!(
        kind(volume.unlock_vmk(&[0; 31])),
        ErrorKind::InvalidCredential
    );
    assert_eq!(
        kind(volume.unlock_fvek(&[0; 64])),
        ErrorKind::InvalidCredential
    );
    assert_eq!(
        kind(volume.unlock_clear([0; 16])),
        ErrorKind::ProtectorNotFound
    );
    assert_eq!(
        kind(volume.unlock_clear(RECOVERY_ID)),
        ErrorKind::Unsupported
    );
    let mut bytes = fixture(0x8004, 512);
    for i in 0..3 {
        mutate(&mut bytes, i, |b| {
            let n = u32::from_le_bytes(b[64..68].try_into().unwrap()) as usize + 64;
            b[n - 1] ^= 1;
        });
    }
    assert_eq!(
        kind(inspect(bytes, &resources()).unlock_vmk(&(160..192).collect::<Vec<u8>>())),
        ErrorKind::AuthenticationFailed
    );
}

#[test]
fn source_changes_cancellation_and_backend_errors_survive_deferred_reads() {
    let source = Arc::new(Image::new(fixture(0x8004, 512)));
    let r = resources();
    let volume = BitLockerVolume::inspect(
        source.clone(),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &r,
    )
    .unwrap();
    let reader = volume.unlock_clear(CLEAR_ID).unwrap();
    source.length.store(1, Ordering::Relaxed);
    let error = reader.read_exact_at(0, &mut [0]).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<bitlocker::Error>()
            .unwrap()
            .kind,
        ErrorKind::SourceChanged
    );
    source.length.store(LENGTH as u64, Ordering::Relaxed);
    source.failure.store(BOOT as u64, Ordering::Relaxed);
    let error = reader.read_exact_at(0, &mut [0]).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<bitlocker::Error>()
            .unwrap()
            .kind,
        ErrorKind::Io
    );
    r.cancellation.cancel();
    assert_eq!(kind(volume.unlock_clear(CLEAR_ID)), ErrorKind::Cancelled);
    assert!(reader.read_exact_at(0, &mut []).is_err());
}

#[test]
fn resource_limits_refuse_work_and_release_all_reservations() {
    let source = Arc::new(Image::new(fixture(0x8004, 512)));
    for limits in [
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
        Limits {
            max_metadata_bytes: 128,
            ..Limits::default()
        },
        Limits {
            max_read_bytes: 511,
            ..Limits::default()
        },
    ] {
        let r = resources();
        assert_eq!(
            kind(BitLockerVolume::inspect(
                source.clone(),
                MetadataSelection::RequireAgreement,
                limits,
                &r
            )),
            ErrorKind::ResourceLimit
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let volume = BitLockerVolume::inspect(
        source.clone(),
        MetadataSelection::RequireAgreement,
        Limits {
            max_kdf_iterations: 0,
            ..Limits::default()
        },
        &r,
    )
    .unwrap();
    let before = r.memory.used();
    assert_eq!(
        kind(volume.unlock_recovery(RECOVERY_ID, &RecoveryPassword::parse(PASSWORD).unwrap())),
        ErrorKind::ResourceLimit
    );
    assert_eq!(r.memory.used(), before);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    r.cancellation.cancel();
    let calls = source.calls.load(Ordering::Relaxed);
    assert_eq!(
        kind(BitLockerVolume::inspect(
            source.clone(),
            MetadataSelection::RequireAgreement,
            Limits::default(),
            &r
        )),
        ErrorKind::Cancelled
    );
    assert_eq!(source.calls.load(Ordering::Relaxed), calls);
}

#[test]
fn decrypted_reader_is_concurrent_without_shared_seek_or_scratch() {
    let reader = Arc::new(
        inspect(fixture(0x8005, 4096), &resources())
            .unlock_clear(CLEAR_ID)
            .unwrap(),
    );
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let reader = reader.clone();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let mut bytes = [0; 4096];
                    reader.read_exact_at(0x2000, &mut bytes).unwrap();
                    assert_eq!(bytes.as_slice(), plaintext(4096, false));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn encrypted_reader_feeds_existing_ntfs_and_filesystem_dispatch() {
    use aes::{Aes128, cipher::KeyInit};
    use partmgr::{
        fs_core::FileRead,
        fs_ntfs::{NtfsReadLimits, NtfsVolume},
    };
    use xts_mode::Xts128;
    let plain = ntfs_fixture::ntfs_audit_seed();
    let mut image = fixture(0x8004, 512);
    let key: Vec<u8> = (0..32).collect();
    let cipher = Xts128::new(Aes128::new(key[..16].into()), Aes128::new(key[16..].into()));
    // Synthetic integration fixture. Crypto correctness has separate independent vectors.
    // Only sectors inside the declared inner NTFS volume matter to this test.
    for (number, sector) in plain.chunks_exact(512).enumerate().take(512) {
        let logical = number * 512;
        let physical = if number == 0 { BOOT } else { logical };
        image[physical..physical + 512].copy_from_slice(sector);
        cipher.encrypt_sector(
            &mut image[physical..physical + 512],
            ((physical / 512) as u128).to_le_bytes(),
        );
    }
    let r = resources();
    let reader: Arc<dyn ReadAt> = Arc::new(inspect(image, &r).unlock_clear(CLEAR_ID).unwrap());
    let candidates = partmgr::fs_image::probe(reader.as_ref(), &r).unwrap();
    assert!(candidates.contains(&partmgr::fs_image::ReadFormat::Ntfs));
    let ntfs = NtfsVolume::open(
        reader,
        NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        &r,
    )
    .unwrap();
    let file = ntfs.open_file(24, &r).unwrap();
    let mut bytes = vec![0; file.len() as usize];
    assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), bytes.len());
    assert_eq!(bytes, b"hello");
}

#[test]
fn wrong_recovery_password_fails_authentication_and_refunds_scratch() {
    let r = resources();
    let volume = inspect(fixture(0x8004, 512), &r);
    let before = r.memory.used();
    let password =
        RecoveryPassword::parse("000000-000000-000000-000000-000000-000000-000000-000000").unwrap();
    assert_eq!(
        kind(volume.unlock_recovery(RECOVERY_ID, &password)),
        ErrorKind::AuthenticationFailed
    );
    assert_eq!(r.memory.used(), before);
}

#[test]
fn tpm_protectors_are_inspectable_but_not_treated_as_recovery_keys() {
    let mut bytes = fixture(0x8004, 512);
    for i in 0..3 {
        mutate(&mut bytes, i, |b| w(b, 112 + 8 + 26, 0x0100));
    }
    let volume = inspect(bytes, &resources());
    assert_eq!(volume.protectors().next().unwrap().protection_type, 0x0100);
    assert_eq!(
        kind(volume.unlock_recovery(RECOVERY_ID, &RecoveryPassword::parse(PASSWORD).unwrap())),
        ErrorKind::Unsupported
    );
}

#[test]
fn plaintext_identity_is_distinct_and_preserves_ciphertext_ancestry() {
    use partmgr::io::SourceIdentity;
    struct Identified(Image);
    impl ReadAt for Identified {
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn source_identity(&self) -> Option<SourceIdentity> {
            Some(SourceIdentity::new(0x1234, 77, self.len()))
        }
        fn ancestor_identities(&self) -> Vec<SourceIdentity> {
            vec![SourceIdentity::new(0x1234, 55, self.len())]
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(at, out)
        }
    }
    let source = Arc::new(Identified(Image::new(fixture(0x8004, 512))));
    let encrypted_identity = source.source_identity().unwrap();
    let r = resources();
    let volume = BitLockerVolume::inspect(
        source,
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &r,
    )
    .unwrap();
    let first = volume.unlock_fvek(&[0; 32]).unwrap();
    let second = volume.unlock_fvek(&[1; 32]).unwrap();
    assert_ne!(first.source_identity(), Some(encrypted_identity));
    assert_ne!(first.source_identity(), second.source_identity());
    assert_eq!(
        first.source_identity(),
        Some(first.provenance().plaintext_view)
    );
    assert_eq!(
        first.provenance().encrypted_source,
        Some(encrypted_identity)
    );
    assert!(first.ancestor_identities().contains(&encrypted_identity));
    assert!(
        first
            .ancestor_identities()
            .contains(&SourceIdentity::new(0x1234, 55, LENGTH as u64))
    );
    assert_eq!(first.provenance().volume, *first.info());
    assert_eq!(first.provenance().relocated_boot_offset, BOOT as u64);
    assert_eq!(
        first.provenance().metadata_offsets,
        OFFSETS.map(|at| at as u64)
    );
}

#[test]
fn changed_source_identity_is_rejected_even_at_unchanged_length() {
    use partmgr::io::SourceIdentity;
    struct ChangingIdentity {
        image: Image,
        generation: AtomicU64,
    }
    impl ReadAt for ChangingIdentity {
        fn len(&self) -> u64 {
            self.image.len()
        }
        fn source_identity(&self) -> Option<SourceIdentity> {
            Some(SourceIdentity::new(
                7,
                u128::from(self.generation.load(Ordering::Relaxed)),
                self.len(),
            ))
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.image.read_exact_at(at, out)
        }
    }
    let source = Arc::new(ChangingIdentity {
        image: Image::new(fixture(0x8004, 512)),
        generation: AtomicU64::new(1),
    });
    let volume = BitLockerVolume::inspect(
        source.clone(),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &resources(),
    )
    .unwrap();
    let unlocked = volume.unlock_fvek(&[0; 32]).unwrap();
    source.generation.store(2, Ordering::Relaxed);
    let error = unlocked.read_exact_at(0x2000, &mut [0; 1]).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<bitlocker::Error>()
            .unwrap()
            .kind,
        ErrorKind::SourceChanged
    );
}

#[test]
fn typed_fvek_binds_cipher_and_preserves_independent_plaintext_vectors() {
    use bitlocker::{FullVolumeKey, ReadSupport};
    for method in [0x8004, 0x8005] {
        let volume = inspect(fixture(method, 512), &resources());
        assert_eq!(volume.read_support().unwrap(), ReadSupport::Supported);
        let key = FullVolumeKey::new(
            method,
            &(0..if method == 0x8004 { 32 } else { 64 }).collect::<Vec<u8>>(),
        )
        .unwrap();
        let reader = volume.unlock_with_fvek(&key).unwrap();
        assert_eq!(reader.key_evidence(), KeyEvidence::CallerSupplied);
        let mut out = [0; 512];
        reader.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out.as_slice(), plaintext(512, true));
        let (wrong_method, wrong_len) = if method == 0x8004 {
            (0x8005, 64)
        } else {
            (0x8004, 32)
        };
        let wrong = FullVolumeKey::new(wrong_method, &vec![0; wrong_len]).unwrap();
        assert_eq!(
            kind(volume.unlock_with_fvek(&wrong)),
            ErrorKind::InvalidCredential
        );
    }
}

#[test]
fn typed_fvek_rejects_lengths_methods_and_redacts_debug() {
    use bitlocker::FullVolumeKey;
    assert_eq!(
        kind(FullVolumeKey::new(0x8004, &[0; 64])),
        ErrorKind::InvalidCredential
    );
    assert_eq!(
        kind(FullVolumeKey::new(0x8005, &[0; 32])),
        ErrorKind::InvalidCredential
    );
    assert_eq!(
        kind(FullVolumeKey::new(0x8000, &[0; 32])),
        ErrorKind::Unsupported
    );
    let key = FullVolumeKey::new(0x8004, &[0xab; 32]).unwrap();
    assert_eq!(key.encryption_method(), 0x8004);
    assert_eq!(
        format!("{key:?}"),
        "FullVolumeKey { encryption_method: 32772, .. }"
    );
}

#[test]
fn read_support_reports_profile_limits_without_key_work() {
    use bitlocker::{ReadLimitation, ReadSupport};
    for (state, method, reason) in [
        (2, 0x8004, ReadLimitation::ConversionState),
        (4, 0x8000, ReadLimitation::EncryptionMethod),
    ] {
        let mut bytes = fixture(0x8004, 512);
        for index in 0..3 {
            mutate(&mut bytes, index, |metadata| {
                w(metadata, 12, state);
                w(metadata, 100, method);
            });
        }
        let volume = inspect(bytes, &resources());
        assert_eq!(
            volume.read_support().unwrap(),
            ReadSupport::Unsupported(reason)
        );
    }
    let mut bytes = fixture(0x8004, 512);
    for index in 0..3 {
        mutate(&mut bytes, index, |metadata| q(metadata, 56, LENGTH as u64));
    }
    let volume = inspect(bytes, &resources());
    assert_eq!(kind(volume.read_support()), ErrorKind::InvalidData);
}

fn with_extended_descriptor(mut image: Vec<u8>, mutate_body: impl Fn(&mut [u8])) -> Vec<u8> {
    let mut body = hex(
        "0000210200000000002000000000000005004c00000000000a0000000000000000000000000000000000000000020000000200000a000000000000005866000002000000000000001001010200202102000000000000010000000000",
    );
    q(&mut body, 0, BOOT as u64);
    q(&mut body, 8, 512);
    q(&mut body, 76, 0x80000);
    mutate_body(&mut body);
    let descriptor = entry(15, 15, &body);
    for offset in OFFSETS {
        let old_size =
            u32::from_le_bytes(image[offset + 64..offset + 68].try_into().unwrap()) as usize;
        let new_size = old_size + descriptor.len();
        let block_size = (64 + new_size).next_multiple_of(16);
        let mut metadata = vec![0; block_size + 8];
        metadata[..64 + old_size].copy_from_slice(&image[offset..offset + 64 + old_size]);
        metadata[64 + old_size..64 + new_size].copy_from_slice(&descriptor);
        w(&mut metadata, 8, (block_size / 16) as u16);
        d(&mut metadata, 64, new_size as u32);
        d(&mut metadata, 76, new_size as u32);
        w(&mut metadata, block_size, 8);
        w(&mut metadata, block_size + 2, 1);
        let checksum = crc(&metadata[..block_size]);
        d(&mut metadata, block_size + 4, checksum);
        image[offset..offset + metadata.len()].copy_from_slice(&metadata);
    }
    image
}

#[test]
fn observed_completed_extended_descriptor_is_decoded_and_reserved() {
    let bytes = with_extended_descriptor(fixture(0x8004, 512), |_| {});
    let volume = inspect(bytes, &resources());
    assert_eq!(
        volume.read_support().unwrap(),
        bitlocker::ReadSupport::Supported
    );
    let reader = volume.unlock_clear(CLEAR_ID).unwrap();
    let mut bytes = [0xab; 512];
    reader.read_exact_at(0x80000, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 512]);
}

#[test]
fn extended_descriptor_rejects_unknown_policy_and_invalid_regions() {
    for (offset, value) in [
        (16, 6u64),
        (18, 60),
        (20, 1),
        (24, 0x4b),
        (32, 0x90000),
        (40, 512),
        (52, 11),
        (60, 0x6659),
        (64, 3),
        (72, 0x02010111),
    ] {
        let bytes = with_extended_descriptor(fixture(0x8004, 512), |body| match offset {
            16 | 18 => w(body, offset, value as u16),
            20 | 40 | 60 | 72 => d(body, offset, value as u32),
            _ => q(body, offset, value),
        });
        let volume = inspect(bytes, &resources());
        assert_eq!(
            kind(volume.unlock_clear(CLEAR_ID)),
            ErrorKind::Unsupported,
            "field {offset}"
        );
    }
    for (offset, value) in [
        (44, 4096u64),
        (48, 256),
        (76, 0x80001),
        (84, 0),
        (76, LENGTH as u64),
        (84, u64::MAX),
        (76, BOOT as u64),
        (76, OFFSETS[0] as u64),
        (76, 0),
    ] {
        let bytes = with_extended_descriptor(fixture(0x8004, 512), |body| {
            if offset < 52 {
                d(body, offset, value as u32);
            } else {
                q(body, offset, value);
            }
        });
        let volume = inspect(bytes, &resources());
        assert_eq!(
            kind(volume.unlock_clear(CLEAR_ID)),
            ErrorKind::InvalidData,
            "field {offset} value {value}"
        );
    }
}

#[test]
fn native_version_two_crc_header_is_bounded_and_checks_crc() {
    let mut bytes = fixture(0x8004, 512);
    for &offset in &OFFSETS {
        let size = usize::from(word(&bytes, offset + 8)) * 16;
        w(&mut bytes, offset + size, (65536 - size) as u16);
        w(&mut bytes, offset + size + 2, 2);
    }
    let r = resources();
    assert!(inspect(bytes.clone(), &r).unlock_clear(CLEAR_ID).is_ok());
    for (length, version) in [(7, 2), (65535, 2), (8, 3)] {
        let mut malformed = bytes.clone();
        for &offset in &OFFSETS {
            let size = usize::from(word(&malformed, offset + 8)) * 16;
            w(&mut malformed, offset + size, length);
            w(&mut malformed, offset + size + 2, version);
        }
        assert_eq!(
            kind(BitLockerVolume::inspect(
                Arc::new(Image::new(malformed)),
                MetadataSelection::RequireAgreement,
                Limits::default(),
                &r
            )),
            ErrorKind::InvalidData
        );
    }
    for &offset in &OFFSETS {
        let size = usize::from(word(&bytes, offset + 8)) * 16;
        bytes[offset + size + 4] ^= 1;
    }
    assert_eq!(
        kind(BitLockerVolume::inspect(
            Arc::new(Image::new(bytes)),
            MetadataSelection::RequireAgreement,
            Limits::default(),
            &r
        )),
        ErrorKind::InvalidData
    );
}

#[cfg(feature = "bitlocker-tpm")]
#[test]
fn tpm_preflight_rejects_factors_mapping_cancellation_and_source_change_without_commands() {
    use partmgr::bitlocker_tpm_host::{CommandTransport, Tpm2Provider};
    struct NoCommands;
    impl CommandTransport for NoCommands {
        fn transact(&mut self, _: &[u8], _: &mut [u8]) -> std::io::Result<usize> {
            panic!("preflight failure must not contact TPM");
        }
    }
    fn portable_kind<T>(result: core::result::Result<T, bitlocker::TpmUnlockError>) -> ErrorKind {
        match result {
            Err(bitlocker::TpmUnlockError::Volume(error)) => error.kind,
            _ => panic!("expected portable preflight failure"),
        }
    }
    let mut provider = Tpm2Provider::new(NoCommands);
    let r = resources();
    let source = Arc::new(Image::new(fixture(0x8004, 512)));
    let volume = BitLockerVolume::inspect(
        source.clone(),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        &r,
    )
    .unwrap();
    for identifier in [RECOVERY_ID, CLEAR_ID] {
        assert_eq!(
            portable_kind(volume.authenticate_tpm(identifier, &mut provider, 0x81000001, &[1; 32])),
            ErrorKind::Unsupported
        );
    }
    source.length.store(LENGTH as u64 - 1, Ordering::Relaxed);
    assert_eq!(
        portable_kind(volume.authenticate_tpm(RECOVERY_ID, &mut provider, 0x81000001, &[1; 32])),
        ErrorKind::SourceChanged
    );
    source.length.store(LENGTH as u64, Ordering::Relaxed);
    r.cancellation.cancel();
    assert_eq!(
        portable_kind(volume.authenticate_tpm(RECOVERY_ID, &mut provider, 0x81000001, &[1; 32])),
        ErrorKind::Cancelled
    );
    let mut bytes = fixture(0x8004, 512);
    for index in 0..3 {
        mutate(&mut bytes, index, |metadata| w(metadata, 12, 2));
    }
    let volume = inspect(bytes, &resources());
    assert_eq!(
        portable_kind(volume.unlock_tpm([0xff; 16], &mut provider, 0x81000001, &[1; 32])),
        ErrorKind::Unsupported
    );
}
