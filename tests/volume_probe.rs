use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_image::ReadFormat,
    io::{self, ReadAt},
    volume_probe::{self, BitLockerEnvelope, Candidate},
};
use std::sync::atomic::{AtomicU64, Ordering};

struct Image {
    bytes: Vec<u8>,
    reads: AtomicU64,
    fail_after_header: bool,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reads: AtomicU64::new(0),
            fail_after_header: false,
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_after_header && offset != 0 {
            return Err(io::Error::other("unexpected filesystem read"));
        }
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    }
}

#[test]
fn encrypted_signature_prevents_filesystem_fallback() {
    let mut image = Image::new(vec![0; 65536]);
    image.bytes[3..11].copy_from_slice(b"-FVE-FS-");
    image.bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
    image.fail_after_header = true;
    assert!(matches!(
        volume_probe::probe(&image, &resources()).unwrap(),
        Candidate::BitLocker(BitLockerEnvelope::Fixed)
    ));
    assert_eq!(image.reads.load(Ordering::Relaxed), 1);
}

#[test]
fn removable_envelope_precedes_plaintext_ntfs_candidate() {
    let mut image = Image::new(vec![0; 512]);
    image.bytes[3..11].copy_from_slice(b"NTFS    ");
    image.bytes[424..440].copy_from_slice(&[
        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 1,
    ]);
    assert!(matches!(
        volume_probe::probe(&image, &resources()).unwrap(),
        Candidate::BitLocker(BitLockerEnvelope::ToGo)
    ));
}

#[test]
fn plaintext_candidates_retain_their_memory_charge() {
    let mut image = Image::new(vec![0; 512]);
    image.bytes[3..11].copy_from_slice(b"NTFS    ");
    let r = resources();
    let Candidate::Plaintext(formats) = volume_probe::probe(&image, &r).unwrap() else {
        panic!("expected plaintext candidate")
    };
    assert_eq!(formats.get(), &[ReadFormat::Ntfs]);
    assert!(r.memory.used() > 0);
    drop(formats);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn truncated_and_empty_signatures_are_unknown() {
    for bytes in [vec![], b"xxx-FVE-FS".to_vec(), vec![0; 512]] {
        assert!(matches!(
            volume_probe::probe(&Image::new(bytes), &resources()).unwrap(),
            Candidate::Unknown
        ));
    }
}

#[test]
fn cancellation_and_budget_failure_do_not_read_source() {
    let image = Image::new(vec![0; 512]);
    let r = resources();
    r.cancellation.cancel();
    assert!(
        matches!(volume_probe::probe(&image, &r), Err(error) if error.kind == ErrorKind::Cancelled)
    );
    let r = Resources {
        memory: Budget::new(511),
        cancellation: Cancellation::default(),
    };
    assert!(
        matches!(volume_probe::probe(&image, &r), Err(error) if error.kind == ErrorKind::BudgetExhausted)
    );
    assert_eq!(image.reads.load(Ordering::Relaxed), 0);
}
