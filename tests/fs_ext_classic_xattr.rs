#![cfg(feature = "std")]
//! Independently framed classic fixtures; these are modeled, not native-tool evidence.
#[path = "fixtures/ext2_clean.rs"]
mod clean;
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditLimits, audit},
    io,
};
use std::sync::Arc;
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.0
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn d(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
const ROOT: usize = 5 * 1024 + 128;
const FILE: usize = 5 * 1024 + 10 * 128;
fn fixture() -> Vec<u8> {
    let mut b = clean::fixture();
    d(&mut b, 1024 + 92, 8);
    b[3073] |= 1;
    d(&mut b, 1024 + 12, 54);
    w(&mut b, 2048 + 12, 54);
    for inode in [ROOT, FILE] {
        d(&mut b, inode + 104, 9);
        d(&mut b, inode + 28, 4);
    }
    let at = 9 * 1024;
    d(&mut b, at, 0xea020000);
    d(&mut b, at + 4, 2);
    d(&mut b, at + 8, 1);
    // Native user.x, opaque binary including NUL. Container/payload are distinct.
    b[at + 32] = 1;
    b[at + 33] = 1;
    w(&mut b, at + 34, 1020);
    d(&mut b, at + 40, 4);
    b[at + 48] = b'x';
    b[at + 1020..at + 1024].copy_from_slice(&[0, 255, 7, 0]);
    b
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtAuditLimits {
    ExtAuditLimits {
        blocks: 64,
        inodes: 16,
        work: 10_000_000,
        directory_blocks: 16,
        directory_entries: 32,
        findings: 64,
    }
}
fn open(b: Vec<u8>, r: &Resources) -> ExtVolume {
    ExtVolume::open(Arc::new(Image(b)), r).unwrap()
}
#[test]
fn shared_external_block_counts_distinct_inodes_not_hardlink_aliases() {
    let r = r();
    let volume = open(fixture(), &r);
    assert!(!volume.geometry().is_classic());
    let report = audit(&volume, limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.owned_blocks(), 3);
    assert_eq!(report.allocated_inodes(), 2);
    assert_eq!(report.free_ranges()[0].offset, 10 * 1024);
    assert_eq!(
        volume.inode(11, &r).unwrap().raw_metadata()[104..108],
        9u32.to_le_bytes()
    );
    drop(report);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn wrong_refcount_malformed_container_unallocated_and_payload_alias_never_clean() {
    for mutation in 0..5 {
        let r = r();
        let mut b = fixture();
        match mutation {
            0 => d(&mut b, 9 * 1024 + 4, 3),
            1 => d(&mut b, 9 * 1024, 0),
            2 => d(&mut b, 9 * 1024 + 4, 0),
            3 => b[3073] &= !1,
            4 => d(&mut b, FILE + 40, 9),
            _ => unreachable!(),
        }
        let volume = open(b, &r);
        let result = audit(&volume, limits(), &r);
        assert!(!result.as_ref().is_ok_and(|report| report.is_clean()));
        drop(result);
        drop(volume);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn external_xattr_sector_accounting_preserves_fast_and_slow_unfollowed_symlinks() {
    for fast in [true, false] {
        let r = r();
        let mut b = fixture();
        w(&mut b, FILE, 0xa1ff);
        b[7 * 1024 + 31] = 7;
        b[7 * 1024 + 47] = 7;
        if fast {
            d(&mut b, FILE + 4, 2);
            d(&mut b, FILE + 28, 2);
            b[FILE + 40..FILE + 100].fill(0);
            b[FILE + 40..FILE + 42].copy_from_slice(b"xy");
            b[3072] &= !(1 << 7);
            d(&mut b, 1024 + 12, 55);
            w(&mut b, 2048 + 12, 55);
        } else {
            d(&mut b, FILE + 4, 60);
            b[8 * 1024..9 * 1024].fill(0);
            b[8 * 1024..8 * 1024 + 60].fill(b'y');
        }
        let volume = open(b, &r);
        let target = volume.symlink_target(11, 1, &r).unwrap();
        assert_eq!(target.len(), if fast { 2 } else { 60 });
        drop(target);
        let report = audit(&volume, limits(), &r).unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        drop(report);
        drop(volume);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn absent_feature_and_work_cancel_limits_do_not_produce_clean_authority() {
    let r = r();
    let mut b = fixture();
    d(&mut b, 1024 + 92, 0);
    let volume = open(b, &r);
    assert!(volume.inode(11, &r).is_err());
    assert!(audit(&volume, limits(), &r).is_err());
    drop(volume);
    let volume = open(fixture(), &r);
    assert!(
        audit(
            &volume,
            ExtAuditLimits {
                work: 100,
                ..limits()
            },
            &r
        )
        .is_err()
    );
    r.cancellation.cancel();
    assert!(audit(&volume, limits(), &r).is_err());
    drop(volume);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn exact_audit_work_boundary_and_external_read_cancellation_refund() {
    let r = r();
    let source = fixture();
    let original = source.clone();
    let volume = open(source, &r);
    let mut low = 0usize;
    let mut high = limits().work;
    while low < high {
        let mid = low + (high - low) / 2;
        let result = audit(
            &volume,
            ExtAuditLimits {
                work: mid,
                ..limits()
            },
            &r,
        );
        let clean = result.as_ref().is_ok_and(|report| report.is_clean());
        drop(result);
        assert_eq!(r.memory.used(), 0);
        if clean {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    assert!(low >= 4 * 1024 * 258); // two distinct owners plus root's two decoder scans.
    let report = audit(
        &volume,
        ExtAuditLimits {
            work: low,
            ..limits()
        },
        &r,
    )
    .unwrap();
    assert!(report.is_clean());
    drop(report);
    assert!(
        audit(
            &volume,
            ExtAuditLimits {
                work: low - 1,
                ..limits()
            },
            &r
        )
        .is_err()
    );
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    struct CancelImage {
        bytes: Vec<u8>,
        cancel: Cancellation,
    }
    impl ReadAt for CancelImage {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let at = offset as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            if at == 9 * 1024 {
                self.cancel.cancel();
            }
            Ok(())
        }
    }
    let r = super_resources();
    let image = Arc::new(CancelImage {
        bytes: original,
        cancel: r.cancellation.clone(),
    });
    let volume = ExtVolume::open(image.clone(), &r).unwrap();
    assert!(audit(&volume, limits(), &r).is_err());
    assert_eq!(image.bytes, fixture());
    drop(volume);
    assert_eq!(r.memory.used(), 0);
}
fn super_resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}

#[allow(dead_code)]
#[path = "fixtures/fs_ext_modern.rs"]
mod modern;
// Independently forward-polynomial restamping, separate from production CRC.
fn forward(mut state: u32, bytes: &[u8]) -> u32 {
    state = state.reverse_bits();
    for &byte in bytes {
        state ^= u32::from(byte.reverse_bits()) << 24;
        for _ in 0..8 {
            state = (state << 1)
                ^ if state & 0x80000000 != 0 {
                    0x1edc6f41
                } else {
                    0
                };
        }
    }
    state.reverse_bits()
}
const MODERN_FILE: usize = 5 * 1024 + 11 * 256;
fn modern_symlink(fast: bool) -> Vec<u8> {
    let (mut b, _) = modern::fixture();
    w(&mut b, MODERN_FILE, 0xa1ff);
    if fast {
        d(&mut b, MODERN_FILE + 4, 8);
        d(&mut b, MODERN_FILE + 28, 2);
        d(&mut b, MODERN_FILE + 32, 0);
        b[MODERN_FILE + 40..MODERN_FILE + 100].fill(0);
        b[MODERN_FILE + 40..MODERN_FILE + 48].copy_from_slice(b"relative");
    } else {
        d(&mut b, MODERN_FILE + 4, 60);
        d(&mut b, MODERN_FILE + 28, 4);
        w(&mut b, MODERN_FILE + 56, 1);
        b[10 * 1024..11 * 1024].fill(0);
        b[10 * 1024..10 * 1024 + 60].fill(b's');
    }
    for block in if fast { 10..12 } else { 11..12 } {
        let bit = block - 1;
        b[3 * 1024 + bit / 8] &= !(1 << (bit % 8));
    }
    let free = if fast { 53 } else { 52 };
    d(&mut b, 1024 + 12, free);
    w(&mut b, 2048 + 12, free as u16);
    b[9 * 1024 + 31] = 7;
    let seed = forward(
        forward(0x12345678, &2u32.to_le_bytes()),
        &0u32.to_le_bytes(),
    );
    let crc = forward(seed, &b[9 * 1024..9 * 1024 + 1012]);
    d(&mut b, 9 * 1024 + 1020, crc);
    let bcrc = forward(0x12345678, &b[3 * 1024..3 * 1024 + 8]);
    w(&mut b, 2048 + 24, bcrc as u16);
    w(&mut b, 2048 + 56, (bcrc >> 16) as u16);
    w(&mut b, 2048 + 30, 0);
    let crc = forward(forward(0x12345678, &0u32.to_le_bytes()), &b[2048..2112]);
    w(&mut b, 2048 + 30, crc as u16);
    let crc = forward(!0, &b[1024..2044]);
    d(&mut b, 2044, crc);
    modern::inode_checksum(&mut b, 12);
    b
}
#[test]
fn modern_fast_and_extent_slow_symlinks_keep_external_ea_and_complete_ownership() {
    for fast in [true, false] {
        let r = r();
        let bytes = modern_symlink(fast);
        let before = bytes.clone();
        let v = open(bytes, &r);
        let target = v.symlink_target(12, 1, &r).unwrap();
        assert_eq!(target.len(), if fast { 8 } else { 60 });
        assert!(target.iter().all(|b| *b != 0));
        drop(target);
        let report = audit(&v, limits(), &r).unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.allocated_inodes(), 2);
        drop(report);
        drop(v);
        assert_eq!(r.memory.used(), 0);
        assert_eq!(before, modern_symlink(fast));
    }
}
#[test]
fn modern_symlink_extent_sector_alias_checksum_and_fast_flag_defects_refuse() {
    for mutation in 0..6 {
        let r = r();
        let fast = mutation == 0;
        let mut bytes = modern_symlink(fast);
        match mutation {
            0 => d(&mut bytes, MODERN_FILE + 32, 0x80000),
            1 => w(&mut bytes, MODERN_FILE + 56, 32769),
            2 => d(&mut bytes, MODERN_FILE + 52, 1),
            3 => d(&mut bytes, MODERN_FILE + 28, 2),
            4 => d(&mut bytes, MODERN_FILE + 60, 12),
            5 => d(&mut bytes, MODERN_FILE + 60, 3),
            _ => unreachable!(),
        };
        modern::inode_checksum(&mut bytes, 12);
        let v = open(bytes, &r);
        let result = audit(&v, limits(), &r);
        assert!(!result.as_ref().is_ok_and(|report| report.is_clean()));
        drop(result);
        drop(v);
        assert_eq!(r.memory.used(), 0);
    }
    let r = r();
    let mut bytes = modern_symlink(false);
    bytes[MODERN_FILE + 16] ^= 1;
    let v = open(bytes, &r);
    assert!(v.inode(12, &r).is_err());
    assert!(audit(&v, limits(), &r).is_err());
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
