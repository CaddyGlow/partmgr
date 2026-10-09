#![cfg(feature = "std")]

#[path = "fixtures/ext2_clean.rs"]
mod independent;
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{self, ExtAuditLimits},
};
use std::sync::Arc;
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes())
}
fn d(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes())
}
fn be(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes())
}
fn fixture(extents: bool, version: u32) -> Vec<u8> {
    let mut b = independent::fixture();
    b.resize(2048 * 1024, 0);
    d(&mut b, 1028, 2048);
    d(&mut b, 1056, 2048);
    d(&mut b, 1060, 2048);
    d(&mut b, 1116, 4);
    d(&mut b, 1120, if extents { 0x42 } else { 2 });
    b[1128..1144].fill(7);
    d(&mut b, 1248, 8);
    b[3072..4096].fill(0);
    for bit in 2047..8192 {
        b[3072 + bit / 8] |= 1 << (bit % 8)
    }
    let last = if extents { 1043 } else { 1048 };
    for block in (1..=8).chain(20..=last) {
        let bit = block - 1;
        b[3072 + bit / 8] |= 1 << (bit % 8)
    }
    let free = 2047 - 8 - (last - 20 + 1);
    d(&mut b, 1036, free as u32);
    w(&mut b, 2060, free as u16);
    let inode = 5 * 1024 + 7 * 128;
    w(&mut b, inode, 0o100600);
    w(&mut b, inode + 26, 1);
    d(&mut b, inode + 4, 1024 * 1024);
    d(&mut b, inode + 28, if extents { 2048 } else { 2058 });
    if extents {
        d(&mut b, inode + 32, 0x80000);
        let root = inode + 40;
        w(&mut b, root, 0xf30a);
        w(&mut b, root + 2, 1);
        w(&mut b, root + 4, 4);
        w(&mut b, root + 16, 1024);
        d(&mut b, root + 20, 20);
    } else {
        for slot in 0..12 {
            d(&mut b, inode + 40 + slot * 4, 20 + slot as u32)
        }
        d(&mut b, inode + 88, 1044);
        d(&mut b, inode + 92, 1045);
        for slot in 0..256 {
            d(&mut b, 1044 * 1024 + slot * 4, 32 + slot as u32)
        }
        for leaf in 0..3 {
            d(&mut b, 1045 * 1024 + leaf * 4, 1046 + leaf as u32);
            for slot in 0..if leaf == 2 { 244 } else { 256 } {
                d(
                    &mut b,
                    (1046 + leaf) * 1024 + slot * 4,
                    288 + leaf as u32 * 256 + slot as u32,
                )
            }
        }
    }
    let at = 20 * 1024;
    be(&mut b, at, 0xc03b3998);
    be(&mut b, at + 4, version);
    be(&mut b, at + 12, 1024);
    be(&mut b, at + 16, 1024);
    be(&mut b, at + 20, 1);
    be(&mut b, at + 24, 1);
    if version == 4 {
        b[at + 48..at + 64].fill(7);
        be(&mut b, at + 64, 1)
    }
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
        blocks: 2048,
        inodes: 16,
        work: 262144,
        directory_blocks: 4,
        directory_entries: 32,
        findings: 32,
    }
}
#[test]
fn inactive_internal_jbd_v1_v2_classic_and_extents_have_complete_hidden_ownership() {
    for extents in [false, true] {
        for version in [3, 4] {
            let r = r();
            let v = ExtVolume::open(Arc::new(Image(fixture(extents, version))), &r).unwrap();
            assert!(v.geometry().has_journal());
            let file = v.open_file(11, 4, &r).unwrap();
            let mut data = [0; 17];
            file.read_at(17, &mut data, &r).unwrap();
            assert_eq!(data, [73; 17]);
            let a = fs_ext_audit::audit(&v, limits(), &r).unwrap();
            assert!(a.is_clean(), "{:?}", a.findings());
            assert_eq!(a.allocated_inodes(), 2);
            assert_eq!(a.owned_blocks(), if extents { 1026 } else { 1031 });
            drop((file, a, v));
            assert_eq!(r.memory.used(), 0)
        }
    }
}
#[test]
fn inactive_start_never_overrides_fs_recovery_uuid_features_or_geometry() {
    for (at, value) in [
        (1120, 6),
        (1082, 0),
        (1248, 0),
        (1252, 99),
        (20 * 1024 + 28, 2),
        (20 * 1024 + 32, 5),
        (20 * 1024 + 40, 8),
        (20 * 1024 + 12, 2048),
        (20 * 1024 + 16, 2),
        (20 * 1024 + 48, 99),
    ] {
        let r = r();
        let mut b = fixture(false, 4);
        if at == 1082 {
            w(&mut b, at, value as u16)
        } else if at >= 20 * 1024 {
            be(&mut b, at, value)
        } else {
            d(&mut b, at, value)
        }
        assert!(ExtVolume::open(Arc::new(Image(b)), &r).is_err(), "at{at}");
        assert_eq!(r.memory.used(), 0)
    }
    let r = r();
    r.cancellation.cancel();
    assert!(ExtVolume::open(Arc::new(Image(fixture(false, 4))), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

// Independent polynomial long division, rather than production's reflected loop.
fn journal_checksum(b: &mut [u8]) {
    let at = 20 * 1024;
    b[at + 252..at + 256].fill(0);
    let mut state = !0u32;
    for &byte in &b[at..at + 1024] {
        state ^= u32::from(byte.reverse_bits()) << 24;
        for _ in 0..8 {
            let high = state & 0x8000_0000 != 0;
            state <<= 1;
            if high {
                state ^= 0x1edc6f41;
            }
        }
    }
    be(b, at + 252, state.reverse_bits());
}

#[test]
fn inactive_checksum_v2_v3_validate_entire_header_before_audit() {
    for feature in [8, 9, 16, 17] {
        let mut image = fixture(true, 4);
        let at = 20 * 1024;
        be(&mut image, at + 40, feature);
        image[at + 80] = 4;
        journal_checksum(&mut image);
        let resources = r();
        let volume = ExtVolume::open(Arc::new(Image(image.clone())), &resources).unwrap();
        let audit = fs_ext_audit::audit(&volume, limits(), &resources).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        drop((audit, volume));
        assert_eq!(resources.memory.used(), 0);
        for offset in [24, 88, 252, 256, 1023] {
            let mut damaged = image.clone();
            damaged[at + offset] ^= 1;
            let resources = r();
            let error = ExtVolume::open(Arc::new(Image(damaged)), &resources)
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(resources.memory.used(), 0);
        }
        for (offset, value) in [(40, 24), (36, 1), (40, 20), (68, 1), (84, 1)] {
            let mut damaged = image.clone();
            be(&mut damaged, at + offset, value);
            journal_checksum(&mut damaged);
            let resources = r();
            assert!(ExtVolume::open(Arc::new(Image(damaged)), &resources).is_err());
            assert_eq!(resources.memory.used(), 0);
        }
        let mut damaged = image;
        damaged[at + 80] = 1;
        journal_checksum(&mut damaged);
        assert_eq!(
            ExtVolume::open(Arc::new(Image(damaged)), &r())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
