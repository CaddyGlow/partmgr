#![cfg(feature = "std")]

#[path = "fixtures/ext2_clean.rs"]
mod clean_fixture;
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditFinding as Finding, ExtAuditLimits, audit},
};
use std::sync::Arc;
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(o).map_err(io::Error::other)?;
        let end = at
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtAuditLimits {
    ExtAuditLimits {
        blocks: 32768,
        inodes: 8192,
        work: 1_000_000,
        directory_blocks: 256,
        directory_entries: 1024,
        findings: 1024,
    }
}
fn w(b: &mut [u8], o: usize, n: u16) {
    b[o..o + 2].copy_from_slice(&n.to_le_bytes())
}
fn d(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes())
}
const FILE: usize = 5 * 1024 + 10 * 128;
// Independent small raw ext2 fixture: standard reserved inodes, root, hard-linked file.
fn fixture() -> Vec<u8> {
    clean_fixture::fixture()
}

fn volume(b: Vec<u8>, r: &Resources) -> ExtVolume {
    ExtVolume::open(Arc::new(Image(b)), r).unwrap()
}
fn symlink_fixture(target: &[u8], fast: bool) -> Vec<u8> {
    let mut raw = fixture();
    w(&mut raw, FILE, 0xa1ff);
    d(&mut raw, FILE + 4, target.len() as u32);
    raw[FILE + 40..FILE + 100].fill(0);
    raw[7 * 1024 + 24 + 7] = 7;
    raw[7 * 1024 + 40 + 7] = 7;
    if fast {
        d(&mut raw, FILE + 28, 0);
        raw[FILE + 40..FILE + 40 + target.len()].copy_from_slice(target);
        // Opaque unused inline suffix must not become apparent block pointers.
        raw[FILE + 41 + target.len()..FILE + 100].fill(0xff);
        raw[3072] &= !(1 << 7);
        d(&mut raw, 1036, 56);
        w(&mut raw, 2060, 56);
    } else {
        d(&mut raw, FILE + 28, 2);
        d(&mut raw, FILE + 40, 8);
        raw[8192..9216].fill(0xcc);
        raw[8192..8192 + target.len()].copy_from_slice(target);
        raw[8192 + target.len()] = 0;
    }
    raw
}
#[test]
fn exact_unfollowed_fast_and_one_direct_targets_count_aliases_and_ownership() {
    for (length, fast) in [(1, true), (59, true), (60, false), (1023, false)] {
        let r = resources();
        let target = (0..length).map(|i| 1 + (i % 255) as u8).collect::<Vec<_>>();
        let v = volume(symlink_fixture(&target, fast), &r);
        let report = audit(&v, limits(), &r).unwrap();
        assert!(
            report.is_clean(),
            "length={length} fast={fast}: {:?}",
            report.findings()
        );
        assert!(report.complete());
        assert!(report.namespace_complete());
        assert_eq!(report.allocated_inodes(), 2);
        assert_eq!(report.owned_blocks(), if fast { 1 } else { 2 });
        let decoded = v.symlink_target(11, 1, &r).unwrap();
        assert_eq!(decoded.as_slice(), target);
        drop((decoded, report));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_symlink_storage_is_not_mistaken_for_clean_ownership() {
    for attack in 0..7 {
        let r = resources();
        let mut raw = symlink_fixture(&[0x81; 60], false);
        match attack {
            0 => d(&mut raw, FILE + 4, 0),
            1 => d(&mut raw, FILE + 4, 1024),
            2 => raw[8192 + 60] = 1,
            3 => raw[8192 + 17] = 0,
            4 => d(&mut raw, FILE + 44, 9),
            5 => d(&mut raw, FILE + 28, 3),
            6 => {
                raw = symlink_fixture(&[0x81; 59], true);
                raw[FILE + 4..FILE + 8].copy_from_slice(&60u32.to_le_bytes());
            }
            _ => unreachable!(),
        }
        let v = volume(raw, &r);
        let error = audit(&v, limits(), &r).err().unwrap();
        assert_eq!(
            error.kind,
            ErrorKind::InvalidData,
            "attack={attack}: {error:?}"
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn symlink_reference_type_free_crosslink_and_lost_blocks_are_reported() {
    for attack in 0..5 {
        let r = resources();
        let mut raw = symlink_fixture(&[b'x'; 60], false);
        match attack {
            0 => {
                raw[3072] &= !(1 << 7);
                d(&mut raw, 1036, 56);
                w(&mut raw, 2060, 56);
            }
            1 => d(&mut raw, FILE + 40, 7),
            2 => raw[7 * 1024 + 40 + 7] = 1,
            3 => w(&mut raw, FILE + 26, 1),
            4 => {
                raw = symlink_fixture(b"../missing", true);
                raw[3072] |= 1 << 7;
                d(&mut raw, 1036, 55);
                w(&mut raw, 2060, 55);
            }
            _ => unreachable!(),
        }
        let v = volume(raw, &r);
        let report = audit(&v, limits(), &r).unwrap();
        assert!(!report.is_clean());
        assert!(
            report.findings().iter().any(|finding| matches!(
                (attack, finding),
                (0, Finding::ReferencedFreeBlock { block: 8, .. })
                    | (1, Finding::CrossLink { block: 7, .. })
                    | (2, Finding::DirectoryType { inode: 11, .. })
                    | (
                        3,
                        Finding::LinkCount {
                            inode: 11,
                            actual: 2,
                            ..
                        },
                    )
                    | (4, Finding::LostBlock { block: 8 })
            )),
            "attack={attack}: {:?}",
            report.findings()
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn symlink_audit_cancel_and_work_exhaustion_never_return_readiness() {
    let r = resources();
    let v = volume(symlink_fixture(b"../missing", true), &r);
    let mut small = limits();
    small.work = 16;
    assert_eq!(
        audit(&v, small, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    r.cancellation.cancel();
    assert_eq!(
        audit(&v, limits(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn short_block_backed_source_stays_outside_canonical_audit_profile() {
    let r = resources();
    let v = volume(symlink_fixture(b"../missing", false), &r);
    assert_eq!(
        audit(&v, limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn coherent_extent_backed_symlink_is_unsupported_before_direct_layout_checks() {
    let r = resources();
    let mut raw = symlink_fixture(&[b'x'; 60], false);
    d(&mut raw, 1120, 0x42); // FILETYPE | EXTENTS, without metadata checksums.
    d(&mut raw, FILE + 32, 0x80000);
    raw[FILE + 40..FILE + 100].fill(0);
    w(&mut raw, FILE + 40, 0xf30a);
    w(&mut raw, FILE + 42, 1);
    w(&mut raw, FILE + 44, 4);
    w(&mut raw, FILE + 46, 0); // Inline depth-zero extent root.
    d(&mut raw, FILE + 52, 0);
    w(&mut raw, FILE + 56, 1);
    w(&mut raw, FILE + 58, 0);
    d(&mut raw, FILE + 60, 8);
    let v = volume(raw, &r);
    assert_eq!(
        audit(&v, limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
}
