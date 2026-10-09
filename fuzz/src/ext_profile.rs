// Independently constructed extent mapping over the classic specification fixture.
#[path = "../../tests/fixtures/ext2_clean.rs"]
mod fixture;
pub(crate) fn seed() -> Vec<u8> {
    let mut b = fixture::fixture();
    let inode = 6400;
    let d = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let w = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    d(&mut b, 1120, 0x42);
    d(&mut b, inode + 32, 0x80000);
    d(&mut b, inode + 4, 4096);
    d(&mut b, inode + 28, 6);
    b[inode + 40..inode + 100].fill(0);
    let root = inode + 40;
    w(&mut b, root, 0xf30a);
    w(&mut b, root + 2, 2);
    w(&mut b, root + 4, 4);
    d(&mut b, root + 12, 0);
    w(&mut b, root + 16, 1);
    d(&mut b, root + 20, 8);
    d(&mut b, root + 24, 2);
    w(&mut b, root + 28, 32770);
    d(&mut b, root + 32, 9);
    b[3073] |= 3;
    d(&mut b, 1036, 53);
    w(&mut b, 2060, 53);
    b[9 * 1024..11 * 1024].fill(0xdd);
    b
}
#[cfg(test)]
mod tests {
    use partmgr::{
        fs_core::*,
        fs_ext::ExtVolume,
        fs_ext_audit::{ExtAuditLimits, audit},
    };
    #[test]
    fn extent_seed_reaches_clean_audit_and_hole_unwritten_payload() {
        let r = Resources {
            memory: Budget::new(256 << 10),
            cancellation: Cancellation::default(),
        };
        let v = ExtVolume::open(std::sync::Arc::new(crate::Bytes(super::seed())), &r).unwrap();
        let proof = audit(
            &v,
            ExtAuditLimits {
                blocks: 128,
                inodes: 64,
                work: 65536,
                directory_blocks: 64,
                directory_entries: 128,
                findings: 32,
            },
            &r,
        )
        .unwrap();
        assert!(proof.is_clean(), "{:?}", proof.findings());
        let file = v.open_file(11, 64, &r).unwrap();
        let mut out = [0xaa; 4096];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 4096);
        assert!(out[..1024].iter().all(|v| *v == 73));
        assert!(out[1024..].iter().all(|v| *v == 0));
        drop(file);
        drop(proof);
        drop(v);
        assert_eq!(r.memory.used(), 0);
    }
}

#[allow(dead_code)]
#[path = "../../tests/fixtures/fs_ext_modern.rs"]
mod modern;
pub(crate) fn modern_seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![modern::fixture().0, modern::without_extents().0];
    seeds.extend(modern::mutation_seeds());
    seeds
}
#[test]
fn modern_seeds_reach_public_clean_audit_payload_and_refund() {
    use partmgr::{
        fs_core::*,
        fs_ext::ExtVolume,
        fs_ext_audit::{ExtAuditLimits, audit},
    };
    for (bytes, payload) in [modern::fixture(), modern::without_extents()] {
        crate::ext(&bytes);
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let volume = ExtVolume::open(std::sync::Arc::new(crate::Bytes(bytes)), &r).unwrap();
        assert!(!volume.geometry().is_classic());
        assert!(volume.geometry().has_metadata_checksums());
        let report = audit(
            &volume,
            ExtAuditLimits {
                blocks: 128,
                inodes: 64,
                work: 65536,
                directory_blocks: 64,
                directory_entries: 128,
                findings: 32,
            },
            &r,
        )
        .unwrap();
        assert!(report.is_clean());
        drop(report);
        let file = volume.open_file(12, 64, &r).unwrap();
        drop(volume);
        assert_eq!(read_all(&file, 2048, &r).unwrap().get(), &payload);
        r.cancellation.cancel();
        assert!(file.read_at(file.len(), &mut [], &r).is_err());
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
    for seed in modern::mutation_seeds() {
        crate::ext(&seed);
    }
}
