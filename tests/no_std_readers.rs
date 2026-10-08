//! Remaining reader engines exercised through the alloc-only positional boundary.
#![cfg(not(feature = "std"))]
use partmgr::{fs_core::*, io, io::ReadAt};
use std::sync::Arc;
#[allow(dead_code)]
#[path = "fixtures/hfs_clean.rs"]
mod hfs_fixture;
#[allow(dead_code)]
#[path = "fixtures/jfs_clean.rs"]
mod jfs_fixture;
#[allow(dead_code)]
#[path = "fixtures/ntfs_basic.rs"]
mod ntfs_fixture;
#[allow(dead_code)]
#[path = "fixtures/xfs_clean.rs"]
mod xfs_fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn eof(file: &dyn FileRead, r: &Resources) {
    let mut out = [17; 8];
    assert_eq!(file.read_at(file.len(), &mut out, r).unwrap(), 0);
    assert_eq!(file.read_at(u64::MAX, &mut out, r).unwrap(), 0);
    assert_eq!(out, [17; 8]);
}
#[test]
fn hfs_native_forks_read_without_std() {
    use partmgr::fs_hfs::*;
    let r = resources();
    let volume = HfsVolume::open(
        Arc::new(Bytes(hfs_fixture::hfs_seed())),
        HfsReadLimits {
            blocks: 65536,
            nodes: 4096,
            records: 512,
            extents: 2048,
            work: 16 << 20,
        },
        &r,
    )
    .unwrap();
    let object = volume
        .lookup(&[NativeName::Bytes(b"dAtA".to_vec())], &r)
        .unwrap();
    let file = volume.open_fork(&object, &StreamKind::Data, &r).unwrap();
    let mut out = [0; 31];
    assert_eq!(file.read_at(3 * 512 - 8, &mut out, &r).unwrap(), 31);
    assert_eq!(
        out,
        std::array::from_fn(|i| ((3 * 512 - 8 + i) * 17 % 251) as u8)
    );
    eof(&file, &r);
    let fork = volume
        .open_fork(&object, &StreamKind::ResourceFork, &r)
        .unwrap();
    let mut resource = [0; 5];
    fork.read_at(0, &mut resource, &r).unwrap();
    assert_eq!(&resource, b"RSRC!");
}
#[test]
fn jfs_sparse_payload_reads_without_std() {
    use partmgr::fs_jfs::*;
    let r = resources();
    let volume = JfsVolume::open(
        Arc::new(Bytes(jfs_fixture::jfs_seed())),
        JfsReadLimits {
            blocks: 65536,
            inodes: 512,
            entries: 1024,
            pages: 1024,
            extents: 4096,
            work: 64 << 20,
        },
        &r,
    )
    .unwrap();
    let object = volume
        .lookup(&[NativeName::Utf16(jfs_fixture::name())], &r)
        .unwrap();
    let file = volume.open_file(&object, &r).unwrap();
    let mut out = vec![0xff; 4 * 4096 + 7];
    file.read_at(0, &mut out, &r).unwrap();
    assert!(out[4096..8192].iter().all(|b| *b == 0));
    assert!(out[12288..].iter().all(|b| *b == 0));
    assert!(out[..4096].iter().any(|b| *b != 0));
    eof(&file, &r);
}
#[test]
fn xfs_sparse_payload_reads_without_std() {
    use partmgr::fs_xfs::*;
    let r = resources();
    let fixture = xfs_fixture::xfs_seed();
    let expected = fixture[16 * 4096..18 * 4096].to_vec();
    let volume = XfsVolume::open(
        Arc::new(Bytes(fixture)),
        XfsReadLimits {
            allocation_groups: 8,
            inodes: 256,
            metadata_records: 4096,
            extent_records: 256,
            work: 1_000_000,
            log_bytes: 128 << 20,
        },
        &r,
    )
    .unwrap();
    let file = volume.open_file(67, &r).unwrap();
    let mut out = vec![17; 16384];
    file.read_at(0, &mut out, &r).unwrap();
    assert!(out[..4096].iter().all(|b| *b == 0));
    assert!(out[12288..].iter().all(|b| *b == 0));
    assert_eq!(&out[4096..12288], expected);
    eof(&file, &r);
}
#[test]
fn ntfs_resident_and_sparse_payloads_read_without_std() {
    use partmgr::fs_ntfs::*;
    let r = resources();
    let volume = NtfsVolume::open(
        Arc::new(Bytes(ntfs_fixture::fixture())),
        NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        &r,
    )
    .unwrap();
    let resident = volume.open_file(24, &r).unwrap();
    let mut small = [0; 8];
    assert_eq!(resident.read_at(0, &mut small, &r).unwrap(), 5);
    assert_eq!(&small[..5], b"hello");
    eof(&resident, &r);
    let sparse = volume.open_file(25, &r).unwrap();
    let mut out = [0xff; 1600];
    assert_eq!(sparse.read_at(0, &mut out, &r).unwrap(), 1536);
    assert!(out[..512].iter().all(|b| *b == 0x31));
    assert!(out[512..1024].iter().all(|b| *b == 0));
    assert!(out[1024..1280].iter().all(|b| *b == 0x72));
    assert!(out[1280..1536].iter().all(|b| *b == 0));
    eof(&sparse, &r);
}
