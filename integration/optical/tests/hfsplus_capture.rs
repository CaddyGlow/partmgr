#![cfg(feature = "native-writer")]
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
    fs_hfsplus_audit::HfsPlusAuditLimits,
    fs_hfsplus_tree::HfsPlusTreeSource,
};
use partmgr_optical::write::{ByteNames, WriteLimits, WritePolicy, stage_iso, stage_udf};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[path = "../../../tests/fixtures/hfsplus_clean.rs"]
mod fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
#[test]
fn hfs_resource_fork_cannot_be_silently_lost_during_optical_capture() {
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let volume = HfsPlusVolume::open(
        Arc::new(Bytes(fixture::hfsplus_seed(false))),
        HfsPlusReadLimits {
            blocks: 256,
            nodes: 64,
            records: 128,
            extents: 256,
            work: 2_000_000,
        },
        &r,
    )
    .unwrap();
    let tree = Arc::new(
        HfsPlusTreeSource::inventory(
            volume,
            HfsPlusAuditLimits {
                blocks: 256,
                objects: 128,
                depth: 16,
                work: 100_000,
                findings: 32,
            },
            &r,
        )
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let limits = WriteLimits {
        maximum_entries: 32,
        maximum_bytes: 1 << 20,
        maximum_extents: 64,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    };
    for udf in [false, true] {
        let result = if udf {
            stage_udf(
                tree.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::UdfOptions::default(),
            )
        } else {
            stage_iso(
                tree.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnly,
                directory.path(),
                &libmkiso::IsoOptions::default(),
            )
        };
        let error = match result {
            Ok(_) => panic!("resource fork must be preserved or rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("resource forks unsupported"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    let baseline = r.memory.used();
    let staged = stage_udf(
        tree.clone(),
        r.clone(),
        limits,
        WritePolicy::ContentOnlyResourceForkAsNamedStream,
        directory.path(),
        &libmkiso::UdfOptions {
            revision: libmkiso::UdfRevision::V201,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(staged.report().resource_forks_as_named_streams, 2);
    let bytes = std::fs::read(staged.path()).unwrap();
    let reader = libmkiso::UdfReader::open(&bytes, libmkiso::UdfLimits::default()).unwrap();
    let index = reader
        .entries()
        .iter()
        .position(|e| {
            e.stream
                .as_ref()
                .is_some_and(|s| s.name == "com.apple.ResourceFork")
                && e.size == 5
        })
        .unwrap();
    let stream = reader.entries()[index].stream.as_ref().unwrap();
    assert!(stream.owner.is_some());
    assert!(!stream.system);
    let mut fork = [0; 5];
    assert_eq!(reader.read_at(index, 0, &mut fork).unwrap(), 5);
    assert_eq!(&fork, b"RSRC!");
    let empty = reader
        .entries()
        .iter()
        .position(|e| {
            e.size == 0
                && e.stream
                    .as_ref()
                    .is_some_and(|s| s.name == "com.apple.ResourceFork")
        })
        .unwrap();
    assert!(
        reader.entries()[empty]
            .stream
            .as_ref()
            .unwrap()
            .owner
            .is_some()
    );
    assert_eq!(reader.read_at(empty, 0, &mut fork).unwrap(), 0);
    drop(staged);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    assert_eq!(r.memory.used(), baseline);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
