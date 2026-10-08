#![cfg(feature = "native-writer")]
use partmgr::{
    fs_apfs::ApfsReadLimits,
    fs_apfs_audit::ApfsAuditLimits,
    fs_core::{Budget, Cancellation, Resources},
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
};
use partmgr_optical::write::{ByteNames, WriteLimits, WritePolicy, stage_iso, stage_udf};
use std::sync::Arc;
#[path = "../../../tests/fixtures/apfs_clean.rs"]
#[allow(dead_code)]
mod fixture;

#[test]
fn apfs_resource_fork_requires_explicit_udf_named_stream_transformation() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.apfs");
    std::fs::write(&source_path, fixture::apfs_seed()).unwrap();
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let image = Arc::new(
        ReadImage::open(
            Arc::new(virtdisk::RawDisk::open(&source_path).unwrap()),
            ReadOptions::Apfs {
                read: ApfsReadLimits {
                    blocks: 65536,
                    checkpoint_blocks: 256,
                    objects: 256,
                    records: 256,
                    work: 64 << 20,
                },
                audit: ApfsAuditLimits {
                    blocks: 65536,
                    objects: 512,
                    depth: 32,
                    work: 64 << 20,
                    findings: 64,
                },
                volume_oid: 1026,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap(),
    );
    let limits = WriteLimits {
        maximum_entries: 32,
        maximum_bytes: 1 << 20,
        maximum_extents: 64,
        page_entries: 8,
        byte_names: ByteNames::Utf8,
    };
    let baseline = r.memory.used();
    assert!(
        stage_udf(
            image.clone(),
            r.clone(),
            limits.clone(),
            WritePolicy::ContentOnly,
            directory.path(),
            &libmkiso::UdfOptions {
                revision: libmkiso::UdfRevision::V201,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), baseline);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    for iso in [false, true] {
        let result = if iso {
            stage_iso(
                image.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnlyResourceForkAsNamedStream,
                directory.path(),
                &libmkiso::IsoOptions::default(),
            )
        } else {
            stage_udf(
                image.clone(),
                r.clone(),
                limits.clone(),
                WritePolicy::ContentOnlyResourceForkAsNamedStream,
                directory.path(),
                &libmkiso::UdfOptions {
                    revision: libmkiso::UdfRevision::V102,
                    ..Default::default()
                },
            )
        };
        assert!(result.is_err());
        assert_eq!(r.memory.used(), baseline);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let staged = stage_udf(
        image.clone(),
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
    assert_eq!(staged.report().resource_forks_as_named_streams, 1);
    assert_eq!(staged.report().streams, 1);
    let bytes = std::fs::read(staged.path()).unwrap();
    let reader = libmkiso::UdfReader::open(&bytes, libmkiso::UdfLimits::default()).unwrap();
    let data_index = reader
        .entries()
        .iter()
        .position(|e| e.name == "Aé-file" && e.stream.is_none())
        .unwrap();
    let fork_index = reader
        .entries()
        .iter()
        .position(|e| {
            e.stream
                .as_ref()
                .is_some_and(|s| s.name == "com.apple.ResourceFork")
        })
        .unwrap();
    let fork = &reader.entries()[fork_index];
    assert_eq!(fork.stream.as_ref().unwrap().owner, Some(data_index));
    let mut resource = [0; 8];
    assert_eq!(reader.read_at(fork_index, 0, &mut resource).unwrap(), 8);
    assert_eq!(&resource, b"resource");
    let mut data = vec![0xaa; 16397];
    assert_eq!(
        reader.read_at(data_index, 0, &mut data).unwrap(),
        data.len()
    );
    for (i, value) in data.into_iter().enumerate() {
        assert_eq!(
            value,
            if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                0
            } else {
                (i % 4096 * 17 % 251) as u8
            }
        );
    }
    let staged_path = staged.path().to_path_buf();
    drop(staged);
    assert!(!staged_path.exists());
    assert_eq!(r.memory.used(), baseline);
    drop(image);
    assert_eq!(r.memory.used(), 0);
}
