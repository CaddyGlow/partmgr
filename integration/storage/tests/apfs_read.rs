use partmgr::{
    fs_apfs::ApfsReadLimits,
    fs_apfs_audit::ApfsAuditLimits,
    fs_core::{Budget, Cancellation, NativeName, Resources, StreamKind, TreeSource},
    fs_image::{AllocationEvidence, AllocationPolicy, ReadImage, ReadOptions},
};
use std::{io::Read, path::PathBuf, sync::Arc};
use virtdisk::{DiskView, Image, ImageFormat, ReadAt};

#[test]
#[cfg(target_os = "linux")]
#[ignore = "explicit native APFS converted-image gate requires PARTMGR_APFS_CONTAINER_RAW, PARTMGR_APFS_CONTAINER_IMAGES and fresh PARTMGR_APFS_CONTAINER_EVIDENCE"]
fn normal_and_compressed_qcow2_partitioned_apfs_facade_and_retained_fork() {
    let raw =
        PathBuf::from(std::env::var_os("PARTMGR_APFS_CONTAINER_RAW").expect("supply raw image"));
    let images = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_CONTAINER_IMAGES")
            .expect("supply converted images directory"),
    );
    let evidence = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_CONTAINER_EVIDENCE")
            .expect("supply fresh evidence directory"),
    );
    std::fs::create_dir(&evidence).expect("evidence destination must be absent");
    let raw_length = raw.metadata().unwrap().len();
    assert_eq!(raw_length, 66 << 20, "explicit64MiB partitioned profile");
    let mut receipt = format!(
        "scope=registry virtdisk normal/compressed QCOW2 logical equality and partitioned APFS common-facade complete allocation/payload/fork; native filesystem checks are separate\nraw={}\n",
        raw.display()
    );
    for profile in ["normal", "compressed"] {
        let path = images.join(format!("{profile}.qcow2"));
        let image = Image::open(&path, Some(ImageFormat::Qcow2)).unwrap();
        assert_eq!(image.len(), raw_length);
        let mut source = std::fs::File::open(&raw).unwrap();
        let mut expected = vec![0; 1 << 20];
        let mut actual = vec![0; 1 << 20];
        let mut offset = 0;
        while offset < raw_length {
            let count = usize::try_from((raw_length - offset).min(expected.len() as u64)).unwrap();
            source.read_exact(&mut expected[..count]).unwrap();
            image.read_exact_at(offset, &mut actual[..count]).unwrap();
            assert_eq!(actual[..count], expected[..count], "logical offset{offset}");
            offset += count as u64;
        }
        let resources = Resources {
            memory: Budget::new(1 << 30),
            cancellation: Cancellation::default(),
        };
        let region: Arc<dyn ReadAt> =
            Arc::new(DiskView::new(Arc::new(image), 1 << 20, 64 << 20).unwrap());
        let filesystem = ReadImage::open(
            region,
            ReadOptions::Apfs {
                read: ApfsReadLimits {
                    blocks: 32768,
                    checkpoint_blocks: 256,
                    objects: 2048,
                    records: 8192,
                    work: 512 << 20,
                },
                audit: ApfsAuditLimits {
                    blocks: 32768,
                    objects: 4096,
                    depth: 32,
                    work: 512 << 20,
                    findings: 1024,
                },
                volume_oid: 1026,
            },
            AllocationPolicy::RequireClean,
            &resources,
        )
        .unwrap();
        assert_eq!(
            filesystem.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        let page = filesystem
            .directory_page(&filesystem.root(), None, 16, &resources)
            .unwrap();
        let object = page
            .entries
            .iter()
            .find(|entry| entry.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
            .unwrap()
            .object
            .clone();
        let data = filesystem
            .open_stream(&object, &StreamKind::Data, &resources)
            .unwrap();
        let fork = filesystem
            .open_stream(&object, &StreamKind::ResourceFork, &resources)
            .unwrap();
        drop(page);
        drop(filesystem);
        assert_eq!(data.len(), 16397);
        let mut bytes = vec![0; 16397];
        let mut done = 0;
        while done < bytes.len() {
            let end = (done + 73).min(bytes.len());
            let count = data
                .read_at(done as u64, &mut bytes[done..end], &resources)
                .unwrap();
            assert!(count > 0 && count <= end - done);
            done += count;
        }
        for (index, byte) in bytes.iter().enumerate() {
            let expected = if (4096..8192).contains(&index) || (12288..16384).contains(&index) {
                0
            } else {
                (index % 4096 * 17 % 251) as u8
            };
            assert_eq!(*byte, expected, "full payload offset{index}");
        }
        let mut fork_bytes = [0; 8];
        assert_eq!(fork.len(), 8);
        assert_eq!(fork.read_at(0, &mut fork_bytes, &resources).unwrap(), 8);
        assert_eq!(&fork_bytes, b"resource");
        resources.cancellation.cancel();
        assert!(data.read_at(data.len(), &mut [], &resources).is_err());
        assert!(fork.read_at(fork.len(), &mut [], &resources).is_err());
        drop(data);
        drop(fork);
        assert_eq!(resources.memory.used(), 0);
        std::fs::write(evidence.join(format!("{profile}-data.bin")), bytes).unwrap();
        std::fs::write(evidence.join(format!("{profile}-fork.bin")), fork_bytes).unwrap();
        receipt.push_str(&format!("profile={profile} image={} logical_bytes={raw_length} complete_data_bytes=16397 complete_fork_bytes=8 owner_drop_retention=true cancelled_eof_rejected=true reservations_refunded=true\n", path.display()));
    }
    receipt.push_str("status=passed\n");
    std::fs::write(evidence.join("receipt.txt"), receipt).unwrap();
}
