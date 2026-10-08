use partmgr::{
    fs_core::{Budget, Cancellation, NativeName, Resources, StreamKind, TreeSource},
    fs_exfat_audit::ExfatAuditLimits,
    fs_exfat_tree::ExfatTreeLimits,
    fs_exfat_volume::ExfatReadLimits,
    fs_ext_audit::ExtAuditLimits,
    fs_fat_audit::FatAuditLimits,
    fs_image::{AllocationEvidence, AllocationPolicy, ReadImage, ReadOptions},
    layout::DiskLayout,
};
use std::{io::Read, path::PathBuf, sync::Arc};
use virtdisk::{DiskView, Image, ImageFormat, ReadAt};

fn options(family: &str) -> ReadOptions {
    match family {
        "ext16" => ReadOptions::Ext2 {
            audit: ExtAuditLimits {
                blocks: 65536,
                inodes: 16384,
                work: 64 << 20,
                directory_blocks: 4096,
                directory_entries: 4096,
                findings: 128,
            },
            objects: 4096,
            entries: 4096,
            map_blocks: 65536,
            directory_slots: 4096,
        },
        "exfat32" => ReadOptions::Exfat {
            read: ExfatReadLimits {
                max_chain_clusters: 131072,
                max_directory_slots: 4096,
                max_upcase_bytes: 131072,
            },
            audit: ExfatAuditLimits {
                clusters: 131072,
                entries: 4096,
                directory_slots: 8192,
                work: 64 << 20,
                findings: 128,
            },
            tree: ExfatTreeLimits {
                objects: 4096,
                directory_clusters: 4096,
            },
        },
        _ => ReadOptions::Fat {
            audit: FatAuditLimits {
                clusters: 200000,
                entries: 4096,
                directory_slots: 8192,
                findings: 128,
            },
            objects: 4096,
        },
    }
}

fn native_name(family: &str, alias: &str, raw: &[u8]) -> NativeName {
    if family == "exfat32" {
        NativeName::Utf16(alias.encode_utf16().collect())
    } else {
        NativeName::Bytes(raw.to_vec())
    }
}

#[test]
#[ignore = "explicit retained native matrix requires PARTMGR_PARTITION_RAW, PARTMGR_PARTITION_CONTAINERS and fresh PARTMGR_PARTITION_READ_EVIDENCE"]
fn partitioned_three_payloads_through_normal_and_compressed_qcow2() {
    let raw = PathBuf::from(std::env::var_os("PARTMGR_PARTITION_RAW").expect("raw checkpoint"));
    let containers = PathBuf::from(
        std::env::var_os("PARTMGR_PARTITION_CONTAINERS").expect("converted checkpoint"),
    );
    let evidence =
        PathBuf::from(std::env::var_os("PARTMGR_PARTITION_READ_EVIDENCE").expect("fresh evidence"));
    std::fs::create_dir(&evidence).expect("evidence must be absent");
    let mut receipt = String::from(
        "scope=immutable registry container logical equality and common-facade native three-payload matrix; no editing or firmware claim\n",
    );
    for (family, length) in [
        ("fat12", 1474560),
        ("fat16", 32 << 20),
        ("fat32", 64 << 20),
        ("exfat32", 32 << 20),
        ("ext16", 16 << 20),
    ] {
        for scheme in ["gpt", "mbr"] {
            let label = format!("{family}-{scheme}");
            for profile in ["normal", "compressed"] {
                let image = Image::open(
                    containers.join(&label).join(format!("{profile}.qcow2")),
                    Some(ImageFormat::Qcow2),
                )
                .unwrap();
                let mut raw_file = std::fs::File::open(raw.join(format!("{label}.img"))).unwrap();
                let disk_len = raw_file.metadata().unwrap().len();
                assert_eq!(image.len(), disk_len);
                let mut expected = vec![0; 65536];
                let mut actual = vec![0; 65536];
                for offset in (0..disk_len).step_by(65536) {
                    let count = usize::try_from((disk_len - offset).min(65536)).unwrap();
                    raw_file.read_exact(&mut expected[..count]).unwrap();
                    image.read_exact_at(offset, &mut actual[..count]).unwrap();
                    assert_eq!(actual[..count], expected[..count]);
                }
                let resources = Resources {
                    memory: Budget::new(256 << 20),
                    cancellation: Cancellation::default(),
                };
                let range = match DiskLayout::inspect(&image, 512).unwrap() {
                    DiskLayout::Gpt(table) => {
                        assert_eq!(scheme, "gpt");
                        table.entries().first().unwrap().range().unwrap()
                    }
                    DiskLayout::Mbr(table) => {
                        assert_eq!(scheme, "mbr");
                        table.entries().first().unwrap().range()
                    }
                };
                let offset = range.start().checked_mul(512).unwrap();
                let region_length = range.sectors().checked_mul(512).unwrap();
                assert_eq!(offset, 1 << 20);
                assert_eq!(region_length, length);
                let region: Arc<dyn ReadAt> =
                    Arc::new(DiskView::new(Arc::new(image), offset, region_length).unwrap());
                let fs = ReadImage::open(
                    region,
                    options(family),
                    AllocationPolicy::RequireClean,
                    &resources,
                )
                .unwrap();
                assert_eq!(
                    fs.allocation_evidence(),
                    AllocationEvidence::CleanProfileAudit
                );
                let root = fs.directory_page(&fs.root(), None, 16, &resources).unwrap();
                let nest = root
                    .entries
                    .iter()
                    .find(|e| e.name == native_name(family, "NEST", b"NEST       "))
                    .unwrap();
                let nested = fs
                    .directory_page(&nest.object, None, 16, &resources)
                    .unwrap();
                let models = [
                    (
                        native_name(family, "PAYLOAD.BIN", b"PAYLOAD BIN"),
                        vec![0x76; 512],
                        false,
                    ),
                    (
                        native_name(family, "BIG.BIN", b"BIG     BIN"),
                        (0..4099).map(|i| ((i * 37 + 11) % 251) as u8).collect(),
                        false,
                    ),
                    (
                        native_name(family, "CHILD.BIN", b"CHILD   BIN"),
                        (0..1025).map(|i| ((i * 19 + 7) % 253) as u8).collect(),
                        true,
                    ),
                ];
                let mut handles = Vec::new();
                for (name, model, child) in models {
                    let entries = if child {
                        &nested.entries
                    } else {
                        &root.entries
                    };
                    let object = &entries.iter().find(|e| e.name == name).unwrap().object;
                    handles.push((
                        fs.open_stream(object, &StreamKind::Data, &resources)
                            .unwrap(),
                        model,
                    ));
                }
                drop(nested);
                drop(root);
                drop(fs);
                for (index, (file, model)) in handles.iter().enumerate() {
                    assert_eq!(file.len(), model.len() as u64);
                    let mut bytes = vec![0; model.len()];
                    for offset in (0..bytes.len()).step_by(73) {
                        let end = (offset + 73).min(bytes.len());
                        assert_eq!(
                            file.read_at(offset as u64, &mut bytes[offset..end], &resources)
                                .unwrap(),
                            end - offset
                        );
                    }
                    assert_eq!(&bytes, model);
                    std::fs::write(
                        evidence.join(format!("{label}-{profile}-{index}.bin")),
                        bytes,
                    )
                    .unwrap();
                }
                resources.cancellation.cancel();
                for (file, _) in &handles {
                    assert!(file.read_at(file.len(), &mut [], &resources).is_err());
                }
                drop(handles);
                assert_eq!(resources.memory.used(), 0);
                receipt.push_str(&format!("case={label}-{profile} logical_bytes={disk_len} payloads=3 retained_owner_drop=true cancelled_eof=true refunded=true\n"));
            }
        }
    }
    receipt.push_str("status=passed\n");
    std::fs::write(evidence.join("receipt.txt"), receipt).unwrap();
}
