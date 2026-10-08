//! Hosted execution of the alloc-only library and caller-supplied portable I/O.
#![cfg(not(feature = "std"))]
use partmgr::io::ReadAt;
use partmgr::{fs_core::*, io, storage::Storage};
use std::sync::Arc;
const PAYLOAD: &[u8] = b"alloc-only payload alloc-only payload alloc-only payload alloc-only payload alloc-only payload alloc-only payload alloc-only payload alloc-only payload";
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
struct Target {
    bytes: Vec<u8>,
    flushes: usize,
}
impl Target {
    fn new(length: usize) -> Self {
        Self {
            bytes: vec![0xff; length],
            flushes: 0,
        }
    }
}
impl Storage for Target {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
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
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let count = bytes.len().min(997);
        let end = start
            .checked_add(count)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    }
}
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 42,
        generation: 1,
        native: vec![n],
    }
}
fn payload() -> Arc<dyn ReadAt> {
    Arc::new(Bytes(PAYLOAD.to_vec()))
}
fn verify(file: &dyn FileRead, r: &Resources) {
    let mut bytes = vec![0; PAYLOAD.len() + 16];
    let count = file.read_at(0, &mut bytes, r).unwrap();
    assert_eq!(&bytes[..count], PAYLOAD);
    assert_eq!(file.read_at(u64::MAX, &mut bytes, r).unwrap(), 0);
}
struct Tree;
struct File;
impl FileRead for File {
    fn identity(&self) -> &ObjectId {
        static ID: std::sync::OnceLock<ObjectId> = std::sync::OnceLock::new();
        ID.get_or_init(|| id(1))
    }
    fn len(&self) -> u64 {
        PAYLOAD.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        if at >= self.len() {
            return Ok(0);
        }
        let count = out.len().min(PAYLOAD.len() - at as usize);
        out[..count].copy_from_slice(&PAYLOAD[at as usize..at as usize + count]);
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        visitor(LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: ExtentKind::Data,
        })
    }
}
impl TreeSource for Tree {
    fn root(&self) -> ObjectId {
        id(0)
    }
    fn stability(&self) -> SourceStability {
        SourceStability::ImmutableSnapshot
    }
    fn revalidate(&self, object: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if *object != id(0) && *object != id(1) {
            return Err(Error::new(ErrorKind::StalePlan, "unknown fixture object"));
        }
        Ok(())
    }
    fn metadata(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(object, r)?;
        Budgeted::try_new(&r.memory, 256, || {
            Ok(Metadata {
                created: MetadataField::Absent,
                modified: MetadataField::Absent,
                accessed: MetadataField::Absent,
                owner: MetadataField::Absent,
                mode: MetadataField::Absent,
                security: MetadataField::Absent,
                attributes: vec![],
                native_flags: MetadataField::Absent,
                symlink_target: MetadataField::Absent,
                reparse_data: MetadataField::Absent,
            })
        })
    }
    fn directory_page(
        &self,
        object: &ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.revalidate(object, r)?;
        assert_eq!(*object, id(0));
        assert!(maximum > 0);
        assert!(continuation.is_none());
        let reservation = r.memory.reserve(256)?;
        Ok(DirectoryPage {
            entries: vec![DirectoryEntry {
                name: NativeName::Bytes(b"FILE.TXT".to_vec()),
                object: id(1),
                kind: ObjectKind::File,
            }],
            next: None,
            reservation,
        })
    }
    fn streams(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.revalidate(object, r)?;
        Budgeted::try_new(&r.memory, 128, || {
            Ok(if *object == id(0) {
                vec![]
            } else {
                vec![StreamInfo {
                    kind: StreamKind::Data,
                    length: PAYLOAD.len() as u64,
                }]
            })
        })
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(object, r)?;
        assert_eq!(*object, id(1));
        assert_eq!(*stream, StreamKind::Data);
        Ok(Arc::new(File))
    }
}
#[test]
fn fat_builder_emits_and_reads_without_std() {
    use partmgr::{fs_fat::*, fs_fat_builder::*};
    let r = resources();
    let length = 1440 * 1024;
    let plan = FatBuildPlan::new(
        length,
        FatBuildOptions {
            family: FatFamily::Fat12,
            sectors_per_cluster: 1,
            volume_id: 42,
        },
        &[FatBuildFile {
            name: "FILE.TXT".into(),
            source: payload(),
        }],
        &r,
    )
    .unwrap();
    let mut target = Target::new(length as usize);
    plan.emit(&mut target, &r).unwrap();
    assert_eq!(target.flushes, 1);
    let volume = FatVolume::open(Arc::new(Bytes(target.bytes))).unwrap();
    let directory = volume.root_directory(16, 128, &r).unwrap();
    let entry = directory
        .lookup(&NativeName::Bytes(b"FILE    TXT".to_vec()))
        .unwrap()
        .unwrap();
    verify(&volume.open_entry(entry, 16, &r).unwrap(), &r);
}
#[test]
fn exfat_builder_emits_and_reads_without_std() {
    use partmgr::{fs_exfat_builder::*, fs_exfat_volume::*};
    let r = resources();
    let length = 8 << 20;
    let plan = ExfatBuildPlan::new(
        length,
        ExfatBuildOptions {
            cluster_shift: 3,
            volume_id: 42,
            name_profile: ExfatBuildNameProfile::RecommendedTable,
        },
        &[ExfatBuildEntry {
            identity: id(1),
            parent: None,
            name: "FILE.TXT".encode_utf16().collect(),
            source: Some(ExfatBuildSource::ReadAt(payload())),
        }],
        ExfatBuildMetadataPolicy::DeterministicDefaults,
        ExfatBuildLimits {
            objects: 16,
            name_units: 256,
            clusters: 10000,
            depth: 8,
            directory_slots: 128,
        },
        &r,
    )
    .unwrap();
    let mut target = Target::new(length as usize);
    plan.emit(&mut target, &r).unwrap();
    let volume = ExfatVolume::open(
        Arc::new(Bytes(target.bytes)),
        ExfatReadLimits {
            max_chain_clusters: 10000,
            max_directory_slots: 128,
            max_upcase_bytes: 131072,
        },
        &r,
    )
    .unwrap();
    let directory = volume.root_directory(&r).unwrap();
    let entry = directory
        .lookup(&"FILE.TXT".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .unwrap();
    verify(&volume.open_file(entry, &r).unwrap(), &r);
}
#[test]
fn ext_builder_emits_and_reads_without_std() {
    use partmgr::{fs_ext::ExtVolume, fs_ext_builder::*};
    let r = resources();
    let length = 8 << 20;
    let plan = ExtBuildPlan::new(
        length,
        ExtBuildOptions {
            block_size: 1024,
            blocks_per_group: 4096,
            uuid: [42; 16],
        },
        vec![ExtBuildObject {
            identity: id(1),
            source: Some(ExtBuildSource::ReadAt(payload())),
        }],
        vec![ExtBuildLink {
            object: id(1),
            parent: None,
            name: b"FILE.TXT".to_vec(),
        }],
        ExtBuildMetadata {
            file_permissions: 0o644,
            directory_permissions: 0o755,
            uid: 0,
            gid: 0,
            timestamp: 946684800,
        },
        ExtBuildLimits {
            objects: 128,
            links: 128,
            name_bytes: 1024,
            blocks: 16384,
            work: 4_000_000,
            depth: 8,
        },
        &r,
    )
    .unwrap();
    let mut target = Target::new(length as usize);
    plan.emit(&mut target, &r).unwrap();
    let volume = ExtVolume::open(Arc::new(Bytes(target.bytes)), &r).unwrap();
    let directory = volume.directory(2, 16, 128, &r).unwrap();
    let entry = directory
        .entries()
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"FILE.TXT".to_vec()))
        .unwrap();
    verify(&volume.open_file(entry.inode, 16, &r).unwrap(), &r);
}
#[test]
fn hfsplus_builder_emits_and_reads_without_std() {
    use partmgr::{fs_copy::*, fs_hfsplus::*, fs_hfsplus_builder::*};
    let r = resources();
    let plan = HfsPlusBuildPlan::prepare(
        Arc::new(Tree),
        HfsPlusBuildOptions {
            allocation_block_bytes: 4096,
            blocks: 512,
            case: HfsPlusBuildCase::AsciiFold,
            volume_name: "Portable".encode_utf16().collect(),
            limits: CopyLimits {
                objects: 16,
                pages: 16,
                page_entries: 4,
            },
            names: CopyNamePolicy::StrictUtf8,
            metadata: HfsPlusBuildMetadata::ContentOnlyDefaults,
        },
        &r,
    )
    .unwrap();
    let mut target = Target::new(plan.image_bytes() as usize);
    plan.emit(&mut target, &r).unwrap();
    let volume = HfsPlusVolume::open(
        Arc::new(Bytes(target.bytes)),
        HfsPlusReadLimits {
            blocks: 4096,
            nodes: 1024,
            records: 1024,
            extents: 1024,
            work: 16 << 20,
        },
        &r,
    )
    .unwrap();
    let object = volume
        .lookup(
            &[NativeName::Utf16("FILE.TXT".encode_utf16().collect())],
            &r,
        )
        .unwrap();
    verify(
        &volume.open_fork(&object, &StreamKind::Data, &r).unwrap(),
        &r,
    );
}
#[test]
fn apfs_builder_emits_audits_and_reads_without_std() {
    use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_apfs_builder::*};
    let r = resources();
    let plan = ApfsBuildPlan::plan(
        Arc::new(Tree),
        ApfsBuildOptions {
            image_bytes: 2 << 20,
            container_uuid: [42; 16],
            volume_uuid: [43; 16],
            volume_label: b"Portable".to_vec(),
            names: ApfsBuildNames::ExactBytes,
            metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
                uid: 0,
                gid: 0,
                file_permissions: 0o644,
                directory_permissions: 0o755,
                timestamp: 1_500_000_000_000_000_000,
            }),
            limits: ApfsBuildLimits {
                objects: 128,
                occurrences: 256,
                name_bytes: 65536,
                depth: 32,
                blocks: 32768,
                work: 128 << 20,
                page_entries: 4,
            },
        },
        &r,
    )
    .unwrap();
    let mut target = Target::new(plan.image_bytes() as usize);
    let report = plan.emit(&mut target, &r).unwrap();
    let raw: Arc<dyn ReadAt> = Arc::new(Bytes(target.bytes));
    let limits = ApfsReadLimits {
        blocks: 32768,
        checkpoint_blocks: 256,
        objects: 256,
        records: 512,
        work: 128 << 20,
    };
    assert!(
        report
            .audit(
                raw.clone(),
                limits,
                ApfsAuditLimits {
                    blocks: 32768,
                    objects: 4096,
                    depth: 64,
                    work: 128 << 20,
                    findings: 64
                },
                &r
            )
            .unwrap()
            .is_clean()
    );
    let volume = ApfsVolume::open(
        ApfsContainer::open(raw, limits, &r).unwrap(),
        report.volume_oid,
        &r,
    )
    .unwrap();
    let object = volume
        .lookup(&[NativeName::Bytes(b"FILE.TXT".to_vec())], &r)
        .unwrap();
    verify(&volume.open_file(&object, &r).unwrap(), &r);
}
#[test]
fn jffs2_builder_emits_audits_and_reads_without_std() {
    use partmgr::{
        fs_flash::*, fs_jffs2::*, fs_jffs2_audit::*, fs_jffs2_builder::*, fs_jffs2_tree::*,
    };
    let r = resources();
    for endian in [Jffs2Endian::Little, Jffs2Endian::Big] {
        for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
            let geometry = FlashGeometry {
                layout: FlashLayout::LogicalNor,
                erased_byte: 255,
                programming: FlashProgramming::ClearBitsOnly,
                erase_bytes: 65536,
                program_bytes: 4,
            };
            let plan = Jffs2BuildPlan::from_tree_compressed(
                Arc::new(Tree),
                262144,
                Jffs2BuildOptions {
                    geometry,
                    endian,
                    names: Jffs2BuildNamePolicy::NativeBytesOnly,
                    metadata: Jffs2BuildMetadataPolicy::ReplaceWithDefaults(Jffs2BuildMetadata {
                        uid: 0,
                        gid: 0,
                        file_permissions: 0o644,
                        directory_permissions: 0o755,
                        symlink_permissions: 0o777,
                        timestamp: 123456,
                    }),
                    zero_nodes: true,
                },
                Jffs2BuildLimits {
                    objects: 16,
                    entries: 32,
                    native_bytes: 4096,
                    records: 128,
                    image_bytes: 1 << 20,
                    depth: 8,
                    work: 4096,
                    node_data_bytes: 4096,
                    scratch_bytes: 4096,
                },
                codec,
                &r,
            )
            .unwrap();
            let mut target = Target::new(262144);
            plan.emit(&mut target, &r).unwrap();
            let volume = Jffs2Volume::open_compressed(
                Arc::new(Bytes(target.bytes)),
                geometry,
                endian,
                Jffs2ReadLimits {
                    scan_bytes: 1 << 20,
                    nodes: 512,
                    inodes: 64,
                    fragments: 512,
                    native_bytes: 4096,
                    work: 1000000,
                },
                Jffs2CompressionLimits {
                    compressed_node_bytes: 4096,
                    decoded_node_bytes: 4096,
                    compressed_bytes: 1 << 20,
                    decoded_bytes: 1 << 20,
                    work: 4 << 20,
                },
                &r,
            )
            .unwrap();
            let tree = Jffs2TreeSource::inventory(
                volume,
                Jffs2AuditLimits {
                    entries: 128,
                    work: 128,
                    findings: 16,
                },
                &r,
            )
            .unwrap();
            let page = tree.directory_page(&tree.root(), None, 4, &r).unwrap();
            verify(
                tree.open_stream(&page.entries[0].object, &StreamKind::Data, &r)
                    .unwrap()
                    .as_ref(),
                &r,
            );
        }
    }
}

#[test]
fn gpt_edit_commit_and_backup_recovery_without_std() {
    use partmgr::{
        codec,
        guid::Guid,
        layout::{DiskLayout, Geometry, GptLayout, LbaRange},
        recovery::{RecoveryReport, RecoverySource},
        storage::StorageReader,
    };
    let mut target = Target::new(2 << 20);
    target.bytes.fill(0);
    let geometry = Geometry::new(target.bytes.len() as u64, 512).unwrap();
    let disk_id: Guid = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
    let kind: Guid = "0fc63daf-8483-4772-8e79-3d69d8477de4".parse().unwrap();
    let partition_id: Guid = "11223344-5566-7788-99aa-bbccddeeff00".parse().unwrap();
    let mut layout = GptLayout::initialize(geometry, disk_id, 128, 128).unwrap();
    layout
        .edit_batch(|edit| {
            edit.create(1, kind, partition_id, LbaRange::new(64, 128)?)?;
            edit.rename(1, "portable")
        })
        .unwrap();
    let proposal = DiskLayout::Gpt(layout);
    let plan = codec::initialize_plan(&StorageReader::new(&target).unwrap(), &proposal).unwrap();
    let reopened = codec::commit_and_inspect(&plan, &mut target, 512).unwrap();
    let DiskLayout::Gpt(gpt) = reopened else {
        panic!("expected GPT")
    };
    assert_eq!(gpt.entries()[0].name().to_string().unwrap(), "portable");
    assert!(target.flushes >= 3);
    target.bytes[512 + 16] ^= 1;
    let reader = StorageReader::new(&target).unwrap();
    let report = RecoveryReport::inspect(&reader, 512, &[]).unwrap();
    let repair = report.repair_plan(&reader, RecoverySource::Backup).unwrap();
    codec::commit_and_inspect(&repair, &mut target, 512).unwrap();
}
