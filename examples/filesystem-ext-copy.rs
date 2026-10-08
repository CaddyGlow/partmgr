//! Content-only FAT/ext2/exFAT region -> classic ext2 image with explicit publication.
//! Source bytes must remain immutable for all inventory and deferred reads.
use partmgr::{
    codec::initialize_plan,
    fs_copy::CopyLimits,
    fs_core::{Budget, Cancellation, Preservation, Resources, TreeSource},
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_tree::{ExfatTreeLimits, ExfatTreeSource},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditLimits, audit as audit_ext},
    fs_ext_builder::{ExtBuildLimits, ExtBuildMetadata, ExtBuildOptions},
    fs_ext_copy::{ExtCopyMetadataPolicy, ExtCopyNamePolicy, ExtCopyOptions, ExtCopyPlan},
    fs_fat::FatVolume,
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_fat_tree::FatTreeSource,
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
    fs_storage::{BoundedSession, SectorGeometry},
    guid::Guid,
    layout::{DiskLayout, Geometry, GptLayout, LbaRange, MbrLayout},
    storage::FileStorage,
};
use std::{path::PathBuf, sync::Arc};
use virtdisk::{DiskView, RawDisk, ReadAt};
#[derive(Debug)]
struct OutputStageFailure {
    stage: &'static str,
    cause: Box<dyn std::error::Error + Send + Sync>,
}
impl std::fmt::Display for OutputStageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed; output was not published and temporary staging is discarded: {}",
            self.stage, self.cause
        )
    }
}
impl std::error::Error for OutputStageFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
fn stage<T, E: std::error::Error + Send + Sync + 'static>(
    name: &'static str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|cause| {
        Box::new(OutputStageFailure {
            stage: name,
            cause: Box::new(cause),
        }) as Box<dyn std::error::Error>
    })
}
fn limits() -> FatAuditLimits {
    FatAuditLimits {
        clusters: 500_000,
        entries: 4096,
        directory_slots: 32768,
        findings: 1024,
    }
}
#[path = "support/pipeline.rs"]
mod copy_pipeline;
use copy_pipeline::CopyPipeline;
use partmgr::fs_pipeline::{Completion, FailureState, Layer, Recovery};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipeline = CopyPipeline::new();
    let result = run(&mut pipeline);
    pipeline.finish(result.as_ref().err().map(|error| error.as_ref()));
    result
}
fn run(pipeline: &mut CopyPipeline) -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or("usage: filesystem-ext-copy [--source-profile fat|ext2|ext|exfat] SOURCE OFFSET LENGTH DEST OUTPUT_MIB --metadata-policy content-only-deterministic-defaults --names exact-bytes|bytes-and-utf16-to-utf8 [--partition-table gpt|mbr]")?;
    let (source_profile, source_path) = if first == "--source-profile" {
        (
            args.next().ok_or("supply source profile")?,
            args.next().ok_or("supply SOURCE")?,
        )
    } else {
        ("fat".to_string(), first)
    };
    let offset: u64 = args.next().ok_or("supply OFFSET")?.parse()?;
    let length: u64 = args.next().ok_or("supply LENGTH")?.parse()?;
    let destination = PathBuf::from(args.next().ok_or("supply DEST")?);
    let image_bytes = match args.next().as_deref() {
        Some("16") => 16 << 20,
        Some("32") => 32 << 20,
        Some("64") => 64 << 20,
        _ => return Err("OUTPUT_MIB must be 16, 32 or 64".into()),
    };
    if destination.try_exists()? {
        return Err("destination already exists; no staging output created".into());
    }
    if args.next().as_deref() != Some("--metadata-policy")
        || args.next().as_deref() != Some("content-only-deterministic-defaults")
    {
        return Err(
            "explicit --metadata-policy content-only-deterministic-defaults required".into(),
        );
    }
    if args.next().as_deref() != Some("--names") {
        return Err("explicit --names policy required".into());
    }
    let names = match args.next().as_deref() {
        Some("exact-bytes") => ExtCopyNamePolicy::ExactBytes,
        Some("bytes-and-utf16-to-utf8") => ExtCopyNamePolicy::BytesAndUtf16ToUtf8,
        _ => return Err("names must be exact-bytes or bytes-and-utf16-to-utf8".into()),
    };
    let table_profile = match args.next().as_deref() {
        None => None,
        Some("--partition-table") => Some(args.next().ok_or("supply gpt or mbr")?),
        _ => return Err("unexpected argument".into()),
    };
    if table_profile
        .as_deref()
        .is_some_and(|s| !matches!(s, "gpt" | "mbr"))
    {
        return Err("partition table must be gpt or mbr".into());
    }
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let region_start = if table_profile.is_some() { 1 << 20 } else { 0 };
    let disk_bytes = image_bytes + if table_profile.is_some() { 2 << 20 } else { 0 };
    let partition = LbaRange::new(region_start / 512, (region_start + image_bytes) / 512)?;
    let layout = match table_profile.as_deref() {
        Some("gpt") => {
            let mut table = GptLayout::initialize(
                Geometry::new(disk_bytes, 512)?,
                Guid::from_bytes([0x31; 16]),
                128,
                128,
            )?;
            table.create(
                1,
                "0fc63daf-8483-4772-8e79-3d69d8477de4".parse()?,
                Guid::from_bytes([0x32; 16]),
                partition,
            )?;
            Some(DiskLayout::Gpt(table))
        }
        Some("mbr") => {
            let mut table = MbrLayout::initialize(Geometry::new(disk_bytes, 512)?, 0x504d4558);
            table.create(1, 0x83, partition, false)?;
            Some(DiskLayout::Mbr(table))
        }
        _ => None,
    };
    let resources = Resources {
        memory: Budget::new(512 << 20),
        cancellation: Cancellation::default(),
    };
    pipeline.raw(layout.is_some());
    pipeline.begin(Layer::Source, FailureState::Unchanged, Recovery::None);
    let raw: Arc<dyn ReadAt> = Arc::new(RawDisk::open(source_path)?);
    let region: Arc<dyn ReadAt> = Arc::new(DiskView::new(raw, offset, length)?);
    let source: Arc<dyn TreeSource> = match source_profile.as_str() {
        "fat" => {
            let source_audit = audit_fat(region.clone(), limits(), &resources)?;
            if !source_audit.namespace_complete() || !source_audit.findings().is_empty() {
                return Err("source ownership/state audit failed; no destination written".into());
            }
            drop(source_audit);
            println!("source_profile=fat source_allocation_audit=complete");
            Arc::new(FatTreeSource::inventory(
                FatVolume::open(region)?,
                4096,
                500_000,
                32768,
                &resources,
            )?)
        }
        "ext2" | "ext" => {
            let audit = ExtAuditLimits {
                blocks: 1_000_000,
                inodes: 500_000,
                work: 32_000_000,
                directory_blocks: 500_000,
                directory_entries: 32768,
                findings: 1024,
            };
            let options = if source_profile == "ext2" {
                ReadOptions::Ext2 {
                    audit,
                    objects: 4096,
                    entries: 32768,
                    map_blocks: 500_000,
                    directory_slots: 32768,
                }
            } else {
                ReadOptions::Ext {
                    audit,
                    objects: 4096,
                    entries: 32768,
                    map_blocks: 500_000,
                    directory_slots: 32768,
                }
            };
            let image =
                ReadImage::open(region, options, AllocationPolicy::RequireClean, &resources)?;
            println!(
                "source_profile={source_profile} source_family={:?} source_allocation_audit=complete",
                image.profile().family
            );
            Arc::new(image)
        }
        "exfat" => {
            let cluster_limit = usize::try_from((length / 512).min(500_000))?;
            let read_limits = ExfatReadLimits {
                max_chain_clusters: cluster_limit,
                max_directory_slots: 32768,
                max_upcase_bytes: 131072,
            };
            let source_audit = audit_exfat(
                region.clone(),
                read_limits,
                ExfatAuditLimits {
                    clusters: cluster_limit,
                    entries: 4096,
                    directory_slots: 1_000_000,
                    work: 4_000_000,
                    findings: 1024,
                },
                &resources,
            )?;
            if !source_audit.is_clean() {
                return Err(
                    "source exFAT ownership/state audit failed; no destination written".into(),
                );
            }
            drop(source_audit);
            let volume = ExfatVolume::open(region, read_limits, &resources)?;
            let tree = ExfatTreeSource::inventory(
                volume,
                ExfatTreeLimits {
                    objects: 4096,
                    directory_clusters: cluster_limit,
                },
                &resources,
            )?;
            println!(
                "source_profile=exfat source_namespace=validated source_allocation_audit=complete"
            );
            Arc::new(tree)
        }
        _ => return Err("source profile must be fat,ext2,ext,exfat".into()),
    };
    pipeline.complete(
        Layer::Source,
        Completion::Validated,
        "immutable source inventory and complete ownership audit",
    );
    pipeline.begin(Layer::Copy, FailureState::Unchanged, Recovery::None);
    let plan = ExtCopyPlan::new(source, image_options(image_bytes, names), &resources)?;
    let transformations = plan
        .outcomes()
        .iter()
        .filter(|outcome| matches!(outcome.decision, Preservation::Transform { .. }))
        .count();
    println!(
        "copy_preflight=complete content_only=true source_stability=caller_guarantee metadata_policy=content_only_deterministic_defaults transformed_classes={transformations}"
    );
    let mut classes = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for outcome in plan.outcomes() {
        let counts = classes.entry(outcome.class).or_default();
        match outcome.decision {
            Preservation::Preserve => counts.0 += 1,
            Preservation::Transform { .. } => counts.1 += 1,
            Preservation::Reject { .. } => return Err("preflight metadata rejection".into()),
        }
    }
    for (class, (preserved, transformed)) in classes {
        println!("metadata_class={class} preserved={preserved} transformed={transformed}");
    }
    println!(
        "name_conversion={names:?} hardlinks=preserved uid=0 gid=0 file_mode=0644 directory_mode=0755 native_seconds=0"
    );
    pipeline.complete(
        Layer::Copy,
        Completion::Validated,
        "copy preflight; explicit content-only metadata and name policies",
    );
    pipeline.begin(
        Layer::Filesystem,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
    );
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.as_file().set_len(disk_bytes)?;
    let mut storage = BoundedSession::new(
        FileStorage::open(staged.path())?,
        region_start,
        image_bytes,
        SectorGeometry::new(Some(512), None)?,
    )?;
    let report = stage(
        "filesystem emission/verification",
        plan.emit(&mut storage, &resources),
    )?;
    drop(storage);
    pipeline.complete(
        Layer::Filesystem,
        Completion::Durable,
        "emission barriers and complete stream verification",
    );
    pipeline.begin(
        Layer::Copy,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
    );
    pipeline.complete(
        Layer::Copy,
        Completion::Validated,
        "complete declared stream models; explicit content-only transformations",
    );
    println!("filesystem_emit=completed region_offset={region_start} region_bytes={image_bytes}");
    if let Some(layout) = &layout {
        pipeline.begin(
            Layer::Partition,
            FailureState::UnpublishedStaging,
            Recovery::DiscardStaging,
        );
        let source = RawDisk::open(staged.path())?;
        let table_plan = stage("partition table planning", initialize_plan(&source, layout))?;
        let mut table_storage = FileStorage::open(staged.path())?;
        stage(
            "partition table commit",
            table_plan.commit(&mut table_storage),
        )?;
        drop(table_storage);
        let inspected = stage(
            "partition table reopen",
            DiskLayout::inspect(&RawDisk::open(staged.path())?, 512),
        )?;
        let matches = match inspected {
            DiskLayout::Gpt(table) => {
                table_profile.as_deref() == Some("gpt")
                    && table
                        .entries()
                        .first()
                        .is_some_and(|entry| entry.range() == Some(partition))
            }
            DiskLayout::Mbr(table) => {
                table_profile.as_deref() == Some("mbr")
                    && table
                        .entries()
                        .first()
                        .is_some_and(|entry| entry.range() == partition)
            }
        };
        if !matches {
            return Err("partition table reopen mismatch; output remains unpublished".into());
        }
        println!(
            "partition_commit=completed partition_reopen=validated scheme={}",
            table_profile.as_deref().unwrap()
        );
        pipeline.complete(
            Layer::Partition,
            Completion::Durable,
            "table commit and reopened range validation",
        );
    }
    pipeline.begin(
        Layer::Filesystem,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
    );
    let reopened: Arc<dyn ReadAt> = Arc::new(DiskView::new(
        Arc::new(RawDisk::open(staged.path())?),
        region_start,
        image_bytes,
    )?);
    let volume = stage("filesystem reopen", ExtVolume::open(reopened, &resources))?;
    let audit = stage(
        "filesystem allocation audit",
        audit_ext(
            &volume,
            ExtAuditLimits {
                blocks: 1_000_000,
                inodes: 500_000,
                work: 32_000_000,
                directory_blocks: 500_000,
                directory_entries: 32768,
                findings: 1024,
            },
            &resources,
        ),
    )?;
    if !audit.is_clean() {
        return Err(
            "staged ext2 ownership/reference audit failed; output remains unpublished".into(),
        );
    }
    println!(
        "filesystem_flush=complete reopened_audit=complete verified_bytes={} files={}",
        report.verified_bytes, report.files
    );
    pipeline.complete(
        Layer::Filesystem,
        Completion::Durable,
        "emission barriers and complete reopened allocation audit",
    );
    drop(audit);
    drop(volume);
    drop(plan);
    copy_pipeline::publish(staged, &destination, parent, &mut pipeline.report)?;
    println!(
        "publication=completed destination={}",
        destination.display()
    );
    println!(
        "publication_directory_flush=complete boot=unverified partition={} container=raw",
        table_profile.as_deref().unwrap_or("standalone")
    );
    Ok(())
}
fn image_options(image_bytes: u64, names: ExtCopyNamePolicy) -> ExtCopyOptions {
    ExtCopyOptions {
        image_bytes,
        filesystem: ExtBuildOptions {
            block_size: 1024,
            blocks_per_group: 8192,
            uuid: *b"partmgr-extcopy1",
        },
        names,
        metadata: ExtCopyMetadataPolicy::ContentOnlyDefaults(ExtBuildMetadata {
            file_permissions: 0o644,
            directory_permissions: 0o755,
            uid: 0,
            gid: 0,
            timestamp: 0,
        }),
        limits: CopyLimits {
            objects: 4096,
            pages: 8192,
            page_entries: 64,
        },
        build_limits: ExtBuildLimits {
            objects: 4096,
            links: 32768,
            name_bytes: 16 << 20,
            blocks: 1_000_000,
            work: 32_000_000,
            depth: 256,
        },
    }
}
