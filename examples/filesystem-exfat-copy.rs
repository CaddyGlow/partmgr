//! Content-only FAT/ext2/exFAT region -> nested exFAT image, with unpublished staging.
//! Source bytes must remain immutable for all inventory and deferred reads.
use partmgr::{
    fs_copy::{CopyLimits, CopyNamePolicy},
    fs_core::{Budget, Cancellation, Preservation, Resources, TreeSource},
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_builder::{ExfatBuildLimits, ExfatBuildNameProfile, ExfatBuildOptions},
    fs_exfat_copy::{ExfatCopyMetadataPolicy, ExfatCopyOptions, ExfatCopyPlan},
    fs_exfat_tree::{ExfatTreeLimits, ExfatTreeSource},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    fs_ext_audit::ExtAuditLimits,
    fs_fat::FatVolume,
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_fat_tree::FatTreeSource,
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
};
#[path = "support/destination.rs"]
mod destination_output;
use destination_output::{DestinationLayout, stage};
use std::{path::PathBuf, sync::Arc};
use virtdisk::{DiskView, RawDisk, ReadAt};
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
        .ok_or("usage: filesystem-exfat-copy [--source-profile fat|ext2|ext|exfat] SOURCE OFFSET LENGTH DEST OUTPUT_MIB --metadata-policy content-only-deterministic-defaults [--partition-table gpt|mbr]")?;
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
        Some("32") => 32 << 20,
        Some("64") => 64 << 20,
        _ => return Err("OUTPUT_MIB must be32or64".into()),
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
    let table_profile = match args.next().as_deref() {
        None => None,
        Some("--partition-table") => Some(args.next().ok_or("supply gpt or mbr")?),
        _ => return Err("unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = DestinationLayout::new(image_bytes, table_profile, 0x07)?;
    let resources = Resources {
        memory: Budget::new(512 << 20),
        cancellation: Cancellation::default(),
    };
    pipeline.raw(output.scheme.is_some());
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
    let mut options = image_options(image_bytes);
    if matches!(source_profile.as_str(), "ext2" | "ext") {
        options.names = CopyNamePolicy::StrictUtf8;
    }
    pipeline.complete(
        Layer::Source,
        Completion::Validated,
        "immutable source inventory and complete ownership audit",
    );
    pipeline.begin(Layer::Copy, FailureState::Unchanged, Recovery::None);
    let plan = ExfatCopyPlan::new(source, options, &resources)?;
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
        "name_conversion={} native_utf16=exact destination_comparison=recommended_exfat_table",
        if matches!(source_profile.as_str(), "ext2" | "ext") {
            "strict_utf8"
        } else {
            "fat_ascii_aliases_for_byte_names"
        }
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
    staged.as_file().set_len(output.disk_bytes)?;
    let mut storage = output.session(staged.path())?;
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
    println!(
        "filesystem_emit=completed region_offset={} region_bytes={}",
        output.offset, image_bytes
    );
    if output.scheme.is_some() {
        pipeline.begin(
            Layer::Partition,
            FailureState::UnpublishedStaging,
            Recovery::DiscardStaging,
        );
        output.commit_table(staged.path())?;
        pipeline.complete(
            Layer::Partition,
            Completion::Durable,
            "table commit and reopened type/range validation",
        );
    }
    pipeline.begin(
        Layer::Filesystem,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
    );
    let reopened = output.reopen(staged.path())?;
    let read_limits = ExfatReadLimits {
        max_chain_clusters: usize::try_from(image_bytes / 512)?,
        max_directory_slots: 32768,
        max_upcase_bytes: 131072,
    };
    let audit = stage(
        "filesystem allocation audit",
        audit_exfat(
            reopened,
            read_limits,
            ExfatAuditLimits {
                clusters: 500_000,
                entries: 4096,
                directory_slots: 1_000_000,
                work: 4_000_000,
                findings: 1024,
            },
            &resources,
        ),
    )?;
    if !audit.is_clean() {
        return Err("staged exFAT ownership/state audit failed; output remains unpublished".into());
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
    drop(plan);
    copy_pipeline::publish(staged, &destination, parent, &mut pipeline.report)?;
    println!(
        "publication=completed destination={}",
        destination.display()
    );
    println!(
        "publication_directory_flush=complete boot=unverified partition={} container=raw",
        output.scheme.as_deref().unwrap_or("standalone")
    );
    Ok(())
}
fn image_options(image_bytes: u64) -> ExfatCopyOptions {
    ExfatCopyOptions {
        image_bytes,
        filesystem: ExfatBuildOptions {
            cluster_shift: 3,
            volume_id: 0x45584350,
            name_profile: ExfatBuildNameProfile::RecommendedTable,
        },
        names: CopyNamePolicy::FatAsciiShortAliases,
        metadata: ExfatCopyMetadataPolicy::ContentOnlyDeterministicDefaults,
        limits: CopyLimits {
            objects: 4096,
            pages: 8192,
            page_entries: 64,
        },
        build_limits: ExfatBuildLimits {
            objects: 4096,
            name_units: 1_044_480,
            clusters: 500_000,
            depth: 256,
            directory_slots: 1_000_000,
        },
    }
}
