//! Content-only FAT/ext2/exFAT region -> nested FAT image, with unpublished staging.
//! Source bytes must remain immutable for all inventory and deferred reads.
use partmgr::{
    fs_copy::{CopyLimits, CopyNamePolicy, FatCopyOptions, FatCopyPlan},
    fs_core::{Budget, Cancellation, Preservation, Resources, TreeSource},
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_tree::{ExfatTreeLimits, ExfatTreeSource},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    fs_ext_audit::ExtAuditLimits,
    fs_fat::{FatFamily, FatVolume},
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_fat_builder::{FatBuildOptions, FatTreeMetadataPolicy},
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or("usage: filesystem-fat-copy [--source-profile fat|ext2|ext|exfat] SOURCE OFFSET LENGTH DEST FAT_FAMILY [--partition-table gpt|mbr]")?;
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
    let (family, image_bytes) = match args.next().as_deref() {
        Some("12") => (FatFamily::Fat12, 1440 * 1024),
        Some("16") => (FatFamily::Fat16, 32 * 1024 * 1024),
        Some("32") => (FatFamily::Fat32, 64 * 1024 * 1024),
        _ => return Err("FAT_FAMILY must be 12,16,32".into()),
    };
    if destination.try_exists()? {
        return Err("destination already exists; no staging output created".into());
    }
    let table_profile = match args.next().as_deref() {
        None => None,
        Some("--partition-table") => Some(args.next().ok_or("supply gpt or mbr")?),
        _ => return Err("unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = DestinationLayout::new(
        image_bytes,
        table_profile,
        match family {
            FatFamily::Fat12 => 0x01,
            FatFamily::Fat16 => 0x06,
            FatFamily::Fat32 => 0x0c,
        },
    )?;
    let resources = Resources {
        memory: Budget::new(512 << 20),
        cancellation: Cancellation::default(),
    };
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
    let mut options = image_options(family, image_bytes);
    if matches!(source_profile.as_str(), "ext2" | "ext") {
        options.names = CopyNamePolicy::StrictUtf8;
    }
    let plan = FatCopyPlan::new(source, options, &resources)?;
    let transformations = plan
        .outcomes()
        .iter()
        .filter(|outcome| matches!(outcome.decision, Preservation::Transform { .. }))
        .count();
    println!(
        "copy_preflight=complete content_only=true source_stability=caller_guarantee transformed_classes={transformations}"
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
    println!(
        "filesystem_emit=completed region_offset={} region_bytes={}",
        output.offset, image_bytes
    );
    output.commit_table(staged.path())?;
    let reopened = output.reopen(staged.path())?;
    let audit = stage(
        "filesystem allocation audit",
        audit_fat(reopened, limits(), &resources),
    )?;
    if !audit.namespace_complete() || !audit.findings().is_empty() {
        return Err("staged FAT ownership/state audit failed; output remains unpublished".into());
    }
    println!(
        "filesystem_flush=complete reopened_audit=complete verified_bytes={} files={}",
        report.verified_bytes, report.files
    );
    drop(audit);
    drop(plan);
    staged.persist_noclobber(&destination)?;
    println!(
        "publication=completed destination={}",
        destination.display()
    );
    std::fs::File::open(parent)?.sync_all().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "image published at {}; publication-directory durability uncertain: {error}",
                destination.display()
            ),
        )
    })?;
    println!(
        "publication_directory_flush=complete boot=unverified partition={} container=raw",
        output.scheme.as_deref().unwrap_or("standalone")
    );
    Ok(())
}
fn image_options(family: FatFamily, image_bytes: u64) -> FatCopyOptions {
    FatCopyOptions {
        image_bytes,
        filesystem: FatBuildOptions {
            family,
            sectors_per_cluster: 1,
            volume_id: 0x46534350,
        },
        names: CopyNamePolicy::FatAsciiShortAliases,
        metadata: FatTreeMetadataPolicy::DeterministicDefaults,
        limits: CopyLimits {
            objects: 4096,
            pages: 8192,
            page_entries: 64,
        },
    }
}
