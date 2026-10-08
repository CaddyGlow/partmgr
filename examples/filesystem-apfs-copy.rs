//! Explicit content-only APFS region reauthoring into an unpublished native image.
//! Source bytes must remain immutable throughout inventory and deferred reads.
use partmgr::{
    fs_apfs::ApfsReadLimits,
    fs_apfs_audit::ApfsAuditLimits,
    fs_apfs_builder::{
        ApfsBuildDefaults, ApfsBuildLimits, ApfsBuildMetadata, ApfsBuildNames, ApfsBuildOptions,
        ApfsBuildPlan,
    },
    fs_core::{Budget, Cancellation, Resources},
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
    fs_pipeline::{Completion, FailureState, Layer, Outcome, PipelineReport, Recovery},
};
#[path = "support/destination.rs"]
#[allow(dead_code)]
mod destination_output;
use destination_output::{DestinationLayout, stage};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use virtdisk::{DiskView, RawDisk, ReadAt};
#[path = "support/pipeline.rs"]
#[allow(dead_code)]
mod copy_pipeline;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = PipelineReport::new();
    let result = run(&mut report);
    if result.is_ok() {
        print!("{report}");
    } else {
        eprint!("{report}");
    }
    result
}
fn run(pipeline: &mut PipelineReport) -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let source_path = args.next().ok_or("usage: filesystem-apfs-copy SOURCE OFFSET LENGTH VOLUME_OID DEST OUTPUT_MIB --metadata-policy content-only-deterministic-defaults [--partition-table gpt|mbr]")?;
    let offset: u64 = args.next().ok_or("supply OFFSET")?.parse()?;
    let length: u64 = args.next().ok_or("supply LENGTH")?.parse()?;
    let volume_oid: u64 = args.next().ok_or("supply explicit VOLUME_OID")?.parse()?;
    let destination = PathBuf::from(args.next().ok_or("supply DEST")?);
    let mib: u64 = args.next().ok_or("supply OUTPUT_MIB")?.parse()?;
    if !(1..=128).contains(&mib) {
        return Err("OUTPUT_MIB must be 1 through 128".into());
    }
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
    let scheme = match args.next().as_deref() {
        None => None,
        Some("--partition-table") => Some(args.next().ok_or("supply gpt or mbr")?),
        _ => return Err("unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let image_bytes = mib << 20;
    let output = DestinationLayout::with_type(
        image_bytes,
        scheme,
        0xaf,
        "7c3457ef-0000-11aa-aa11-00306543ecac".parse()?,
    )?;
    pipeline.record(
        Layer::Container,
        Outcome::NotApplicable {
            reason: "standalone raw output; no virtual-container conversion".into(),
        },
    );
    if output.scheme.is_none() {
        pipeline.record(
            Layer::Partition,
            Outcome::NotApplicable {
                reason: "standalone filesystem output".into(),
            },
        );
    }
    let resources = Resources {
        memory: Budget::new(1 << 30),
        cancellation: Cancellation::default(),
    };
    let read = ApfsReadLimits {
        blocks: 32768,
        checkpoint_blocks: 256,
        objects: 2048,
        records: 8192,
        work: 512 << 20,
    };
    let audit = ApfsAuditLimits {
        blocks: 32768,
        objects: 4096,
        depth: 32,
        work: 512 << 20,
        findings: 1024,
    };
    let region = pipeline.observe(
        Layer::Source,
        "immutable bounded source opening",
        Completion::Validated,
        FailureState::Unchanged,
        Recovery::None,
        (|| -> Result<Arc<dyn ReadAt>, Box<dyn std::error::Error>> {
            let raw: Arc<dyn ReadAt> = Arc::new(RawDisk::open(source_path)?);
            Ok(Arc::new(DiskView::new(raw, offset, length)?))
        })(),
    )?;
    let source = pipeline.observe(
        Layer::Source,
        "immutable APFS inventory and complete allocation audit",
        Completion::Validated,
        FailureState::Unchanged,
        Recovery::None,
        stage(
            "source inventory/audit",
            ReadImage::open(
                region,
                ReadOptions::Apfs {
                    read,
                    audit,
                    volume_oid,
                },
                AllocationPolicy::RequireClean,
                &resources,
            ),
        ),
    )?;
    let plan = pipeline.observe(
        Layer::Filesystem,
        "native builder preflight and explicit metadata policy",
        Completion::Validated,
        FailureState::Unchanged,
        Recovery::None,
        stage(
            "filesystem preflight",
            ApfsBuildPlan::plan(
                Arc::new(source),
                ApfsBuildOptions {
                    image_bytes,
                    container_uuid: [0x71; 16],
                    volume_uuid: [0x72; 16],
                    volume_label: b"Partmgr authored".to_vec(),
                    names: ApfsBuildNames::ExactBytes,
                    metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
                        uid: 501,
                        gid: 20,
                        file_permissions: 0o640,
                        directory_permissions: 0o750,
                        timestamp: 0,
                    }),
                    limits: ApfsBuildLimits {
                        objects: 4096,
                        occurrences: 8192,
                        name_bytes: 1 << 20,
                        depth: 32,
                        blocks: 32768,
                        work: 512 << 20,
                        page_entries: 128,
                    },
                },
                &resources,
            ),
        ),
    )?;
    for outcome in plan.outcomes() {
        println!(
            "metadata_class={} inspection={:?} decision={:?}",
            outcome.class, outcome.inspection, outcome.decision
        );
    }
    println!(
        "source_profile=apfs source_allocation_audit=complete names=exact_utf8_bytes metadata=explicit_defaults source_volume_oid={volume_oid}"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (staged, mut storage) = pipeline.observe(
        Layer::Filesystem,
        "unpublished bounded output preparation",
        Completion::Validated,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
        (|| -> Result<_, Box<dyn std::error::Error>> {
            let staged = tempfile::NamedTempFile::new_in(parent)?;
            staged.as_file().set_len(output.disk_bytes)?;
            let storage = output.session(staged.path())?;
            Ok((staged, storage))
        })(),
    )?;
    let report = pipeline.observe(
        Layer::Filesystem,
        "native emission barriers and complete stream verification",
        Completion::Durable,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
        stage(
            "filesystem emission/verification",
            plan.emit(&mut storage, &resources),
        ),
    )?;
    pipeline.record(Layer::Copy, Outcome::Completed { assurance: Completion::Validated, detail: "complete DATA/resource-fork models; explicit content-only metadata defaults, not faithful metadata preservation".into() });
    drop(storage);
    if output.scheme.is_some() {
        pipeline.observe(
            Layer::Partition,
            "table commit and reopened type/range validation",
            Completion::Durable,
            FailureState::UnpublishedStaging,
            Recovery::DiscardStaging,
            output.commit_table(staged.path()),
        )?;
    }
    let reopened = pipeline.observe(
        Layer::Filesystem,
        "staged filesystem reopening",
        Completion::Durable,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
        output.reopen(staged.path()),
    )?;
    let proof = pipeline.observe(
        Layer::Filesystem,
        "emission barriers and complete reopened allocation audit",
        Completion::Durable,
        FailureState::UnpublishedStaging,
        Recovery::DiscardStaging,
        stage(
            "filesystem reopened allocation audit",
            report.audit(reopened, read, audit, &resources),
        ),
    )?;
    if !proof.is_complete() || !proof.is_clean() {
        pipeline.record(
            Layer::Filesystem,
            Outcome::Failed {
                state: FailureState::UnpublishedStaging,
                reason: "staged APFS ownership audit is incomplete or unclean".into(),
                recovery: Recovery::DiscardStaging,
            },
        );
        return Err("staged APFS ownership audit failed; output remains unpublished".into());
    }
    drop(proof);
    drop(plan);
    if resources.memory.used() != 0 {
        pipeline.record(
            Layer::Copy,
            Outcome::Failed {
                state: FailureState::UnpublishedStaging,
                reason: "retained filesystem reservations did not refund".into(),
                recovery: Recovery::DiscardStaging,
            },
        );
        return Err(
            "retained filesystem reservations did not refund; output remains unpublished".into(),
        );
    }
    println!(
        "filesystem_flush=complete reopened_audit=complete verified_bytes={} files={} output_volume_oid={}",
        report.image_bytes, report.files, report.volume_oid
    );
    copy_pipeline::publish(staged, &destination, parent, pipeline)?;
    println!(
        "publication=completed destination={} publication_directory_flush=complete partition={} offset={} length={} container=raw boot=unverified",
        destination.display(),
        output.scheme.as_deref().unwrap_or("standalone"),
        output.offset,
        output.filesystem_bytes
    );
    Ok(())
}
