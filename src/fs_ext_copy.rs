//! Deferred common-tree capture into unpublished classic ext2 with preserved hardlinks.
use crate::{
    fs_copy::{CopyLimits, FileInput, MetadataOutcome},
    fs_copy::{CopyPages, MetadataStatus, visit_metadata_fields},
    fs_core::*,
    fs_ext_builder::{
        ExtBuildLimits, ExtBuildLink, ExtBuildMetadata, ExtBuildObject, ExtBuildOptions,
        ExtBuildPlan, ExtBuildReport, ExtBuildSource,
    },
    storage::Storage,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
/// Explicit native name conversion policy.
#[derive(Clone, Copy, Debug)]
pub enum ExtCopyNamePolicy {
    /// Keep byte names exactly; reject UTF16 names.
    ExactBytes,
    /// Keep byte names exactly; encode valid UTF16 names as UTF8, rejecting unpaired surrogates.
    BytesAndUtf16ToUtf8,
}
/// Required metadata treatment; preservation is not implemented in this profile.
#[derive(Clone, Copy, Debug)]
pub enum ExtCopyMetadataPolicy {
    /// Caller-selected global native defaults replace source metadata.
    ContentOnlyDefaults(ExtBuildMetadata),
    /// Reject before emission because arbitrary metadata preservation is unavailable.
    RequirePreservation,
}
/// Geometry, conversion, metadata and independent inventory/build ceilings.
pub struct ExtCopyOptions {
    /// Exact unpublished destination length.
    pub image_bytes: u64,
    /// Classic ext2 geometry and UUID.
    pub filesystem: ExtBuildOptions,
    /// Explicit handling of native names.
    pub names: ExtCopyNamePolicy,
    /// Authorized source metadata treatment.
    pub metadata: ExtCopyMetadataPolicy,
    /// Unique objects including root and pagination bounds.
    pub limits: CopyLimits,
    /// Destination object/link/name/allocation/depth bounds.
    pub build_limits: ExtBuildLimits,
}
/// Reviewed retained source inventory and deterministic unpublished destination.
pub struct ExtCopyPlan {
    source: Arc<dyn TreeSource>,
    objects: Vec<ObjectId>,
    files: Vec<Arc<FileInput>>,
    build: ExtBuildPlan,
    outcomes: Vec<MetadataOutcome>,
    _reservation: Reservation,
}
fn outcome(
    object: &ObjectId,
    class: &'static str,
    field: MetadataStatus,
    out: &mut Vec<MetadataOutcome>,
) {
    let decision = match field {
        MetadataStatus::Absent => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source class absent; destination defaults or omission applied".into(),
        },
        MetadataStatus::Uninspectable => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source class uninspectable; preservation is unverified and not claimed".into(),
        },
        MetadataStatus::Present => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source metadata omitted; deterministic ext2 defaults applied".into(),
        },
    };
    out.push(MetadataOutcome {
        object: object.clone(),
        class,
        decision,
    });
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn unsupported(message: &str) -> Error {
    Error::new(ErrorKind::Unsupported, message)
}
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn convert(name: &NativeName, policy: ExtCopyNamePolicy) -> Result<Vec<u8>> {
    if matches!(name, NativeName::Bytes(bytes) if bytes.len() > 255)
        || matches!(name, NativeName::Utf16(units) if units.len() > 255)
    {
        return Err(invalid("ext2 copy native name exceeds bounded profile"));
    }
    let bytes = match name {
        NativeName::Bytes(bytes) => bytes.clone(),
        NativeName::Utf16(units) if matches!(policy, ExtCopyNamePolicy::BytesAndUtf16ToUtf8) => {
            String::from_utf16(units)
                .map_err(|_| unsupported("ext2 copy UTF16 name has unpaired surrogates"))?
                .into_bytes()
        }
        _ => return Err(unsupported("ext2 copy requires explicit UTF16 conversion")),
    };
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes.contains(&0)
        || bytes.contains(&b'/')
        || bytes == b"."
        || bytes == b".."
    {
        return Err(invalid("ext2 copy invalid native name"));
    }
    Ok(bytes)
}
impl ExtCopyPlan {
    /// Preflight a stable deferred inventory. Regular hardlinks are preserved;
    /// directory aliases, symlinks, special objects and additional streams reject.
    pub fn new(
        source: Arc<dyn TreeSource>,
        options: ExtCopyOptions,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let defaults = match options.metadata {
            ExtCopyMetadataPolicy::ContentOnlyDefaults(defaults) => defaults,
            ExtCopyMetadataPolicy::RequirePreservation => {
                return Err(unsupported("ext2 copy metadata preservation unavailable"));
            }
        };
        let limits = options.limits;
        if limits.objects == 0 || limits.pages == 0 || limits.page_entries == 0 {
            return Err(invalid("ext2 copy inventory limits must be positive"));
        }
        if source.stability() == SourceStability::ChangeDetectionOnly {
            return Err(unsupported(
                "ext2 copy requires stable input or immutable snapshot",
            ));
        }
        let charge = (limits.objects as u128)
            .checked_mul(16384)
            .and_then(|n| n.checked_add(options.build_limits.links as u128 * 1024))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| budget("ext2 copy reservation overflow"))?;
        let reservation = r.memory.reserve(charge)?;
        let root = source.root();
        if root.native.len() > 256 {
            return Err(unsupported(
                "ext2 copy source identity exceeds bounded profile",
            ));
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(limits.objects)
            .map_err(|_| budget("ext2 copy objects"))?;
        objects.push(root.clone());
        let mut definitions = Vec::new();
        definitions
            .try_reserve_exact(limits.objects)
            .map_err(|_| budget("ext2 copy definitions"))?;
        let mut links = Vec::new();
        links
            .try_reserve_exact(options.build_limits.links)
            .map_err(|_| budget("ext2 copy links"))?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(limits.objects)
            .map_err(|_| budget("ext2 copy files"))?;
        let mut kinds = HashMap::new();
        kinds
            .try_reserve(limits.objects)
            .map_err(|_| budget("ext2 copy identities"))?;
        kinds.insert(root.clone(), ObjectKind::Directory);
        let mut directories = VecDeque::new();
        directories
            .try_reserve(limits.objects)
            .map_err(|_| budget("ext2 copy directory queue"))?;
        directories.push_back(root.clone());
        let mut pages = CopyPages::new(limits);
        while let Some(directory) = directories.pop_front() {
            source.revalidate(&directory, r)?;
            if !source.streams(&directory, r)?.is_empty() {
                return Err(unsupported("ext2 copy cannot represent directory streams"));
            }
            let mut continuation = None;
            loop {
                let page = pages.next(source.as_ref(), &directory, continuation.as_deref(), r)?;
                for entry in &page.entries {
                    if entry.object.source != root.source || entry.object.native.len() > 256 {
                        return Err(invalid("ext2 copy foreign or oversized identity"));
                    }
                    if !matches!(entry.kind, ObjectKind::File | ObjectKind::Directory) {
                        return Err(unsupported(
                            "ext2 copy symlinks and special objects unavailable",
                        ));
                    }
                    if links.len() == options.build_limits.links {
                        return Err(budget("ext2 copy link limit"));
                    }
                    let name = convert(&entry.name, options.names)?;
                    if let Some(kind) = kinds.get(&entry.object) {
                        if *kind != entry.kind || entry.kind == ObjectKind::Directory {
                            return Err(invalid(
                                "ext2 copy directory alias or inconsistent object kind",
                            ));
                        }
                    } else {
                        if objects.len() == limits.objects {
                            return Err(budget("ext2 copy unique object limit"));
                        }
                        source.revalidate(&entry.object, r)?;
                        kinds.insert(entry.object.clone(), entry.kind.clone());
                        objects.push(entry.object.clone());
                        let input = if entry.kind == ObjectKind::Directory {
                            directories.push_back(entry.object.clone());
                            None
                        } else {
                            let streams = source.streams(&entry.object, r)?;
                            if streams.len() != 1 || streams[0].kind != StreamKind::Data {
                                return Err(unsupported(
                                    "ext2 copy requires one unnamed data stream",
                                ));
                            }
                            let file = source.open_stream(&entry.object, &StreamKind::Data, r)?;
                            if file.identity() != &entry.object || file.len() != streams[0].length {
                                return Err(invalid(
                                    "ext2 copy source stream identity/length mismatch",
                                ));
                            }
                            let input = Arc::new(FileInput {
                                source: source.clone(),
                                length: file.len(),
                                identity: entry.object.clone(),
                                file,
                                resources: r.clone(),
                            });
                            input.validate(r)?;
                            files.push(input.clone());
                            Some(ExtBuildSource::File(input))
                        };
                        definitions.push(ExtBuildObject {
                            identity: entry.object.clone(),
                            source: input,
                        });
                    }
                    links.push(ExtBuildLink {
                        object: entry.object.clone(),
                        parent: if directory == root {
                            None
                        } else {
                            Some(directory.clone())
                        },
                        name,
                    });
                }
                continuation = page.next.clone();
                if continuation.is_none() {
                    break;
                }
            }
        }
        let mut outcomes = Vec::new();
        outcomes
            .try_reserve_exact(
                objects
                    .len()
                    .checked_mul(12)
                    .ok_or_else(|| budget("ext2 copy outcomes overflow"))?,
            )
            .map_err(|_| budget("ext2 copy outcomes"))?;
        for object in &objects {
            source.revalidate(object, r)?;
            let metadata = source.metadata(object, r)?;
            visit_metadata_fields(&metadata, |class, status| {
                outcome(object, class, status, &mut outcomes);
            });
            outcomes.push(MetadataOutcome {
                object: object.clone(),
                class: "attributes",
                decision: Preservation::Transform {
                    policy: "content-only caller defaults".into(),
                    report: "source extended attributes omitted".into(),
                },
            });
            outcomes.push(MetadataOutcome {
                object: object.clone(),
                class: "names",
                decision: Preservation::Transform {
                    policy: format!("{policy:?}", policy = options.names),
                    report: "byte names exact; UTF16 conversion only when explicitly selected"
                        .into(),
                },
            });
            outcomes.push(MetadataOutcome {
                object: object.clone(),
                class: "hardlinks",
                decision: Preservation::Preserve,
            });
        }
        let build = ExtBuildPlan::new(
            options.image_bytes,
            options.filesystem,
            definitions,
            links,
            defaults,
            options.build_limits,
            r,
        )?;
        Ok(Self {
            source,
            objects,
            files,
            build,
            outcomes,
            _reservation: reservation,
        })
    }
    /// Per-object metadata, name and hardlink decisions before mutation.
    pub fn outcomes(&self) -> &[MetadataOutcome] {
        &self.outcomes
    }
    /// Emit, flush and fully verify an unpublished image; no output publication.
    pub fn emit(
        &self,
        storage: &mut (impl Storage + ?Sized),
        r: &Resources,
    ) -> Result<ExtBuildReport> {
        for object in &self.objects {
            r.cancellation.check()?;
            self.source.revalidate(object, r)?;
        }
        for file in &self.files {
            file.validate(r)?;
        }
        let report = self.build.emit(storage, r)?;
        let post: Result<()> = (|| {
            for file in &self.files {
                file.validate(r)?;
            }
            for object in &self.objects {
                r.cancellation.check()?;
                self.source.revalidate(object, r)?;
            }
            Ok(())
        })();
        if let Err(mut error) = post {
            error.kind = ErrorKind::InterruptedWrite;
            error.context = format!(
                "ext2 copy source validation after staged emission: {}",
                error.context
            );
            return Err(error);
        }
        Ok(report)
    }
}
