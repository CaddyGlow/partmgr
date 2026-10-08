//! Explicit content-only common file-tree capture into a staged exFAT build.
//!
//! No metadata-preserving copy is advertised. The caller chooses name conversion
//! and deterministic metadata replacement before planning. Unsupported object
//! kinds, hard links and additional streams fail before any destination writes.
use crate::{
    fs_copy::{CopyLimits, CopyNamePolicy, FileInput, MetadataOutcome, native_name},
    fs_core::*,
    fs_exfat_builder::{
        ExfatBuildEntry, ExfatBuildLimits, ExfatBuildMetadataPolicy, ExfatBuildOptions,
        ExfatBuildPlan, ExfatBuildReport, ExfatBuildSource,
    },
    storage::Storage,
};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

/// Required explicit metadata treatment.
#[derive(Clone, Copy, Debug)]
pub enum ExfatCopyMetadataPolicy {
    /// Authorize dropping source metadata and synthesizing exFAT deterministic defaults.
    ContentOnlyDeterministicDefaults,
    /// Fail before any output: preservation has no implementation in this profile.
    RequirePreservation,
}
/// Explicit destination, conversion and resource policies for a content-only copy.
pub struct ExfatCopyOptions {
    /// Exact unpublished destination byte length.
    pub image_bytes: u64,
    /// Destination exFAT geometry and deterministic serial number.
    pub filesystem: ExfatBuildOptions,
    /// Explicit source byte-name interpretation.
    pub names: CopyNamePolicy,
    /// Authorized replacement of source metadata with deterministic defaults.
    pub metadata: ExfatCopyMetadataPolicy,
    /// Inventory work bounds.
    pub limits: CopyLimits,
    /// Destination builder inventory/geometry bounds.
    pub build_limits: ExfatBuildLimits,
}
/// Reviewed inventory and unpublished exFAT destination plan.
pub struct ExfatCopyPlan {
    source: Arc<dyn TreeSource>,
    objects: Vec<ObjectId>,
    files: Vec<Arc<FileInput>>,
    build: ExfatBuildPlan,
    outcomes: Vec<MetadataOutcome>,
    _reservation: Reservation,
}
fn outcome<T>(
    object: &ObjectId,
    class: &'static str,
    field: &MetadataField<T>,
    out: &mut Vec<MetadataOutcome>,
) {
    let decision = match field {
        MetadataField::Absent => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source class absent; destination defaults or omission applied".into(),
        },
        MetadataField::Uninspectable { .. } => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source class uninspectable; preservation is unverified and not claimed".into(),
        },
        MetadataField::Known(_) | MetadataField::Opaque { .. } => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source metadata omitted; deterministic exFAT defaults applied".into(),
        },
    };
    out.push(MetadataOutcome {
        object: object.clone(),
        class,
        decision,
    });
}
impl ExfatCopyPlan {
    /// Preflight an actual inventory using explicitly authorized content-only defaults.
    ///
    /// The source must guarantee stable deferred reads; change detection alone
    /// does not satisfy the immutable exFAT payload input contract. Hard links are
    /// rejected instead of silently splitting source identities. Named/system
    /// streams, forks, symlinks and special objects are unavailable in this profile.
    /// Reserve 16384 bytes/object conservatively for inventory, outcomes and queues,
    /// in addition to the builder's retained accounting and source-owned caches.
    pub fn new(
        source: Arc<dyn TreeSource>,
        options: ExfatCopyOptions,
        resources: &Resources,
    ) -> Result<Self> {
        let ExfatCopyOptions {
            image_bytes: length,
            filesystem: options,
            names,
            metadata,
            limits,
            build_limits,
        } = options;
        if matches!(metadata, ExfatCopyMetadataPolicy::RequirePreservation) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "exFAT copy metadata preservation is not implemented",
            ));
        }
        resources.cancellation.check()?;
        if limits.objects == 0 || limits.pages == 0 || limits.page_entries == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "copy inventory limits must be positive",
            ));
        }
        if source.stability() == SourceStability::ChangeDetectionOnly {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "copy requires caller-guaranteed stable input or an immutable snapshot",
            ));
        }
        let reservation =
            resources
                .memory
                .reserve((limits.objects as u64).checked_mul(16384).ok_or_else(|| {
                    Error::new(ErrorKind::BudgetExhausted, "copy inventory budget overflow")
                })?)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(limits.objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(limits.objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut outcomes = Vec::new();
        outcomes
            .try_reserve_exact(
                limits.objects.checked_mul(12).ok_or_else(|| {
                    Error::new(ErrorKind::BudgetExhausted, "copy outcome overflow")
                })?,
            )
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut seen = HashSet::new();
        seen.try_reserve(limits.objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut directories = VecDeque::new();
        directories
            .try_reserve(limits.objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let root = source.root();
        if root.native.len() > 256 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "source native identity exceeds copy profile limit",
            ));
        }
        seen.insert(root.clone());
        objects.push(root.clone());
        directories.push_back(root.clone());
        let mut pages = 0;
        while let Some(directory) = directories.pop_front() {
            if !source.streams(&directory, resources)?.get().is_empty() {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "copy profile cannot represent directory or root streams",
                ));
            }
            let mut continuation = None;
            loop {
                resources.cancellation.check()?;
                if pages == limits.pages {
                    return Err(Error::new(
                        ErrorKind::BudgetExhausted,
                        "copy directory page limit exceeded",
                    ));
                }
                pages += 1;
                let page = source.directory_page(
                    &directory,
                    continuation.as_deref(),
                    limits.page_entries,
                    resources,
                )?;
                if page.entries.len() > limits.page_entries {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "source exceeded requested directory page size",
                    ));
                }
                for entry in &page.entries {
                    if objects.len() == limits.objects {
                        return Err(Error::new(
                            ErrorKind::BudgetExhausted,
                            "copy object limit exceeded",
                        ));
                    }
                    if entry.object.source != root.source || entry.object.native.len() > 256 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "copy inventory has foreign or oversized identity",
                        ));
                    }
                    if !seen.insert(entry.object.clone()) {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "exFAT content-only copy cannot preserve hard links or directory aliases",
                        ));
                    }
                    let payload = match entry.kind {
                        ObjectKind::Directory => {
                            directories.push_back(entry.object.clone());
                            None
                        }
                        ObjectKind::File => {
                            let streams = source.streams(&entry.object, resources)?;
                            if streams.get().len() != 1 || streams.get()[0].kind != StreamKind::Data
                            {
                                return Err(Error::new(
                                    ErrorKind::Unsupported,
                                    "copy profile requires exactly one ordinary data stream",
                                ));
                            }
                            let file =
                                source.open_stream(&entry.object, &StreamKind::Data, resources)?;
                            if file.identity() != &entry.object
                                || file.len() != streams.get()[0].length
                            {
                                return Err(Error::new(
                                    ErrorKind::StalePlan,
                                    "copy stream identity or length changed after inventory",
                                ));
                            }
                            let input = Arc::new(FileInput {
                                source: source.clone(),
                                length: file.len(),
                                file,
                                identity: entry.object.clone(),
                                resources: resources.clone(),
                            });
                            files.push(input.clone());
                            Some(ExfatBuildSource::File(input))
                        }
                        ObjectKind::Symlink | ObjectKind::Special => {
                            return Err(Error::new(
                                ErrorKind::Unsupported,
                                "exFAT copy profile cannot represent symlinks or special objects",
                            ));
                        }
                    };
                    entries.push(ExfatBuildEntry {
                        identity: entry.object.clone(),
                        parent: if directory == root {
                            None
                        } else {
                            Some(directory.clone())
                        },
                        name: native_name(&entry.name, names)?,
                        source: payload,
                    });
                    objects.push(entry.object.clone());
                }
                continuation = page.next.clone();
                if continuation
                    .as_ref()
                    .is_some_and(|token| token.len() > 1024)
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "copy continuation exceeds bounded token profile",
                    ));
                }
                if continuation.is_none() {
                    break;
                }
            }
        }
        for object in &objects {
            source.revalidate(object, resources)?;
            let metadata = source.metadata(object, resources)?;
            let metadata = metadata.get();
            outcome(object, "created", &metadata.created, &mut outcomes);
            outcome(object, "modified", &metadata.modified, &mut outcomes);
            outcome(object, "accessed", &metadata.accessed, &mut outcomes);
            outcome(object, "owner", &metadata.owner, &mut outcomes);
            outcome(object, "mode", &metadata.mode, &mut outcomes);
            outcome(object, "security", &metadata.security, &mut outcomes);
            outcome(
                object,
                "native_flags",
                &metadata.native_flags,
                &mut outcomes,
            );
            outcome(
                object,
                "symlink_target",
                &metadata.symlink_target,
                &mut outcomes,
            );
            outcome(
                object,
                "reparse_data",
                &metadata.reparse_data,
                &mut outcomes,
            );
            outcomes.push(MetadataOutcome {
                object: object.clone(),
                class: "attributes",
                decision: if metadata.attributes.is_empty() {
                    Preservation::Preserve
                } else {
                    Preservation::Transform {
                        policy: "content-only deterministic defaults".into(),
                        report: "all source extended attributes omitted".into(),
                    }
                },
            });
            outcomes.push(MetadataOutcome { object: object.clone(), class: "names", decision: Preservation::Transform { policy: format!("explicit name conversion {names:?}"), report:"native UTF-16 names retained; byte names converted by explicit policy; recommended exFAT up-case profile applies".into() } });
        }
        let build = ExfatBuildPlan::new(
            length,
            options,
            &entries,
            ExfatBuildMetadataPolicy::DeterministicDefaults,
            build_limits,
            resources,
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
    /// Per-object preservation decisions for review before writing.
    pub fn outcomes(&self) -> &[MetadataOutcome] {
        &self.outcomes
    }
    /// Emit and verify an unpublished image, revalidating source inventory boundaries.
    /// Source detection failure after emission is a staged interruption, not rollback.
    pub fn emit(
        &self,
        storage: &mut (impl Storage + ?Sized),
        resources: &Resources,
    ) -> Result<ExfatBuildReport> {
        for object in &self.objects {
            resources.cancellation.check()?;
            self.source.revalidate(object, resources)?;
        }
        for file in &self.files {
            file.validate(resources)?;
        }
        let report = self.build.emit(storage, resources)?;
        for file in &self.files {
            if let Err(mut error) = file.validate(resources) {
                error.kind = ErrorKind::InterruptedWrite;
                error.context = format!(
                    "exFAT copy source stream changed after emission: {}",
                    error.context
                );
                return Err(error);
            }
        }
        for object in &self.objects {
            if let Err(mut error) = resources
                .cancellation
                .check()
                .and_then(|()| self.source.revalidate(object, resources))
            {
                error.kind = ErrorKind::InterruptedWrite;
                error.context = format!(
                    "copy source validation failed after staged exFAT emission: {}",
                    error.context
                );
                return Err(error);
            }
        }
        Ok(report)
    }
}
