//! Explicit content-only file-tree capture into a staged FAT build.
//!
//! No metadata-preserving copy is advertised. The caller chooses name conversion
//! and deterministic metadata replacement before planning. Unsupported object
//! kinds, hard links and additional streams fail before any destination writes.
use crate::{
    fs_core::*,
    fs_fat_builder::{
        FatBuildOptions, FatBuildPlan, FatBuildReport, FatBuildTreeEntry, FatTreeMetadataPolicy,
    },
    storage::Storage,
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::Arc,
};
use virtdisk::ReadAt;

/// Explicit interpretation of source byte names; exact UTF-16 names remain native.
#[derive(Clone, Copy, Debug)]
pub enum CopyNamePolicy {
    /// Eleven-byte FAT ASCII short aliases, with base/extension space padding.
    FatAsciiShortAliases,
    /// Decode other filesystem byte names as strict UTF-8, rejecting invalid bytes.
    StrictUtf8,
}
/// Explicit bounded inventory limits, independent of payload buffering.
#[derive(Clone, Copy, Debug)]
pub struct CopyLimits {
    /// Total objects including the root.
    pub objects: usize,
    /// Total directory pages; even empty pages consume a unit of work.
    pub pages: usize,
    /// Maximum entries requested per page.
    pub page_entries: usize,
}
/// Explicit destination, conversion and resource policies for a content-only copy.
pub struct FatCopyOptions {
    /// Exact unpublished destination byte length.
    pub image_bytes: u64,
    /// Destination FAT geometry and deterministic serial number.
    pub filesystem: FatBuildOptions,
    /// Explicit source byte-name interpretation.
    pub names: CopyNamePolicy,
    /// Authorized replacement of source metadata with deterministic defaults.
    pub metadata: FatTreeMetadataPolicy,
    /// Inventory work bounds.
    pub limits: CopyLimits,
}
/// Declared treatment of one actual source metadata class.
#[derive(Clone, Debug)]
pub struct MetadataOutcome {
    /// Source-scoped object identity.
    pub object: ObjectId,
    /// Native class whose preservation was evaluated.
    pub class: &'static str,
    /// Explicit transformation/rejection decision, including uninspectable fields.
    pub decision: Preservation,
}
/// Reviewed inventory and unpublished FAT destination plan.
pub struct FatCopyPlan {
    source: Arc<dyn TreeSource>,
    objects: Vec<ObjectId>,
    build: FatBuildPlan,
    outcomes: Vec<MetadataOutcome>,
    _reservation: Reservation,
}
struct FileInput {
    source: Arc<dyn TreeSource>,
    file: Arc<dyn FileRead>,
    identity: ObjectId,
    length: u64,
    resources: Resources,
}
impl ReadAt for FileInput {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.source
            .revalidate(&self.identity, &self.resources)
            .map_err(io::Error::other)?;
        if self.file.identity() != &self.identity || self.file.len() != self.length {
            return Err(io::Error::other("copy source stream changed"));
        }
        let mut done = 0;
        while done < out.len() {
            let n = self
                .file
                .read_at(offset + done as u64, &mut out[done..], &self.resources)
                .map_err(io::Error::other)?;
            if n == 0 || n > out.len() - done {
                return Err(io::Error::other(
                    "copy source returned invalid positional count",
                ));
            }
            done += n;
        }
        if self.file.identity() != &self.identity || self.file.len() != self.length {
            return Err(io::Error::other("copy source stream changed during read"));
        }
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.source
            .revalidate(&self.identity, &self.resources)
            .map_err(io::Error::other)?;
        Ok(())
    }
}
pub(crate) fn native_name(name: &NativeName, policy: CopyNamePolicy) -> Result<Vec<u16>> {
    fn collect(units: impl Iterator<Item = u16> + Clone, source: bool) -> Result<Vec<u16>> {
        let count = units.clone().count();
        if count > 255 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                if source {
                    "source name exceeds destination UTF-16 limit"
                } else {
                    "converted name exceeds destination UTF-16 limit"
                },
            ));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(count)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "name conversion allocation"))?;
        out.extend(units);
        Ok(out)
    }
    match name {
        NativeName::Utf16(units) => collect(units.iter().copied(), true),
        NativeName::Bytes(bytes) => {
            if bytes.len() > 1020 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "byte name exceeds bounded conversion limit",
                ));
            }
            match policy {
                CopyNamePolicy::StrictUtf8 => collect(
                    std::str::from_utf8(bytes)
                        .map_err(|_| {
                            Error::new(
                                ErrorKind::Unsupported,
                                "source byte name is not valid UTF-8",
                            )
                        })?
                        .encode_utf16(),
                    false,
                ),
                CopyNamePolicy::FatAsciiShortAliases => {
                    if bytes.len() != 11 || !bytes.is_ascii() {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "source name is not an ASCII FAT short alias",
                        ));
                    }
                    let base = bytes[..8]
                        .split_at(
                            bytes[..8]
                                .iter()
                                .rposition(|&b| b != b' ')
                                .map_or(0, |i| i + 1),
                        )
                        .0;
                    let extension = bytes[8..]
                        .split_at(
                            bytes[8..]
                                .iter()
                                .rposition(|&b| b != b' ')
                                .map_or(0, |i| i + 1),
                        )
                        .0;
                    let dot = (!extension.is_empty()).then_some(u16::from(b'.'));
                    collect(
                        base.iter()
                            .copied()
                            .map(u16::from)
                            .chain(dot)
                            .chain(extension.iter().copied().map(u16::from)),
                        false,
                    )
                }
            }
        }
    }
}

fn outcome<T>(
    object: &ObjectId,
    class: &'static str,
    field: &MetadataField<T>,
    out: &mut Vec<MetadataOutcome>,
) {
    let decision = match field {
        MetadataField::Absent => Preservation::Preserve,
        MetadataField::Uninspectable { .. } => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source class uninspectable; preservation is unverified and not claimed".into(),
        },
        MetadataField::Known(_) | MetadataField::Opaque { .. } => Preservation::Transform {
            policy: "content-only deterministic defaults".into(),
            report: "source metadata omitted; deterministic FAT defaults applied".into(),
        },
    };
    out.push(MetadataOutcome {
        object: object.clone(),
        class,
        decision,
    });
}
impl FatCopyPlan {
    /// Preflight an actual inventory using explicitly authorized content-only defaults.
    ///
    /// The source must guarantee stable deferred reads; change detection alone
    /// does not satisfy the immutable FAT payload input contract. Hard links are
    /// rejected instead of silently splitting source identities. Named/system
    /// streams, forks, symlinks and special objects are unavailable in this profile.
    /// Reserve 16384 bytes/object conservatively for inventory, outcomes and queues,
    /// in addition to the builder's retained accounting and source-owned caches.
    pub fn new(
        source: Arc<dyn TreeSource>,
        options: FatCopyOptions,
        resources: &Resources,
    ) -> Result<Self> {
        let FatCopyOptions {
            image_bytes: length,
            filesystem: options,
            names,
            metadata,
            limits,
        } = options;
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
                            "FAT content-only copy cannot preserve hard links or directory aliases",
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
                            Some(Arc::new(FileInput {
                                source: source.clone(),
                                length: file.len(),
                                file,
                                identity: entry.object.clone(),
                                resources: resources.clone(),
                            }) as Arc<dyn ReadAt>)
                        }
                        ObjectKind::Symlink | ObjectKind::Special => {
                            return Err(Error::new(
                                ErrorKind::Unsupported,
                                "FAT copy profile cannot represent symlinks or special objects",
                            ));
                        }
                    };
                    entries.push(FatBuildTreeEntry {
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
            outcomes.push(MetadataOutcome { object: object.clone(), class: "names", decision: Preservation::Transform { policy: format!("explicit name conversion {names:?}"), report:"native UTF-16 names retained; byte names interpreted by selected policy; FAT aliases generated".into() } });
        }
        let build = FatBuildPlan::new_tree(length, options, &entries, metadata, resources)?;
        Ok(Self {
            source,
            objects,
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
    ) -> Result<FatBuildReport> {
        for object in &self.objects {
            resources.cancellation.check()?;
            self.source.revalidate(object, resources)?;
        }
        let report = self.build.emit(storage, resources)?;
        for object in &self.objects {
            if let Err(mut error) = resources
                .cancellation
                .check()
                .and_then(|()| self.source.revalidate(object, resources))
            {
                error.kind = ErrorKind::InterruptedWrite;
                error.context = format!(
                    "copy source validation failed after staged FAT emission: {}",
                    error.context
                );
                return Err(error);
            }
        }
        Ok(report)
    }
}
