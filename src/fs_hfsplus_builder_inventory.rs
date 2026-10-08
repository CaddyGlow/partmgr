//! Staged common-tree inventory with explicit content-only metadata defaults.
use super::{bad, budget, builder_layout, catalog_key, metadata_builder, vector};
use crate::{
    fs_copy::{CopyLimits, CopyNamePolicy, MetadataOutcome, native_name},
    fs_core::*,
};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone, Copy)]
pub(crate) enum MetadataPolicy {
    ContentOnlyDefaults,
    NativeHfsCatalogFields,
}
struct Directory {
    metadata: Option<metadata_builder::CatalogMetadata>,
    identity: ObjectId,
    parent: u32,
    name: Vec<u16>,
}
struct File {
    metadata: Option<metadata_builder::CatalogMetadata>,
    parent: u32,
    name: Vec<u16>,
    data: Arc<dyn FileRead>,
    resource: Option<Arc<dyn FileRead>>,
}
struct BoundInput {
    source: Arc<dyn TreeSource>,
    file: Arc<dyn FileRead>,
    identity: ObjectId,
    length: u64,
}
impl BoundInput {
    fn validate(&self, r: &Resources) -> Result<()> {
        self.source.revalidate(&self.identity, r)?;
        if self.file.identity() != &self.identity || self.file.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "HFS+ inventory stream changed",
            ));
        }
        Ok(())
    }
}
impl FileRead for BoundInput {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, at: u64, bytes: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        self.validate(r)?;
        let count = self.file.read_at(at, bytes, r)?;
        self.validate(r)?;
        r.cancellation.check()?;
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.validate(r)?;
        self.file.visit_extents(r, visitor)?;
        self.validate(r)
    }
}
pub(crate) struct Plan {
    root_metadata: Option<metadata_builder::CatalogMetadata>,
    source: Arc<dyn TreeSource>,
    objects: Vec<ObjectId>,
    directories: Vec<Directory>,
    files: Vec<File>,
    outcomes: Vec<MetadataOutcome>,
    binary: bool,
    _lease: Reservation,
}
impl Plan {
    pub(crate) fn new(
        source: Arc<dyn TreeSource>,
        limits: CopyLimits,
        names: CopyNamePolicy,
        policy: MetadataPolicy,
        binary: bool,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if limits.objects == 0 || limits.pages == 0 || limits.page_entries == 0 {
            return Err(bad("HFS+ zero inventory limits"));
        }
        if source.stability() == SourceStability::ChangeDetectionOnly {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "HFS+ inventory requires stable deferred input",
            ));
        }
        let _lease = r.memory.reserve(
            (limits.objects as u64)
                .checked_mul(16384)
                .ok_or_else(|| budget("HFS+ common inventory charge"))?,
        )?;
        let root = source.root();
        let selected_metadata = |identity: &ObjectId, directory: bool| -> Result<_> {
            match policy {
                MetadataPolicy::ContentOnlyDefaults => Ok(None),
                MetadataPolicy::NativeHfsCatalogFields => {
                    let metadata = source.metadata(identity, r)?;
                    Ok(Some(metadata_builder::from_native_hfs(
                        metadata.get(),
                        directory,
                    )?))
                }
            }
        };
        let root_metadata = selected_metadata(&root, true)?;
        if root.native.len() > 256 {
            return Err(bad("HFS+ oversized root identity"));
        }
        let mut objects = vector(limits.objects)?;
        objects.push(root.clone());
        let mut seen = HashSet::new();
        seen.try_reserve(limits.objects)
            .map_err(|_| budget("HFS+ identity inventory"))?;
        seen.insert(root.clone());
        let mut directories = vector(limits.objects)?;
        let mut files = vector(limits.objects)?;
        let mut queue = vector(limits.objects)?;
        queue.push((root, 2u32));
        let mut keys = vector(limits.objects)?;
        let mut pages = 0usize;
        let mut cursor = 0;
        while cursor < queue.len() {
            let (directory, parent) = queue[cursor].clone();
            cursor += 1;
            if !source.streams(&directory, r)?.get().is_empty() {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HFS+ directory streams authoring unavailable",
                ));
            }
            let mut continuation = None;
            loop {
                r.cancellation.check()?;
                if pages == limits.pages {
                    return Err(budget("HFS+ inventory page ceiling"));
                }
                pages += 1;
                let page = source.directory_page(
                    &directory,
                    continuation.as_deref(),
                    limits.page_entries,
                    r,
                )?;
                if page.entries.len() > limits.page_entries {
                    return Err(bad("HFS+ source exceeded requested page"));
                }
                for entry in &page.entries {
                    if objects.len() == limits.objects {
                        return Err(budget("HFS+ inventory object ceiling"));
                    }
                    if entry.object.source != objects[0].source || entry.object.native.len() > 256 {
                        return Err(bad("HFS+ foreign or oversized inventory identity"));
                    }
                    if !seen.insert(entry.object.clone()) {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "HFS+ native hardlink authoring not yet implemented",
                        ));
                    }
                    let name = native_name(&entry.name, names)?;
                    if name.is_empty() || name.iter().any(|u| *u == 0 || *u == 47) {
                        return Err(bad("HFS+ inventory native name"));
                    }
                    let (key, _key_lease) = catalog_key(parent, &name, binary, r)?;
                    keys.push(super::super::key(&key[2..], 0, binary)?);
                    match entry.kind {
                        ObjectKind::Directory => {
                            let cnid = u32::try_from(directories.len())
                                .ok()
                                .and_then(|n| n.checked_add(16))
                                .ok_or_else(|| budget("HFS+ directory identity capacity"))?;
                            directories.push(Directory {
                                metadata: selected_metadata(&entry.object, true)?,
                                identity: entry.object.clone(),
                                parent,
                                name,
                            });
                            queue.push((entry.object.clone(), cnid));
                        }
                        ObjectKind::File => {
                            let streams = source.streams(&entry.object, r)?;
                            let mut data = None;
                            let mut resource = None;
                            for stream in streams.get() {
                                let slot = match stream.kind {
                                    StreamKind::Data => &mut data,
                                    StreamKind::ResourceFork => &mut resource,
                                    _ => {
                                        return Err(Error::new(
                                            ErrorKind::Unsupported,
                                            "HFS+ named/system stream authoring unavailable",
                                        ));
                                    }
                                };
                                if slot.is_some() {
                                    return Err(bad("HFS+ repeated source stream"));
                                }
                                let file = source.open_stream(&entry.object, &stream.kind, r)?;
                                let bound = BoundInput {
                                    source: source.clone(),
                                    file,
                                    identity: entry.object.clone(),
                                    length: stream.length,
                                };
                                bound.validate(r)?;
                                *slot = Some(Arc::new(bound) as Arc<dyn FileRead>);
                            }
                            files.push(File {
                                metadata: selected_metadata(&entry.object, false)?,
                                parent,
                                name,
                                data: data.ok_or_else(|| bad("HFS+ source missing data stream"))?,
                                resource,
                            });
                        }
                        _ => {
                            return Err(Error::new(
                                ErrorKind::Unsupported,
                                "HFS+ special object authoring unavailable",
                            ));
                        }
                    }
                    objects.push(entry.object.clone());
                }
                if page.next.as_ref().is_some_and(|token| token.len() > 1024) {
                    return Err(bad("HFS+ oversized continuation"));
                }
                continuation = page.next.clone();
                if continuation.is_none() {
                    break;
                }
            }
        }
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(bad("HFS+ common inventory name collision"));
        }
        let capacity = limits
            .objects
            .checked_mul(10)
            .ok_or_else(|| budget("HFS+ metadata outcome count"))?;
        let mut outcomes = vector(capacity)?;
        for identity in &objects {
            source.revalidate(identity, r)?;
            let metadata = source.metadata(identity, r)?;
            let m = metadata.get();
            for (class, status) in [
                ("created", status(&m.created)),
                ("modified", status(&m.modified)),
                ("accessed", status(&m.accessed)),
                ("owner", status(&m.owner)),
                ("mode", status(&m.mode)),
                ("security", status(&m.security)),
                ("native_flags", status(&m.native_flags)),
                ("symlink_target", status(&m.symlink_target)),
                ("reparse_data", status(&m.reparse_data)),
                (
                    "attributes",
                    if m.attributes.is_empty() {
                        "empty"
                    } else {
                        "present"
                    },
                ),
            ] {
                outcomes.push(MetadataOutcome {
                    object: identity.clone(),
                    class,
                    decision: match policy {
                        MetadataPolicy::NativeHfsCatalogFields if matches!(class, "created" | "modified" | "accessed" | "owner" | "mode") => Preservation::Preserve,
                        MetadataPolicy::NativeHfsCatalogFields => Preservation::Transform {
                            policy: "native HFS catalog ownership, permissions and five dates".into(),
                            report: format!("source class {status}; attribute/backup dates extracted from checked catalog; other catalog bytes, flags and attributes are not preserved"),
                        },
                        MetadataPolicy::ContentOnlyDefaults => Preservation::Transform {
                            policy: "content-only HFS+ deterministic defaults".into(),
                            report: format!("source class {status}; original metadata is not preserved"),
                        },
                    },
                });
            }
        }
        Ok(Self {
            root_metadata,
            source,
            objects,
            directories,
            files,
            outcomes,
            binary,
            _lease,
        })
    }
    pub(crate) fn outcomes(&self) -> &[MetadataOutcome] {
        &self.outcomes
    }
    pub(crate) fn emit(
        &self,
        block_size: u32,
        blocks: u32,
        name: &[u16],
        r: &Resources,
        emit: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<u64> {
        for identity in &self.objects {
            self.source.revalidate(identity, r)?;
        }
        let _scratch = r.memory.reserve(
            (self.objects.len() as u64)
                .checked_mul(128)
                .ok_or_else(|| budget("HFS+ borrowed inventory charge"))?,
        )?;
        let mut directories = vector(self.directories.len())?;
        for directory in &self.directories {
            self.source.revalidate(&directory.identity, r)?;
            directories.push(builder_layout::DirectorySource {
                metadata: directory.metadata.as_ref(),
                parent: directory.parent,
                name: &directory.name,
            });
        }
        let mut files = vector(self.files.len())?;
        for file in &self.files {
            files.push(builder_layout::FileSource {
                metadata: file.metadata.as_ref(),
                parent: file.parent,
                name: &file.name,
                data: file.data.as_ref(),
                resource: file.resource.as_deref(),
            });
        }
        let length = builder_layout::emit_tree(
            builder_layout::TreeSource {
                root_metadata: self.root_metadata.as_ref(),
                block_size,
                blocks,
                binary: self.binary,
                name,
                directories: &directories,
                files: &files,
            },
            r,
            emit,
        )?;
        for identity in &self.objects {
            self.source.revalidate(identity, r)?;
        }
        Ok(length)
    }
}
fn status<T>(field: &MetadataField<T>) -> &'static str {
    match field {
        MetadataField::Absent => "absent",
        MetadataField::Known(_) => "known",
        MetadataField::Opaque { .. } => "opaque",
        MetadataField::Uninspectable { .. } => "uninspectable",
    }
}
