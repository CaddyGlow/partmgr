//! Staged content-only optical authoring directly from common filesystem trees.
//! Native metadata preservation requires a separately implemented mapping profile.
use libmkiso::{
    preservation,
    tree_source::{
        ContentSource, DeferredContent, FileTreeSource, SourceIdentity, TreeEntry, TreeEntryKind,
        TreeExtent, TreeInventory, TreeStream,
    },
};
use partmgr::fs_core::{
    self as core, FileRead, NativeName, ObjectId, Reservation, Resources, SourceStability,
    StreamKind, TreeSource,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    path::Path,
    sync::{Arc, Mutex},
};
/// Interpretation of byte names. UTF-16 names always require valid scalar encoding.
#[derive(Clone, Copy, Debug)]
pub enum ByteNames {
    /// Exact UTF-8 byte names, rejecting invalid UTF-8.
    Utf8,
    /// Exact FAT eleven-byte ASCII 8.3 aliases, converted explicitly to base.extension.
    FatShortAscii,
}
/// Preservation request, resolved before authoring starts.
#[derive(Clone, Copy, Debug)]
pub enum WritePolicy {
    /// Preserve namespace relationships and logical contents; report discarded metadata.
    ContentOnly,
    /// Explicitly transform resource forks into UDF named streams called
    /// `com.apple.ResourceFork`; preserve bytes, without native fork semantics.
    ContentOnlyResourceForkAsNamedStream,
    /// Require native metadata fidelity; currently rejected before staging.
    RequireMetadata,
}
/// Bounds and explicit native-name interpretation for the bridge.
#[derive(Clone, Debug)]
pub struct WriteLimits {
    /// Maximum emitted namespace entries.
    pub maximum_entries: usize,
    /// Maximum inventoried metadata bytes, independent of payload size.
    pub maximum_bytes: usize,
    /// Maximum logical extents across all unique file objects.
    pub maximum_extents: usize,
    /// Maximum entries in one common-source directory page.
    pub page_entries: usize,
    /// Interpretation of native byte names.
    pub byte_names: ByteNames,
}
/// Explicit content-only transformation report. This is not faithful capture evidence.
#[derive(Clone, Debug, Default)]
pub struct WriteReport {
    /// Namespace entries emitted.
    pub entries: usize,
    /// Unique file identities; aliases retain hard-link relationships.
    pub files: usize,
    /// Metadata inspections deliberately transformed to destination defaults.
    pub metadata_objects: usize,
    /// Known native fields deliberately discarded, with no guessed epoch or owner mapping.
    pub known_metadata_fields: usize,
    /// Uninspectable native fields explicitly reported as unpreserved.
    pub uninspectable_metadata_fields: usize,
    /// Opaque native fields rejected for transplantation and discarded under ContentOnly.
    pub opaque_metadata_fields: usize,
    /// Native FAT short aliases explicitly converted to destination names.
    pub fat_short_names: usize,
    /// Sparse/unwritten ranges materialized to logical zeros for ISO.
    pub materialized_zero_ranges: usize,
    /// Sparse/unwritten ranges retained as UDF allocation semantics.
    pub retained_zero_ranges: usize,
    /// UDF named/root/system streams emitted with their owning object.
    pub streams: usize,
    /// Resource forks explicitly transformed into `com.apple.ResourceFork` streams.
    pub resource_forks_as_named_streams: usize,
    /// Sparse allocation ranges within named streams transformed to logical zero bytes.
    pub materialized_stream_zero_ranges: usize,
}
/// Closed unpublished image with bridge accounting retained until this guard drops.
/// Dropping deletes the temporary image. Publication is a separate caller operation.
pub struct StagedOptical {
    path: tempfile::TempPath,
    report: WriteReport,
    _lease: Arc<Reservation>,
}
impl StagedOptical {
    /// Inspect the closed staged file path without publishing it.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Review content-only transformations.
    pub fn report(&self) -> &WriteReport {
        &self.report
    }
}
fn err(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn duplicate(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len()).map_err(io::Error::other)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn id_copy(id: &ObjectId) -> io::Result<ObjectId> {
    Ok(ObjectId {
        source: id.source,
        generation: id.generation,
        native: duplicate(&id.native)?,
    })
}
fn text_copy(text: &str) -> io::Result<String> {
    let mut v = String::new();
    v.try_reserve_exact(text.len()).map_err(io::Error::other)?;
    v.push_str(text);
    Ok(v)
}
fn name_charge(name: &NativeName) -> io::Result<usize> {
    match name {
        NativeName::Bytes(b) => b.len().checked_mul(2),
        NativeName::Utf16(u) => u.len().checked_mul(5),
    }
    .ok_or_else(|| err("native name accounting overflow"))
}
fn name(name: &NativeName, policy: ByteNames) -> io::Result<(String, Vec<u8>, bool)> {
    let (text, raw, fat) = match name {
        NativeName::Bytes(bytes) => match policy {
            ByteNames::Utf8 => (
                text_copy(
                    std::str::from_utf8(bytes).map_err(|_| err("native name is not UTF-8"))?,
                )?,
                duplicate(bytes)?,
                false,
            ),
            ByteNames::FatShortAscii => {
                if bytes.len() != 11 || !bytes.iter().all(|b| b.is_ascii() && !b.is_ascii_control())
                {
                    return Err(err("FAT short alias is not eleven ASCII bytes"));
                }
                let base = std::str::from_utf8(&bytes[..8])
                    .unwrap()
                    .trim_end_matches(' ');
                let extension = std::str::from_utf8(&bytes[8..])
                    .unwrap()
                    .trim_end_matches(' ');
                if base.is_empty() || base.contains(' ') || extension.contains(' ') {
                    return Err(err("invalid FAT alias padding"));
                }
                let mut text = text_copy(base)?;
                text.try_reserve_exact(extension.len() + 1)
                    .map_err(io::Error::other)?;
                if !extension.is_empty() {
                    text.push('.');
                    text.push_str(extension);
                }
                (text, duplicate(bytes)?, true)
            }
        },
        NativeName::Utf16(units) => {
            let mut raw = Vec::new();
            raw.try_reserve_exact(
                units
                    .len()
                    .checked_mul(2)
                    .ok_or_else(|| err("name overflow"))?,
            )
            .map_err(io::Error::other)?;
            for u in units {
                raw.extend_from_slice(&u.to_le_bytes());
            }
            let mut text = String::new();
            text.try_reserve_exact(
                units
                    .len()
                    .checked_mul(3)
                    .ok_or_else(|| err("name overflow"))?,
            )
            .map_err(io::Error::other)?;
            for scalar in char::decode_utf16(units.iter().copied()) {
                text.push(
                    scalar.map_err(|_| {
                        err("destination cannot represent unpaired UTF-16 surrogate")
                    })?,
                );
            }
            (text, raw, false)
        }
    };
    if text.is_empty() || text == "." || text == ".." || text.contains(['/', '\\', '\0']) {
        return Err(err("unsafe or empty native path component"));
    }
    Ok((text, raw, fat))
}
fn metadata_report(metadata: &core::Metadata, report: &mut WriteReport) {
    fn field<T>(value: &core::MetadataField<T>, report: &mut WriteReport) {
        match value {
            core::MetadataField::Known(_) => report.known_metadata_fields += 1,
            core::MetadataField::Uninspectable { .. } => report.uninspectable_metadata_fields += 1,
            core::MetadataField::Opaque { .. } => report.opaque_metadata_fields += 1,
            core::MetadataField::Absent => {}
        }
    }
    field(&metadata.created, report);
    field(&metadata.modified, report);
    field(&metadata.accessed, report);
    field(&metadata.owner, report);
    field(&metadata.mode, report);
    field(&metadata.security, report);
    field(&metadata.native_flags, report);
    field(&metadata.symlink_target, report);
    field(&metadata.reparse_data, report);
    for (_, value) in &metadata.attributes {
        field(value, report);
    }
}
struct Payload {
    tree: Arc<dyn TreeSource>,
    file: Arc<dyn FileRead>,
    object: ObjectId,
    resources: Resources,
    identity: SourceIdentity,
    start: u64,
    file_length: u64,
    _lease: Arc<Reservation>,
}
impl ContentSource for Payload {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }
    fn validate(&self, expected: SourceIdentity) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        if expected != self.identity
            || self.file.identity() != &self.object
            || self.file.len() != self.file_length
        {
            return Err(err("deferred source identity changed"));
        }
        self.tree
            .revalidate(&self.object, &self.resources)
            .map_err(io::Error::other)
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.validate(self.identity)?;
        let count = self
            .identity
            .size
            .saturating_sub(offset)
            .min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let at = self
            .start
            .checked_add(offset)
            .ok_or_else(|| err("deferred offset overflow"))?;
        let got = self
            .file
            .read_at(at, &mut buffer[..count], &self.resources)
            .map_err(io::Error::other)?;
        if got > count {
            return Err(err("source read exceeded requested range"));
        }
        self.validate(self.identity)?;
        Ok(got)
    }
}
struct Bridge {
    tree: Arc<dyn TreeSource>,
    resources: Resources,
    limits: WriteLimits,
    udf: bool,
    hard_links: bool,
    resource_forks_as_named: bool,
    lease: Arc<Reservation>,
    report: Mutex<WriteReport>,
}
impl Bridge {
    fn new(
        tree: Arc<dyn TreeSource>,
        resources: Resources,
        limits: WriteLimits,
        udf: bool,
        hard_links: bool,
        policy: WritePolicy,
    ) -> anyhow::Result<Self> {
        resources.cancellation.check()?;
        if matches!(policy, WritePolicy::RequireMetadata) {
            anyhow::bail!(
                "native metadata preservation is unsupported: timestamp epochs, ownership, ACLs and opaque fields have no validated destination mapping"
            );
        }
        if tree.stability() == SourceStability::ChangeDetectionOnly {
            anyhow::bail!(
                "optical authoring requires immutable snapshot or caller-guaranteed stable source"
            );
        }
        if limits.maximum_entries == 0 || limits.page_entries == 0 {
            anyhow::bail!("nonzero inventory/page limits required");
        }
        let bytes = (limits.maximum_bytes as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add((limits.maximum_entries as u64).checked_mul(2048)?))
            .ok_or_else(|| err("bridge accounting overflow"))?;
        let lease = Arc::new(resources.memory.reserve(bytes)?);
        Ok(Self {
            tree,
            resources,
            limits,
            udf,
            hard_links,
            resource_forks_as_named: matches!(
                policy,
                WritePolicy::ContentOnlyResourceForkAsNamedStream
            ),
            lease,
            report: Mutex::new(WriteReport::default()),
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn named_streams(
        &self,
        owner: &ObjectId,
        infos: &[core::StreamInfo],
        optical_object: u128,
        root: bool,
        count: &mut usize,
        allocated: &mut usize,
        extents: &mut usize,
        cap: usize,
        bytes_cap: usize,
        report: &mut WriteReport,
    ) -> io::Result<(Vec<TreeStream>, Vec<TreeStream>)> {
        let mut named = Vec::new();
        let mut system = Vec::new();
        if infos.len() > cap {
            return Err(err("stream inventory exceeds entry cap"));
        }
        for info in infos {
            let resource_name = NativeName::Bytes(b"com.apple.ResourceFork".to_vec());
            let (native, is_system) = match &info.kind {
                StreamKind::Data if !root => continue,
                StreamKind::Named(name) => (name, false),
                StreamKind::ResourceFork if self.resource_forks_as_named && !root => {
                    (&resource_name, false)
                }
                StreamKind::System(name) if root => (name, true),
                _ => return Err(err("unsupported stream kind or non-root system stream")),
            };
            if !self.udf {
                return Err(err("ISO named/root/system streams unsupported"));
            }
            *count = count
                .checked_add(1)
                .filter(|n| *n <= cap)
                .ok_or_else(|| err("stream entry cap"))?;
            let units = match native {
                NativeName::Bytes(b) => b.len(),
                NativeName::Utf16(u) => u.len(),
            };
            if units > bytes_cap || name_charge(native)? > bytes_cap {
                return Err(err("stream native name exceeds byte cap"));
            }
            let (text, raw, _) = name(native, self.limits.byte_names)?;
            if text.starts_with("*UDF") {
                return Err(err("reserved UDF stream name"));
            }
            *allocated = allocated
                .checked_add(1024)
                .and_then(|n| n.checked_add(text.len()))
                .and_then(|n| n.checked_add(raw.len()))
                .and_then(|n| n.checked_add(owner.native.len()))
                .filter(|n| *n <= bytes_cap)
                .ok_or_else(|| err("stream metadata byte cap"))?;
            let destination = if is_system { &mut system } else { &mut named };
            if destination.iter().any(|s: &TreeStream| s.name == text) {
                return Err(err("duplicate mapped stream name"));
            }
            let file = self
                .tree
                .open_stream(owner, &info.kind, &self.resources)
                .map_err(io::Error::other)?;
            if file.identity() != owner || file.len() != info.length {
                return Err(err("stream identity/length drift"));
            }
            let mut position = 0;
            file.visit_extents(&self.resources, &mut |extent| {
                *extents = extents
                    .checked_add(1)
                    .filter(|n| *n <= self.limits.maximum_extents)
                    .ok_or_else(|| {
                        core::Error::new(
                            core::ErrorKind::BudgetExhausted,
                            "named stream extent cap",
                        )
                    })?;
                if extent.offset != position
                    || extent.length == 0
                    || position
                        .checked_add(extent.length)
                        .is_none_or(|n| n > file.len())
                {
                    return Err(core::Error::new(
                        core::ErrorKind::InvalidData,
                        "named stream invalid extent map",
                    ));
                }
                position += extent.length;
                if extent.kind != core::ExtentKind::Data {
                    report.materialized_stream_zero_ranges += 1;
                }
                Ok(())
            })
            .map_err(io::Error::other)?;
            if position != file.len() {
                return Err(err("named stream map incomplete"));
            }
            destination.try_reserve(1).map_err(io::Error::other)?;
            destination.push(TreeStream {
                name: text,
                native_name: raw,
                metadata: preservation::Metadata::default(),
                content: DeferredContent::new(Arc::new(Payload {
                    tree: self.tree.clone(),
                    file: file.clone(),
                    object: id_copy(owner)?,
                    resources: self.resources.clone(),
                    identity: SourceIdentity {
                        object: (optical_object << 64) | *count as u128,
                        generation: owner.generation,
                        size: file.len(),
                    },
                    start: 0,
                    file_length: file.len(),
                    _lease: self.lease.clone(),
                })),
            });
            report.streams += 1;
            if info.kind == StreamKind::ResourceFork {
                report.resource_forks_as_named_streams += 1;
            }
        }
        Ok((named, system))
    }
}
impl FileTreeSource for Bridge {
    fn inventory(&self, maximum_entries: usize, maximum_bytes: usize) -> io::Result<TreeInventory> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        let entries_cap = maximum_entries.min(self.limits.maximum_entries);
        let bytes_cap = maximum_bytes.min(self.limits.maximum_bytes);
        let mut inventory = TreeInventory::default();
        let root = self.tree.root();
        if root.native.len() > bytes_cap {
            return Err(err("root identity exceeds metadata cap"));
        }
        let root_metadata = self
            .tree
            .metadata(&root, &self.resources)
            .map_err(io::Error::other)?;
        let mut report = WriteReport {
            metadata_objects: 1,
            ..WriteReport::default()
        };
        metadata_report(&root_metadata, &mut report);
        drop(root_metadata);
        let mut allocated = 0usize;
        let mut extent_count = 0usize;
        let mut stream_count = 0usize;
        let root_infos = self
            .tree
            .streams(&root, &self.resources)
            .map_err(io::Error::other)?;
        let (root_streams, system_streams) = self.named_streams(
            &root,
            &root_infos,
            0,
            true,
            &mut stream_count,
            &mut allocated,
            &mut extent_count,
            entries_cap,
            bytes_cap,
            &mut report,
        )?;
        inventory.root_streams = root_streams;
        inventory.system_streams = system_streams;
        let mut queue = VecDeque::new();
        queue.try_reserve(entries_cap).map_err(io::Error::other)?;
        queue.push_back((id_copy(&root)?, String::new()));
        let mut directories = HashSet::new();
        directories
            .try_reserve(
                entries_cap
                    .checked_add(1)
                    .ok_or_else(|| err("directory count overflow"))?,
            )
            .map_err(io::Error::other)?;
        directories.insert(root);
        let mut files: HashMap<ObjectId, (u128, String)> = HashMap::new();
        files.try_reserve(entries_cap).map_err(io::Error::other)?;
        inventory
            .entries
            .try_reserve_exact(entries_cap)
            .map_err(io::Error::other)?;
        while let Some((directory, parent_path)) = queue.pop_front() {
            let mut continuation = None;
            loop {
                self.resources
                    .cancellation
                    .check()
                    .map_err(io::Error::other)?;
                let page = self
                    .tree
                    .directory_page(
                        &directory,
                        continuation.as_deref(),
                        self.limits.page_entries,
                        &self.resources,
                    )
                    .map_err(io::Error::other)?;
                if page.entries.len() > self.limits.page_entries {
                    return Err(err("source exceeded page cap"));
                }
                for entry in &page.entries {
                    if inventory
                        .entries
                        .len()
                        .checked_add(stream_count)
                        .is_none_or(|n| n >= entries_cap)
                    {
                        return Err(err("optical inventory entry limit"));
                    }
                    let name_units = match &entry.name {
                        NativeName::Bytes(bytes) => bytes.len(),
                        NativeName::Utf16(units) => units.len(),
                    };
                    if name_units > bytes_cap || name_charge(&entry.name)? > bytes_cap {
                        return Err(err("native name exceeds metadata cap"));
                    }
                    let (component, native_name, fat) = name(&entry.name, self.limits.byte_names)?;
                    let path_bytes = parent_path
                        .len()
                        .checked_add(component.len())
                        .and_then(|n| n.checked_add(1))
                        .ok_or_else(|| err("path overflow"))?;
                    allocated = allocated
                        .checked_add(
                            path_bytes
                                .checked_mul(3)
                                .and_then(|n| n.checked_add(native_name.len()))
                                .and_then(|n| {
                                    n.checked_add(entry.object.native.len().saturating_mul(3))
                                })
                                .ok_or_else(|| err("inventory overflow"))?,
                        )
                        .ok_or_else(|| err("inventory overflow"))?;
                    if allocated > bytes_cap {
                        return Err(err("optical inventory byte limit"));
                    }
                    let mut path = text_copy(&parent_path)?;
                    path.try_reserve_exact(component.len() + 1)
                        .map_err(io::Error::other)?;
                    if !path.is_empty() {
                        path.push('/');
                    }
                    path.push_str(&component);
                    if inventory.entries.iter().any(|prior| prior.path == path) {
                        return Err(err("destination name collision"));
                    }
                    let metadata = self
                        .tree
                        .metadata(&entry.object, &self.resources)
                        .map_err(io::Error::other)?;
                    metadata_report(&metadata, &mut report);
                    drop(metadata);
                    report.metadata_objects += 1;
                    if fat {
                        report.fat_short_names += 1;
                    }
                    let streams = self
                        .tree
                        .streams(&entry.object, &self.resources)
                        .map_err(io::Error::other)?;
                    if streams.iter().any(|s| {
                        !matches!(s.kind, StreamKind::Data | StreamKind::Named(_))
                            && !(self.resource_forks_as_named && s.kind == StreamKind::ResourceFork)
                    }) {
                        return Err(err(
                            "non-root system streams and resource forks unsupported",
                        ));
                    }
                    if !self.udf && streams.iter().any(|s| s.kind != StreamKind::Data) {
                        return Err(err("ISO named streams unsupported"));
                    }
                    let (object, kind) = match entry.kind {
                        core::ObjectKind::Directory => {
                            if streams.iter().any(|s| s.kind == StreamKind::Data) {
                                return Err(err("directory ordinary stream unsupported"));
                            }
                            if !directories.insert(id_copy(&entry.object)?) {
                                return Err(err("directory alias or cycle"));
                            }
                            queue.push_back((id_copy(&entry.object)?, text_copy(&path)?));
                            (
                                (inventory.entries.len() + 1) as u128,
                                TreeEntryKind::Directory,
                            )
                        }
                        core::ObjectKind::File => {
                            if streams
                                .iter()
                                .filter(|s| s.kind == StreamKind::Data)
                                .count()
                                != 1
                            {
                                return Err(err("only one ordinary data stream is supported"));
                            }
                            if let Some((object, target)) = files.get(&entry.object) {
                                if !self.hard_links {
                                    return Err(err("ISO hard links require Rock Ridge"));
                                }
                                (*object, TreeEntryKind::HardLink(text_copy(target)?))
                            } else {
                                let object = (inventory.entries.len() + 1) as u128;
                                let file = self
                                    .tree
                                    .open_stream(&entry.object, &StreamKind::Data, &self.resources)
                                    .map_err(io::Error::other)?;
                                if file.identity() != &entry.object
                                    || file.len()
                                        != streams
                                            .iter()
                                            .find(|s| s.kind == StreamKind::Data)
                                            .unwrap()
                                            .length
                                {
                                    return Err(err(
                                        "stream identity/length differs from inventory",
                                    ));
                                }
                                let mut extents = Vec::new();
                                let mut position = 0u64;
                                file.visit_extents(&self.resources, &mut |extent| {
                                    extent_count += 1;
                                    if extent_count > self.limits.maximum_extents {
                                        return Err(core::Error::new(
                                            core::ErrorKind::BudgetExhausted,
                                            "optical extent cap",
                                        ));
                                    }
                                    if extent.offset != position
                                        || extent.length == 0
                                        || position
                                            .checked_add(extent.length)
                                            .is_none_or(|end| end > file.len())
                                    {
                                        return Err(core::Error::new(
                                            core::ErrorKind::InvalidData,
                                            "invalid common logical extent map",
                                        ));
                                    }
                                    position += extent.length;
                                    allocated = allocated
                                        .checked_add(512)
                                        .and_then(|n| n.checked_add(entry.object.native.len()))
                                        .filter(|n| *n <= bytes_cap)
                                        .ok_or_else(|| {
                                            core::Error::new(
                                                core::ErrorKind::BudgetExhausted,
                                                "optical extent metadata byte cap",
                                            )
                                        })?;
                                    if self.udf
                                        && extent.kind != core::ExtentKind::Data
                                        && (!extent.offset.is_multiple_of(2048)
                                            || (position != file.len()
                                                && !extent.length.is_multiple_of(2048)))
                                    {
                                        return Err(core::Error::new(
                                            core::ErrorKind::Unsupported,
                                            "UDF sparse boundaries must align to optical blocks",
                                        ));
                                    }
                                    if extent.kind == core::ExtentKind::Data
                                        && let Some(TreeExtent::Data(previous)) = extents.last_mut()
                                    {
                                        let size = previous
                                            .len()
                                            .checked_add(extent.length)
                                            .ok_or_else(|| {
                                                core::Error::new(
                                                    core::ErrorKind::InvalidData,
                                                    "data extent overflow",
                                                )
                                            })?;
                                        *previous = DeferredContent::new(Arc::new(Payload {
                                            tree: self.tree.clone(),
                                            file: file.clone(),
                                            object: id_copy(&entry.object).map_err(|e| {
                                                core::Error::io("copy source identity", e)
                                            })?,
                                            resources: self.resources.clone(),
                                            identity: SourceIdentity {
                                                object,
                                                generation: entry.object.generation,
                                                size,
                                            },
                                            start: position - size,
                                            file_length: file.len(),
                                            _lease: self.lease.clone(),
                                        }));
                                        return Ok(());
                                    }
                                    extents.try_reserve(1).map_err(|e| {
                                        core::Error::new(
                                            core::ErrorKind::BudgetExhausted,
                                            e.to_string(),
                                        )
                                    })?;
                                    let translated = match extent.kind {
                                        core::ExtentKind::Hole => {
                                            if self.udf {
                                                report.retained_zero_ranges += 1;
                                            } else {
                                                report.materialized_zero_ranges += 1;
                                            }
                                            TreeExtent::Hole(extent.length)
                                        }
                                        core::ExtentKind::Unwritten => {
                                            if self.udf {
                                                report.retained_zero_ranges += 1;
                                            } else {
                                                report.materialized_zero_ranges += 1;
                                            }
                                            TreeExtent::AllocatedHole(extent.length)
                                        }
                                        core::ExtentKind::Data => TreeExtent::Data(
                                            DeferredContent::new(Arc::new(Payload {
                                                tree: self.tree.clone(),
                                                file: file.clone(),
                                                object: id_copy(&entry.object).map_err(|e| {
                                                    core::Error::io("copy source identity", e)
                                                })?,
                                                resources: self.resources.clone(),
                                                identity: SourceIdentity {
                                                    object,
                                                    generation: entry.object.generation,
                                                    size: extent.length,
                                                },
                                                start: extent.offset,
                                                file_length: file.len(),
                                                _lease: self.lease.clone(),
                                            })),
                                        ),
                                    };
                                    extents.push(translated);
                                    Ok(())
                                })
                                .map_err(io::Error::other)?;
                                if position != file.len() {
                                    return Err(err("logical map does not cover file"));
                                }
                                files.insert(id_copy(&entry.object)?, (object, text_copy(&path)?));
                                report.files += 1;
                                (object, TreeEntryKind::File(extents))
                            }
                        }
                        _ => {
                            return Err(err(
                                "symbolic links and special objects require an explicit preservation profile",
                            ));
                        }
                    };
                    let entry_streams = if matches!(kind, TreeEntryKind::HardLink(_)) {
                        Vec::new()
                    } else {
                        let (named, system) = self.named_streams(
                            &entry.object,
                            &streams,
                            object,
                            false,
                            &mut stream_count,
                            &mut allocated,
                            &mut extent_count,
                            entries_cap - inventory.entries.len() - 1,
                            bytes_cap,
                            &mut report,
                        )?;
                        if !system.is_empty() {
                            return Err(err("non-root system stream"));
                        }
                        named
                    };
                    inventory.entries.push(TreeEntry {
                        path,
                        native_name,
                        object,
                        kind,
                        metadata: preservation::Metadata::default(),
                        streams: entry_streams,
                    });
                    inventory.validate_budget(entries_cap, bytes_cap)?;
                }
                match &page.next {
                    None => break,
                    Some(next) => {
                        if page.entries.is_empty() || continuation.as_ref() == Some(next) {
                            return Err(err("directory page makes no progress"));
                        }
                        if next.len() > bytes_cap {
                            return Err(err("continuation exceeds metadata cap"));
                        }
                        continuation = Some(duplicate(next)?);
                    }
                }
            }
        }
        // ISO sorts by depth/path before translation. Canonicalize aliases to that
        // same order so every target precedes all names sharing its object.
        inventory.entries.sort_by(|a, b| {
            a.path
                .split('/')
                .count()
                .cmp(&b.path.split('/').count())
                .then(a.path.cmp(&b.path))
        });
        for (object, original) in files.values() {
            let original_index = inventory
                .entries
                .iter()
                .position(|e| e.path == *original)
                .ok_or_else(|| err("hard-link original missing"))?;
            let canonical = inventory
                .entries
                .iter()
                .position(|e| e.object == *object)
                .ok_or_else(|| err("hard-link identity missing"))?;
            let target = text_copy(&inventory.entries[canonical].path)?;
            if canonical != original_index {
                let file = std::mem::replace(
                    &mut inventory.entries[original_index].kind,
                    TreeEntryKind::HardLink(text_copy(&target)?),
                );
                inventory.entries[canonical].kind = file;
                let streams = std::mem::take(&mut inventory.entries[original_index].streams);
                inventory.entries[canonical].streams = streams;
            }
            for (index, entry) in inventory.entries.iter_mut().enumerate() {
                if entry.object == *object && index != canonical {
                    entry.kind = TreeEntryKind::HardLink(text_copy(&target)?);
                }
            }
        }
        report.entries = inventory.entries.len();
        *self
            .report
            .lock()
            .map_err(|_| err("report lock poisoned"))? = report;
        Ok(inventory)
    }
}
/// Stage ISO without host extraction or publication. Sparse ranges become logical zeros.
pub fn stage_iso(
    source: Arc<dyn TreeSource>,
    resources: Resources,
    limits: WriteLimits,
    policy: WritePolicy,
    directory: &Path,
    options: &libmkiso::IsoOptions,
) -> anyhow::Result<StagedOptical> {
    let bridge = Bridge::new(source, resources, limits, false, options.rock_ridge, policy)?;
    let path = libmkiso::stage_iso9660_from_tree_source(&bridge, directory, options, || {
        bridge
            .resources
            .cancellation
            .check()
            .map_err(|e| libmkiso::IsoError::Io(io::Error::other(e)))
    })?;
    let report = bridge
        .report
        .lock()
        .map_err(|_| err("report lock poisoned"))?
        .clone();
    Ok(StagedOptical {
        path,
        report,
        _lease: bridge.lease.clone(),
    })
}
/// Stage UDF without host extraction or publication, retaining supported sparse semantics.
pub fn stage_udf(
    source: Arc<dyn TreeSource>,
    resources: Resources,
    limits: WriteLimits,
    policy: WritePolicy,
    directory: &Path,
    options: &libmkiso::UdfOptions,
) -> anyhow::Result<StagedOptical> {
    let bridge = Bridge::new(source, resources, limits, true, true, policy)?;
    let image = libmkiso::UdfImage::from_tree_source(
        &bridge,
        bridge.limits.maximum_entries,
        bridge.limits.maximum_bytes,
    )?;
    let (path, _hash) = image.stage_with_cancel(directory, options, || {
        bridge
            .resources
            .cancellation
            .check()
            .map_err(anyhow::Error::from)
    })?;
    let report = bridge
        .report
        .lock()
        .map_err(|_| err("report lock poisoned"))?
        .clone();
    Ok(StagedOptical {
        path,
        report,
        _lease: bridge.lease.clone(),
    })
}
