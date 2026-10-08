//! Native optical topology, owned streams and explicit source metadata inspection.
use crate::read::{OpticalReadEntry, OpticalReadIndex};
use libmkiso::{preservation::Field, topology::Parent};
use partmgr::fs_core::*;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
static NEXT_TREE: AtomicU64 = AtomicU64::new(1);
fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn alloc(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::BudgetExhausted, error.to_string())
}
fn bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(input.len()).map_err(alloc)?;
    v.extend_from_slice(input);
    Ok(v)
}
fn name(input: &NativeName) -> Result<NativeName> {
    Ok(match input {
        NativeName::Bytes(b) => NativeName::Bytes(bytes(b)?),
        NativeName::Utf16(u) => {
            let mut v = Vec::new();
            v.try_reserve_exact(u.len()).map_err(alloc)?;
            v.extend_from_slice(u);
            NativeName::Utf16(v)
        }
    })
}
fn id(input: &ObjectId) -> Result<ObjectId> {
    Ok(ObjectId {
        source: input.source,
        generation: input.generation,
        native: bytes(&input.native)?,
    })
}
fn valid_leaf(input: &NativeName) -> bool {
    match input {
        NativeName::Bytes(b) => {
            !b.is_empty() && b != b"." && b != b".." && !b.iter().any(|c| *c == 0 || *c == b'/')
        }
        NativeName::Utf16(u) => {
            !u.is_empty()
                && u.as_slice() != [46]
                && u.as_slice() != [46, 46]
                && !u.iter().any(|c| *c == 0 || *c == 47)
        }
    }
}
fn name_bytes(n: &NativeName) -> usize {
    match n {
        NativeName::Bytes(b) => b.len(),
        NativeName::Utf16(u) => u.len() * 2,
    }
}
/// Immutable complete selected optical namespace, excluding owned streams from directory pages.
/// Parser objects are released before construction; no unsafe Send/Sync bridge is used.
pub struct OpticalTreeSource {
    index: OpticalReadIndex,
    nodes: HashMap<ObjectId, usize>,
    children: HashMap<ObjectId, Vec<usize>>,
    streams: HashMap<ObjectId, Vec<(StreamKind, usize)>>,
    cookie: u64,
    _reservation: Reservation,
}
impl OpticalTreeSource {
    /// Retain native parent relationships and semantic leaf names without display-path splitting.
    /// UDF hard-linked files share ICB identities; directory aliases/cycles and inconsistent
    /// duplicate stream ownership fail closed. Metadata and specials remain inspectable.
    pub fn new(index: OpticalReadIndex, resources: &Resources) -> Result<Self> {
        resources.cancellation.check()?;
        index.context.revalidate()?;
        let charge = (index.entries().len() as u64)
            .checked_mul(4096)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| alloc("optical tree envelope overflow"))?;
        let reservation = resources.memory.reserve(charge)?;
        let mut nodes = HashMap::new();
        nodes
            .try_reserve(index.entries().len() + 1)
            .map_err(alloc)?;
        nodes.insert(id(&index.root_identity)?, usize::MAX);
        let mut children: HashMap<ObjectId, Vec<usize>> = HashMap::new();
        children
            .try_reserve(index.entries().len() + 1)
            .map_err(alloc)?;
        children.insert(id(&index.root_identity)?, Vec::new());
        let mut streams: HashMap<ObjectId, Vec<(StreamKind, usize)>> = HashMap::new();
        streams
            .try_reserve(index.entries().len() + 1)
            .map_err(alloc)?;
        for (i, e) in index.entries().iter().enumerate() {
            resources.cancellation.check()?;
            if e.stream.is_some() {
                continue;
            }
            if !valid_leaf(&e.leaf) {
                return Err(bad("invalid optical native leaf"));
            }
            if let Some(previous) = nodes.get(&e.identity) {
                if *previous == usize::MAX || e.kind == ObjectKind::Directory {
                    return Err(bad("optical directory alias or root alias"));
                }
                let old = &index.entries()[*previous];
                if !old.same_object(e) {
                    return Err(bad("inconsistent optical hard-link object"));
                }
            } else {
                nodes.insert(id(&e.identity)?, i);
            }
            if e.kind == ObjectKind::Directory {
                children.insert(id(&e.identity)?, Vec::new());
            }
        }
        for (i, e) in index.entries().iter().enumerate() {
            resources.cancellation.check()?;
            if let Some(stream) = &e.stream {
                if e.parent.is_some() {
                    return Err(bad("optical stream has ordinary parent"));
                }
                let owner = match stream.owner {
                    None => &index.root_identity,
                    Some(n) => {
                        let owner = index
                            .entries()
                            .get(n)
                            .ok_or_else(|| bad("optical stream owner out of range"))?;
                        if owner.stream.is_some() {
                            return Err(bad("stream owns another stream"));
                        }
                        &owner.identity
                    }
                };
                if !nodes.contains_key(owner) {
                    return Err(bad("missing optical stream owner"));
                }
                let kind = if stream.system {
                    StreamKind::System(name(&e.leaf)?)
                } else {
                    StreamKind::Named(name(&e.leaf)?)
                };
                let list = streams.entry(id(owner)?).or_default();
                if let Some((_, old)) = list.iter().find(|(k, _)| *k == kind) {
                    let old = &index.entries()[*old];
                    if old.identity != e.identity || !old.same_object(e) {
                        return Err(bad("ambiguous optical owned stream"));
                    }
                } else {
                    list.try_reserve_exact(1).map_err(alloc)?;
                    list.push((kind, i));
                }
                continue;
            }
            let parent = match e
                .parent
                .ok_or_else(|| bad("ordinary optical entry lacks parent"))?
            {
                Parent::Root => &index.root_identity,
                Parent::Entry(n) => {
                    let p = index
                        .entries()
                        .get(n)
                        .ok_or_else(|| bad("optical parent index out of range"))?;
                    if p.kind != ObjectKind::Directory || p.stream.is_some() {
                        return Err(bad("optical parent is not ordinary directory"));
                    }
                    &p.identity
                }
            };
            let list = children
                .get_mut(parent)
                .ok_or_else(|| bad("optical parent missing from tree"))?;
            if list.iter().any(|old| index.entries()[*old].leaf == e.leaf) {
                return Err(bad("duplicate optical native directory name"));
            }
            list.try_reserve_exact(1).map_err(alloc)?;
            list.push(i);
            // Every occurrence must reach the explicit root through native parents.
            let mut current = i;
            let mut hops = 0;
            loop {
                hops += 1;
                if hops > index.entries().len().min(index.max_depth.saturating_add(1)) {
                    return Err(bad("optical parent cycle"));
                }
                match index.entries()[current]
                    .parent
                    .ok_or_else(|| bad("optical parent chain missing"))?
                {
                    Parent::Root => break,
                    Parent::Entry(n) => {
                        if n >= index.entries().len() {
                            return Err(bad("optical parent chain outside index"));
                        }
                        current = n;
                    }
                }
            }
        }
        Ok(Self {
            index,
            nodes,
            children,
            streams,
            cookie: NEXT_TREE.fetch_add(1, Ordering::Relaxed),
            _reservation: reservation,
        })
    }
    /// Borrow the retained native inspection, including metadata of owned streams
    /// that the common object metadata contract does not expose separately.
    pub fn inspection(&self) -> &OpticalReadIndex {
        &self.index
    }
    fn object(&self, object: &ObjectId, resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        self.index.context.revalidate()?;
        self.nodes.get(object).copied().ok_or_else(|| {
            Error::new(
                ErrorKind::StalePlan,
                "optical identity/source/generation not inventoried",
            )
        })
    }
    fn native_metadata(&self, n: usize) -> &libmkiso::preservation::Metadata {
        if n == usize::MAX {
            &self.index.root_metadata
        } else {
            &self.index.entries()[n].metadata
        }
    }
}
impl TreeSource for OpticalTreeSource {
    fn root(&self) -> ObjectId {
        self.index.root_identity.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn revalidate(&self, object: &ObjectId, resources: &Resources) -> Result<()> {
        self.object(object, resources).map(|_| ())
    }
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>> {
        let n = self.object(object, resources)?;
        let m = self.native_metadata(n);
        let charge = (m.allocation_bytes() as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| alloc("optical metadata envelope overflow"))?;
        Budgeted::try_new(&resources.memory, charge, || {
            translate(
                m,
                if n == usize::MAX {
                    None
                } else {
                    Some(&self.index.entries()[n])
                },
            )
        })
    }
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        resources: &Resources,
    ) -> Result<DirectoryPage> {
        let node = self.object(directory, resources)?;
        if maximum_entries == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "zero optical page limit",
            ));
        }
        let list = self.children.get(directory).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidOperation,
                "optical object is not directory",
            )
        })?;
        let start = match continuation {
            None => 0,
            Some(b) => {
                if b.len() != 24
                    || u64::from_le_bytes(b[0..8].try_into().unwrap()) != self.cookie
                    || u64::from_le_bytes(b[8..16].try_into().unwrap()) != node as u64
                {
                    return Err(bad(
                        "optical continuation belongs to another directory/tree",
                    ));
                }
                usize::try_from(u64::from_le_bytes(b[16..24].try_into().unwrap())).map_err(alloc)?
            }
        };
        if start > list.len() {
            return Err(bad("optical continuation outside directory"));
        }
        let end = start.saturating_add(maximum_entries).min(list.len());
        let charge = list[start..end].iter().try_fold(64u64, |total, i| {
            let e = &self.index.entries()[*i];
            total
                .checked_add(
                    (std::mem::size_of::<DirectoryEntry>()
                        + name_bytes(&e.leaf)
                        + e.identity.native.len()) as u64,
                )
                .ok_or_else(|| alloc("optical page overflow"))
        })?;
        let reservation = resources.memory.reserve(charge)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(end - start).map_err(alloc)?;
        for i in &list[start..end] {
            resources.cancellation.check()?;
            let e = &self.index.entries()[*i];
            entries.push(DirectoryEntry {
                name: name(&e.leaf)?,
                object: id(&e.identity)?,
                kind: e.kind.clone(),
            });
        }
        let next = if end < list.len() {
            let mut b = bytes(&self.cookie.to_le_bytes())?;
            b.try_reserve_exact(16).map_err(alloc)?;
            b.extend_from_slice(&(node as u64).to_le_bytes());
            b.extend_from_slice(&(end as u64).to_le_bytes());
            Some(b)
        } else {
            None
        };
        Ok(DirectoryPage {
            entries,
            next,
            reservation,
        })
    }
    fn streams(
        &self,
        object: &ObjectId,
        resources: &Resources,
    ) -> Result<Budgeted<Vec<StreamInfo>>> {
        let n = self.object(object, resources)?;
        let ordinary = n != usize::MAX && self.index.entries()[n].kind == ObjectKind::File;
        let extra = self.streams.get(object);
        let count = usize::from(ordinary) + extra.map_or(0, Vec::len);
        let names = extra.map_or(0, |v| {
            v.iter()
                .map(|(_, i)| name_bytes(&self.index.entries()[*i].leaf))
                .sum::<usize>()
        });
        let charge = (count as u64)
            .checked_mul((std::mem::size_of::<StreamInfo>() + 32) as u64)
            .and_then(|n| n.checked_add(names as u64))
            .ok_or_else(|| alloc("optical stream list overflow"))?;
        Budgeted::try_new(&resources.memory, charge, || {
            let mut result = Vec::new();
            result.try_reserve_exact(count).map_err(alloc)?;
            if ordinary {
                result.push(StreamInfo {
                    kind: StreamKind::Data,
                    length: self.index.entries()[n]
                        .file_length()
                        .ok_or_else(|| bad("optical file lacks data handle"))?,
                });
            }
            if let Some(extra) = extra {
                for (kind, i) in extra {
                    let kind = match kind {
                        StreamKind::Named(n) => StreamKind::Named(name(n)?),
                        StreamKind::System(n) => StreamKind::System(name(n)?),
                        _ => return Err(bad("invalid optical associated stream kind")),
                    };
                    result.push(StreamInfo {
                        kind,
                        length: self.index.entries()[*i]
                            .file_length()
                            .ok_or_else(|| bad("optical owned stream lacks handle"))?,
                    });
                }
            }
            Ok(result)
        })
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        resources: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        let n = self.object(object, resources)?;
        if *stream == StreamKind::Data
            && n != usize::MAX
            && self.index.entries()[n].kind == ObjectKind::File
        {
            return self.index.open_file(n);
        }
        if let Some((_, i)) = self
            .streams
            .get(object)
            .and_then(|v| v.iter().find(|(kind, _)| kind == stream))
        {
            let file = self.index.open_file(*i)?;
            let reservation = resources
                .memory
                .reserve((std::mem::size_of::<OwnedFile>() + object.native.len()) as u64)?;
            return Ok(Arc::new(OwnedFile {
                identity: id(object)?,
                file,
                _reservation: reservation,
            }));
        }
        Err(Error::new(
            ErrorKind::InvalidOperation,
            "optical stream is not owned by this object",
        ))
    }
}
fn opaque(field: &Field<Vec<u8>>, interpretation: &str) -> Result<MetadataField<Vec<u8>>> {
    Ok(match field {
        Field::Absent => MetadataField::Absent,
        Field::Uninspected => MetadataField::Uninspectable {
            reason: interpretation.into(),
        },
        Field::Present(b) | Field::NotWritable(b) => MetadataField::Opaque {
            bytes: bytes(b)?,
            interpretation: interpretation.into(),
        },
    })
}
fn translate(
    m: &libmkiso::preservation::Metadata,
    entry: Option<&OpticalReadEntry>,
) -> Result<Metadata> {
    let unknown = || {
        MetadataField::Uninspectable{reason:"native optical timestamp epoch/clock conversion is not implemented; exact fields retained as attributes".into()}
    };
    let mut attributes = Vec::new();
    let timestamp_count = match &m.timestamps {
        Field::Present(v) | Field::NotWritable(v) => v.len(),
        _ => 0,
    };
    attributes
        .try_reserve_exact(timestamp_count + 4)
        .map_err(alloc)?;
    fn status<T>(field: &Field<T>) -> u8 {
        match field {
            Field::Absent => 0,
            Field::Uninspected => 1,
            Field::Present(_) => 2,
            Field::NotWritable(_) => 3,
        }
    }
    attributes.push((
        NativeName::Bytes(bytes(b"optical.inspection-state")?),
        MetadataField::Known(bytes(&[
            status(&m.native_name),
            status(&m.timestamps),
            status(&m.ownership),
            status(&m.permissions),
            status(&m.extensions),
            status(&m.opaque),
        ])?),
    ));
    attributes.push((
        NativeName::Bytes(bytes(b"optical.stored-name")?),
        opaque(&m.native_name, "exact stored namespace identifier")?,
    ));
    attributes.push((
        NativeName::Bytes(bytes(b"optical.extensions")?),
        opaque(
            &m.extensions,
            "native extension bytes; transplantation not established",
        )?,
    ));
    if let Field::Present(values) | Field::NotWritable(values) = &m.timestamps {
        for (kind, stamp) in values {
            let label = format!("optical.timestamp.{kind}");
            attributes.push((
                NativeName::Bytes(bytes(label.as_bytes())?),
                MetadataField::Opaque {
                    bytes: bytes(&stamp.bytes)?,
                    interpretation: format!(
                        "native {:?} timestamp precision {:?}; no epoch conversion",
                        stamp.encoding, stamp.precision
                    ),
                },
            ));
        }
    }
    if let Some(target) = entry.and_then(|e| e.link_target.as_ref()) {
        attributes.push((
            NativeName::Bytes(bytes(b"optical.decoded-link-target")?),
            MetadataField::Known(bytes(target.as_bytes())?),
        ));
    }
    Ok(Metadata {
        created: if matches!(m.timestamps, Field::Absent) {
            MetadataField::Absent
        } else {
            unknown()
        },
        modified: if matches!(m.timestamps, Field::Absent) {
            MetadataField::Absent
        } else {
            unknown()
        },
        accessed: if matches!(m.timestamps, Field::Absent) {
            MetadataField::Absent
        } else {
            unknown()
        },
        owner: match &m.ownership {
            Field::Absent => MetadataField::Absent,
            Field::Uninspected => MetadataField::Uninspectable {
                reason: "optical ownership uninspected".into(),
            },
            Field::Present((uid, gid)) | Field::NotWritable((uid, gid)) => {
                let mut b = bytes(&uid.to_le_bytes())?;
                b.try_reserve_exact(4).map_err(alloc)?;
                b.extend_from_slice(&gid.to_le_bytes());
                MetadataField::Known(b)
            }
        },
        mode: match m.permissions {
            Field::Absent => MetadataField::Absent,
            Field::Uninspected => MetadataField::Uninspectable {
                reason: "optical native permissions uninspected".into(),
            },
            Field::Present(mode) | Field::NotWritable(mode) => MetadataField::Known(mode),
        },
        security: MetadataField::Uninspectable {
            reason: "optical security descriptors not classified by published inspection API"
                .into(),
        },
        attributes,
        native_flags: opaque(
            &m.opaque,
            "source-scoped native opaque object fields; relocation not established",
        )?,
        symlink_target: if entry.is_some_and(|e| e.kind == ObjectKind::Symlink) {
            MetadataField::Uninspectable{reason:"decoded link target retained as attribute; exact encoded native target unavailable".into()}
        } else {
            MetadataField::Absent
        },
        reparse_data: MetadataField::Uninspectable {
            reason: "optical extensions are retained but reparse semantics not classified".into(),
        },
    })
}

struct OwnedFile {
    identity: ObjectId,
    file: Arc<dyn FileRead>,
    _reservation: Reservation,
}
impl FileRead for OwnedFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8], resources: &Resources) -> Result<usize> {
        self.file.read_at(offset, buffer, resources)
    }
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.file.visit_extents(resources, visitor)
    }
}
