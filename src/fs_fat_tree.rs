//! Bounded FAT capture inventory implementing the common deferred tree source.
//!
//! Inventory is an explicit full-tree operation, separate from ordinary direct
//! file access. It is not a global allocation audit. FAT native timestamp fields
//! remain opaque; no metadata-preserving optical capture is claimed.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
use crate::{
    fs_core::*,
    fs_fat::{FatEntry, FatVolume},
};

struct Node {
    entry: Option<FatEntry>,
    children: Vec<ObjectId>,
}

/// Immutable, source-scoped FAT namespace inventory with deferred payload reads.
pub struct FatTreeSource {
    volume: FatVolume,
    root: ObjectId,
    nodes: HashMap<ObjectId, Node>,
    max_clusters: usize,
    _inventory: Reservation,
}
impl FatTreeSource {
    /// Inventory a complete native tree with explicit object, slot and chain limits.
    ///
    /// Reserves a conservative 2048 bytes/object for maps, cloned native names,
    /// identifiers and traversal work before allocation. Individual directory
    /// decoding uses the same pool and retains its own scratch/index charge.
    /// Multiple directory names sharing a cluster are rejected as cycles/aliases.
    pub fn inventory(
        volume: FatVolume,
        maximum_objects: usize,
        max_clusters: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        if maximum_objects == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "inventory requires room for root",
            ));
        }
        let bytes = (maximum_objects as u64)
            .checked_mul(2048)
            .ok_or_else(|| Error::new(ErrorKind::BudgetExhausted, "inventory budget overflow"))?;
        let reservation = resources.memory.reserve(bytes)?;
        let mut nodes = HashMap::new();
        nodes
            .try_reserve(maximum_objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut pending = VecDeque::new();
        pending
            .try_reserve(maximum_objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        let mut seen_directories = HashSet::new();
        seen_directories
            .try_reserve(maximum_objects)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        if let Some(cluster) = volume.geometry().root_cluster() {
            seen_directories.insert(cluster);
        }
        let root = volume.root_identity();
        nodes.insert(
            root.clone(),
            Node {
                entry: None,
                children: Vec::new(),
            },
        );
        pending.push_back(root.clone());
        while let Some(parent) = pending.pop_front() {
            resources.cancellation.check()?;
            let entry = nodes.get(&parent).and_then(|n| n.entry.as_ref());
            let directory = match entry {
                None => volume.root_directory(max_clusters, max_slots, resources),
                Some(entry) => volume.read_directory(entry, max_clusters, max_slots, resources),
            }
            .map_err(|e| Error::io("inventory FAT directory", e))?;
            if directory.entries().len() > maximum_objects - nodes.len() {
                return Err(Error::new(
                    ErrorKind::BudgetExhausted,
                    "FAT inventory object limit exceeded",
                ));
            }
            let mut children = Vec::new();
            children
                .try_reserve_exact(directory.entries().len())
                .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
            for entry in directory.entries() {
                resources.cancellation.check()?;
                let id = entry.identity().clone();
                if nodes.contains_key(&id) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "repeated FAT directory slot identity",
                    ));
                }
                if entry.is_directory() {
                    let raw = entry.raw_metadata();
                    let cluster = u32::from(u16::from_le_bytes([raw[26], raw[27]]))
                        | (u32::from(u16::from_le_bytes([raw[20], raw[21]])) << 16);
                    if !seen_directories.insert(cluster) {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "FAT directory cycle or alias",
                        ));
                    }
                    pending.push_back(id.clone());
                }
                children.push(id.clone());
                nodes.insert(
                    id,
                    Node {
                        entry: Some(entry.clone()),
                        children: Vec::new(),
                    },
                );
            }
            nodes
                .get_mut(&parent)
                .expect("queued inventory node exists")
                .children = children;
        }
        Ok(Self {
            volume,
            root,
            nodes,
            max_clusters,
            _inventory: reservation,
        })
    }
    fn node(&self, object: &ObjectId) -> Result<&Node> {
        self.nodes.get(object).ok_or_else(|| {
            Error::new(
                ErrorKind::StalePlan,
                "object belongs to another inventory or generation",
            )
        })
    }
    fn token_prefix(&self, object: &ObjectId) -> Vec<u8> {
        let mut token = object.source.to_le_bytes().to_vec();
        token.extend_from_slice(&object.native);
        token
    }
}
impl TreeSource for FatTreeSource {
    fn root(&self) -> ObjectId {
        self.root.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>> {
        resources.cancellation.check()?;
        let node = self.node(object)?;
        Budgeted::try_new(&resources.memory, 4096, || {
            let (created, modified, accessed, native_flags) = if let Some(entry) = &node.entry {
                let raw = entry.raw_metadata();
                (
                    MetadataField::Opaque {
                        bytes: raw[13..18].to_vec(),
                        interpretation:
                            "FAT creation date/time and centiseconds; conversion unimplemented"
                                .into(),
                    },
                    MetadataField::Opaque {
                        bytes: raw[22..26].to_vec(),
                        interpretation: "FAT modification date/time; conversion unimplemented"
                            .into(),
                    },
                    MetadataField::Opaque {
                        bytes: raw[18..20].to_vec(),
                        interpretation: "FAT access date; conversion unimplemented".into(),
                    },
                    MetadataField::Known(raw[11..13].to_vec()),
                )
            } else {
                (
                    MetadataField::Absent,
                    MetadataField::Absent,
                    MetadataField::Absent,
                    MetadataField::Absent,
                )
            };
            Ok(Metadata {
                created,
                modified,
                accessed,
                owner: MetadataField::Absent,
                mode: MetadataField::Absent,
                security: MetadataField::Absent,
                attributes: Vec::new(),
                native_flags,
                symlink_target: MetadataField::Absent,
                reparse_data: MetadataField::Absent,
            })
        })
    }
    fn directory_page(
        &self,
        object: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        resources: &Resources,
    ) -> Result<DirectoryPage> {
        resources.cancellation.check()?;
        let node = self.node(object)?;
        if maximum_entries == 0
            || node
                .entry
                .as_ref()
                .is_some_and(|entry| !entry.is_directory())
        {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "invalid FAT directory page request",
            ));
        }
        let prefix = self.token_prefix(object);
        let start = match continuation {
            None => 0,
            Some(token) if token.len() == prefix.len() + 8 && token.starts_with(&prefix) => {
                usize::try_from(u64::from_le_bytes(
                    token[prefix.len()..]
                        .try_into()
                        .expect("checked token length"),
                ))
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        "page token exceeds address space",
                    )
                })?
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "foreign FAT directory continuation",
                ));
            }
        };
        if start > node.children.len() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "page continuation exceeds directory",
            ));
        }
        let count = maximum_entries.min(node.children.len() - start);
        let bytes = (count as u64)
            .checked_mul(1024)
            .and_then(|n| n.checked_add(64))
            .ok_or_else(|| {
                Error::new(ErrorKind::BudgetExhausted, "directory page budget overflow")
            })?;
        let reservation = resources.memory.reserve(bytes)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        for child in &node.children[start..start + count] {
            resources.cancellation.check()?;
            let entry = self.nodes[child]
                .entry
                .as_ref()
                .expect("child has native slot");
            entries.push(DirectoryEntry {
                name: entry.name().clone(),
                object: child.clone(),
                kind: if entry.is_directory() {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        let next = if start + count < node.children.len() {
            let mut token = prefix;
            token.extend_from_slice(&((start + count) as u64).to_le_bytes());
            Some(token)
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
        resources.cancellation.check()?;
        let entry = self.node(object)?.entry.as_ref();
        Budgeted::try_new(
            &resources.memory,
            crate::platform::mem::size_of::<StreamInfo>() as u64,
            || {
                Ok(match entry {
                    Some(entry) if !entry.is_directory() => vec![StreamInfo {
                        kind: StreamKind::Data,
                        length: u64::from(entry.len()),
                    }],
                    _ => Vec::new(),
                })
            },
        )
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        resources: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        resources.cancellation.check()?;
        if stream != &StreamKind::Data {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "baseline FAT has no named streams or resource forks",
            ));
        }
        let entry = self.node(object)?.entry.as_ref().ok_or_else(|| {
            Error::new(ErrorKind::InvalidOperation, "root has no ordinary stream")
        })?;
        let file = self
            .volume
            .open_entry(entry, self.max_clusters, resources)
            .map_err(|e| Error::io("open FAT namespace file", e))?;
        Ok(Arc::new(file))
    }
    fn revalidate(&self, object: &ObjectId, resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        self.node(object)?;
        // Input immutability remains a caller guarantee; identities verify scope,
        // not concurrent external mutation or mounted access.
        Ok(())
    }
}
