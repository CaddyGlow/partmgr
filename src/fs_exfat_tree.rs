//! Bounded exFAT tree inventory over the strict volume reader.
//! No global allocation audit, writable profile or source snapshot is implied.
use crate::{
    fs_core::*,
    fs_exfat_volume::{ExfatDirectory, ExfatEntry, ExfatVolume},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
/// Retained tree/inventory ceilings, independent of the volume's per-operation limits.
#[derive(Clone, Copy, Debug)]
pub struct ExfatTreeLimits {
    /// Maximum namespace objects, including the implicit root.
    pub objects: usize,
    /// Maximum aggregate allocated clusters across all inventoried directories.
    pub directory_clusters: usize,
}
struct Locator {
    directory: Arc<ExfatDirectory>,
    slot: usize,
}
struct Node {
    entry: Option<Locator>,
    children: Vec<ObjectId>,
}
impl Node {
    fn entry(&self) -> Option<&ExfatEntry> {
        self.entry.as_ref().map(|e| &e.directory.entries()[e.slot])
    }
}
fn allocation(message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message.to_string())
}
fn bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(allocation)?;
    out.extend_from_slice(input);
    Ok(out)
}
fn text(input: &str) -> Result<String> {
    let mut out = String::new();
    out.try_reserve_exact(input.len()).map_err(allocation)?;
    out.push_str(input);
    Ok(out)
}
fn id(input: &ObjectId) -> Result<ObjectId> {
    Ok(ObjectId {
        source: input.source,
        generation: input.generation,
        native: bytes(&input.native)?,
    })
}
fn name(input: &[u16]) -> Result<NativeName> {
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(allocation)?;
    out.extend_from_slice(input);
    Ok(NativeName::Utf16(out))
}
/// Complete caller-stabilized exFAT namespace with retained native metadata and deferred files.
///
/// Entry locators retain their directory decoder's memory lease, avoiding detached
/// copies of raw entry sets. Namespace identities remain physical slots scoped to
/// the volume open; shared file allocations are not interpreted as hard links.
pub struct ExfatTreeSource {
    volume: ExfatVolume,
    root: ObjectId,
    nodes: HashMap<ObjectId, Node>,
    _inventory: Reservation,
}
impl ExfatTreeSource {
    /// Inventory the complete tree with bounded traversal and directory ownership checks.
    ///
    /// Rejects duplicate directory slots and overlapping directory allocation maps,
    /// including aliases/cycles with distinct first clusters. exFAT has no dot/dot-dot
    /// entries: parent relationships come solely from the validated containing entry.
    /// The volume reader owns name folding, native set checks and allocation decoding.
    /// This remains distinct from auditing ownership of all files and free space.
    pub fn inventory(
        volume: ExfatVolume,
        limits: ExfatTreeLimits,
        resources: &Resources,
    ) -> Result<Self> {
        volume.check_stability(resources)?;
        if limits.objects == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT tree requires root capacity",
            ));
        }
        let charge = (limits.objects as u64)
            .checked_mul(2048)
            .and_then(|n| n.checked_add((limits.directory_clusters as u64).checked_mul(64)?))
            .ok_or_else(|| allocation("exFAT inventory accounting overflow"))?;
        let reservation = resources.memory.reserve(charge)?;
        let mut nodes = HashMap::new();
        nodes.try_reserve(limits.objects).map_err(allocation)?;
        let mut pending = VecDeque::new();
        pending.try_reserve(limits.objects).map_err(allocation)?;
        let mut claimed = HashSet::new();
        claimed
            .try_reserve(limits.directory_clusters)
            .map_err(allocation)?;
        let root = volume.root_identity();
        nodes.insert(
            id(&root)?,
            Node {
                entry: None,
                children: Vec::new(),
            },
        );
        pending.push_back(id(&root)?);
        while let Some(parent) = pending.pop_front() {
            volume.check_stability(resources)?;
            let directory = match nodes.get(&parent).and_then(Node::entry) {
                None => volume.root_directory(resources)?,
                Some(entry) => volume.read_directory(entry, resources)?,
            };
            if directory.allocation_clusters().len()
                > limits.directory_clusters.saturating_sub(claimed.len())
            {
                return Err(allocation("exFAT aggregate directory cluster cap"));
            }
            for cluster in directory.allocation_clusters() {
                resources.cancellation.check()?;
                if !claimed.insert(*cluster) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "exFAT directory allocation alias or cycle",
                    ));
                }
            }
            if directory.entries().len() > limits.objects - nodes.len() {
                return Err(allocation("exFAT tree object cap"));
            }
            let directory = Arc::new(directory);
            let mut children = Vec::new();
            children
                .try_reserve_exact(directory.entries().len())
                .map_err(allocation)?;
            for (slot, entry) in directory.entries().iter().enumerate() {
                resources.cancellation.check()?;
                let identity = entry.identity();
                if identity.source != root.source
                    || identity.native.len() > 16
                    || nodes.contains_key(identity)
                {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "repeated or foreign exFAT slot identity",
                    ));
                }
                if entry.is_directory() {
                    pending.push_back(id(identity)?);
                }
                children.push(id(identity)?);
                nodes.insert(
                    id(identity)?,
                    Node {
                        entry: Some(Locator {
                            directory: directory.clone(),
                            slot,
                        }),
                        children: Vec::new(),
                    },
                );
            }
            nodes
                .get_mut(&parent)
                .expect("queued exFAT parent exists")
                .children = children;
        }
        Ok(Self {
            volume,
            root,
            nodes,
            _inventory: reservation,
        })
    }
    fn node(&self, object: &ObjectId) -> Result<&Node> {
        if object.source != self.root.source || object.native.len() > 16 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign exFAT tree identity",
            ));
        }
        self.nodes.get(object).ok_or_else(|| {
            Error::new(
                ErrorKind::StalePlan,
                "exFAT slot identity or generation is outside inventory",
            )
        })
    }
    fn prefix(object: &ObjectId) -> Result<Vec<u8>> {
        let mut token = Vec::new();
        token
            .try_reserve_exact(24 + object.native.len() + 8)
            .map_err(allocation)?;
        token.extend_from_slice(&object.source.to_le_bytes());
        token.extend_from_slice(&object.generation.to_le_bytes());
        token.extend_from_slice(&object.native);
        Ok(token)
    }
}
fn timestamp(
    primary: &[u8; 32],
    offset: usize,
    increment: Option<usize>,
    timezone: usize,
) -> Result<MetadataField<NativeTimestamp>> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(6).map_err(allocation)?;
    raw.extend_from_slice(&primary[offset..offset + 4]);
    if let Some(index) = increment {
        raw.push(primary[index]);
    }
    raw.push(primary[timezone]);
    Ok(MetadataField::Opaque {
        bytes: raw,
        interpretation: text(
            "exFAT packed date/time, optional 10ms increment and UTC-offset byte; typed conversion is not implemented",
        )?,
    })
}
impl TreeSource for ExfatTreeSource {
    fn root(&self) -> ObjectId {
        self.root.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>> {
        self.volume.check_stability(resources)?;
        let node = self.node(object)?;
        Budgeted::try_new(&resources.memory, 4096, || {
            let (created, modified, accessed, native_flags) = match node.entry() {
                None => (
                    MetadataField::Absent,
                    MetadataField::Absent,
                    MetadataField::Absent,
                    MetadataField::Absent,
                ),
                Some(entry) => {
                    let primary = &entry.raw_metadata()[0];
                    (
                        timestamp(primary, 8, Some(20), 22)?,
                        timestamp(primary, 12, Some(21), 23)?,
                        timestamp(primary, 16, None, 24)?,
                        MetadataField::Known(bytes(&entry.attributes().to_le_bytes())?),
                    )
                }
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
        self.volume.check_stability(resources)?;
        let node = self.node(object)?;
        if maximum_entries == 0 || node.entry().is_some_and(|e| !e.is_directory()) {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "invalid exFAT directory page request",
            ));
        }
        let _scratch = resources.memory.reserve(64)?;
        let prefix = Self::prefix(object)?;
        let start = match continuation {
            None => 0,
            Some(token) if token.len() == prefix.len() + 8 && token.starts_with(&prefix) => {
                usize::try_from(u64::from_le_bytes(
                    token[prefix.len()..].try_into().unwrap(),
                ))
                .map_err(allocation)?
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "foreign exFAT directory continuation",
                ));
            }
        };
        if start > node.children.len() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "exFAT continuation exceeds directory",
            ));
        }
        let count = maximum_entries.min(node.children.len() - start);
        let charge = (count as u64)
            .checked_mul(1024)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(|| allocation("exFAT page accounting overflow"))?;
        let reservation = resources.memory.reserve(charge)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(allocation)?;
        for child in &node.children[start..start + count] {
            resources.cancellation.check()?;
            let entry = self.nodes[child]
                .entry()
                .expect("child owns native exFAT entry");
            entries.push(DirectoryEntry {
                name: name(entry.name())?,
                object: id(child)?,
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
        self.volume.check_stability(resources)?;
        let entry = self.node(object)?.entry();
        Budgeted::try_new(
            &resources.memory,
            std::mem::size_of::<StreamInfo>() as u64,
            || {
                let mut streams = Vec::new();
                if let Some(entry) = entry
                    && !entry.is_directory()
                {
                    streams.try_reserve_exact(1).map_err(allocation)?;
                    streams.push(StreamInfo {
                        kind: StreamKind::Data,
                        length: entry.len(),
                    });
                }
                Ok(streams)
            },
        )
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        resources: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.volume.check_stability(resources)?;
        let node = self.node(object)?;
        if stream != &StreamKind::Data {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "exFAT profile has no named streams or resource forks",
            ));
        }
        let entry = node
            .entry()
            .filter(|entry| !entry.is_directory())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    "exFAT directory/root has no ordinary stream",
                )
            })?;
        Ok(Arc::new(self.volume.open_file(entry, resources)?))
    }
    fn revalidate(&self, object: &ObjectId, resources: &Resources) -> Result<()> {
        self.volume.check_stability(resources)?;
        self.node(object)?;
        Ok(())
    }
}
