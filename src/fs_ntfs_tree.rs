//! Validated NTFS user namespace inventory from native $I30 indexes.
use crate::{
    fs_core::*,
    fs_ntfs::{NtfsDirectoryEntry, NtfsDirectoryLimits, NtfsRecord, NtfsVolume},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn allocation(_: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::BudgetExhausted, "NTFS inventory allocation")
}
struct Node {
    record: NtfsRecord,
    children: Vec<NtfsDirectoryEntry>,
    length: Option<u64>,
}
/// Explicit capture namespace selection; exclusions are surfaced as opaque root metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsTreePolicy {
    /// Require all root objects; unsupported system streams fail inventory.
    Complete,
    /// Exclude validated reserved root records 0..11 and retain their exact occurrence report.
    UserNamespace,
}
/// Validated native namespace inventory with an explicit completeness policy.
pub struct NtfsTreeSource {
    volume: NtfsVolume,
    root: ObjectId,
    nodes: HashMap<ObjectId, Node>,
    excluded: Vec<NtfsDirectoryEntry>,
    _reservation: Reservation,
}
impl NtfsTreeSource {
    /// Inventory native indexes, bounded by name occurrences and directory depth.
    /// Defaults to Complete: unavailable reserved system-object capture fails explicitly.
    /// Special user files and directory aliases also fail.
    pub fn inventory(
        volume: NtfsVolume,
        maximum_occurrences: usize,
        maximum_depth: usize,
        index_limits: NtfsDirectoryLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::inventory_with_policy(
            volume,
            maximum_occurrences,
            maximum_depth,
            index_limits,
            NtfsTreePolicy::Complete,
            r,
        )
    }
    /// Explicit opt-in namespace policy; inspect `excluded_entries` before capture.
    pub fn inventory_with_policy(
        volume: NtfsVolume,
        maximum_occurrences: usize,
        maximum_depth: usize,
        index_limits: NtfsDirectoryLimits,
        policy: NtfsTreePolicy,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if maximum_occurrences == 0 {
            return Err(allocation("root capacity"));
        }
        let reservation = r.memory.reserve(
            (maximum_occurrences as u64)
                .checked_mul(4096)
                .and_then(|n| n.checked_add(12288))
                .ok_or_else(|| allocation("overflow"))?,
        )?;
        let mut excluded = Vec::new();
        excluded.try_reserve_exact(12).map_err(allocation)?;
        let root = volume.root_identity(r)?;
        let mut nodes = HashMap::new();
        nodes.try_reserve(maximum_occurrences).map_err(allocation)?;
        let mut pending = VecDeque::new();
        pending
            .try_reserve(maximum_occurrences)
            .map_err(allocation)?;
        let root_record = volume.record(5, r)?;
        root_record.check_tree_profile()?;
        nodes.insert(
            root.clone(),
            Node {
                record: root_record,
                children: Vec::new(),
                length: None,
            },
        );
        pending.push_back((root.clone(), 0usize));
        let mut occurrences = 1usize;
        while let Some((parent, depth)) = pending.pop_front() {
            r.cancellation.check()?;
            if depth > maximum_depth {
                return Err(allocation("directory depth"));
            }
            let directory = volume.directory(&parent, index_limits, r)?;
            let mut children = Vec::new();
            children
                .try_reserve_exact(directory.entries().len())
                .map_err(allocation)?;
            for entry in directory.entries() {
                r.cancellation.check()?;
                let number = u64::from_le_bytes(
                    entry
                        .identity
                        .native
                        .as_slice()
                        .try_into()
                        .map_err(|_| bad("native identity"))?,
                );
                if occurrences == maximum_occurrences {
                    return Err(allocation("occurrence limit"));
                }
                occurrences += 1;
                if number < 24 {
                    if policy == NtfsTreePolicy::Complete {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "complete NTFS capture requires reserved system streams",
                        ));
                    }
                    if excluded.len() == 12 {
                        return Err(bad("NTFS repeated reserved metadata aliases"));
                    }
                    if parent != root || number > 11 {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "reserved NTFS object alias outside supported root metadata",
                        ));
                    }
                    excluded.push(entry.clone());
                    continue;
                }
                if entry.is_directory && nodes.contains_key(&entry.identity) {
                    return Err(bad("NTFS directory cycle or alias"));
                }
                if !nodes.contains_key(&entry.identity) {
                    let record = volume.record(number, r)?;
                    record.check_tree_profile()?;
                    let length = if entry.is_directory {
                        if depth >= maximum_depth {
                            return Err(allocation("directory depth"));
                        }
                        pending.push_back((
                            entry.identity.clone(),
                            depth.checked_add(1).ok_or_else(|| allocation("depth"))?,
                        ));
                        None
                    } else {
                        Some(volume.open_object(&entry.identity, r)?.len())
                    };
                    nodes.insert(
                        entry.identity.clone(),
                        Node {
                            record,
                            children: Vec::new(),
                            length,
                        },
                    );
                }
                children.push(entry.clone());
            }
            nodes.get_mut(&parent).expect("queued node").children = children;
        }
        Ok(Self {
            volume,
            root,
            nodes,
            excluded,
            _reservation: reservation,
        })
    }
    /// Exact native root names, selectors and identities intentionally excluded by policy.
    pub fn excluded_entries(&self) -> &[NtfsDirectoryEntry] {
        &self.excluded
    }
    fn node(&self, id: &ObjectId) -> Result<&Node> {
        self.nodes
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::StalePlan, "foreign NTFS inventory identity"))
    }
    fn prefix(id: &ObjectId) -> Result<[u8; 32]> {
        if id.native.len() != 8 {
            return Err(Error::new(ErrorKind::StalePlan, "NTFS token identity"));
        }
        let mut b = [0; 32];
        b[..16].copy_from_slice(&id.source.to_le_bytes());
        b[16..24].copy_from_slice(&id.generation.to_le_bytes());
        b[24..32].copy_from_slice(&id.native);
        Ok(b)
    }
}
impl TreeSource for NtfsTreeSource {
    fn root(&self) -> ObjectId {
        self.root.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(id, r)?;
        let original = self.node(id)?.record.metadata(r)?;
        let names = self.node(id)?.record.names();
        let name_bytes = names
            .iter()
            .try_fold(0usize, |sum, n| {
                let NativeName::Utf16(units) = &n.name else {
                    return None;
                };
                sum.checked_add(13 + units.len() * 2)
            })
            .ok_or_else(|| allocation("name metadata size"))?;
        let excluded = if id == &self.root {
            self.excluded.as_slice()
        } else {
            &[]
        };
        let excluded_bytes = excluded
            .iter()
            .try_fold(0usize, |sum, n| {
                let NativeName::Utf16(units) = &n.name else {
                    return None;
                };
                sum.checked_add(35 + units.len() * 2)
            })
            .ok_or_else(|| allocation("excluded metadata size"))?;
        let charge = (name_bytes as u64)
            .checked_add(excluded_bytes as u64)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| allocation("metadata charge"))?;
        Budgeted::try_new(&r.memory, charge, || {
            let mut metadata = original.get().clone();
            metadata
                .attributes
                .try_reserve_exact(2)
                .map_err(allocation)?;
            if !names.is_empty() {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(name_bytes).map_err(allocation)?;
                for n in names {
                    r.cancellation.check()?;
                    bytes.extend_from_slice(&n.parent_record.to_le_bytes());
                    bytes.extend_from_slice(&n.parent_sequence.to_le_bytes());
                    bytes.push(n.namespace);
                    let NativeName::Utf16(units) = &n.name else {
                        return Err(bad("native name class"));
                    };
                    bytes.extend_from_slice(&(units.len() as u16).to_le_bytes());
                    for c in units {
                        bytes.extend_from_slice(&c.to_le_bytes());
                    }
                }
                metadata.attributes.push((NativeName::Bytes(b"ntfs.FILE_NAME.occurrences".to_vec()),MetadataField::Opaque{bytes,interpretation:"Native parent record:u64, sequence:u16, namespace:u8, units:u16, UTF16LE; references require relocation policy".into()}));
            }
            if !excluded.is_empty() {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(excluded_bytes)
                    .map_err(allocation)?;
                for e in excluded {
                    r.cancellation.check()?;
                    bytes.extend_from_slice(&e.identity.source.to_le_bytes());
                    bytes.extend_from_slice(&e.identity.generation.to_le_bytes());
                    bytes.extend_from_slice(&e.identity.native);
                    bytes.push(e.namespace);
                    let NativeName::Utf16(name) = &e.name else {
                        return Err(bad("native name class"));
                    };
                    bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    for c in name {
                        bytes.extend_from_slice(&c.to_le_bytes());
                    }
                }
                metadata.attributes.push((NativeName::Bytes(b"ntfs.capture.excluded-root-metadata".to_vec()),MetadataField::Opaque{bytes,interpretation:"Explicit UserNamespace policy excluded reserved root occurrences; source:u128, sequence:u64, record:u64, namespace:u8, units:u16, UTF16LE. Whole-volume capture is not claimed".into()}));
            }
            Ok(metadata)
        })
    }
    fn directory_page(
        &self,
        id: &ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        if !node.record.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "NTFS non-directory page",
            ));
        }
        if maximum == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "NTFS empty page capacity",
            ));
        }
        let prefix = Self::prefix(id)?;
        let start = if let Some(t) = continuation {
            if t.len() != 40 || t[..32] != prefix {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS foreign continuation",
                ));
            }
            usize::try_from(u64::from_le_bytes(t[32..].try_into().unwrap())).map_err(allocation)?
        } else {
            0
        };
        if start > node.children.len() {
            return Err(bad("NTFS page offset"));
        }
        let end = start.saturating_add(maximum).min(node.children.len());
        let reservation = r.memory.reserve(
            ((end - start) as u64)
                .checked_mul(1024)
                .and_then(|n| n.checked_add(128))
                .ok_or_else(|| allocation("page budget"))?,
        )?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(end - start).map_err(allocation)?;
        for entry in &node.children[start..end] {
            r.cancellation.check()?;
            entries.push(DirectoryEntry {
                object: entry.identity.clone(),
                name: entry.name.clone(),
                kind: if entry.is_directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        let next = if end < node.children.len() {
            let mut t = Vec::new();
            t.try_reserve_exact(40).map_err(allocation)?;
            t.extend_from_slice(&prefix);
            t.extend_from_slice(&(end as u64).to_le_bytes());
            Some(t)
        } else {
            None
        };
        Ok(DirectoryPage {
            entries,
            next,
            reservation,
        })
    }
    fn streams(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        Budgeted::try_new(&r.memory, 256, || {
            let mut streams = Vec::new();
            streams
                .try_reserve_exact(usize::from(node.length.is_some()))
                .map_err(allocation)?;
            if let Some(length) = node.length {
                streams.push(StreamInfo {
                    kind: StreamKind::Data,
                    length,
                });
            }
            Ok(streams)
        })
    }
    fn open_stream(
        &self,
        id: &ObjectId,
        stream: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(id, r)?;
        if *stream != StreamKind::Data || self.node(id)?.length.is_none() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "NTFS requested stream unavailable",
            ));
        }
        Ok(Arc::new(self.volume.open_object(id, r)?))
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        let node = self.node(id)?;
        let number = u64::from_le_bytes(
            id.native
                .as_slice()
                .try_into()
                .map_err(|_| bad("native identity"))?,
        );
        let record = self.volume.record(number, r)?;
        if record.identity() != id || record.is_directory() != node.record.is_directory() {
            return Err(Error::new(ErrorKind::StalePlan, "NTFS record changed"));
        }
        if let Some(length) = node.length
            && self.volume.open_object(id, r)?.len() != length
        {
            return Err(Error::new(ErrorKind::StalePlan, "NTFS data length changed"));
        }
        Ok(())
    }
}
