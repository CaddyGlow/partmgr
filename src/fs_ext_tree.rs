//! Bounded classic ext2 namespace inventory with deferred shared-contract reads.
//! This does not audit cross-inode allocation ownership or establish source isolation.
use crate::{
    fs_core::*,
    fs_ext::{ExtInode, ExtVolume},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    sync::Arc,
};
fn allocation(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::BudgetExhausted, error.to_string())
}
fn native(error: io::Error) -> Error {
    if let Some(cause) = error.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
        return Error::new(cause.kind, cause.context.clone());
    }
    if error.kind() == io::ErrorKind::Unsupported {
        Error::new(ErrorKind::Unsupported, error.to_string())
    } else if error.kind() == io::ErrorKind::InvalidData {
        Error::new(ErrorKind::InvalidData, error.to_string())
    } else {
        Error::io("ext2 inventory access", error)
    }
}
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(allocation)?;
    result.extend_from_slice(bytes);
    Ok(result)
}
fn copy_id(id: &ObjectId) -> Result<ObjectId> {
    Ok(ObjectId {
        source: id.source,
        generation: id.generation,
        native: copy_bytes(&id.native)?,
    })
}
fn copy_name(name: &NativeName) -> Result<NativeName> {
    match name {
        NativeName::Bytes(bytes) => Ok(NativeName::Bytes(copy_bytes(bytes)?)),
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            "ext2 native name is not bytes",
        )),
    }
}
fn kind(inode: &ExtInode) -> Result<ObjectKind> {
    match inode.mode() & 0xf000 {
        0x8000 => Ok(ObjectKind::File),
        0x4000 => Ok(ObjectKind::Directory),
        0xa000 => Ok(ObjectKind::Symlink),
        0x1000 | 0x2000 | 0x6000 | 0xc000 => Err(Error::new(
            ErrorKind::Unsupported,
            "ext2 FIFO/device/socket preservation is not implemented",
        )),

        _ => Err(Error::new(
            ErrorKind::Unsupported,
            "ext2 tree has an invalid or unsupported inode type",
        )),
    }
}
struct Node {
    inode: ExtInode,
    target: Option<Budgeted<Vec<u8>>>,
    children: Vec<DirectoryEntry>,
}
/// Complete bounded inventory of a caller-stabilized classic ext2 namespace.
pub struct ExtTreeSource {
    volume: ExtVolume,
    root: ObjectId,
    nodes: HashMap<ObjectId, Node>,
    max_blocks: usize,
    _inventory: Reservation,
}
impl ExtTreeSource {
    /// Inventory all reachable files and directories under explicit object/name/work limits.
    ///
    /// Hard-linked regular files share identities. Directory aliases/cycles are rejected.
    /// Every directory must contain exactly one correct dot and dot-dot reference.
    /// Conservative retained accounting charges 1024 bytes per object and name entry;
    /// directory decode scratch and deferred indexes use the same shared memory pool.
    pub fn inventory(
        volume: ExtVolume,
        maximum_objects: usize,
        maximum_entries: usize,
        max_blocks: usize,
        max_slots: usize,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        if maximum_objects == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 inventory requires root capacity",
            ));
        }
        let bytes = (maximum_objects as u64)
            .checked_add(maximum_entries as u64)
            .and_then(|n| n.checked_mul(1024))
            .ok_or_else(|| allocation("ext2 inventory accounting overflow"))?;
        let reservation = resources.memory.reserve(bytes)?;
        let mut nodes = HashMap::new();
        nodes.try_reserve(maximum_objects).map_err(allocation)?;
        let mut pending = VecDeque::new();
        pending.try_reserve(maximum_objects).map_err(allocation)?;
        let mut directories = HashSet::new();
        directories
            .try_reserve(maximum_objects)
            .map_err(allocation)?;
        let root_inode = volume.inode(2, resources).map_err(native)?;
        if kind(&root_inode)? != ObjectKind::Directory {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ext2 root is not directory",
            ));
        }
        let root = volume.identity(2, resources).map_err(native)?;
        nodes.insert(
            copy_id(&root)?,
            Node {
                inode: root_inode,
                target: None,
                children: Vec::new(),
            },
        );
        pending.push_back((copy_id(&root)?, 2));
        directories.insert(2);
        let mut entry_count = 0usize;
        while let Some((parent, parent_inode)) = pending.pop_front() {
            resources.cancellation.check()?;
            let number = nodes[&parent].inode.number();
            let directory = volume
                .directory(number, max_blocks, max_slots, resources)
                .map_err(native)?;
            let mut dot = false;
            let mut dotdot = false;
            let real_count = directory
                .entries()
                .iter()
                .filter(|e| !matches!(&e.name,NativeName::Bytes(n) if n==b"." || n==b".."))
                .count();
            entry_count = entry_count
                .checked_add(real_count)
                .filter(|n| *n <= maximum_entries)
                .ok_or_else(|| allocation("ext2 inventory entry limit exceeded"))?;
            let mut children = Vec::new();
            children.try_reserve_exact(real_count).map_err(allocation)?;
            for entry in directory.entries() {
                resources.cancellation.check()?;
                if matches!(&entry.name,NativeName::Bytes(n) if n==b".") {
                    if dot || entry.inode != number {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "ext2 invalid dot reference",
                        ));
                    }
                    dot = true;
                    continue;
                }
                if matches!(&entry.name,NativeName::Bytes(n) if n==b"..") {
                    if dotdot || entry.inode != parent_inode {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "ext2 invalid dot-dot reference",
                        ));
                    }
                    dotdot = true;
                    continue;
                }
                let inode = volume.inode(entry.inode, resources).map_err(native)?;
                let object_kind = kind(&inode)?;
                let identity = volume.identity(entry.inode, resources).map_err(native)?;
                if !nodes.contains_key(&identity) && nodes.len() == maximum_objects {
                    return Err(allocation("ext2 inventory object limit exceeded"));
                }
                if object_kind == ObjectKind::Directory {
                    if !directories.insert(entry.inode) {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "ext2 directory cycle or alias",
                        ));
                    }
                    pending.push_back((copy_id(&identity)?, number));
                }
                if !nodes.contains_key(&identity) {
                    if nodes.len() == maximum_objects {
                        return Err(allocation("ext2 inventory object limit exceeded"));
                    }
                    let target = if object_kind == ObjectKind::Symlink {
                        Some(
                            volume
                                .symlink_target(inode.number(), max_blocks, resources)
                                .map_err(native)?,
                        )
                    } else {
                        None
                    };
                    nodes.insert(
                        copy_id(&identity)?,
                        Node {
                            inode,
                            target,
                            children: Vec::new(),
                        },
                    );
                }
                children.push(DirectoryEntry {
                    name: copy_name(&entry.name)?,
                    object: identity,
                    kind: object_kind,
                });
            }
            if !dot || !dotdot {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ext2 directory lacks dot topology",
                ));
            }
            nodes
                .get_mut(&parent)
                .expect("queued directory exists")
                .children = children;
        }
        Ok(Self {
            volume,
            root,
            nodes,
            max_blocks,
            _inventory: reservation,
        })
    }
    fn node(&self, object: &ObjectId) -> Result<&Node> {
        if object.source != self.root.source || object.native.len() != 4 {
            return Err(Error::new(ErrorKind::StalePlan, "foreign ext2 identity"));
        }
        self.nodes.get(object).ok_or_else(|| {
            Error::new(
                ErrorKind::StalePlan,
                "foreign ext2 source identity or generation",
            )
        })
    }
    fn prefix(object: &ObjectId) -> Result<[u8; 28]> {
        if object.native.len() != 4 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 native identity length",
            ));
        }
        let mut result = [0; 28];
        result[..16].copy_from_slice(&object.source.to_le_bytes());
        result[16..24].copy_from_slice(&object.generation.to_le_bytes());
        result[24..].copy_from_slice(&object.native);
        Ok(result)
    }
}
fn opaque<T>(value: &[u8], meaning: &str) -> Result<MetadataField<T>> {
    let mut interpretation = String::new();
    interpretation
        .try_reserve_exact(meaning.len())
        .map_err(allocation)?;
    interpretation.push_str(meaning);
    Ok(MetadataField::Opaque {
        bytes: copy_bytes(value)?,
        interpretation,
    })
}
fn native_time<T>(seconds: &[u8], extension: &[u8], at: usize) -> Result<MetadataField<T>> {
    let mut encoding = copy_bytes(seconds)?;
    if extension.len() >= at + 4 {
        encoding.try_reserve_exact(4).map_err(allocation)?;
        encoding.extend_from_slice(&extension[at..at + 4]);
    }
    opaque(
        &encoding,
        "native little-endian ext time seconds followed by declared epoch/nanosecond extension; conversion deferred",
    )
}
impl TreeSource for ExtTreeSource {
    fn root(&self) -> ObjectId {
        self.root.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(object, resources)?;
        let node = self.node(object)?;
        let inode = &node.inode;
        let raw = inode.raw_metadata();
        let extra = inode.raw_extended_metadata();
        let xattrs = self
            .volume
            .decoder()
            .xattr_encoding(inode, resources)
            .map_err(native)?;
        let charge = 4096 + node.target.as_ref().map_or(0, |t| t.len() as u64);
        let charge = charge + xattrs.len() as u64;
        Budgeted::try_new(&resources.memory, charge, || {
            let mut owner = copy_bytes(&inode.uid().to_le_bytes())?;
            owner.try_reserve_exact(4).map_err(allocation)?;
            owner.extend_from_slice(&inode.gid().to_le_bytes());
            let mut attributes = Vec::new();
            attributes.try_reserve_exact(4).map_err(allocation)?;
            attributes.push((
                NativeName::Bytes(copy_bytes(b"ext2.inode.ctime")?),
                native_time(&raw[12..16], extra, 4)?,
            ));
            attributes.push((
                NativeName::Bytes(copy_bytes(b"ext2.inode.dtime")?),
                opaque(
                    &raw[20..24],
                    "little-endian inode deletion-time field; zero for accepted live linked inode",
                )?,
            ));
            if !extra.is_empty() {
                attributes.push((NativeName::Bytes(copy_bytes(b"ext.inode.extension")?), opaque(extra, "exact declared Linux inode extension; version/project/checksum fields retain native encoding")?));
            }
            let security = MetadataField::Absent;
            let security = if !xattrs.is_empty() {
                attributes.push((NativeName::Bytes(copy_bytes(b"ext.xattrs")?),opaque(&xattrs,"little-endian inode/external-block/inline-length/external-length framing followed by exact native xattr containers; CRC and layout validated, ACL/value interpretation and relocation remain unknown")?));
                MetadataField::Uninspectable { reason:"native xattr containers retained; ACL and security value encodings are not interpreted".into() }
            } else {
                security
            };
            Ok(Metadata {
                created: if extra.len() >= 24 {
                    opaque(
                        &extra[16..24],
                        "native little-endian ext birth-time seconds and epoch/nanosecond extension; conversion deferred",
                    )?
                } else {
                    MetadataField::Absent
                },
                modified: native_time(&raw[16..20], extra, 8)?,
                accessed: native_time(&raw[8..12], extra, 12)?,
                owner: MetadataField::Known(owner),
                mode: MetadataField::Known(u32::from(inode.mode())),
                security,
                attributes,
                native_flags: MetadataField::Known(copy_bytes(&raw[32..36])?),
                symlink_target: match &node.target {
                    Some(t) => MetadataField::Known(NativeName::Bytes(copy_bytes(t)?)),
                    None => MetadataField::Absent,
                },
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
        self.revalidate(object, resources)?;
        let node = self.node(object)?;
        if maximum_entries == 0 || kind(&node.inode)? != ObjectKind::Directory {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 directory page request",
            ));
        }
        let prefix = Self::prefix(object)?;
        let start = match continuation {
            None => 0,
            Some(t) if t.len() == 36 && t[..28] == prefix => {
                usize::try_from(u64::from_le_bytes(t[28..].try_into().unwrap()))
                    .map_err(allocation)?
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "foreign ext2 continuation",
                ));
            }
        };
        if start > node.children.len() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 continuation past directory",
            ));
        }
        let count = maximum_entries.min(node.children.len() - start);
        let bytes = (count as u64)
            .checked_mul(1024)
            .and_then(|n| n.checked_add(36))
            .ok_or_else(|| allocation("ext2 page accounting overflow"))?;
        let reservation = resources.memory.reserve(bytes)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(allocation)?;
        for entry in &node.children[start..start + count] {
            resources.cancellation.check()?;
            entries.push(DirectoryEntry {
                name: copy_name(&entry.name)?,
                object: copy_id(&entry.object)?,
                kind: entry.kind.clone(),
            });
        }
        let next = if start + count < node.children.len() {
            let mut token = Vec::new();
            token.try_reserve_exact(36).map_err(allocation)?;
            token.extend_from_slice(&prefix);
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
        self.revalidate(object, resources)?;
        let inode = &self.node(object)?.inode;
        Budgeted::try_new(
            &resources.memory,
            std::mem::size_of::<StreamInfo>() as u64,
            || {
                let mut result = Vec::new();
                if kind(inode)? == ObjectKind::File {
                    result.try_reserve_exact(1).map_err(allocation)?;
                    result.push(StreamInfo {
                        kind: StreamKind::Data,
                        length: inode.len(),
                    });
                }
                Ok(result)
            },
        )
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        resources: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(object, resources)?;
        let inode = &self.node(object)?.inode;
        if stream != &StreamKind::Data {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 named streams unsupported",
            ));
        }
        if kind(inode)? != ObjectKind::File {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 directory has no data stream",
            ));
        }
        Ok(Arc::new(
            self.volume
                .open_file(inode.number(), self.max_blocks, resources)
                .map_err(native)?,
        ))
    }
    fn revalidate(&self, object: &ObjectId, resources: &Resources) -> Result<()> {
        resources.cancellation.check()?;
        let node = self.node(object)?;
        if self
            .volume
            .identity(node.inode.number(), resources)
            .map_err(native)?
            != *object
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 inode generation changed",
            ));
        }
        Ok(())
    }
}
