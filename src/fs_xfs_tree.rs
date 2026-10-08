//! Common lossless-byte namespace adapter for the strict XFS v5 shortform baseline.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{collections::VecDeque, sync::Arc};
use crate::{
    fs_core::*,
    fs_xfs::{XfsVolume, budget, bytes, invalid, u32be},
};
/// Independent bounds for retained namespace inventory.
#[derive(Clone, Copy, Debug)]
pub struct XfsTreeLimits {
    /// Maximum unique reachable objects, including root and shared regular objects.
    pub objects: usize,
    /// Maximum names; multiple hardlink names count separately.
    pub entries: usize,
    /// Maximum directory depth below the root.
    pub depth: usize,
}
struct Node {
    children: Vec<DirectoryEntry>,
}
/// Complete reachable caller-stabilized tree; global allocation audit remains separate.
pub struct XfsTreeSource {
    volume: XfsVolume,
    nodes: Vec<Option<Node>>,
    root: ObjectId,
    _lease: Reservation,
}
fn id(value: &ObjectId) -> Result<ObjectId> {
    Ok(ObjectId {
        source: value.source,
        generation: value.generation,
        native: bytes(&value.native)?,
    })
}
impl XfsTreeSource {
    /// Inventory exact names, shared file identities and checked shortform parent topology.
    pub fn inventory(volume: XfsVolume, limits: XfsTreeLimits, r: &Resources) -> Result<Self> {
        volume.check_stability(r)?;
        if limits.objects == 0 {
            return Err(budget("XFS tree root capacity"));
        }
        let charge = limits.objects as u128 * 1024
            + limits.entries as u128 * 1024
            + volume.inodes.len() as u128 * 64;
        let lease = r
            .memory
            .reserve(u64::try_from(charge).map_err(|_| budget("XFS tree accounting"))?)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(volume.inodes.len())
            .map_err(|_| budget("XFS tree index"))?;
        nodes.resize_with(volume.inodes.len(), || None);
        let root = volume.identity(volume.geometry().root_inode())?;
        let root_index = volume
            .inodes
            .binary_search_by_key(&volume.geometry().root_inode(), |i| i.number())
            .map_err(|_| invalid("XFS tree absent root"))?;
        if !volume.inodes[root_index].is_directory() {
            return Err(invalid("XFS tree regular root"));
        }
        nodes[root_index] = Some(Node {
            children: Vec::new(),
        });
        let mut objects = 1usize;
        let mut entries = 0usize;
        let mut pending = VecDeque::new();
        pending
            .try_reserve(limits.objects.min(volume.inodes.len()))
            .map_err(|_| budget("XFS tree queue"))?;
        pending.push_back((root_index, volume.geometry().root_inode(), 0));
        while let Some((index, parent, depth)) = pending.pop_front() {
            volume.check_stability(r)?;
            let inode = &volume.inodes[index];
            if inode.parent_inode() != Some(parent) {
                return Err(invalid("XFS tree shortform parent disagreement"));
            }
            let mut children = Vec::new();
            children
                .try_reserve_exact(inode.directory_entries().len())
                .map_err(|_| budget("XFS tree names"))?;
            for entry in inode.directory_entries() {
                r.cancellation.check()?;
                entries = entries
                    .checked_add(1)
                    .ok_or_else(|| budget("XFS tree entry overflow"))?;
                if entries > limits.entries {
                    return Err(budget("XFS tree entry cap"));
                }
                let child = volume
                    .inodes
                    .binary_search_by_key(&entry.inode, |i| i.number())
                    .map_err(|_| invalid("XFS tree unallocated inode reference"))?;
                let target = &volume.inodes[child];
                if volume.geometry.system.contains(&entry.inode)
                    || (target.is_directory() && entry.file_type != 2)
                    || (!target.is_directory() && entry.file_type != 1)
                {
                    return Err(invalid("XFS tree filetype/system reference"));
                }
                if target.is_directory() && nodes[child].is_some() {
                    return Err(invalid("XFS tree directory alias/cycle"));
                }
                if nodes[child].is_none() {
                    objects += 1;
                    if objects > limits.objects {
                        return Err(budget("XFS tree object cap"));
                    }
                    nodes[child] = Some(Node {
                        children: Vec::new(),
                    });
                    if target.is_directory() {
                        if depth >= limits.depth {
                            return Err(budget("XFS tree depth cap"));
                        }
                        pending.push_back((child, inode.number(), depth + 1));
                    }
                }
                children.push(DirectoryEntry {
                    name: NativeName::Bytes(bytes(&entry.name)?),
                    object: volume.identity(entry.inode)?,
                    kind: if target.is_directory() {
                        ObjectKind::Directory
                    } else {
                        ObjectKind::File
                    },
                });
            }
            nodes[index].as_mut().unwrap().children = children;
        }
        Ok(Self {
            volume,
            nodes,
            root,
            _lease: lease,
        })
    }
    fn index(&self, object: &ObjectId) -> Result<usize> {
        if object.source != self.root.source || object.native.len() != 8 {
            return Err(Error::new(ErrorKind::StalePlan, "foreign XFS identity"));
        }
        let number = u64::from_le_bytes(object.native[..8].try_into().unwrap());
        let index = self
            .volume
            .inodes
            .binary_search_by_key(&number, |i| i.number())
            .map_err(|_| Error::new(ErrorKind::StalePlan, "unallocated XFS identity"))?;
        if self.nodes[index].is_none()
            || object.generation != u64::from(self.volume.inodes[index].generation())
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "unreachable or reused XFS identity",
            ));
        }
        Ok(index)
    }
    fn prefix(object: &ObjectId) -> Result<Vec<u8>> {
        let mut prefix = Vec::new();
        prefix
            .try_reserve_exact(32)
            .map_err(|_| budget("XFS page token"))?;
        prefix.extend_from_slice(&object.source.to_le_bytes());
        prefix.extend_from_slice(&object.generation.to_le_bytes());
        prefix.extend_from_slice(&object.native);
        Ok(prefix)
    }
}
fn time(raw: &[u8], offset: usize) -> Result<MetadataField<NativeTimestamp>> {
    let mut epoch = String::new();
    epoch
        .try_reserve_exact(14)
        .map_err(|_| budget("XFS timestamp epoch"))?;
    epoch.push_str("Unix 1970 UTC");
    Ok(MetadataField::Known(NativeTimestamp {
        ticks: i128::from(u32be(raw, offset) as i32) * 1_000_000_000
            + i128::from(u32be(raw, offset + 4)),
        ticks_per_second: 1_000_000_000,
        epoch,
    }))
}
impl TreeSource for XfsTreeSource {
    fn root(&self) -> ObjectId {
        self.root.clone()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(object, r)?;
        let inode = &self.volume.inodes[self.index(object)?];
        let raw = inode.raw_metadata();
        Budgeted::try_new(&r.memory, 4096, || {
            let mut attributes = Vec::new();
            attributes
                .try_reserve_exact(1)
                .map_err(|_| budget("XFS metadata attributes"))?;
            let mut interpretation = String::new();
            let meaning = "Exact checksummed XFS v3 inode; native project id, ctime and other fields retained, transplantation unsupported";
            interpretation
                .try_reserve_exact(meaning.len())
                .map_err(|_| budget("XFS metadata meaning"))?;
            interpretation.push_str(meaning);
            attributes.push((
                NativeName::Bytes(bytes(b"xfs.native_inode")?),
                MetadataField::Opaque {
                    bytes: bytes(raw)?,
                    interpretation,
                },
            ));
            Ok(Metadata {
                created: time(raw, 144)?,
                modified: time(raw, 40)?,
                accessed: time(raw, 32)?,
                owner: MetadataField::Known(bytes(&raw[8..16])?),
                mode: MetadataField::Known(u32::from(inode.mode())),
                security: MetadataField::Absent,
                attributes,
                native_flags: MetadataField::Known(bytes(&raw[90..92])?),
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
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.revalidate(object, r)?;
        let index = self.index(object)?;
        if maximum_entries == 0 || !self.volume.inodes[index].is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "XFS directory page request",
            ));
        }
        let children = &self.nodes[index].as_ref().unwrap().children;
        let prefix = Self::prefix(object)?;
        let start = match continuation {
            None => 0,
            Some(token) if token.len() == 40 && token[..32] == prefix => {
                usize::try_from(u64::from_le_bytes(token[32..40].try_into().unwrap()))
                    .map_err(|_| invalid("XFS page offset"))?
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "foreign XFS continuation",
                ));
            }
        };
        if start > children.len() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "XFS continuation past end",
            ));
        }
        let count = maximum_entries.min(children.len() - start);
        let reservation = r.memory.reserve(count as u64 * 1024 + 128)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| budget("XFS directory page"))?;
        for e in &children[start..start + count] {
            r.cancellation.check()?;
            let NativeName::Bytes(name) = &e.name else {
                return Err(invalid("XFS native name encoding"));
            };
            entries.push(DirectoryEntry {
                name: NativeName::Bytes(bytes(name)?),
                object: id(&e.object)?,
                kind: e.kind.clone(),
            });
        }
        let next = if start + count < children.len() {
            let mut token = Vec::new();
            token
                .try_reserve_exact(40)
                .map_err(|_| budget("XFS continuation allocation"))?;
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
    fn streams(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.revalidate(object, r)?;
        let i = &self.volume.inodes[self.index(object)?];
        Budgeted::try_new(&r.memory, 128, || {
            let mut out = Vec::new();
            if !i.is_directory() {
                out.try_reserve_exact(1)
                    .map_err(|_| budget("XFS stream inventory"))?;
                out.push(StreamInfo {
                    kind: StreamKind::Data,
                    length: i.len(),
                });
            }
            Ok(out)
        })
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(object, r)?;
        if stream != &StreamKind::Data {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "XFS named streams outside baseline",
            ));
        }
        Ok(Arc::new(self.volume.open_file(
            self.volume.inodes[self.index(object)?].number(),
            r,
        )?))
    }
    fn revalidate(&self, object: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.check_stability(r)?;
        self.index(object)?;
        Ok(())
    }
}
