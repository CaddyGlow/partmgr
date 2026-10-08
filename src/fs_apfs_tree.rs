//! Complete common native tree inventory for the explicitly audited APFS Linux profiles.
use crate::{
    fs_apfs::{ApfsVolume, bad, budget, vector},
    fs_apfs_audit::{ApfsAuditLimits, audit_apfs},
    fs_core::*,
};
use std::sync::Arc;
/// Complete user namespace for the explicitly supported APFS profiles.
/// Unsupported inode payload and security profiles fail before inventory publication.
pub struct ApfsTreeSource {
    volume: ApfsVolume,
}
impl ApfsTreeSource {
    /// Require complete clean allocation/reference audit and caller-selected inventory caps.
    pub fn inventory(volume: ApfsVolume, limits: ApfsAuditLimits, r: &Resources) -> Result<Self> {
        let proof = audit_apfs(&volume, limits, r)?;
        if !proof.is_clean() {
            return Err(bad("APFS tree requires clean complete profile audit"));
        }
        Ok(Self { volume })
    }
    /// Indexed immutable source volume.
    pub fn volume(&self) -> &ApfsVolume {
        &self.volume
    }
    fn token(&self, id: &ObjectId, index: usize) -> Result<Vec<u8>> {
        let n: u64 = index.try_into().map_err(|_| budget("APFS page cursor"))?;
        let mut v = vector(48)?;
        v.extend_from_slice(&id.source.to_be_bytes());
        v.extend_from_slice(&id.generation.to_be_bytes());
        v.extend_from_slice(&id.native);
        v.extend_from_slice(&n.to_be_bytes());
        Ok(v)
    }
}
impl TreeSource for ApfsTreeSource {
    fn root(&self) -> ObjectId {
        self.volume.root_identity()
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.volume.metadata(id, r)
    }
    fn directory_page(
        &self,
        id: &ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        if maximum == 0 {
            return Err(budget("APFS zero page maximum"));
        }
        self.volume.revalidate(id, r)?;
        let entries = self.volume.directory(id, r)?;
        let start = if let Some(t) = continuation {
            if t.len() != 48 || t[..40] != self.token(id, 0)?[..40] {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "foreign APFS page continuation",
                ));
            }
            usize::try_from(u64::from_be_bytes(t[40..48].try_into().unwrap()))
                .map_err(|_| bad("APFS cursor size"))?
        } else {
            0
        };
        if start > entries.get().len() {
            return Err(bad("APFS page cursor bounds"));
        }
        let n = maximum.min(entries.get().len() - start);
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(2048)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("APFS page charge"))?,
        )?;
        let mut out = vector(n)?;
        for e in &entries.get()[start..start + n] {
            r.cancellation.check()?;
            let NativeName::Bytes(units) = &e.name else {
                return Err(bad("APFS native name class"));
            };
            let mut name = vector(units.len())?;
            name.extend_from_slice(units);
            let mut native = vector(e.object.native.len())?;
            native.extend_from_slice(&e.object.native);
            out.push(DirectoryEntry {
                name: NativeName::Bytes(name),
                object: ObjectId {
                    source: e.object.source,
                    generation: e.object.generation,
                    native,
                },
                kind: if e.kind == ObjectKind::Directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        let next = if start + n < entries.get().len() {
            Some(self.token(id, start + n)?)
        } else {
            None
        };
        Ok(DirectoryPage {
            entries: out,
            next,
            reservation: lease,
        })
    }
    fn streams(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.volume.revalidate(id, r)?;
        let node = self.volume.node(id)?;
        let charge = node
            .streams
            .len()
            .checked_mul(1024)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| bad("APFS stream inventory charge overflow"))?;
        Budgeted::try_new(&r.memory, charge as u64, || {
            let mut streams = vector(node.streams.len())?;
            for stream in &node.streams {
                streams.push(StreamInfo {
                    kind: stream.kind.clone(),
                    length: stream.length,
                });
            }
            Ok(streams)
        })
    }
    fn open_stream(
        &self,
        id: &ObjectId,
        kind: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        Ok(Arc::new(self.volume.open_stream(id, kind, r)?))
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.revalidate(id, r)
    }
}
