//! Complete common native tree inventory for the explicitly audited JFS Linux profiles.
use crate::{
    fs_core::*,
    fs_jfs::{JfsVolume, bad, budget, vector},
    fs_jfs_audit::{JfsAuditLimits, audit_jfs},
};
use std::sync::Arc;
/// Complete user namespace for the explicitly supported JFS profiles.
/// Unsupported inode payload and security profiles fail before inventory publication.
pub struct JfsTreeSource {
    volume: JfsVolume,
}
impl JfsTreeSource {
    /// Require complete clean allocation/reference audit and caller-selected inventory caps.
    pub fn inventory(volume: JfsVolume, limits: JfsAuditLimits, r: &Resources) -> Result<Self> {
        let proof = audit_jfs(&volume, limits, r)?;
        if !proof.is_clean() {
            return Err(bad("JFS tree requires clean complete profile audit"));
        }
        Ok(Self { volume })
    }
    /// Indexed immutable source volume.
    pub fn volume(&self) -> &JfsVolume {
        &self.volume
    }
    fn token(&self, id: &ObjectId, index: usize) -> Result<Vec<u8>> {
        let n: u64 = index.try_into().map_err(|_| budget("JFS page cursor"))?;
        let mut v = vector(40)?;
        v.extend_from_slice(&id.source.to_be_bytes());
        v.extend_from_slice(&id.generation.to_be_bytes());
        v.extend_from_slice(&id.native);
        v.extend_from_slice(&n.to_be_bytes());
        Ok(v)
    }
}
impl TreeSource for JfsTreeSource {
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
            return Err(budget("JFS zero page maximum"));
        }
        self.volume.revalidate(id, r)?;
        let count = self.volume.directory_len(id)?;
        let start = if let Some(t) = continuation {
            if t.len() != 40 || t[..32] != self.token(id, 0)?[..32] {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "foreign JFS page continuation",
                ));
            }
            usize::try_from(u64::from_be_bytes(t[32..40].try_into().unwrap()))
                .map_err(|_| bad("JFS cursor size"))?
        } else {
            0
        };
        if start > count {
            return Err(bad("JFS page cursor bounds"));
        }
        let n = maximum.min(count - start);
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(768)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("JFS page charge"))?,
        )?;
        let out = self.volume.directory_entries(id, start..start + n, r)?;
        let next = if start + n < count {
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
        Budgeted::try_new(&r.memory, 256, || {
            let mut streams = vector(2)?;
            if !node.directory {
                streams.push(StreamInfo {
                    kind: StreamKind::Data,
                    length: node.length,
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
        if *kind != StreamKind::Data {
            return Err(Error::new(ErrorKind::Unsupported, "JFS stream profile"));
        }
        Ok(Arc::new(self.volume.open_file(id, r)?))
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.revalidate(id, r)
    }
}
