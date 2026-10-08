//! Complete common native tree inventory for the explicitly audited JFS Linux profiles.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::Arc;
use crate::{
    fs_core::*,
    fs_jfs::{JfsVolume, bad, budget, vector},
    fs_jfs_audit::{JfsAuditLimits, audit_jfs},
};
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
        let range = crate::fs_pagination::range(id, continuation, maximum, count)?;
        let start = range.start;
        let n = range.len();
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(768)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("JFS page charge"))?,
        )?;
        let out = self.volume.directory_entries(id, start..start + n, r)?;
        let next = if start + n < count {
            Some(crate::fs_pagination::token(id, start + n)?)
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
