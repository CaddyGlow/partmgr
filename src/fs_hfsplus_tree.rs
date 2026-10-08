//! Complete common native tree inventory for the explicitly audited HFS+/HFSX profiles.
use crate::{
    fs_core::*,
    fs_hfsplus::{HfsPlusVolume, bad, budget, vector},
    fs_hfsplus_audit::{HfsPlusAuditLimits, audit_hfsplus},
};
use std::sync::Arc;
/// Complete native inventory. No system namespace or resource fork is silently excluded.
pub struct HfsPlusTreeSource {
    volume: HfsPlusVolume,
}
impl HfsPlusTreeSource {
    /// Require complete clean allocation/reference audit and caller-selected inventory caps.
    pub fn inventory(
        volume: HfsPlusVolume,
        limits: HfsPlusAuditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let proof = audit_hfsplus(&volume, limits, r)?;
        if !proof.is_clean() {
            return Err(bad("HFS+ tree requires clean complete profile audit"));
        }
        Ok(Self { volume })
    }
    /// Indexed immutable source volume.
    pub fn volume(&self) -> &HfsPlusVolume {
        &self.volume
    }
}
impl TreeSource for HfsPlusTreeSource {
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
            return Err(budget("HFS+ zero page maximum"));
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
                .ok_or_else(|| budget("HFS+ page charge"))?,
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
                    length: node.forks[0].length,
                });
                streams.push(StreamInfo {
                    kind: StreamKind::ResourceFork,
                    length: node.forks[1].length,
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
        Ok(Arc::new(self.volume.open_fork(id, kind, r)?))
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.revalidate(id, r)
    }
}
