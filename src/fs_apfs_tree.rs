//! Complete common native tree inventory for the explicitly audited APFS Linux profiles.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::Arc;
use crate::{
    fs_apfs::{ApfsAuditedReader, ApfsVolume, bad, budget, vector},
    fs_apfs_audit::ApfsAuditLimits,
    fs_core::*,
};
/// Complete user namespace for the explicitly supported APFS profiles.
/// Unsupported inode payload and security profiles fail before inventory publication.
pub struct ApfsTreeSource {
    volume: ApfsVolume,
    audited: ApfsAuditedReader,
}
impl ApfsTreeSource {
    /// Require complete clean allocation/reference audit and caller-selected inventory caps.
    /// The caller must keep source bytes immutable for the lifetime of this tree.
    /// Payload reads reuse this audit; use `revalidate` for a full validation boundary.
    pub fn inventory(volume: ApfsVolume, limits: ApfsAuditLimits, r: &Resources) -> Result<Self> {
        let audited = volume.audited_reader(limits, r)?;
        Ok(Self { volume, audited })
    }
    /// Indexed immutable source volume.
    pub fn volume(&self) -> &ApfsVolume {
        &self.volume
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
        let count = self.volume.directory_len(id)?;
        let range = crate::fs_pagination::range(id, continuation, maximum, count)?;
        let start = range.start;
        let n = range.len();
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(2048)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| budget("APFS page charge"))?,
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
        Ok(Arc::new(self.audited.open_stream(id, kind, r)?))
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.node(id)?;
        self.audited.revalidate(r)
    }
}
