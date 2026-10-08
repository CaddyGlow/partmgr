//! APFS editing codec profile, including object-map ghost leaf records.
use crate::fs_apfs_disk::{self, GhostPolicy};
pub(super) use crate::fs_apfs_disk::{NodeFields, compare, d, q, seal, w};
use crate::fs_core::Result;
pub(super) fn node(f: NodeFields, records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>> {
    fs_apfs_disk::node(f, records, GhostPolicy::AllowOmapLeaf)
}
