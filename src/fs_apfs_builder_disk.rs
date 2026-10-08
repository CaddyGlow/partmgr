//! Native records and strict serialization for fresh APFS authoring.
use crate::fs_apfs_disk::{self, GhostPolicy};
pub(super) use crate::fs_apfs_disk::{
    BLOCK, NodeFields, budget, compare, d, invalid, object, q, seal, w, zero,
};
use crate::fs_core::Result;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
pub(super) type Records = Vec<(Vec<u8>, Vec<u8>)>;
pub(super) fn key(id: u64, kind: u64) -> Vec<u8> {
    ((kind << 60) | id).to_le_bytes().to_vec()
}
pub(super) struct InodeFields {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub timestamp: u64,
    pub links: u32,
    pub stream: Option<(u64, u64, u64)>,
    pub sparse: u64,
    pub resource: bool,
}
pub(super) fn inode(parent: u64, id: u64, name: &[u8], f: InodeFields) -> Result<Vec<u8>> {
    let InodeFields {
        mode,
        uid,
        gid,
        timestamp,
        links,
        stream,
        sparse,
        resource,
    } = f;
    let mut b = zero(92)?;
    q(&mut b, 0, parent);
    q(&mut b, 8, id);
    for at in [16, 24, 32, 40] {
        q(&mut b, at, timestamp);
    }
    q(
        &mut b,
        48,
        if sparse != 0 { 0x200 } else { 0 } | if resource { 0x4000 } else { 0 },
    );
    d(&mut b, 56, links);
    d(&mut b, 72, uid);
    d(&mut b, 76, gid);
    w(&mut b, 80, mode);
    let mut n = name.to_vec();
    n.push(0);
    let mut fields = vec![(4u8, 2u8, n)];
    if let Some((length, allocated, private)) = stream {
        q(&mut b, 8, private);
        let mut ds = zero(40)?;
        q(&mut ds, 0, length);
        q(&mut ds, 8, allocated);
        fields.push((8, 32, ds));
        if sparse != 0 {
            fields.push((13, 40, sparse.to_le_bytes().to_vec()));
        }
    }
    let used = fields.iter().try_fold(0usize, |n, (_, _, v)| {
        n.checked_add(v.len().next_multiple_of(8))
            .ok_or_else(|| budget("APFS inode xfields overflow"))
    })?;
    let start = b.len();
    let count = fields.len();
    b.try_reserve_exact(4 + 4 * count + used)
        .map_err(|_| budget("APFS inode xfields allocation"))?;
    b.resize(start + 4 + 4 * count + used, 0);
    w(&mut b, start, count as u16);
    w(&mut b, start + 2, used as u16);
    let mut at = start + 4 + 4 * count;
    for (i, (kind, flags, value)) in fields.into_iter().enumerate() {
        b[start + 4 + 4 * i] = kind;
        b[start + 5 + 4 * i] = flags;
        w(&mut b, start + 6 + 4 * i, value.len() as u16);
        b[at..at + value.len()].copy_from_slice(&value);
        at += value.len().next_multiple_of(8);
    }
    Ok(b)
}
pub(super) fn name_key(id: u64, kind: u64, name: &[u8]) -> Result<Vec<u8>> {
    let length = u16::try_from(name.len() + 1).map_err(|_| invalid("APFS name length"))?;
    let mut k = key(id, kind);
    k.extend_from_slice(&length.to_le_bytes());
    k.extend_from_slice(name);
    k.push(0);
    Ok(k)
}
pub(super) fn directory(
    parent: u64,
    id: u64,
    name: &[u8],
    directory: bool,
    time: u64,
    sibling: Option<u64>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut v = zero(18)?;
    q(&mut v, 0, id);
    q(&mut v, 8, time);
    w(&mut v, 16, if directory { 4 } else { 8 });
    if let Some(s) = sibling {
        v.extend_from_slice(&[1, 0, 8, 0, 1, 2, 8, 0]);
        v.extend_from_slice(&s.to_le_bytes());
    }
    Ok((name_key(parent, 9, name)?, v))
}
pub(super) fn node(f: NodeFields, records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>> {
    fs_apfs_disk::node(f, records, GhostPolicy::Reject)
}
