//! Pure APFS block encoding shared by authoring and owned editing.
use crate::fs_core::{Error, ErrorKind, Result};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
pub(crate) const BLOCK: usize = 4096;
pub(crate) fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(crate) fn zero(n: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    b.try_reserve_exact(n)
        .map_err(|_| budget("APFS builder allocation"))?;
    b.resize(n, 0);
    Ok(b)
}
pub(crate) fn w(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn d(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn q(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn seal(b: &mut [u8]) {
    let modulus = u64::from(u32::MAX);
    let (mut a, mut c) = (0u64, 0u64);
    for word in b[8..].as_chunks::<4>().0 {
        a = (a + u64::from(u32::from_le_bytes(*word))) % modulus;
        c = (c + a) % modulus;
    }
    let low = modulus - ((a + c) % modulus);
    let high = modulus - ((a + low) % modulus);
    q(b, 0, low | high << 32);
}
pub(crate) fn object(id: u64, kind: u32, subtype: u32) -> Result<Vec<u8>> {
    let mut b = zero(BLOCK)?;
    q(&mut b, 8, id);
    q(&mut b, 16, 1);
    d(&mut b, 24, kind);
    d(&mut b, 28, subtype);
    Ok(b)
}
pub(crate) fn compare(a: &[u8], b: &[u8]) -> crate::platform::cmp::Ordering {
    let scalar = |k: &[u8], p| u64::from_le_bytes(k[p..p + 8].try_into().unwrap());
    let (x, y) = (scalar(a, 0), scalar(b, 0));
    (x & 0x0fff_ffff_ffff_ffff)
        .cmp(&(y & 0x0fff_ffff_ffff_ffff))
        .then((x >> 60).cmp(&(y >> 60)))
        .then_with(|| match x >> 60 {
            5 | 8 => scalar(a, 8).cmp(&scalar(b, 8)),
            4 | 9 => a[10..].cmp(&b[10..]),
            _ => a[8..].cmp(&b[8..]),
        })
}
/// Empty object-map leaf values are a recovery/editing profile, never fresh authoring.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum GhostPolicy {
    Reject,
    AllowOmapLeaf,
}
/// A node is serialized from records, with explicit bounds before every copy.
/// Root footer counts describe the complete tree, including descendants.
pub(crate) struct NodeFields {
    pub id: u64,
    pub storage: u32,
    pub subtype: u32,
    pub level: u16,
    pub root: bool,
    pub fixed: Option<(usize, usize)>,
    pub totals: (u64, u64, usize, usize),
}
pub(crate) fn node(
    f: NodeFields,
    records: &[(Vec<u8>, Vec<u8>)],
    ghosts: GhostPolicy,
) -> Result<Vec<u8>> {
    let NodeFields {
        id,
        storage,
        subtype,
        level,
        root,
        fixed,
        totals,
    } = f;
    let mut b = object(id, storage | if root { 2 } else { 3 }, subtype)?;
    let end = BLOCK - if root { 40 } else { 0 };
    let entry = if fixed.is_some() { 4 } else { 8 };
    let table = records
        .len()
        .checked_mul(entry)
        .ok_or_else(|| budget("APFS node table overflow"))?
        .max(if let Some((ks, vs)) = fixed {
            ((BLOCK - 56) / (ks + if level == 0 { vs } else { 8 } + 4)) * 4
        } else {
            128
        });
    let base = 56usize
        .checked_add(table)
        .ok_or_else(|| budget("APFS node table overflow"))?;
    let mut front = base;
    let mut back = end;
    for (i, (k, v)) in records.iter().enumerate() {
        if k.len() > u16::MAX as usize || v.len() > u16::MAX as usize {
            return Err(invalid("APFS record field exceeds native size"));
        }
        let ghost = ghosts == GhostPolicy::AllowOmapLeaf
            && subtype == 9
            && level == 0
            && fixed == Some((16, 8))
            && v.is_empty();
        if let Some((ks, vs)) = fixed
            && (k.len() != ks || (!ghost && v.len() != if level == 0 { vs } else { 8 }))
        {
            return Err(invalid("APFS fixed tree record size"));
        }
        let next = front
            .checked_add(k.len())
            .ok_or_else(|| budget("APFS node overflow"))?;
        back = back
            .checked_sub(v.len())
            .ok_or_else(|| invalid("APFS record exceeds node"))?;
        if next > back || base > end {
            return Err(invalid("APFS records exceed node"));
        }
        let at = 56 + i * entry;
        w(&mut b, at, (front - base) as u16);
        if fixed.is_some() {
            w(
                &mut b,
                at + 2,
                if ghost { 65535 } else { (end - back) as u16 },
            );
        } else {
            w(&mut b, at + 2, k.len() as u16);
            w(&mut b, at + 4, (end - back) as u16);
            w(&mut b, at + 6, v.len() as u16);
        }
        b[front..next].copy_from_slice(k);
        b[back..back + v.len()].copy_from_slice(v);
        front = next;
    }
    w(
        &mut b,
        32,
        u16::from(root) + 2 * u16::from(level == 0) + 4 * u16::from(fixed.is_some()),
    );
    w(&mut b, 34, level);
    d(&mut b, 36, records.len() as u32);
    w(&mut b, 42, table as u16);
    w(&mut b, 44, (front - base) as u16);
    w(&mut b, 46, (back - front) as u16);
    w(&mut b, 48, u16::MAX);
    w(&mut b, 52, u16::MAX);
    if root {
        let flags = if storage == 0x40000000 {
            0x10
        } else if storage == 0x80000000 {
            0xc
        } else {
            0
        };
        d(&mut b, end, flags | if fixed.is_some() { 0 } else { 0x40 });
        d(&mut b, end + 4, BLOCK as u32);
        if let Some((ks, vs)) = fixed {
            d(&mut b, end + 8, ks as u32);
            d(&mut b, end + 12, vs as u32);
        }
        d(&mut b, end + 16, totals.2 as u32);
        d(&mut b, end + 20, totals.3 as u32);
        q(&mut b, end + 24, totals.0);
        q(&mut b, end + 32, totals.1);
    }
    seal(&mut b);
    Ok(b)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn fields(subtype: u32, level: u16) -> NodeFields {
        NodeFields {
            id: 42,
            storage: 0x40000000,
            subtype,
            level,
            root: true,
            fixed: Some((16, 8)),
            totals: (1, 1, 16, 8),
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn ghost_values_require_the_editing_object_map_leaf_profile() {
        let records = vec![(vec![0; 16], vec![])];
        assert_eq!(
            node(fields(9, 0), &records, GhostPolicy::Reject)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidOperation,
        );
        let encoded = node(fields(9, 0), &records, GhostPolicy::AllowOmapLeaf).unwrap();
        assert_eq!(&encoded[58..60], &u16::MAX.to_le_bytes());
        for (subtype, level) in [(14, 0), (9, 1)] {
            assert!(node(fields(subtype, level), &records, GhostPolicy::AllowOmapLeaf).is_err());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn ordinary_records_encode_identically_under_both_profiles() {
        let records = vec![(vec![0; 16], vec![1; 8])];
        assert_eq!(
            node(fields(9, 0), &records, GhostPolicy::Reject).unwrap(),
            node(fields(9, 0), &records, GhostPolicy::AllowOmapLeaf).unwrap(),
        );
    }
}
