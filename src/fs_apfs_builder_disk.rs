//! Native block serialization for fresh APFS authoring; no template image input.
use crate::fs_core::{Error, ErrorKind, Result};
pub(super) const BLOCK: usize = 4096;
pub(super) type Records = Vec<(Vec<u8>, Vec<u8>)>;
pub(super) fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
pub(super) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(super) fn zero(n: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    b.try_reserve_exact(n)
        .map_err(|_| budget("APFS builder allocation"))?;
    b.resize(n, 0);
    Ok(b)
}
pub(super) fn w(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn d(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn q(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn seal(b: &mut [u8]) {
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
pub(super) fn object(id: u64, kind: u32, subtype: u32) -> Result<Vec<u8>> {
    let mut b = zero(BLOCK)?;
    q(&mut b, 8, id);
    q(&mut b, 16, 1);
    d(&mut b, 24, kind);
    d(&mut b, 28, subtype);
    Ok(b)
}
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
pub(super) fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
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
/// A node is serialized from records, with explicit bounds before every copy.
/// Root footer counts describe the complete tree, including descendants.
pub(super) struct NodeFields {
    pub id: u64,
    pub storage: u32,
    pub subtype: u32,
    pub level: u16,
    pub root: bool,
    pub fixed: Option<(usize, usize)>,
    pub totals: (u64, u64, usize, usize),
}
pub(super) fn node(f: NodeFields, records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>> {
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
        if let Some((ks, vs)) = fixed
            && (k.len() != ks || v.len() != if level == 0 { vs } else { 8 })
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
            w(&mut b, at + 2, (end - back) as u16);
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
