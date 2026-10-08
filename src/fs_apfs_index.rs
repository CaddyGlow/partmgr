//! Bounded native APFS B-tree and object-map indexing.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{cmp::Ordering as Compare, collections::BTreeMap};
pub(crate) struct Record {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}
pub(crate) struct Tree {
    pub records: Vec<Record>,
    pub pages: Vec<(u64, Vec<u8>)>,
}
#[derive(Clone, Copy)]
pub(crate) enum TreeKind {
    Omap,
    Filesystem,
    Extent,
    Snapshot,
    FreeQueue,
}
fn keycmp(kind: TreeKind, a: &[u8], b: &[u8]) -> Result<Compare> {
    let scalar = |k: &[u8], p: usize| {
        if k.len() >= p + 8 {
            Ok(u64le(k, p))
        } else {
            Err(bad("APFS short tree key"))
        }
    };
    if matches!(kind, TreeKind::Omap | TreeKind::FreeQueue) {
        if a.len() != 16 || b.len() != 16 {
            return Err(bad("APFS fixed tree key"));
        }
        return Ok(scalar(a, 0)?
            .cmp(&scalar(b, 0)?)
            .then(scalar(a, 8)?.cmp(&scalar(b, 8)?)));
    }
    let ak = scalar(a, 0)?;
    let bk = scalar(b, 0)?;
    let first = (ak & 0x0fffffffffffffff)
        .cmp(&(bk & 0x0fffffffffffffff))
        .then((ak >> 60).cmp(&(bk >> 60)));
    if first != Compare::Equal {
        return Ok(first);
    }
    match ak >> 60 {
        5 | 8 => {
            if a.len() != 16 || b.len() != 16 {
                return Err(bad("APFS file extent key size"));
            }
            Ok(scalar(a, 8)?.cmp(&scalar(b, 8)?))
        }
        4 | 9 => {
            if a.len() < 11 || b.len() < 11 {
                return Err(bad("APFS native name key"));
            }
            Ok(a[10..].cmp(&b[10..]))
        }
        _ => Ok(a[8..].cmp(&b[8..])),
    }
}
pub(crate) fn tree(
    container: &ApfsContainer,
    root: u64,
    storage: u32,
    kind: TreeKind,
    omap: Option<&BTreeMap<u64, u64>>,
    w: &mut Work,
    r: &Resources,
) -> Result<Tree> {
    struct Walker<'a> {
        c: &'a ApfsContainer,
        storage: u32,
        kind: TreeKind,
        omap: Option<&'a BTreeMap<u64, u64>>,
        w: &'a mut Work,
        r: &'a Resources,
        seen: BTreeSet<u64>,
        out: Tree,
        count: u64,
        nodes: u64,
        fixed: bool,
        keysize: usize,
        valsize: usize,
        ghosts: bool,
    }
    impl Walker<'_> {
        fn visit(&mut self, id: u64, level: Option<u16>, depth: usize) -> Result<Option<Vec<u8>>> {
            if depth > 8 {
                return Err(budget("APFS B-tree depth ceiling"));
            }
            if self.seen.len() == self.w.limits.objects {
                return Err(budget("APFS B-tree node ceiling"));
            }
            let at = if self.storage == 0 {
                *self
                    .omap
                    .ok_or_else(|| bad("APFS absent virtual map"))?
                    .get(&id)
                    .ok_or_else(|| bad("APFS virtual B-tree object missing"))?
            } else if self.storage == 0x80000000 {
                self.c
                    .inner
                    .mappings
                    .iter()
                    .find(|m| m.volume == 0 && m.oid == id)
                    .ok_or_else(|| bad("APFS ephemeral B-tree object missing"))?
                    .address
            } else {
                id
            };
            if !self.seen.insert(at) {
                return Err(bad("APFS B-tree duplicate/cyclic child"));
            }
            let b = read_block(
                self.c.inner.source.as_ref(),
                at,
                self.c.checkpoint().blocks,
                self.w,
                self.r,
            )?;
            let ty = self.storage | if depth == 0 { 2 } else { 3 };
            check_object(&b, Some(id), self.c.checkpoint().xid, Some(ty))?;
            let sub = match self.kind {
                TreeKind::Omap => 11,
                TreeKind::Filesystem => 14,
                TreeKind::Extent => 15,
                TreeKind::Snapshot => 16,
                TreeKind::FreeQueue => 9,
            };
            if u32le(&b, 28) != sub {
                return Err(bad("APFS B-tree subtype"));
            }
            let flags = u16::from_le_bytes(b[32..34].try_into().unwrap());
            let current = u16::from_le_bytes(b[34..36].try_into().unwrap());
            if flags & !7 != 0 {
                return Err(unsupported("APFS hashed/headerless B-tree"));
            }
            if current > 8
                || (current != 0 && u32le(&b, 36) == 0)
                || flags & 1 != u16::from(depth == 0)
                || flags & 2 != 2 * u16::from(current == 0)
                || level.is_some_and(|v| v != current)
            {
                return Err(bad("APFS B-tree level/root/leaf flags"));
            }
            if depth == 0 {
                let f = &b[4056..];
                let expected = if self.storage == 0x40000000 {
                    0x10
                } else if self.storage == 0x80000000 {
                    8
                } else {
                    0
                };
                if u32le(f, 0) & !0x44 != expected || u32le(f, 4) != 4096 {
                    return Err(unsupported("APFS B-tree footer profile"));
                }
                self.ghosts = u32le(f, 0) & 4 != 0;
                if self.ghosts && !matches!(self.kind, TreeKind::FreeQueue) {
                    return Err(unsupported("APFS ghost records outside native free queue"));
                }
                self.fixed = flags & 4 != 0;
                self.keysize = u32le(f, 8) as usize;
                self.valsize = u32le(f, 12) as usize;
                if self.fixed != (self.keysize != 0 && self.valsize != 0)
                    || self.fixed
                        && (self.keysize != 16
                            || self.valsize
                                != if matches!(self.kind, TreeKind::FreeQueue) {
                                    8
                                } else {
                                    16
                                })
                {
                    return Err(unsupported("APFS fixed B-tree sizes"));
                }
                self.count = u64le(f, 24);
                self.nodes = u64le(f, 32);
                if self.count > self.w.limits.records as u64
                    || self.nodes == 0
                    || self.nodes > self.w.limits.objects as u64
                {
                    return Err(budget("APFS B-tree declared counts"));
                }
            } else if flags & 4 != 4 * u16::from(self.fixed) {
                return Err(bad("APFS child fixed-key flag"));
            }
            let read16 = |p| usize::from(u16::from_le_bytes(b[p..p + 2].try_into().unwrap()));
            let n = u32le(&b, 36) as usize;
            let stride = if self.fixed { 4 } else { 8 };
            let table = 56 + read16(40);
            if self.fixed {
                let value = if current != 0 { 8 } else { self.valsize };
                let minimum = (4096 - 56) / (self.keysize + value + 4) * 4;
                if read16(42) < minimum
                    || (!matches!(self.kind, TreeKind::FreeQueue) && read16(42) != minimum)
                {
                    return Err(bad("APFS native fixed table capacity"));
                }
            }
            let table_end = table
                .checked_add(read16(42))
                .ok_or_else(|| bad("APFS table overflow"))?;
            let end = 4096 - if depth == 0 { 40 } else { 0 };
            if table < 56
                || table_end > end
                || n.checked_mul(stride).is_none_or(|v| v > table_end - table)
                || n > self.w.limits.records
            {
                return Err(bad("APFS B-tree table bounds"));
            }
            let free_start = table_end
                .checked_add(read16(44))
                .ok_or_else(|| bad("APFS shared free offset"))?;
            let free_end = free_start
                .checked_add(read16(46))
                .ok_or_else(|| bad("APFS shared free size"))?;
            if free_end > end {
                return Err(bad("APFS B-tree shared free bounds"));
            }
            if read16(48) != 65535 || read16(50) != 0 || read16(52) != 65535 || read16(54) != 0 {
                return Err(unsupported("APFS fragmented B-tree free lists"));
            }
            let mut occupied = vector(
                n.checked_mul(2)
                    .ok_or_else(|| budget("APFS B-tree occupied intervals"))?,
            )?;
            let mut first = None;
            let mut previous: Option<Vec<u8>> = None;
            for i in 0..n {
                self.w.tick(1, self.r)?;
                let p = table + i * stride;
                let ko = read16(p);
                let kl = if self.fixed {
                    self.keysize
                } else {
                    read16(p + 2)
                };
                let vo = read16(p + if self.fixed { 2 } else { 4 });
                let ghost = current == 0
                    && matches!(self.kind, TreeKind::FreeQueue)
                    && self.ghosts
                    && vo == 65535;
                let vl = if ghost {
                    0
                } else if current != 0 {
                    8
                } else if self.fixed {
                    self.valsize
                } else {
                    read16(p + 6)
                };
                let ks = table_end
                    .checked_add(ko)
                    .ok_or_else(|| bad("APFS key offset"))?;
                let ke = ks.checked_add(kl).ok_or_else(|| bad("APFS key size"))?;
                let vs = end
                    .checked_sub(if ghost { 0 } else { vo })
                    .ok_or_else(|| bad("APFS value offset"))?;
                let ve = vs.checked_add(vl).ok_or_else(|| bad("APFS value size"))?;
                if kl == 0 || (vl == 0 && !ghost) || ke > free_start || vs < free_end || ve > end {
                    return Err(bad("APFS B-tree key/value bounds"));
                }
                occupied.push((ks, ke));
                if !ghost {
                    occupied.push((vs, ve));
                }
                let key = &b[ks..ke];
                let val = &b[vs..ve];
                keycmp(self.kind, key, key)?;
                if let Some(old) = &previous
                    && keycmp(self.kind, old, key)? != Compare::Less
                {
                    return Err(bad("APFS B-tree key order/collision"));
                }
                if first.is_none() {
                    first = Some(copy(key)?);
                }
                previous = Some(copy(key)?);
                if current == 0 {
                    if self.out.records.len() == self.w.limits.records {
                        return Err(budget("APFS B-tree record ceiling"));
                    }
                    self.out.records.push(Record {
                        key: copy(key)?,
                        value: copy(val)?,
                    });
                } else {
                    let child = self
                        .visit(u64le(val, 0), Some(current - 1), depth + 1)?
                        .ok_or_else(|| bad("APFS empty internal child"))?;
                    if keycmp(self.kind, key, &child)? != Compare::Equal {
                        return Err(bad("APFS child minimum separator"));
                    }
                }
            }
            occupied.sort_unstable();
            if occupied.windows(2).any(|p| p[0].1 > p[1].0) {
                return Err(bad("APFS overlapping B-tree storage"));
            }
            self.out.pages.push((at, b));
            Ok(first)
        }
    }
    let records = vector(w.limits.records)?;
    let pages = vector(w.limits.objects)?;
    let mut walk = Walker {
        c: container,
        storage,
        kind,
        omap,
        w,
        r,
        seen: BTreeSet::new(),
        out: Tree { records, pages },
        count: 0,
        nodes: 0,
        fixed: false,
        keysize: 0,
        valsize: 0,
        ghosts: false,
    };
    walk.visit(root, None, 0)?;
    if walk.out.records.len() as u64 != walk.count || walk.out.pages.len() as u64 != walk.nodes {
        return Err(bad("APFS B-tree footer actual counts"));
    }
    for pair in walk.out.records.windows(2) {
        if keycmp(kind, &pair[0].key, &pair[1].key)? != Compare::Less {
            return Err(bad("APFS B-tree cross-leaf key order"));
        }
    }
    Ok(walk.out)
}
pub(crate) fn omap(
    container: &ApfsContainer,
    address: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<(BTreeMap<u64, u64>, ObjectPages)> {
    let b = read_block(
        container.inner.source.as_ref(),
        address,
        container.checkpoint().blocks,
        w,
        r,
    )?;
    check_object(
        &b,
        Some(address),
        container.checkpoint().xid,
        Some(0x4000000b),
    )?;
    if u32le(&b, 32) & !1 != 0
        || u32le(&b, 36) != 0
        || u32le(&b, 40) != 0x40000002
        || b[56..88].iter().any(|v| *v != 0)
    {
        return Err(unsupported(
            "APFS object-map snapshot/crypto/revert profile",
        ));
    }
    let indexed = tree(
        container,
        u64le(&b, 48),
        0x40000000,
        TreeKind::Omap,
        None,
        w,
        r,
    )?;
    let mut out = BTreeMap::new();
    let mut latest = BTreeMap::new();
    for item in indexed.records {
        let oid = u64le(&item.key, 0);
        let xid = u64le(&item.key, 8);
        let flags = u32le(&item.value, 0);
        let size = u32le(&item.value, 4);
        let physical = u64le(&item.value, 8);
        if oid == 0 || xid == 0 || flags & !1 != 0 || size != 4096 {
            return Err(unsupported("APFS object-map value profile"));
        }
        range(physical, 1, container.checkpoint().blocks)?;
        if xid <= container.checkpoint().xid && latest.get(&oid).is_none_or(|v| *v < xid) {
            latest.insert(oid, xid);
            if flags & 1 == 0 {
                out.insert(oid, physical);
            } else {
                out.remove(&oid);
            }
        }
    }
    let mut pages = indexed.pages;
    pages
        .try_reserve(1)
        .map_err(|_| budget("APFS object-map page"))?;
    pages.push((address, b));
    Ok((out, pages))
}
