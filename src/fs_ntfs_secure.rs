//! Native $Secure lookup. Read-only structural evidence, not ACL restoration.
use super::{NtfsSecurityDescriptor, NtfsSecurityLimits};
use crate::platform::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_core::*,
    fs_ntfs::{NtfsFile, NtfsRecord, NtfsStreamLimits, NtfsVolume},
};
/// Explicit $Secure index and descriptor ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsSecureLimits {
    /// Descriptor structural limits.
    pub descriptor: NtfsSecurityLimits,
    /// Maximum allocated INDX blocks per index.
    pub blocks: usize,
    /// Maximum security entries per index.
    pub entries: usize,
    /// Maximum index depth, with INDEX_ROOT at depth zero.
    pub depth: usize,
    /// Maximum index visits and bytes read across both indexes and SDS copies.
    pub work: u64,
}
/// Explicit security and extension-resolution ceilings for object-bound inspection.
#[derive(Clone, Copy, Debug)]
pub struct NtfsSecureObjectLimits {
    /// Descriptor and native security index ceilings.
    pub security: NtfsSecureLimits,
    /// Attribute-list and extension-record ceilings.
    pub streams: NtfsStreamLimits,
}
/// Native source of inspected descriptor bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsSecurityOrigin {
    /// Per-record $SECURITY_DESCRIPTOR attribute.
    PerRecord,
    /// $Secure security ID and independently checked native header.
    Secure {
        /// STANDARD_INFORMATION security ID.
        id: u32,
        /// Native descriptor hash (not a cryptographic authentication).
        hash: u32,
        /// Primary $SDS byte offset.
        offset: u64,
    },
}
/// Bound descriptor inspection with native provenance.
pub struct NtfsResolvedSecurity {
    /// Exact source-scoped FILE record and sequence bound to this descriptor.
    record: ObjectId,
    /// Complete unchanged self-relative descriptor and native SID/ACL views.
    descriptor: NtfsSecurityDescriptor,
    /// Native attribute or validated $Secure provenance.
    origin: NtfsSecurityOrigin,
}
impl NtfsResolvedSecurity {
    /// Exact source-scoped record identity bound by the resolver.
    pub fn record(&self) -> &ObjectId {
        &self.record
    }
    /// Lossless native descriptor inspection bound to that record.
    pub fn descriptor(&self) -> &NtfsSecurityDescriptor {
        &self.descriptor
    }
    /// Checked native security lookup provenance.
    pub fn origin(&self) -> NtfsSecurityOrigin {
        self.origin
    }
}
fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn cap(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
fn w(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn d(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn q(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
struct Work<'a> {
    left: u64,
    r: &'a Resources,
}
impl Work<'_> {
    fn tick(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.left = self
            .left
            .checked_sub(n)
            .ok_or_else(|| cap("NTFS Secure work ceiling"))?;
        Ok(())
    }
}
fn read(file: &NtfsFile, at: u64, out: &mut [u8], work: &mut Work<'_>) -> Result<()> {
    if at
        .checked_add(out.len() as u64)
        .is_none_or(|e| e > file.len())
    {
        return Err(bad("NTFS Secure stream read bounds"));
    }
    let mut done = 0;
    while done < out.len() {
        work.tick(1 + (out.len() - done) as u64)?;
        let n = file.read_at(at + done as u64, &mut out[done..], work.r)?;
        if n == 0 || n > out.len() - done {
            return Err(bad("NTFS Secure short read"));
        }
        done += n;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    hash: u32,
    id: u32,
    offset: u64,
    size: u32,
}
impl Header {
    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != 20 {
            return Err(bad("NTFS Secure header size"));
        }
        Ok(Self {
            hash: d(b, 0),
            id: d(b, 4),
            offset: q(b, 8),
            size: d(b, 16),
        })
    }
}
type Key = (u32, u32);
type Task = (u64, usize, Option<Key>, Option<Key>);
fn ascii(s: &str) -> Vec<u8> {
    s.bytes().flat_map(|x| [x, 0]).collect()
}
fn stream(
    volume: &NtfsVolume,
    record: &NtfsRecord,
    kind: u32,
    name: &[u8],
    r: &Resources,
) -> Result<Option<NtfsFile>> {
    let mut found = None;
    for a in record
        .audit_attributes()
        .filter(|a| a.kind == kind && a.name == name)
    {
        if found.is_some() {
            return Err(unsupported("NTFS Secure split stream"));
        }
        found = Some(volume.audit_stream(record, a, r)?);
    }
    Ok(found)
}
fn dense(file: &NtfsFile, r: &Resources) -> Result<()> {
    file.visit_extents(r, &mut |e| {
        if e.kind != ExtentKind::Data {
            return Err(unsupported("NTFS Secure uninitialized/sparse index stream"));
        }
        Ok(())
    })
}
struct Tree {
    allocation: Option<NtfsFile>,
    bitmap: Option<NtfsFile>,
    index_bytes: usize,
    unit: u64,
    blocks: usize,
    hash: bool,
    limits: NtfsSecureLimits,
}
impl Tree {
    fn parse_node(
        &self,
        b: &[u8],
        base: usize,
        bounds: (usize, Option<Key>, Option<Key>),
        tasks: &mut Vec<Task>,
        entries: &mut BTreeMap<Key, Header>,
        work: &mut Work<'_>,
    ) -> Result<()> {
        let (depth, lower, upper) = bounds;
        work.tick(1)?;
        if depth > self.limits.depth {
            return Err(cap("NTFS Secure index depth"));
        }
        let h = b
            .get(base..base + 16)
            .ok_or_else(|| bad("NTFS Secure index header"))?;
        let start = d(h, 0) as usize;
        let used = d(h, 4) as usize;
        let total = d(h, 8) as usize;
        let flags = d(h, 12);
        if start < 16
            || !start.is_multiple_of(8)
            || used > total
            || total > b.len() - base
            || start > used
            || flags > 1
        {
            return Err(bad("NTFS Secure index ranges/flags"));
        }
        let mut at = base + start;
        let end = base + used;
        let mut previous = lower;
        let mut terminal = false;
        while at < end {
            work.tick(1)?;
            let e = b
                .get(at..at + 16)
                .filter(|_| at + 16 <= end)
                .ok_or_else(|| bad("NTFS Secure index entry header"))?;
            let size = usize::from(w(e, 8));
            let keysize = usize::from(w(e, 10));
            let f = w(e, 12);
            let child = f & 1 != 0;
            let last = f & 2 != 0;
            if size < 16
                || !size.is_multiple_of(8)
                || at.checked_add(size).is_none_or(|x| x > end)
                || f & !3 != 0
                || w(e, 14) != 0
                || d(e, 4) != 0
                || child != (flags == 1)
            {
                return Err(bad("NTFS Secure index entry range/flags"));
            }
            let bodyend = at + size - if child { 8 } else { 0 };
            let dataat = usize::from(w(e, 0));
            let datasize = usize::from(w(e, 2));
            let key = if last {
                if keysize != 0 || datasize != 0 || at + size != end {
                    return Err(bad("NTFS Secure terminal entry"));
                }
                terminal = true;
                None
            } else {
                let expected = if self.hash { 8 } else { 4 };
                if keysize != expected
                    || 16 + keysize > size
                    || dataat < 16 + keysize
                    || datasize != 20
                    || at + dataat + datasize > bodyend
                {
                    return Err(bad("NTFS Secure key/value ranges"));
                }
                let key = if self.hash {
                    (d(b, at + 16), d(b, at + 20))
                } else {
                    (0, d(b, at + 16))
                };
                if previous.is_some_and(|p| key <= p) || upper.is_some_and(|u| key >= u) {
                    return Err(bad("NTFS Secure index ordering/child bounds"));
                }
                let value = Header::parse(&b[at + dataat..at + dataat + 20])?;
                if value.id != key.1
                    || self.hash && value.hash != key.0
                    || entries.len() == self.limits.entries
                    || entries.insert(key, value).is_some()
                {
                    return Err(bad(
                        "NTFS Secure duplicate/key header inconsistency or entry ceiling",
                    ));
                }
                Some(key)
            };
            if child {
                let nextdepth = depth
                    .checked_add(1)
                    .filter(|n| *n <= self.limits.depth)
                    .ok_or_else(|| cap("NTFS Secure child depth"))?;
                if tasks.len() >= self.limits.blocks {
                    return Err(cap("NTFS Secure pending nodes"));
                }
                tasks.push((q(b, at + size - 8), nextdepth, previous, key.or(upper)));
            }
            if let Some(key) = key {
                previous = Some(key);
            }
            at += size;
        }
        if !terminal {
            return Err(bad("NTFS Secure missing terminal"));
        }
        Ok(())
    }
    fn collect(&self, root: &[u8], work: &mut Work<'_>) -> Result<BTreeMap<Key, Header>> {
        let mut entries = BTreeMap::new();
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(self.limits.blocks)
            .map_err(|_| cap("NTFS Secure task allocation"))?;
        let mut seen = BTreeSet::new();
        self.parse_node(root, 16, (0, None, None), &mut tasks, &mut entries, work)?;
        while let Some((vcn, depth, low, high)) = tasks.pop() {
            work.tick(1)?;
            let at = vcn
                .checked_mul(self.unit)
                .filter(|at| at.is_multiple_of(self.index_bytes as u64))
                .ok_or_else(|| bad("NTFS Secure child VCN alignment"))?;
            let block = usize::try_from(at / self.index_bytes as u64)
                .map_err(|_| bad("NTFS Secure child address"))?;
            if block >= self.blocks || !seen.insert(block) {
                return Err(bad("NTFS Secure child range/cycle"));
            }
            let bitmap = self
                .bitmap
                .as_ref()
                .ok_or_else(|| bad("NTFS Secure missing index bitmap"))?;
            let mut bit = [0];
            read(bitmap, (block / 8) as u64, &mut bit, work)?;
            if bit[0] & (1 << (block % 8)) == 0 {
                return Err(bad("NTFS Secure child bitmap free"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(self.index_bytes)
                .map_err(|_| cap("NTFS Secure INDX allocation"))?;
            bytes.resize(self.index_bytes, 0);
            read(
                self.allocation
                    .as_ref()
                    .ok_or_else(|| bad("NTFS Secure missing allocation"))?,
                at,
                &mut bytes,
                work,
            )?;
            if bytes[..4] != *b"INDX" || q(&bytes, 16) != vcn {
                return Err(bad("NTFS Secure INDX signature/VCN"));
            }
            let usa = usize::from(w(&bytes, 4));
            let count = usize::from(w(&bytes, 6));
            if count != self.index_bytes / 512 + 1
                || usa < 40
                || usa
                    .checked_add(count * 2)
                    .is_none_or(|e| e > self.index_bytes || e > 510)
            {
                return Err(bad("NTFS Secure INDX USA range"));
            }
            let marker = w(&bytes, usa);
            for sector in 1..count {
                let tail = sector * 512 - 2;
                if w(&bytes, tail) != marker {
                    return Err(bad("NTFS Secure torn INDX USA"));
                }
                let original = w(&bytes, usa + sector * 2).to_le_bytes();
                bytes[tail..tail + 2].copy_from_slice(&original);
            }
            if 24 + (d(&bytes, 24) as usize) < usa + count * 2 {
                return Err(bad("NTFS Secure INDX entry/USA overlap"));
            }
            self.parse_node(
                &bytes,
                24,
                (depth, low, high),
                &mut tasks,
                &mut entries,
                work,
            )?;
        }
        if let Some(bitmap) = &self.bitmap {
            if bitmap.len() < self.blocks.div_ceil(8) as u64
                || bitmap.len() > self.limits.blocks.div_ceil(8).max(8) as u64
            {
                return Err(cap("NTFS Secure bitmap size"));
            }
            for at in 0..bitmap.len() {
                let mut value = [0];
                read(bitmap, at, &mut value, work)?;
                for bit in 0..8 {
                    let block = at * 8 + bit;
                    if value[0] & (1 << bit) != 0
                        && (block >= self.blocks as u64 || !seen.contains(&(block as usize)))
                    {
                        return Err(bad("NTFS Secure allocated unreachable index node"));
                    }
                }
            }
        } else if self.blocks != 0 {
            return Err(bad("NTFS Secure index bitmap absent"));
        }
        Ok(entries)
    }
}
fn index(
    volume: &NtfsVolume,
    secure: &NtfsRecord,
    name: &[u8],
    hash: bool,
    l: NtfsSecureLimits,
    work: &mut Work<'_>,
) -> Result<BTreeMap<Key, Header>> {
    let mut root = None;
    for a in secure
        .audit_attributes()
        .filter(|a| a.kind == 0x90 && a.name == name)
    {
        if root.is_some() || a.nonresident {
            return Err(unsupported("NTFS Secure split/nonresident INDEX_ROOT"));
        }
        root = a.resident;
    }
    let root = root.ok_or_else(|| bad("NTFS Secure INDEX_ROOT absent"))?;
    let allocation = stream(volume, secure, 0xa0, name, work.r)?;
    let bitmap = stream(volume, secure, 0xb0, name, work.r)?;
    index_parts(volume, root, (allocation, bitmap), hash, l, work)
}
fn index_parts(
    volume: &NtfsVolume,
    root: &[u8],
    streams: (Option<NtfsFile>, Option<NtfsFile>),
    hash: bool,
    l: NtfsSecureLimits,
    work: &mut Work<'_>,
) -> Result<BTreeMap<Key, Header>> {
    let (allocation, bitmap) = streams;
    let size = volume.geometry().index_bytes();
    let unit = if (size as u64) < volume.geometry().cluster_bytes() {
        512
    } else {
        volume.geometry().cluster_bytes()
    };
    if root.len() < 32
        || d(root, 0) != 0
        || d(root, 4) != if hash { 0x12 } else { 0x10 }
        || d(root, 8) as usize != size
        || u64::from(root[12]) != size as u64 / unit
        || root[13..16] != [0; 3]
    {
        return Err(unsupported("NTFS Secure index type/collation/geometry"));
    }
    let blocks = if let Some(a) = &allocation {
        dense(a, work.r)?;
        if !a.len().is_multiple_of(size as u64) {
            return Err(bad("NTFS Secure allocation length"));
        }
        usize::try_from(a.len() / size as u64).map_err(|_| cap("NTFS Secure allocated blocks"))?
    } else {
        0
    };
    if blocks > l.blocks {
        return Err(cap("NTFS Secure index block ceiling"));
    }
    if let Some(b) = &bitmap {
        dense(b, work.r)?;
    }
    let tree = Tree {
        allocation,
        bitmap,
        index_bytes: size,
        unit,
        blocks,
        hash,
        limits: l,
    };
    tree.collect(root, work)
}
/// Resolve a bound record's native security descriptor through actual $SII/$SDH/$SDS.
/// Preserves native bytes; does not authenticate the image, evaluate ACLs, or claim restore support.
pub fn lookup_ntfs_security(
    volume: &NtfsVolume,
    record: &NtfsRecord,
    l: NtfsSecureLimits,
    r: &Resources,
) -> Result<NtfsResolvedSecurity> {
    volume.audit_check_source(r)?;
    let number = u64::from_le_bytes(
        record
            .identity()
            .native
            .as_slice()
            .try_into()
            .map_err(|_| bad("NTFS security record identity"))?,
    );
    if volume.record(number, r)?.identity() != record.identity() {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS security foreign/stale FILE identity",
        ));
    }
    let mut perrecord = None;
    let mut id = None;
    for a in record.audit_attributes() {
        if a.kind == 0x50 && a.name.is_empty() {
            if perrecord.is_some() {
                return Err(unsupported("NTFS split security descriptor attribute"));
            }
            perrecord = Some(a);
        }
        if a.kind == 0x10 && a.name.is_empty() {
            let value = a
                .resident
                .ok_or_else(|| unsupported("NTFS nonresident standard security ID"))?;
            if value.len() >= 72 && id.replace(d(value, 52)).is_some() {
                return Err(bad("NTFS duplicate standard security ID"));
            }
        }
    }
    if let Some(attribute) = perrecord {
        if id.is_some_and(|i| i != 0) {
            return Err(unsupported(
                "NTFS mixed per-record/shared security authority",
            ));
        }
        let descriptor = if let Some(value) = attribute.resident {
            NtfsSecurityDescriptor::parse(value, l.descriptor, r)?
        } else {
            let file = volume.audit_stream(record, attribute, r)?;
            dense(&file, r)?;
            let length = usize::try_from(file.len())
                .ok()
                .filter(|n| *n <= l.descriptor.bytes)
                .ok_or_else(|| cap("NTFS per-record security byte ceiling"))?;
            let _lease = r.memory.reserve(length as u64)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| cap("NTFS per-record security allocation"))?;
            bytes.resize(length, 0);
            read(&file, 0, &mut bytes, &mut Work { left: l.work, r })?;
            NtfsSecurityDescriptor::parse(&bytes, l.descriptor, r)?
        };
        volume.audit_check_source(r)?;
        if volume.record(number, r)?.identity() != record.identity() {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS per-record security FILE sequence changed",
            ));
        }
        return Ok(NtfsResolvedSecurity {
            record: record.identity().clone(),
            descriptor,
            origin: NtfsSecurityOrigin::PerRecord,
        });
    }
    let id = id
        .filter(|i| *i != 0)
        .ok_or_else(|| unsupported("NTFS security ID absent"))?;
    let indexed = lookup_ntfs_secure_id(volume, id, l, r)?;
    if volume.record(number, r)?.identity() != record.identity() {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS security FILE sequence changed",
        ));
    }
    Ok(NtfsResolvedSecurity {
        record: record.identity().clone(),
        descriptor: indexed.descriptor,
        origin: indexed.origin,
    })
}
/// Descriptor indexed by native security ID; this does not assign it to a file.
/// File-bound capture uses `lookup_ntfs_security` and the file's stored ID.
pub struct NtfsIndexedSecurity {
    secure_record: ObjectId,
    descriptor: NtfsSecurityDescriptor,
    origin: NtfsSecurityOrigin,
}
impl NtfsIndexedSecurity {
    /// Source-scoped $Secure FILE identity bound to the index evidence.
    pub fn secure_record(&self) -> &ObjectId {
        &self.secure_record
    }
    /// Exact indexed self-relative descriptor bytes and native views.
    pub fn descriptor(&self) -> &NtfsSecurityDescriptor {
        &self.descriptor
    }
    /// Verified native ID/hash/offset provenance.
    pub fn origin(&self) -> NtfsSecurityOrigin {
        self.origin
    }
}
/// Inspect an explicitly selected native $Secure ID without assigning it to a file.
/// Both native indexes, SDS mirrors and descriptor hash must agree.
pub fn lookup_ntfs_secure_id(
    volume: &NtfsVolume,
    id: u32,
    l: NtfsSecureLimits,
    r: &Resources,
) -> Result<NtfsIndexedSecurity> {
    lookup_secure_id_profile(volume, id, l, None, r)
}
/// Inspect an ID with bounded internally resolved $Secure attribute extensions.
/// Both indexes and SDS mirror/hash checks remain mandatory.
pub fn lookup_ntfs_secure_id_with_attributes(
    volume: &NtfsVolume,
    id: u32,
    limits: NtfsSecureObjectLimits,
    r: &Resources,
) -> Result<NtfsIndexedSecurity> {
    lookup_secure_id_profile(volume, id, limits.security, Some(limits.streams), r)
}
fn lookup_secure_id_profile(
    volume: &NtfsVolume,
    id: u32,
    l: NtfsSecureLimits,
    streams: Option<NtfsStreamLimits>,
    r: &Resources,
) -> Result<NtfsIndexedSecurity> {
    volume.audit_check_source(r)?;
    let secure = if streams.is_none() {
        Some(volume.record(9, r)?)
    } else {
        None
    };
    let identity = if let Some(record) = &secure {
        record.identity().clone()
    } else {
        volume.stream_identity(9, r)?
    };
    let charge = (l.entries as u64)
        .checked_mul(256)
        .and_then(|n| n.checked_add((l.blocks as u64).checked_mul(128)?))
        .and_then(|n| n.checked_add(volume.geometry().index_bytes() as u64))
        .ok_or_else(|| cap("NTFS Secure reservation overflow"))?;
    let _lease = r.memory.reserve(charge)?;
    let mut work = Work { left: l.work, r };
    let sii = if let Some(streams) = streams {
        index_resolved(
            volume,
            &identity,
            ("$SII", false),
            NtfsSecureObjectLimits {
                security: l,
                streams,
            },
            &mut work,
        )?
    } else {
        index(
            volume,
            secure.as_ref().unwrap(),
            &ascii("$SII"),
            false,
            l,
            &mut work,
        )?
    };
    let selected = *sii
        .get(&(0, id))
        .ok_or_else(|| bad("NTFS security ID missing from SII"))?;
    let sdh = if let Some(streams) = streams {
        index_resolved(
            volume,
            &identity,
            ("$SDH", true),
            NtfsSecureObjectLimits {
                security: l,
                streams,
            },
            &mut work,
        )?
    } else {
        index(
            volume,
            secure.as_ref().unwrap(),
            &ascii("$SDH"),
            true,
            l,
            &mut work,
        )?
    };
    if sii.len() != sdh.len() || sii.values().any(|h| sdh.get(&(h.hash, h.id)) != Some(h)) {
        return Err(bad("NTFS SII/SDH header disagreement"));
    }
    let size = usize::try_from(selected.size).map_err(|_| bad("NTFS SDS size"))?;
    if size < 40
        || size - 20 > l.descriptor.bytes
        || !size.is_multiple_of(4)
        || !selected.offset.is_multiple_of(16)
        || selected.offset & 0x40000 != 0
        || selected.offset % 0x40000 + size as u64 > 0x40000
    {
        return Err(bad("NTFS SDS descriptor framing"));
    }
    let sds = if let Some(streams) = streams {
        volume.open_native_attribute_stream(&identity, 0x80, &[36, 83, 68, 83], streams, r)?
    } else {
        stream(volume, secure.as_ref().unwrap(), 0x80, &ascii("$SDS"), r)?
            .ok_or_else(|| bad("NTFS SDS stream absent"))?
    };
    dense(&sds, r)?;
    let _scratch = r.memory.reserve(
        (size as u64)
            .checked_mul(2)
            .ok_or_else(|| cap("NTFS SDS scratch reservation"))?,
    )?;
    let mut primary = Vec::new();
    primary
        .try_reserve_exact(size)
        .map_err(|_| cap("NTFS SDS primary allocation"))?;
    primary.resize(size, 0);
    let mut mirror = Vec::new();
    mirror
        .try_reserve_exact(size)
        .map_err(|_| cap("NTFS SDS mirror allocation"))?;
    mirror.resize(size, 0);
    read(&sds, selected.offset, &mut primary, &mut work)?;
    read(
        &sds,
        selected
            .offset
            .checked_add(0x40000)
            .ok_or_else(|| bad("NTFS SDS mirror offset"))?,
        &mut mirror,
        &mut work,
    )?;
    if primary != mirror || Header::parse(&primary[..20])? != selected {
        return Err(bad("NTFS SDS index/primary/mirror disagreement"));
    }
    let hash = primary[20..]
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |sum, n| {
            sum.rotate_left(3).wrapping_add(u32::from_le_bytes(*n))
        });
    if hash != selected.hash {
        return Err(bad("NTFS SDS descriptor hash mismatch"));
    }
    let descriptor = NtfsSecurityDescriptor::parse(&primary[20..], l.descriptor, r)?;
    volume.audit_check_source(r)?;
    let fresh = if streams.is_some() {
        volume.stream_identity(9, r)?
    } else {
        volume.record(9, r)?.identity().clone()
    };
    if fresh != identity {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS security FILE sequence changed",
        ));
    }
    Ok(NtfsIndexedSecurity {
        secure_record: identity,
        descriptor,
        origin: NtfsSecurityOrigin::Secure {
            id,
            hash,
            offset: selected.offset,
        },
    })
}

/// Resolve security for a fresh source-scoped FILE identity, including validated extensions.
/// Preserves descriptor bytes; does not grant restoration or access-check authority.
pub fn lookup_ntfs_security_object(
    volume: &NtfsVolume,
    object: &ObjectId,
    limits: NtfsSecureObjectLimits,
    r: &Resources,
) -> Result<NtfsResolvedSecurity> {
    volume.audit_check_source(r)?;
    let number = u64::from_le_bytes(
        object
            .native
            .as_slice()
            .try_into()
            .map_err(|_| bad("NTFS security object identity"))?,
    );
    if volume.stream_identity(number, r)? != *object {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS security foreign/stale object",
        ));
    }
    let attributes = volume.native_attributes(object, limits.streams, r)?;
    let mut standard = None;
    let mut has_descriptor = false;
    for a in attributes.iter() {
        if a.kind == 0x10 && a.name.is_empty() {
            if standard.is_some() {
                return Err(bad("NTFS duplicate security standard information"));
            }
            standard = Some(
                a.standard_information()
                    .ok_or_else(|| unsupported("NTFS security standard information profile"))?,
            );
        }
        if a.kind == 0x50 && a.name.is_empty() {
            has_descriptor = true;
        }
    }
    let id = standard.and_then(|s| s.security_id).filter(|id| *id != 0);
    let (descriptor, origin) = if has_descriptor {
        if id.is_some() {
            return Err(unsupported(
                "NTFS mixed per-record/shared security authority",
            ));
        }
        let file = volume.open_native_attribute_stream(object, 0x50, &[], limits.streams, r)?;
        dense(&file, r)?;
        let length = usize::try_from(file.len())
            .ok()
            .filter(|n| *n <= limits.security.descriptor.bytes)
            .ok_or_else(|| cap("NTFS resolved security byte ceiling"))?;
        let _scratch = r.memory.reserve(length as u64)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| cap("NTFS resolved security allocation"))?;
        bytes.resize(length, 0);
        read(
            &file,
            0,
            &mut bytes,
            &mut Work {
                left: limits.security.work,
                r,
            },
        )?;
        (
            NtfsSecurityDescriptor::parse(&bytes, limits.security.descriptor, r)?,
            NtfsSecurityOrigin::PerRecord,
        )
    } else {
        let indexed = lookup_ntfs_secure_id_with_attributes(
            volume,
            id.ok_or_else(|| unsupported("NTFS security ID absent"))?,
            limits,
            r,
        )?;
        (indexed.descriptor, indexed.origin)
    };
    volume.audit_check_source(r)?;
    if volume.stream_identity(number, r)? != *object {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS resolved security FILE sequence changed",
        ));
    }
    Ok(NtfsResolvedSecurity {
        record: object.clone(),
        descriptor,
        origin,
    })
}

fn index_resolved(
    volume: &NtfsVolume,
    object: &ObjectId,
    selector: (&str, bool),
    limits: NtfsSecureObjectLimits,
    work: &mut Work<'_>,
) -> Result<BTreeMap<Key, Header>> {
    let name: Vec<u16> = selector.0.encode_utf16().collect();
    let attributes = volume.native_attributes(object, limits.streams, work.r)?;
    let mut root = None;
    for a in attributes
        .iter()
        .filter(|a| a.kind == 0x90 && a.name == name)
    {
        if root.is_some() || a.nonresident || a.flags != 0 {
            return Err(unsupported("NTFS resolved Secure INDEX_ROOT profile"));
        }
        root = Some(());
    }
    root.ok_or_else(|| bad("NTFS resolved Secure INDEX_ROOT absent"))?;
    let file = volume.open_native_attribute_stream(object, 0x90, &name, limits.streams, work.r)?;
    dense(&file, work.r)?;
    let length = usize::try_from(file.len())
        .ok()
        .filter(|n| *n <= volume.geometry().record_bytes())
        .ok_or_else(|| cap("NTFS resolved Secure root byte ceiling"))?;
    let _scratch = work.r.memory.reserve(length as u64)?;
    let mut root = Vec::new();
    root.try_reserve_exact(length)
        .map_err(|_| cap("NTFS resolved Secure root allocation"))?;
    root.resize(length, 0);
    read(&file, 0, &mut root, work)?;
    let open = |kind| -> Result<Option<NtfsFile>> {
        if attributes.iter().any(|a| a.kind == kind && a.name == name) {
            Ok(Some(volume.open_native_attribute_stream(
                object,
                kind,
                &name,
                limits.streams,
                work.r,
            )?))
        } else {
            Ok(None)
        }
    };
    index_parts(
        volume,
        &root,
        (open(0xa0)?, open(0xb0)?),
        selector.1,
        limits.security,
        work,
    )
}
