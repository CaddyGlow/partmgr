//! Immutable APFS checkpoint and object discovery. Volume access is a separate profile.
use crate::fs_core::*;
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    collections::BTreeSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub(crate) type ObjectPages = Vec<(u64, Vec<u8>)>;
type CheckpointMappings = (Vec<ApfsEphemeralMapping>, ObjectPages);
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
#[path = "fs_apfs_index.rs"]
pub(crate) mod index;
pub(crate) fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
pub(crate) fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(crate) fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
pub(crate) fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
pub(crate) fn vector<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("APFS allocation"))?;
    Ok(v)
}
pub(crate) fn copy(b: &[u8]) -> Result<Vec<u8>> {
    let mut v = vector(b.len())?;
    v.extend_from_slice(b);
    Ok(v)
}

/// Explicit container discovery and subsequent metadata ceilings.
#[derive(Clone, Copy, Debug)]
pub struct ApfsReadLimits {
    /// Maximum physical container blocks.
    pub blocks: u64,
    /// Maximum checkpoint descriptor blocks inspected.
    pub checkpoint_blocks: usize,
    /// Maximum mapped ephemeral objects and indexed metadata objects.
    pub objects: usize,
    /// Maximum indexed tree records.
    pub records: usize,
    /// Maximum metadata bytes and traversal visits.
    pub work: u64,
}
/// A mapping retained from the selected checkpoint, not a virtual object-map entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApfsEphemeralMapping {
    /// Exact object type and storage flags.
    pub object_type: u32,
    /// Exact object subtype.
    pub subtype: u32,
    /// Native object length in bytes.
    pub size: u32,
    /// Owning volume identifier, or zero for a container object.
    pub volume: u64,
    /// Ephemeral object identifier.
    pub oid: u64,
    /// Physical container block address.
    pub address: u64,
}
/// Checksum-verified selected checkpoint geometry, without a cleanliness claim.
#[derive(Clone, Debug)]
pub struct ApfsCheckpoint {
    /// APFS family.
    pub family: Family,
    /// Native block size in bytes.
    pub block_size: u32,
    /// Native physical container block count.
    pub blocks: u64,
    /// Exact container UUID bytes.
    pub uuid: [u8; 16],
    /// Selected transaction identifier.
    pub xid: u64,
    /// Physical selected container superblock address.
    pub superblock: u64,
    /// Native container object-map physical address.
    pub object_map: u64,
    /// Native space-manager ephemeral identifier.
    pub space_manager: u64,
    /// All nonzero volume virtual identifiers, in native slot order.
    pub volumes: Vec<u64>,
}
pub(crate) struct Source {
    raw: Arc<dyn ReadAt>,
    length: u64,
    resources: Resources,
}
impl Source {
    pub(crate) fn stable(&self) -> Result<()> {
        self.resources.cancellation.check()?;
        if self.raw.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS source length changed",
            ));
        }
        Ok(())
    }
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.stable().map_err(io::Error::other)?;
        if at
            .checked_add(b.len() as u64)
            .is_none_or(|n| n > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.raw.read_exact_at(at, b)?;
        self.stable().map_err(io::Error::other)
    }
}
pub(crate) struct Work {
    pub(crate) limits: ApfsReadLimits,
    pub(crate) used: u64,
}
impl Work {
    pub(crate) fn tick(&mut self, n: u64, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.used = self
            .used
            .checked_add(n)
            .ok_or_else(|| budget("APFS work overflow"))?;
        if self.used > self.limits.work {
            return Err(budget("APFS work ceiling"));
        }
        Ok(())
    }
}
// Native Fletcher-64 check words exclude the stored eight-byte checksum.
pub(crate) fn checksum(b: &[u8]) -> u64 {
    const M: u64 = u32::MAX as u64;
    let (mut a, mut c) = (0u64, 0u64);
    for word in b[8..].chunks_exact(4) {
        a = (a + u64::from(u32::from_le_bytes(word.try_into().unwrap()))) % M;
        c = (c + a) % M;
    }
    let low = M - (a + c) % M;
    let high = M - (a + low) % M;
    low | high << 32
}
pub(crate) fn check_object(b: &[u8], oid: Option<u64>, xid: u64, kind: Option<u32>) -> Result<()> {
    if b.len() < 32 || !b.len().is_multiple_of(4) || checksum(b) != u64le(b, 0) {
        return Err(bad("APFS object checksum"));
    }
    if oid.is_some_and(|n| n != u64le(b, 8))
        || u64le(b, 8) == 0
        || u64le(b, 16) == 0
        || u64le(b, 16) > xid
    {
        return Err(bad("APFS object identity/transaction"));
    }
    let t = u32le(b, 24);
    if t & 0x38000000 != 0 || t & 0x07ff0000 != 0 {
        return Err(unsupported(
            "APFS encrypted/headerless/nonpersistent object",
        ));
    }
    if kind.is_some_and(|n| n != t) {
        return Err(bad("APFS object type/storage"));
    }
    Ok(())
}
pub(crate) fn range(start: u64, n: u64, blocks: u64) -> Result<()> {
    if n == 0 || start.checked_add(n).is_none_or(|v| v > blocks) {
        return Err(bad("APFS physical range"));
    }
    Ok(())
}
pub(crate) fn read_block(
    source: &dyn ReadAt,
    address: u64,
    blocks: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<Vec<u8>> {
    range(address, 1, blocks)?;
    w.tick(4096, r)?;
    let mut b = vector(4096)?;
    b.resize(4096, 0);
    source
        .read_exact_at(address * 4096, &mut b)
        .map_err(|e| Error::io("APFS metadata block", e))?;
    r.cancellation.check()?;
    Ok(b)
}
fn nx(b: &[u8], blocks: u64, uuid: Option<&[u8]>) -> Result<()> {
    check_object(b, Some(1), u64::MAX, Some(0x80000001))?;
    if &b[32..36] != b"NXSB"
        || u32le(b, 36) != 4096
        || u64le(b, 40) != blocks
        || uuid.is_some_and(|u| u != &b[72..88])
        || u64le(b, 96) <= u64le(b, 16)
    {
        return Err(bad("APFS NX geometry/UUID/next transaction"));
    }
    if u32le(b, 104) & 0x80000000 != 0 || u32le(b, 108) & 0x80000000 != 0 {
        return Err(unsupported("APFS fragmented checkpoint-area trees"));
    }
    let desc = u64::from(u32le(b, 104));
    let data = u64::from(u32le(b, 108));
    range(u64le(b, 112), desc, blocks)?;
    range(u64le(b, 120), data, blocks)?;
    if u32le(b, 128) >= u32le(b, 104)
        || u32le(b, 132) >= u32le(b, 108)
        || u32le(b, 136) >= u32le(b, 104)
        || u32le(b, 140) < 2
        || u32le(b, 140) > u32le(b, 104)
        || u32le(b, 144) >= u32le(b, 108)
        || u32le(b, 148) > u32le(b, 108)
        || u32le(b, 180) > 100
    {
        return Err(bad("APFS checkpoint ring indices/volume slots"));
    }
    if uuid.is_some()
        && ((u64::from(u32le(b, 144)) + u64::from(u32le(b, 148))) % data
            != u64::from(u32le(b, 132))
            || (u64::from(u32le(b, 136)) + u64::from(u32le(b, 140))) % desc
                != u64::from(u32le(b, 128)))
    {
        return Err(bad("APFS checkpoint ring terminal indices"));
    }
    if u64::from(u32le(b, 180)) != blocks.div_ceil(131072).min(100) {
        return Err(bad("APFS size-derived maximum volume count"));
    }
    if u64le(b, 160) == 0 || u64le(b, 152) == 0 || u64le(b, 168) == 0 {
        return Err(bad("APFS required container object identifiers"));
    }
    Ok(())
}
fn mappings(
    source: &dyn ReadAt,
    header: &[u8],
    address: u64,
    blocks: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<CheckpointMappings> {
    let count = u32le(header, 104);
    let base = u64le(header, 112);
    let start = u32le(header, 136);
    let len = u32le(header, 140);
    let xid = u64le(header, 16);
    if base + u64::from((start + len - 1) % count) != address {
        return Err(bad("APFS checkpoint terminal NX position"));
    }
    let mut maps = vector(w.limits.objects)?;
    let mut bound = vector(
        w.limits
            .objects
            .checked_add(len as usize)
            .ok_or_else(|| budget("APFS checkpoint bindings"))?,
    )?;
    let mut ids = BTreeSet::new();
    let mut physical = BTreeSet::new();
    let data_base = u64le(header, 120);
    let data_count = u64::from(u32le(header, 108));
    let data_index = u64::from(u32le(header, 144));
    let data_len = u64::from(u32le(header, 148));
    for i in 0..len - 1 {
        let at = base + u64::from((start + i) % count);
        let b = read_block(source, at, blocks, w, r)?;
        check_object(&b, Some(at), xid, Some(0x4000000c))?;
        if u64le(&b, 16) != xid || u32le(&b, 28) != 0 || u32le(&b, 32) != u32::from(i == len - 2) {
            return Err(bad("APFS checkpoint map transaction/LAST"));
        }
        let n = u32le(&b, 36) as usize;
        if n > (4096 - 40) / 40
            || maps
                .len()
                .checked_add(n)
                .is_none_or(|n| n > w.limits.objects)
        {
            return Err(budget("APFS checkpoint mapping count"));
        }
        for j in 0..n {
            w.tick(1, r)?;
            let p = 40 + j * 40;
            let m = ApfsEphemeralMapping {
                object_type: u32le(&b, p),
                subtype: u32le(&b, p + 4),
                size: u32le(&b, p + 8),
                volume: u64le(&b, p + 16),
                oid: u64le(&b, p + 24),
                address: u64le(&b, p + 32),
            };
            if m.size != 4096 {
                return Err(unsupported("APFS multi-block ephemeral object"));
            }
            if u32le(&b, p + 12) != 0
                || m.oid == 0
                || m.oid >= u64le(header, 88)
                || m.object_type & 0xc0000000 != 0x80000000
                || !ids.insert((m.volume, m.oid))
                || !physical.insert(m.address)
            {
                return Err(bad("APFS duplicate/invalid checkpoint mapping"));
            }
            if m.address < data_base
                || m.address >= data_base + data_count
                || (m.address - data_base + data_count - data_index) % data_count >= data_len
            {
                return Err(bad("APFS ephemeral outside active checkpoint data"));
            }
            let object = read_block(source, m.address, blocks, w, r)?;
            check_object(&object, Some(m.oid), xid, Some(m.object_type))?;
            if u64le(&object, 16) != xid || u32le(&object, 28) != m.subtype {
                return Err(bad("APFS ephemeral transaction/subtype"));
            }
            bound.push((m.address, object));
            maps.push(m);
        }
        bound.push((at, b));
    }
    if maps
        .iter()
        .filter(|m| m.volume == 0 && m.oid == u64le(header, 152) && m.object_type == 0x80000005)
        .count()
        != 1
        || maps
            .iter()
            .filter(|m| m.volume == 0 && m.oid == u64le(header, 168) && m.object_type == 0x80000011)
            .count()
            != 1
    {
        return Err(bad("APFS required ephemeral map bindings"));
    }
    Ok((maps, bound))
}
pub(crate) struct ContainerInner {
    pub(crate) source: Arc<Source>,
    pub(crate) scope: u128,
    pub(crate) checkpoint: ApfsCheckpoint,
    pub(crate) header: Vec<u8>,
    pub(crate) boot: Vec<u8>,
    pub(crate) mappings: Vec<ApfsEphemeralMapping>,
    pub(crate) bindings: Vec<(u64, Vec<u8>)>,
    pub(crate) limits: ApfsReadLimits,
    pub(crate) retained_headers: Vec<(u64, Vec<u8>)>,
    pub(crate) discovery_work: u64,
    _lease: Reservation,
}
/// A validated, bounded container checkpoint. This type does not establish volume ownership.
#[derive(Clone)]
pub struct ApfsContainer {
    pub(crate) inner: Arc<ContainerInner>,
}
impl ApfsContainer {
    /// Select the highest structurally valid checkpoint, validating all its ephemeral objects.
    /// Caller guarantees immutable source bytes for this object and every deferred handle.
    pub fn open(raw: Arc<dyn ReadAt>, limits: ApfsReadLimits, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        let length = raw.len();
        if length < 1048576 || !length.is_multiple_of(4096) {
            return Err(unsupported("APFS 4KiB bare-container profile"));
        }
        let blocks = length / 4096;
        if blocks > limits.blocks {
            return Err(budget("APFS block ceiling"));
        }
        let charge = (limits.objects as u64)
            .checked_mul(16384)
            .and_then(|n| n.checked_add((limits.checkpoint_blocks as u64).checked_mul(8192)?))
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| budget("APFS discovery charge"))?;
        let lease = r.memory.reserve(charge)?;
        let source = Arc::new(Source {
            raw,
            length,
            resources: r.clone(),
        });
        let mut w = Work { limits, used: 0 };
        let boot = read_block(source.as_ref(), 0, blocks, &mut w, r)?;
        nx(&boot, blocks, None)?;
        let count = u32le(&boot, 104) as usize;
        if count > limits.checkpoint_blocks {
            return Err(budget("APFS checkpoint descriptor ceiling"));
        }
        let base = u64le(&boot, 112);
        let mut candidates = vector(count)?;
        for i in 0..count {
            let b = read_block(source.as_ref(), base + i as u64, blocks, &mut w, r)?;
            if &b[32..36] != b"NXSB" {
                continue;
            }
            match nx(&b, blocks, Some(&boot[72..88])) {
                Ok(()) => candidates.push((u64le(&b, 16), base + i as u64, b)),
                Err(e) if e.kind == ErrorKind::InvalidData => {}
                Err(e) => return Err(e),
            }
        }
        let mut retained_headers = vector(candidates.len())?;
        let mut xids = BTreeSet::new();
        for (xid, at, header) in &candidates {
            if !xids.insert(*xid) {
                return Err(bad("APFS ambiguous equal-XID checkpoints"));
            }
            retained_headers.push((*at, copy(header)?));
        }
        candidates.sort_by_key(|a| crate::platform::cmp::Reverse(a.0));
        let mut chosen = None;
        for (_, address, b) in candidates {
            if u64le(&b, 112) != base || u32le(&b, 104) != count as u32 {
                return Err(unsupported("APFS changed descriptor-area profile"));
            }
            match mappings(source.as_ref(), &b, address, blocks, &mut w, r) {
                Ok((maps, bound)) => {
                    chosen = Some((address, b, maps, bound));
                    break;
                }
                Err(e) if e.kind == ErrorKind::InvalidData => {}
                Err(e) => return Err(e),
            }
        }
        let (address, header, mappings, bindings) =
            chosen.ok_or_else(|| bad("APFS no complete valid checkpoint"))?;
        if u64le(&header, 48) & !1 != 0
            || u64le(&header, 56) != 0
            || u64le(&header, 64) != 2
            || header[1280..1312].iter().any(|v| *v != 0)
            || header[1344..1376].iter().any(|v| *v != 0)
        {
            return Err(unsupported("APFS fusion/unknown container feature profile"));
        }
        let mut volumes = vector(100)?;
        let mut seen = BTreeSet::new();
        for i in 0..100 {
            let oid = u64le(&header, 184 + i * 8);
            if oid != 0 {
                if i >= u32le(&header, 180) as usize || !seen.insert(oid) {
                    return Err(bad("APFS volume identifiers/slot bounds"));
                }
                volumes.push(oid);
            }
        }
        let checkpoint = ApfsCheckpoint {
            family: Family::Apfs,
            block_size: 4096,
            blocks,
            uuid: header[72..88].try_into().unwrap(),
            xid: u64le(&header, 16),
            superblock: address,
            object_map: u64le(&header, 160),
            space_manager: u64le(&header, 152),
            volumes,
        };
        let scope = (16u128 << 64)
            | u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                    .map_err(|_| budget("APFS source scope exhausted"))?,
            );
        Ok(Self {
            inner: Arc::new(ContainerInner {
                source,
                scope,
                checkpoint,
                header,
                boot,
                mappings,
                bindings,
                limits,
                retained_headers,
                discovery_work: w.used,
                _lease: lease,
            }),
        })
    }
    pub(crate) fn historical(
        &self,
        address: u64,
        header: &[u8],
        work: u64,
        r: &Resources,
    ) -> Result<Option<Self>> {
        let charge = (self.inner.limits.objects as u64)
            .checked_mul(16384)
            .and_then(|n| {
                n.checked_add((self.inner.limits.checkpoint_blocks as u64).checked_mul(8192)?)
            })
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| budget("APFS historical metadata charge"))?;
        let lease = r.memory.reserve(charge)?;
        let mut w = Work {
            limits: ApfsReadLimits {
                work: self.inner.limits.work.min(work),
                ..self.inner.limits
            },
            used: 0,
        };
        let (mappings, bindings) = match mappings(
            self.inner.source.as_ref(),
            header,
            address,
            self.checkpoint().blocks,
            &mut w,
            r,
        ) {
            Ok(value) => value,
            Err(e) if e.kind == ErrorKind::InvalidData => return Ok(None),
            Err(e) => return Err(e),
        };
        if u64le(header, 48) & !1 != 0
            || u64le(header, 56) != 0
            || u64le(header, 64) != 2
            || header[1280..1312]
                .iter()
                .chain(header[1344..1376].iter())
                .any(|v| *v != 0)
        {
            return Err(unsupported(
                "APFS unsupported historical container features",
            ));
        }
        let mut volumes = vector(100)?;
        let mut seen = BTreeSet::new();
        for i in 0..100 {
            let oid = u64le(header, 184 + i * 8);
            if oid != 0 {
                if i >= u32le(header, 180) as usize || !seen.insert(oid) {
                    return Err(bad("APFS historical volume slots"));
                }
                volumes.push(oid);
            }
        }
        Ok(Some(Self {
            inner: Arc::new(ContainerInner {
                source: self.inner.source.clone(),
                scope: self.inner.scope,
                checkpoint: ApfsCheckpoint {
                    family: Family::Apfs,
                    block_size: 4096,
                    blocks: self.checkpoint().blocks,
                    uuid: self.checkpoint().uuid,
                    xid: u64le(header, 16),
                    superblock: address,
                    object_map: u64le(header, 160),
                    space_manager: u64le(header, 152),
                    volumes,
                },
                header: copy(header)?,
                boot: copy(&self.inner.boot)?,
                mappings,
                bindings,
                limits: self.inner.limits,
                retained_headers: Vec::new(),
                discovery_work: w.used,
                _lease: lease,
            }),
        }))
    }
    /// Selected structural checkpoint. It makes no global free-space or clean-volume claim.
    pub fn checkpoint(&self) -> &ApfsCheckpoint {
        &self.inner.checkpoint
    }
    /// All verified ephemeral mappings in selected native checkpoint order.
    pub fn ephemeral_mappings(&self) -> &[ApfsEphemeralMapping] {
        &self.inner.mappings
    }
    /// Source domain and per-open scope, shared by future volume identities.
    pub fn source_scope(&self) -> u128 {
        self.inner.scope
    }
    /// Check source stability and the complete retained selected checkpoint bindings.
    pub fn revalidate(&self, r: &Resources) -> Result<()> {
        self.inner.source.stable()?;
        let mut w = Work {
            limits: self.inner.limits,
            used: 0,
        };
        for (at, expected) in crate::platform::iter::once((0, &self.inner.boot))
            .chain(crate::platform::iter::once((
                self.inner.checkpoint.superblock,
                &self.inner.header,
            )))
            .chain(self.inner.bindings.iter().map(|(a, b)| (*a, b)))
            .chain(self.inner.retained_headers.iter().map(|(a, b)| (*a, b)))
        {
            let b = read_block(
                self.inner.source.as_ref(),
                at,
                self.inner.checkpoint.blocks,
                &mut w,
                r,
            )?;
            if b != *expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS checkpoint binding changed",
                ));
            }
        }
        Ok(())
    }
}

use crate::fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent};
use crate::platform::collections::BTreeMap;
#[derive(Clone)]
pub(crate) struct Run {
    pub(crate) logical: u64,
    pub(crate) length: u64,
    pub(crate) physical: u64,
}
pub(crate) struct Entry {
    pub(crate) name: Vec<u8>,
    pub(crate) inode: u64,
    pub(crate) kind: u16,
    pub(crate) sibling: Option<u64>,
}
pub(crate) struct Stream {
    pub(crate) kind: StreamKind,
    pub(crate) length: u64,
    pub(crate) allocated: u64,
    pub(crate) id: u64,
    pub(crate) inline: Option<Vec<u8>>,
    pub(crate) runs: Arc<Vec<Run>>,
}
pub(crate) struct Inode {
    pub(crate) id: u64,
    pub(crate) raw: Vec<u8>,
    pub(crate) directory: bool,
    pub(crate) entries: Vec<Entry>,
    pub(crate) streams: Vec<Stream>,
    pub(crate) attrs: Vec<(Vec<u8>, Vec<u8>)>,
}
pub(crate) struct VolumeInner {
    pub(crate) container: ApfsContainer,
    pub(crate) oid: u64,
    pub(crate) header: Vec<u8>,
    pub(crate) nodes: BTreeMap<u64, Inode>,
    pub(crate) pages: Vec<(u64, Vec<u8>)>,
    pub(crate) extent_records: Vec<(u64, u64, u64, u32)>,
    pub(crate) container_page_count: usize,
    pub(crate) decode_work: u64,
    _lease: Reservation,
}
/// An indexed unencrypted case- and normalization-sensitive APFS volume.
/// Unsupported filesystem records fail inventory construction instead of disappearing.
#[derive(Clone)]
pub struct ApfsVolume {
    pub(crate) inner: Arc<VolumeInner>,
}
fn native_name(b: &[u8]) -> Result<Vec<u8>> {
    if b.len() < 2
        || b.last() != Some(&0)
        || b[..b.len() - 1].contains(&0)
        || b[..b.len() - 1].contains(&b'/')
        || crate::platform::str::from_utf8(&b[..b.len() - 1]).is_err()
    {
        return Err(bad("APFS native UTF8 terminated name"));
    }
    copy(&b[..b.len() - 1])
}
fn native_xattr_name(b: &[u8]) -> Result<Vec<u8>> {
    if b.len() < 2
        || b.len() > 822
        || b.last() != Some(&0)
        || b[..b.len() - 1].contains(&0)
        || crate::platform::str::from_utf8(&b[..b.len() - 1]).is_err()
    {
        return Err(bad("APFS native UTF8 xattr name"));
    }
    copy(&b[..b.len() - 1])
}
fn xfields(b: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    if b.len() < 4 {
        return Err(bad("APFS xfield blob bounds"));
    }
    let n = usize::from(u16::from_le_bytes(b[..2].try_into().unwrap()));
    let used = usize::from(u16::from_le_bytes(b[2..4].try_into().unwrap()));
    let mut at = 4 + n * 4;
    if at > b.len() || used != b.len() - at {
        return Err(bad("APFS xfield declared data size"));
    }
    let mut out = vector(n)?;
    let mut seen = BTreeSet::new();
    for i in 0..n {
        let p = 4 + i * 4;
        let kind = b[p];
        let flags = b[p + 1];
        let size = usize::from(u16::from_le_bytes(b[p + 2..p + 4].try_into().unwrap()));
        let end = at
            .checked_add(size)
            .ok_or_else(|| bad("APFS xfield size overflow"))?;
        let aligned = at
            .checked_add(size.next_multiple_of(8))
            .ok_or_else(|| bad("APFS xfield alignment overflow"))?;
        if flags & 0xc4 != 0
            || size == 0
            || end > b.len()
            || aligned > b.len()
            || !seen.insert(kind)
        {
            return Err(bad("APFS xfield flags/range/collision"));
        }
        out.push((kind, copy(&b[at..end])?));
        at = aligned;
    }
    if at != b.len() {
        return Err(bad("APFS xfield trailing allocation"));
    }
    Ok(out)
}
impl ApfsVolume {
    /// Resolve a listed volume through the selected container's native object map.
    pub fn open(container: ApfsContainer, oid: u64, r: &Resources) -> Result<Self> {
        let work = container.inner.limits.work;
        Self::open_bounded(container, oid, work, r)
    }
    pub(crate) fn open_bounded(
        container: ApfsContainer,
        oid: u64,
        work: u64,
        r: &Resources,
    ) -> Result<Self> {
        container.revalidate(r)?;
        if !container.checkpoint().volumes.contains(&oid) {
            return Err(bad("APFS unlisted volume"));
        }
        let limits = ApfsReadLimits {
            work: container.inner.limits.work.min(work),
            ..container.inner.limits
        };
        let charge = (limits.records as u64)
            .checked_mul(16384)
            .and_then(|n| n.checked_add((limits.objects as u64).checked_mul(65536)?))
            .ok_or_else(|| budget("APFS volume metadata charge"))?;
        let lease = r.memory.reserve(charge)?;
        let mut w = Work { limits, used: 0 };
        let (cmap, mut pages) =
            index::omap(&container, container.checkpoint().object_map, &mut w, r)?;
        if cmap.len() != container.checkpoint().volumes.len()
            || cmap
                .keys()
                .any(|id| !container.checkpoint().volumes.contains(id))
        {
            return Err(unsupported("APFS uninspectable container virtual objects"));
        }
        let container_page_count = pages.len();
        let at = *cmap
            .get(&oid)
            .ok_or_else(|| bad("APFS volume object-map lookup"))?;
        let header = read_block(
            container.inner.source.as_ref(),
            at,
            container.checkpoint().blocks,
            &mut w,
            r,
        )?;
        check_object(&header, Some(oid), container.checkpoint().xid, Some(13))?;
        if &header[32..36] != b"APSB" {
            return Err(bad("APFS volume magic"));
        }
        let slot = u32le(&header, 36) as usize;
        if slot >= 100 || u64le(&container.inner.header, 184 + slot * 8) != oid {
            return Err(bad("APFS volume native slot reference"));
        }
        if u64le(&header, 40) & !2 != 0
            || u64le(&header, 48) != 0
            || u64le(&header, 56) != 0
            || u64le(&header, 264) != 1
            || u64le(&header, 208) != 0
            || u64le(&header, 216) != 0
            || u64le(&header, 160) != 0
            || u64le(&header, 168) != 0
            || u16::from_le_bytes(header[964..966].try_into().unwrap()) != 0
            || header[976..1108].iter().any(|v| *v != 0)
        {
            return Err(unsupported(
                "APFS encrypted/snapshot/sealed/special/normalization volume profile",
            ));
        }
        if u32le(&header, 116) != 2
            || u32le(&header, 120) != 0x40000002
            || u32le(&header, 124) != 0x40000002
        {
            return Err(unsupported("APFS volume tree storage types"));
        }
        let (vmap, map_pages) = index::omap(&container, u64le(&header, 128), &mut w, r)?;
        pages.extend(map_pages);
        let fs = index::tree(
            &container,
            u64le(&header, 136),
            0,
            index::TreeKind::Filesystem,
            Some(&vmap),
            &mut w,
            r,
        )?;
        let fs_ids: BTreeSet<_> = fs.pages.iter().map(|(_, b)| u64le(b, 8)).collect();
        if vmap.keys().any(|id| !fs_ids.contains(id)) || vmap.len() != fs_ids.len() {
            return Err(unsupported("APFS uninspectable volume virtual objects"));
        }
        pages.extend(fs.pages);
        let ext = index::tree(
            &container,
            u64le(&header, 144),
            0x40000000,
            index::TreeKind::Extent,
            None,
            &mut w,
            r,
        )?;
        pages.extend(ext.pages);
        let snap = index::tree(
            &container,
            u64le(&header, 152),
            0x40000000,
            index::TreeKind::Snapshot,
            None,
            &mut w,
            r,
        )?;
        pages.extend(snap.pages);
        if !snap.records.is_empty() {
            return Err(unsupported("APFS populated snapshot metadata"));
        }
        pages.push((at, copy(&header)?));
        let mut nodes = BTreeMap::new();
        let mut records = Vec::new();
        for item in fs.records {
            let key = u64le(&item.key, 0);
            let id = key & 0x0fffffffffffffff;
            let kind = key >> 60;
            if kind != 3 {
                records.push((id, kind, item));
                continue;
            }
            if item.key.len() != 8
                || item.value.len() < 92
                || id < 2
                || nodes.len() == limits.objects
            {
                return Err(bad("APFS inode record bounds/identifier/count"));
            }
            let raw = item.value;
            let mode = u16::from_le_bytes(raw[80..82].try_into().unwrap());
            let directory = mode & 0xf000 == 0x4000;
            if !matches!(mode & 0xf000, 0x4000 | 0x8000)
                || u64le(&raw, 48) & !0xc610 != 0
                || u32le(&raw, 68) & 0x20 != 0
                || u64le(&raw, 84) != 0
            {
                return Err(unsupported(
                    "APFS special/compressed/cloned/security inode flags",
                ));
            }
            if directory && u64le(&raw, 48) & 0x410 != 0 {
                return Err(unsupported("APFS cloned directory profile"));
            }
            let mut streams = vector(1)?;
            let mut attrs = vector(8)?;
            let mut named = false;
            for (kind, data) in xfields(&raw[92..])? {
                match kind {
                    4 => {
                        native_name(&data)?;
                        named = true;
                        attrs.push((b"apfs.inode-name".to_vec(), data));
                    }
                    8 => {
                        if data.len() != 40 || directory || u64le(&data, 16) != 0 {
                            return Err(unsupported(
                                "APFS data stream encryption/directory profile",
                            ));
                        }
                        streams.push(Stream {
                            kind: StreamKind::Data,
                            length: u64le(&data, 0),
                            allocated: u64le(&data, 8),
                            id: u64le(&raw, 8),
                            inline: None,
                            runs: Arc::new(Vec::new()),
                        });
                    }
                    3 | 7 | 13 => {
                        attrs.push((format!("apfs.inode-xfield.{kind}").into_bytes(), data))
                    }
                    _ => return Err(unsupported("APFS uninspectable inode xfield")),
                }
            }
            if !named {
                return Err(unsupported("APFS inode without native name xfield"));
            }
            if !directory && streams.is_empty() {
                streams.push(Stream {
                    kind: StreamKind::Data,
                    length: 0,
                    allocated: 0,
                    id: u64le(&raw, 8),
                    inline: None,
                    runs: Arc::new(Vec::new()),
                });
            }
            if nodes
                .insert(
                    id,
                    Inode {
                        id,
                        raw,
                        directory,
                        entries: Vec::new(),
                        streams,
                        attrs,
                    },
                )
                .is_some()
            {
                return Err(bad("APFS duplicate inode"));
            }
        }
        let mut pending_runs = BTreeMap::<u64, Vec<Run>>::new();
        let mut stream_refs = BTreeMap::<u64, u32>::new();
        let mut siblings = BTreeMap::<u64, (u64, u64, Vec<u8>)>::new();
        let mut sibling_maps = BTreeMap::<u64, u64>::new();
        for (id, kind, item) in records {
            w.tick(1, r)?;
            match kind {
                9 => {
                    if item.key.len() < 11
                        || item.value.len() < 18
                        || usize::from(u16::from_le_bytes(item.key[8..10].try_into().unwrap()))
                            != item.key.len() - 10
                    {
                        return Err(unsupported("APFS directory extended/hash record profile"));
                    }
                    let name = native_name(&item.key[10..])?;
                    let mut sibling = None;
                    for (kind, value) in xfields(&item.value[18..])? {
                        if kind != 1 || value.len() != 8 || sibling.is_some() {
                            return Err(unsupported("APFS unknown directory xfield"));
                        }
                        sibling = Some(u64le(&value, 0));
                    }
                    let target = u64le(&item.value, 0);
                    let flags = u16::from_le_bytes(item.value[16..18].try_into().unwrap());
                    if !matches!(flags, 4 | 8) {
                        return Err(unsupported("APFS directory special flags"));
                    }
                    if id == 1 {
                        if sibling.is_some() {
                            return Err(unsupported("APFS system directory sibling profile"));
                        }
                        if !matches!(target, 2 | 3) || !nodes.contains_key(&target) {
                            return Err(unsupported("APFS synthetic-parent system namespace"));
                        }
                        let node = nodes.get_mut(&target).unwrap();
                        node.attrs.push((
                            b"apfs.synthetic-parent-directory-entry".to_vec(),
                            [item.key, item.value].concat(),
                        ));
                    } else {
                        let node = nodes
                            .get_mut(&id)
                            .ok_or_else(|| bad("APFS directory owner absent"))?;
                        if !node.directory {
                            return Err(bad("APFS directory owner type"));
                        }
                        node.entries
                            .try_reserve(1)
                            .map_err(|_| budget("APFS directory entries"))?;
                        node.entries.push(Entry {
                            name,
                            inode: target,
                            kind: flags,
                            sibling,
                        });
                        node.attrs.push((
                            b"apfs.directory-record".to_vec(),
                            [item.key, item.value].concat(),
                        ));
                    }
                }
                5 => {
                    if item.key.len() != 16
                        || item.value.len() < 11
                        || usize::from(u16::from_le_bytes(item.value[8..10].try_into().unwrap()))
                            != item.value.len() - 10
                    {
                        return Err(bad("APFS sibling link bounds"));
                    }
                    let sibling = u64le(&item.key, 8);
                    let parent = u64le(&item.value, 0);
                    let name = native_name(&item.value[10..])?;
                    if sibling < 16
                        || sibling >= u64le(&header, 176)
                        || nodes.contains_key(&sibling)
                        || siblings.insert(sibling, (id, parent, name)).is_some()
                    {
                        return Err(bad("APFS sibling identity collision/bounds"));
                    }
                    nodes
                        .get_mut(&id)
                        .ok_or_else(|| bad("APFS sibling inode absent"))?
                        .attrs
                        .push((
                            b"apfs.sibling-link".to_vec(),
                            [item.key, item.value].concat(),
                        ));
                }
                12 => {
                    if u64le(&header, 40) & 2 == 0 {
                        return Err(unsupported("APFS legacy hardlink map profile"));
                    }
                    if item.key.len() != 8
                        || item.value.len() != 8
                        || sibling_maps.insert(id, u64le(&item.value, 0)).is_some()
                    {
                        return Err(bad("APFS sibling map record"));
                    }
                    nodes
                        .get_mut(&u64le(&item.value, 0))
                        .ok_or_else(|| bad("APFS sibling map target absent"))?
                        .attrs
                        .push((
                            b"apfs.sibling-map".to_vec(),
                            [item.key, item.value].concat(),
                        ));
                }
                8 => {
                    if item.key.len() != 16 || item.value.len() != 24 {
                        return Err(bad("APFS file extent record size"));
                    }
                    let length = u64le(&item.value, 0) & 0x00ffffffffffffff;
                    if u64le(&item.value, 0) >> 56 != 0 || u64le(&item.value, 16) != 0 {
                        return Err(unsupported("APFS encrypted/preallocated extent profile"));
                    }
                    let logical = u64le(&item.key, 8);
                    let physical = u64le(&item.value, 8);
                    if length == 0
                        || !length.is_multiple_of(4096)
                        || !logical.is_multiple_of(4096)
                        || logical.checked_add(length).is_none()
                    {
                        return Err(bad("APFS file extent logical range"));
                    }
                    if physical != 0 {
                        range(physical, length / 4096, container.checkpoint().blocks)?;
                    }
                    let runs = pending_runs.entry(id).or_default();
                    runs.try_reserve(1)
                        .map_err(|_| budget("APFS file extents"))?;
                    runs.push(Run {
                        logical,
                        length,
                        physical,
                    });
                }
                6 => {
                    if item.key.len() != 8
                        || item.value.len() != 4
                        || stream_refs.insert(id, u32le(&item.value, 0)).is_some()
                    {
                        return Err(bad("APFS dstream reference record"));
                    }
                }
                4 => {
                    if item.key.len() < 11
                        || item.value.len() < 4
                        || usize::from(u16::from_le_bytes(item.key[8..10].try_into().unwrap()))
                            != item.key.len() - 10
                    {
                        return Err(bad("APFS xattr record size"));
                    }
                    let name = native_xattr_name(&item.key[10..])?;
                    let flags = u16::from_le_bytes(item.value[..2].try_into().unwrap());
                    let size =
                        usize::from(u16::from_le_bytes(item.value[2..4].try_into().unwrap()));
                    if flags & 2 != 0 && size > 3804 {
                        return Err(bad("APFS native embedded xattr size limit"));
                    }
                    if flags & 2 != 0 && size != item.value.len() - 4
                        || !matches!(flags, 1 | 2 | 10)
                    {
                        return Err(unsupported("APFS external/security/system xattr profile"));
                    }
                    if name == b"com.apple.decmpfs"
                        || name == b"com.apple.system.Security"
                        || name == b"com.apple.fs.symlink"
                    {
                        return Err(unsupported("APFS compressed/security/symlink xattr"));
                    }
                    let node = nodes
                        .get_mut(&id)
                        .ok_or_else(|| bad("APFS xattr owner absent"))?;
                    if name == b"com.apple.ResourceFork" && flags & 8 != 0 {
                        return Err(unsupported("APFS reserved resource flags mutation profile"));
                    }
                    if flags == 1 {
                        if name == b"com.apple.ResourceFork" && node.directory {
                            return Err(unsupported("APFS directory resource fork profile"));
                        }
                        if item.value.len() != 52 {
                            return Err(bad("APFS external resource descriptor size"));
                        }
                        if u64le(&item.value, 28) != 0 {
                            return Err(unsupported("APFS encrypted resource stream"));
                        }
                        let kind = if name == b"com.apple.ResourceFork" {
                            node.attrs
                                .push((b"apfs.resource-dstream".to_vec(), copy(&item.value)?));
                            StreamKind::ResourceFork
                        } else {
                            let mut raw = vector(item.key.len() + item.value.len())?;
                            raw.extend_from_slice(&item.key);
                            raw.extend_from_slice(&item.value);
                            node.attrs.push((b"apfs.xattr-dstream".to_vec(), raw));
                            StreamKind::Named(NativeName::Bytes(copy(&name)?))
                        };
                        node.streams.push(Stream {
                            kind,
                            length: u64le(&item.value, 12),
                            allocated: u64le(&item.value, 20),
                            id: u64le(&item.value, 4),
                            inline: None,
                            runs: Arc::new(Vec::new()),
                        });
                    } else if name == b"com.apple.ResourceFork" {
                        node.streams.push(Stream {
                            kind: StreamKind::ResourceFork,
                            length: size as u64,
                            allocated: 0,
                            id: 0,
                            inline: Some(copy(&item.value[4..])?),
                            runs: Arc::new(Vec::new()),
                        });
                    } else {
                        if flags & 8 != 0 {
                            let mut raw = vector(item.key.len() + item.value.len())?;
                            raw.extend_from_slice(&item.key);
                            raw.extend_from_slice(&item.value);
                            node.attrs.push((b"apfs.xattr-record".to_vec(), raw));
                        }
                        node.attrs.push((name, copy(&item.value[4..])?));
                    }
                }
                _ => return Err(unsupported("APFS unsupported filesystem record type")),
            }
        }
        let shared_runs: BTreeMap<_, _> = pending_runs
            .into_iter()
            .map(|(id, runs)| (id, Arc::new(runs)))
            .collect();
        let mut stream_users = BTreeMap::<u64, (u32, u64, u64, bool, StreamKind)>::new();
        for node in nodes.values_mut() {
            let has_resource = node
                .streams
                .iter()
                .any(|stream| stream.kind == StreamKind::ResourceFork);
            let flags = u64le(&node.raw, 48);
            if (flags & 0x4000 != 0) != has_resource || flags & 0xc000 == 0xc000 {
                return Err(bad("APFS native resource-fork inode flags"));
            }
            for stream in &mut node.streams {
                if stream.inline.is_some() {
                    continue;
                }
                if stream.id < 16 || stream.id >= u64le(&header, 176) {
                    return Err(bad("APFS private stream identity bounds"));
                }
                if stream.kind == StreamKind::Data
                    && stream.id != node.id
                    && u64le(&node.raw, 48) & 0x410 == 0
                {
                    return Err(bad("APFS private stream without clone provenance"));
                }
                let usage = stream_users.entry(stream.id).or_insert((
                    0,
                    stream.length,
                    stream.allocated,
                    true,
                    stream.kind.clone(),
                ));
                if usage.1 != stream.length || usage.2 != stream.allocated || usage.4 != stream.kind
                {
                    return Err(bad("APFS cloned stream size disagreement"));
                }
                usage.3 &= u64le(&node.raw, 48) & 0x410 != 0;
                usage.0 = usage
                    .0
                    .checked_add(1)
                    .ok_or_else(|| bad("APFS stream count overflow"))?;
                stream.runs = shared_runs
                    .get(&stream.id)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(Vec::new()));
                let mut end = 0;
                for run in stream.runs.iter() {
                    if stream.kind != StreamKind::Data && run.physical == 0 {
                        return Err(unsupported("APFS sparse external resource profile"));
                    }
                    if run.logical != end {
                        return Err(bad("APFS non-consecutive native stream extents"));
                    }
                    end = run.logical + run.length;
                }
                if end
                    != stream
                        .length
                        .checked_add(4095)
                        .ok_or_else(|| bad("APFS stream rounded size overflow"))?
                        / 4096
                        * 4096
                {
                    return Err(unsupported(
                        "APFS preallocation/incomplete stream extent profile",
                    ));
                }
            }
        }
        for (&id, (count, _, _, flags, kind)) in &stream_users {
            w.tick(1, r)?;
            let refs = stream_refs.remove(&id);
            if *kind != StreamKind::Data {
                if *count != 1 || refs.is_some() {
                    return Err(unsupported("APFS shared external xattr stream identity"));
                }
                continue;
            }
            if refs.is_some_and(|n| n != *count)
                || !shared_runs.get(&id).is_none_or(|runs| runs.is_empty()) && refs.is_none()
            {
                return Err(bad("APFS shared dstream exact reference count"));
            }
            if *count > 1 && !flags {
                return Err(bad("APFS shared dstream lacks clone flags"));
            }
        }
        if shared_runs.keys().any(|id| !stream_users.contains_key(id)) || !stream_refs.is_empty() {
            return Err(bad("APFS unowned data stream records"));
        }
        if siblings.keys().any(|id| stream_users.contains_key(id)) {
            return Err(bad("APFS sibling/data-stream identity collision"));
        }
        validate_siblings(&mut nodes, &siblings, &sibling_maps, &mut w, r)?;
        if !nodes.get(&2).is_some_and(|n| n.directory)
            || !nodes
                .get(&3)
                .is_some_and(|n| n.directory && n.entries.is_empty() && n.streams.is_empty())
        {
            return Err(unsupported(
                "APFS populated/uninspectable private directory",
            ));
        }
        let mut extent_records = vector(ext.records.len())?;
        for item in ext.records {
            if item.key.len() != 8 || item.value.len() != 20 || u64le(&item.key, 0) >> 60 != 2 {
                return Err(bad("APFS physical extent reference record"));
            }
            let start = u64le(&item.key, 0) & 0x0fffffffffffffff;
            let count = u64le(&item.value, 0) & 0x0fffffffffffffff;
            let kind = u64le(&item.value, 0) >> 60;
            if kind != 1 {
                return Err(unsupported(
                    "APFS shared/updated/dead physical extent references",
                ));
            }
            let refs = u32le(&item.value, 16);
            let owner = u64le(&item.value, 8);
            if refs == 0
                || refs > i32::MAX as u32
                || (owner < 16 && owner != 2)
                || owner >= u64le(&header, 176)
            {
                return Err(bad("APFS physical extent owner/reference bounds"));
            }
            range(start, count, container.checkpoint().blocks)?;
            extent_records.push((start, count, u64le(&item.value, 8), u32le(&item.value, 16)));
        }
        Ok(Self {
            inner: Arc::new(VolumeInner {
                container,
                oid,
                header,
                nodes,
                pages,
                extent_records,
                container_page_count,
                decode_work: w.used,
                _lease: lease,
            }),
        })
    }
    /// Selected underlying container checkpoint.
    pub fn container(&self) -> &ApfsContainer {
        &self.inner.container
    }
    /// Native volume virtual identifier.
    pub fn volume_identifier(&self) -> u64 {
        self.inner.oid
    }
    pub(crate) fn identity(&self, id: u64) -> ObjectId {
        let mut native = self.inner.oid.to_be_bytes().to_vec();
        native.extend_from_slice(&id.to_be_bytes());
        ObjectId {
            source: self.container().source_scope(),
            generation: self.container().checkpoint().xid,
            native,
        }
    }
    /// Actual filesystem root inode 2.
    pub fn root_identity(&self) -> ObjectId {
        self.identity(2)
    }
    pub(crate) fn node(&self, id: &ObjectId) -> Result<&Inode> {
        if id.source != self.container().source_scope()
            || id.generation != self.container().checkpoint().xid
            || id.native.len() != 16
            || id.native[..8] != self.inner.oid.to_be_bytes()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS foreign object identity",
            ));
        }
        self.inner
            .nodes
            .get(&u64::from_be_bytes(id.native[8..].try_into().unwrap()))
            .ok_or_else(|| bad("APFS object absent"))
    }
    /// Recheck retained checkpoint and every indexed metadata object under the caller's stability contract.
    pub fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        self.node(id)?;
        self.container().revalidate(r)?;
        let mut w = Work {
            limits: self.container().inner.limits,
            used: 0,
        };
        for (at, expected) in &self.inner.pages {
            let b = read_block(
                self.container().inner.source.as_ref(),
                *at,
                self.container().checkpoint().blocks,
                &mut w,
                r,
            )?;
            if b != *expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS indexed object changed",
                ));
            }
        }
        Ok(())
    }
    /// Enumerate exact native UTF8 name bytes, without host-path reconstruction.
    pub fn directory(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<DirectoryEntry>>> {
        self.revalidate(id, r)?;
        let n = self.directory_len(id)?;
        let charge = (n as u64)
            .checked_mul(2048)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| budget("APFS directory charge"))?;
        Budgeted::try_new(&r.memory, charge, || self.directory_entries(id, 0..n, r))
    }
    pub(crate) fn directory_len(&self, id: &ObjectId) -> Result<usize> {
        let node = self.node(id)?;
        if !node.directory {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "APFS non-directory",
            ));
        }
        Ok(node.entries.len())
    }
    pub(crate) fn directory_entries(
        &self,
        id: &ObjectId,
        range: crate::platform::ops::Range<usize>,
        r: &Resources,
    ) -> Result<Vec<DirectoryEntry>> {
        let node = self.node(id)?;
        let mut out = vector(range.len())?;
        for entry in &node.entries[range] {
            r.cancellation.check()?;
            let child = self
                .inner
                .nodes
                .get(&entry.inode)
                .ok_or_else(|| bad("APFS directory missing target"))?;
            out.push(DirectoryEntry {
                name: NativeName::Bytes(copy(&entry.name)?),
                object: self.identity(entry.inode),
                kind: if child.directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
            });
        }
        Ok(out)
    }
    /// Exact native-name lookup in the supported case/normalization-sensitive profile.
    pub fn lookup(&self, path: &[NativeName], r: &Resources) -> Result<ObjectId> {
        if path.len() > 256 {
            return Err(budget("APFS lookup depth"));
        }
        let mut id = self.root_identity();
        for name in path {
            self.revalidate(&id, r)?;
            self.directory_len(&id)?;
            let NativeName::Bytes(name) = name else {
                return Err(bad("APFS native name missing"));
            };
            let mut found = None;
            for entry in &self.node(&id)?.entries {
                r.cancellation.check()?;
                if &entry.name == name {
                    found = Some(entry.inode);
                    break;
                }
            }
            id = self.identity(found.ok_or_else(|| bad("APFS native name missing"))?);
        }
        self.revalidate(&id, r)?;
        Ok(id)
    }
    /// Establish a complete ownership proof for repeated reads of caller-guaranteed
    /// immutable bytes. Use the returned handle's explicit revalidation boundary
    /// when beginning or ending an operation that depends on that guarantee.
    pub fn audited_reader(
        &self,
        limits: crate::fs_apfs_audit::ApfsAuditLimits,
        r: &Resources,
    ) -> Result<ApfsAuditedReader> {
        let proof = crate::fs_apfs_audit::audit_apfs(self, limits, r)?;
        if !proof.is_complete() || !proof.is_clean() {
            return Err(bad("APFS file requires complete clean ownership audit"));
        }
        Ok(ApfsAuditedReader {
            volume: self.clone(),
            proof: Arc::new(proof),
            limits,
        })
    }
    /// Open indexed ordinary data without constructing its complete payload.
    pub fn open_file(&self, id: &ObjectId, r: &Resources) -> Result<ApfsFile> {
        self.open_stream(id, &StreamKind::Data, r)
    }
    /// Open indexed ordinary data or an explicitly enumerated embedded resource fork.
    pub fn open_stream(&self, id: &ObjectId, kind: &StreamKind, r: &Resources) -> Result<ApfsFile> {
        self.node(id)?;
        let limits = self.container().inner.limits;
        let audited = self.audited_reader(
            crate::fs_apfs_audit::ApfsAuditLimits {
                blocks: limits.blocks,
                objects: limits.objects.max(limits.records),
                depth: 256,
                work: limits.work,
                findings: limits.records.min(1024),
            },
            r,
        )?;
        self.open_stream_with_proof(id, kind, r, None, &audited.proof)
    }
    fn open_stream_with_proof(
        &self,
        id: &ObjectId,
        kind: &StreamKind,
        r: &Resources,
        retained: Option<Arc<crate::fs_apfs_audit::ApfsAuditReport>>,
        proof: &crate::fs_apfs_audit::ApfsAuditReport,
    ) -> Result<ApfsFile> {
        r.cancellation.check()?;
        self.container().inner.source.stable()?;
        if !proof.is_clean() || !proof.is_complete() {
            return Err(bad("APFS file requires complete clean ownership audit"));
        }
        let node = self.node(id)?;
        let stream = node
            .streams
            .iter()
            .position(|s| &s.kind == kind)
            .ok_or_else(|| unsupported("APFS unavailable stream"))?;
        let s = &node.streams[stream];
        let charge = (s.runs.len() as u64)
            .checked_mul(256)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| budget("APFS file map charge"))?;
        let lease = r.memory.reserve(charge)?;
        let mapped = if s.inline.is_none() {
            let maximum = s
                .runs
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| budget("APFS logical spans"))?;
            let mut spans = vector(maximum)?;
            let mut position = 0;
            for run in s.runs.iter() {
                if run.logical >= s.length {
                    continue;
                }
                if run.logical > position {
                    spans.push(FileExtent {
                        offset: position,
                        length: run.logical - position,
                        kind: MapKind::Hole,
                    });
                }
                let length = run.length.min(s.length - run.logical);
                spans.push(FileExtent {
                    offset: run.logical,
                    length,
                    kind: if run.physical == 0 {
                        MapKind::Hole
                    } else {
                        MapKind::Data(run.physical * 4096)
                    },
                });
                position = run.logical + length;
            }
            if position < s.length {
                spans.push(FileExtent {
                    offset: position,
                    length: s.length - position,
                    kind: MapKind::Hole,
                });
            }
            let source: Arc<dyn ReadAt> = self.container().inner.source.clone();
            Some(
                ExtentFile::new(source, s.length, spans, maximum)
                    .map_err(|e| Error::io("APFS mapped file", e))?,
            )
        } else {
            None
        };
        Ok(ApfsFile {
            volume: self.clone(),
            identity: id.clone(),
            stream,
            mapped,
            audited: retained,
            _lease: lease,
        })
    }
    /// Native POSIX fields, nanosecond timestamps, and opaque native metadata.
    pub fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(id, r)?;
        let node = self.node(id)?;
        let charge = (node.attrs.len() as u64 + 4)
            .checked_mul(8192)
            .ok_or_else(|| budget("APFS metadata charge"))?;
        Budgeted::try_new(&r.memory, charge, || {
            let b = &node.raw;
            let time = |p| {
                MetadataField::Known(NativeTimestamp {
                    ticks: i128::from(u64le(b, p)),
                    ticks_per_second: 1_000_000_000,
                    epoch: "1970-01-01 UTC; native unsigned APFS nanoseconds".into(),
                })
            };
            let mut attrs = vector(node.attrs.len() + 4)?;
            for (name, value) in &node.attrs {
                attrs.push((
                    NativeName::Bytes(copy(name)?),
                    MetadataField::Opaque {
                        bytes: copy(value)?,
                        interpretation:
                            "Native APFS attribute/xfield; no transplantation guarantee".into(),
                    },
                ));
            }
            attrs.push((NativeName::Bytes(b"apfs.inode".to_vec()),MetadataField::Opaque{bytes:copy(b)?,interpretation:"Native inode, parent/private IDs, ctime, flags, link/child counts and extended fields".into()}));
            if node.id == 2 {
                let private = &self.inner.nodes[&3];
                let mut raw = vector(
                    private.raw.len()
                        + private
                            .attrs
                            .iter()
                            .map(|(n, v)| n.len() + v.len() + 16)
                            .sum::<usize>(),
                )?;
                raw.extend_from_slice(&private.raw);
                for (name, value) in &private.attrs {
                    raw.extend_from_slice(&(name.len() as u64).to_le_bytes());
                    raw.extend_from_slice(name);
                    raw.extend_from_slice(&(value.len() as u64).to_le_bytes());
                    raw.extend_from_slice(value);
                }
                attrs.push((NativeName::Bytes(b"apfs.empty-private-directory".to_vec()),MetadataField::Opaque{bytes:raw,interpretation:"Native empty private inode 3 outside root namespace, followed by exact named metadata with little-endian u64 name/value lengths; requires preservation policy".into()}));
                attrs.push((NativeName::Bytes(b"apfs.volume-superblock".to_vec()),MetadataField::Opaque{bytes:copy(&self.inner.header)?,interpretation:"Native volume superblock including UUID, name, role, feature state, modification history and object locations; no transplantation guarantee".into()}));
            }
            Ok(Metadata {
                created: time(16),
                modified: time(24),
                accessed: time(40),
                owner: MetadataField::Known(copy(&b[72..80])?),
                mode: MetadataField::Known(u32::from(u16::from_le_bytes(
                    b[80..82].try_into().unwrap(),
                ))),
                security: MetadataField::Absent,
                attributes: attrs,
                native_flags: MetadataField::Known(copy(&b[48..72])?),
                symlink_target: MetadataField::Absent,
                reparse_data: MetadataField::Absent,
            })
        })
    }
}
/// Source-bound complete ownership proof for repeated immutable payload reads.
/// Metadata is fully rechecked at creation and explicit revalidation boundaries;
/// payload reads check cancellation and source geometry before and after access.
/// The caller must uphold the container's immutable-byte guarantee throughout.
pub struct ApfsAuditedReader {
    volume: ApfsVolume,
    proof: Arc<crate::fs_apfs_audit::ApfsAuditReport>,
    limits: crate::fs_apfs_audit::ApfsAuditLimits,
}
impl ApfsAuditedReader {
    /// Source volume whose ownership proof this handle retains.
    pub fn volume(&self) -> &ApfsVolume {
        &self.volume
    }
    /// Fully recheck indexed metadata and repeat the complete ownership audit.
    pub fn revalidate(&self, r: &Resources) -> Result<()> {
        let proof = crate::fs_apfs_audit::audit_apfs(&self.volume, self.limits, r)?;
        if !proof.is_complete() || !proof.is_clean() {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS audited ownership changed",
            ));
        }
        Ok(())
    }
    /// Open a stream using the retained source-bound complete ownership proof.
    pub fn open_stream(&self, id: &ObjectId, kind: &StreamKind, r: &Resources) -> Result<ApfsFile> {
        self.volume
            .open_stream_with_proof(id, kind, r, Some(self.proof.clone()), &self.proof)
    }
}
/// Deferred immutable data or embedded resource-fork reader retaining indexing/source leases.
pub struct ApfsFile {
    volume: ApfsVolume,
    identity: ObjectId,
    stream: usize,
    mapped: Option<ExtentFile>,
    audited: Option<Arc<crate::fs_apfs_audit::ApfsAuditReport>>,
    _lease: Reservation,
}
impl ApfsFile {
    fn check_binding(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.audited.is_some() {
            self.volume.container().inner.source.stable()
        } else {
            self.volume.revalidate(&self.identity, r)
        }
    }
}
impl FileRead for ApfsFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.volume.node(&self.identity).unwrap().streams[self.stream].length
    }
    fn read_at(&self, at: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        self.check_binding(r)?;
        if at >= self.len() || b.is_empty() {
            return Ok(0);
        }
        let n = if let Some(file) = &self.mapped {
            file.read_at(at, b)
                .map_err(|e| Error::io("APFS deferred data", e))?
        } else {
            let stream = &self.volume.node(&self.identity)?.streams[self.stream];
            let data = stream.inline.as_ref().unwrap();
            let n = b.len().min(
                data.len()
                    .saturating_sub(usize::try_from(at).unwrap_or(usize::MAX)),
            );
            if n != 0 {
                b[..n].copy_from_slice(&data[at as usize..at as usize + n]);
            }
            n
        };
        self.check_binding(r)?;
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        f: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.check_binding(r)?;
        if let Some(file) = &self.mapped {
            for e in file.extents() {
                r.cancellation.check()?;
                f(LogicalExtent {
                    offset: e.offset,
                    length: e.length,
                    kind: match e.kind {
                        MapKind::Data(_) => ExtentKind::Data,
                        MapKind::Hole => ExtentKind::Hole,
                        MapKind::Unwritten => ExtentKind::Unwritten,
                    },
                })?;
            }
        } else if self.len() != 0 {
            f(LogicalExtent {
                offset: 0,
                length: self.len(),
                kind: ExtentKind::Data,
            })?;
        }
        self.check_binding(r)
    }
}

fn validate_siblings(
    nodes: &mut BTreeMap<u64, Inode>,
    siblings: &BTreeMap<u64, (u64, u64, Vec<u8>)>,
    maps: &BTreeMap<u64, u64>,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    if siblings.len() != maps.len() {
        return Err(bad("APFS sibling/map count disagreement"));
    }
    let mut primary = BTreeMap::new();
    for (id, (inode, parent, name)) in siblings {
        w.tick(1, r)?;
        primary.entry(*inode).or_insert((*id, *parent, name));
    }
    let mut used = BTreeSet::new();
    let mut counts = BTreeMap::<u64, u32>::new();
    for node in nodes.values() {
        w.tick(1, r)?;
        for entry in &node.entries {
            w.tick(1, r)?;
            let count = counts.entry(entry.inode).or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| bad("APFS hardlink count overflow"))?;
            if let Some(id) = entry.sibling {
                let target = nodes
                    .get(&entry.inode)
                    .ok_or_else(|| bad("APFS sibling target absent"))?;
                let link = siblings
                    .get(&id)
                    .ok_or_else(|| bad("APFS directory sibling absent"))?;
                if target.directory
                    || !used.insert(id)
                    || link.0 != entry.inode
                    || link.1 != node.id
                    || link.2 != entry.name
                    || maps.get(&id) != Some(&entry.inode)
                {
                    return Err(bad("APFS dangling/mismatched sibling occurrence"));
                }
            } else if primary.contains_key(&entry.inode)
                || nodes
                    .get(&entry.inode)
                    .is_some_and(|n| !n.directory && u32le(&n.raw, 56) > 1)
            {
                return Err(bad("APFS hardlink lacks sibling occurrence"));
            }
        }
    }
    if used.len() != siblings.len() {
        return Err(bad("APFS orphan sibling link"));
    }
    for node in nodes.values() {
        w.tick(1, r)?;
        if node.directory {
            if primary.contains_key(&node.id) {
                return Err(unsupported("APFS directory hardlinks"));
            }
            continue;
        }
        if let Some((_, parent, name)) = primary.get(&node.id) {
            if counts.get(&node.id).copied().unwrap_or(0) != u32le(&node.raw, 56) {
                return Err(bad("APFS native hardlink count"));
            }
            let native = node
                .attrs
                .iter()
                .find(|(key, _)| key == b"apfs.inode-name")
                .ok_or_else(|| bad("APFS hardlink primary name"))?;
            if u64le(&node.raw, 0) != *parent || native.1[..native.1.len() - 1] != **name {
                return Err(bad("APFS primary sibling name/parent"));
            }
        }
    }
    Ok(())
}
