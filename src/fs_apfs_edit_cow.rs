//! Fresh native roots and checkpoint publication. Old roots and allocations remain retained.
use super::*;
use crate::fs_apfs::{
    Work,
    index::{self, TreeKind},
    u32le, u64le,
};
use std::collections::{BTreeMap, BTreeSet};
#[path = "fs_apfs_edit_disk.rs"]
mod disk;
use disk::{d, q, seal, w};
type Records = Vec<(Vec<u8>, Vec<u8>)>;
#[path = "fs_apfs_edit_namespace.rs"]
mod namespace;
pub use namespace::{ApfsCreateMetadata, ApfsMutationPlan};
/// Retained checked native geometry for recovery when the block-zero hint is torn.
/// The caller retains this anchor before mutation; it contains no rollback bytes or journal authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApfsRecoveryAnchor {
    length: u64,
    uuid: [u8; 16],
    descriptor_base: u64,
    descriptor_blocks: u32,
    data_base: u64,
    data_blocks: u32,
    volume_oid: u64,
}
impl ApfsRecoveryAnchor {
    /// Exact portable diagnostic anchor, including a corruption-detection SHA-256.
    pub fn encode(&self) -> [u8; 96] {
        use sha2::{Digest, Sha256};
        let mut bytes = [0; 96];
        bytes[..8].copy_from_slice(b"APCOWA01");
        q(&mut bytes, 8, self.length);
        bytes[16..32].copy_from_slice(&self.uuid);
        q(&mut bytes, 32, self.descriptor_base);
        d(&mut bytes, 40, self.descriptor_blocks);
        q(&mut bytes, 44, self.data_base);
        d(&mut bytes, 52, self.data_blocks);
        q(&mut bytes, 56, self.volume_oid);
        let hash = Sha256::digest(&bytes[..64]);
        bytes[64..].copy_from_slice(&hash);
        bytes
    }
    /// Decode a caller-retained anchor; its digest detects damage and does not authenticate an image.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use sha2::{Digest, Sha256};
        if bytes.len() != 96
            || &bytes[..8] != b"APCOWA01"
            || Sha256::digest(&bytes[..64]).as_slice() != &bytes[64..]
        {
            return Err(invalid("APFS recovery anchor encoding/digest"));
        }
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&bytes[16..32]);
        let anchor = Self {
            length: u64le(bytes, 8),
            uuid,
            descriptor_base: u64le(bytes, 32),
            descriptor_blocks: u32le(bytes, 40),
            data_base: u64le(bytes, 44),
            data_blocks: u32le(bytes, 52),
            volume_oid: u64le(bytes, 56),
        };
        anchor.validate()?;
        Ok(anchor)
    }
    fn validate(&self) -> Result<()> {
        if self.length < 1048576
            || !self.length.is_multiple_of(BLOCK as u64)
            || self.uuid == [0; 16]
            || self.volume_oid == 0
            || self.descriptor_base == 0
            || self.data_base == 0
            || self.descriptor_blocks < 2
            || self.data_blocks == 0
        {
            return Err(invalid("APFS recovery anchor geometry"));
        }
        let blocks = self.length / BLOCK as u64;
        let de = self
            .descriptor_base
            .checked_add(u64::from(self.descriptor_blocks))
            .filter(|e| *e <= blocks)
            .ok_or_else(|| invalid("APFS recovery descriptor range"))?;
        let pe = self
            .data_base
            .checked_add(u64::from(self.data_blocks))
            .filter(|e| *e <= blocks)
            .ok_or_else(|| invalid("APFS recovery data range"))?;
        if self.descriptor_base < pe && self.data_base < de {
            return Err(invalid("APFS recovery checkpoint areas overlap"));
        }
        Ok(())
    }
    fn candidate(
        &self,
        target: &dyn Storage,
        limits: ApfsEditLimits,
        r: &Resources,
    ) -> Result<(u64, [u8; BLOCK])> {
        self.validate()?;
        r.cancellation.check()?;
        if target
            .len()
            .map_err(|e| Error::io("APFS recovery length", e))?
            != self.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS recovery anchor length mismatch",
            ));
        }
        if self.length / BLOCK as u64 > limits.read.blocks
            || self.length / BLOCK as u64 > limits.audit.blocks
            || self.descriptor_blocks as usize > limits.read.checkpoint_blocks
        {
            return Err(budget("APFS recovery scan geometry cap"));
        }
        let charge = u64::from(self.descriptor_blocks)
            .checked_mul(BLOCK as u64)
            .ok_or_else(|| budget("APFS recovery scan work"))?;
        if charge > limits.work {
            return Err(budget("APFS recovery scan ceiling"));
        }
        let mut best = None;
        let mut largest = 0;
        for i in 0..self.descriptor_blocks {
            r.cancellation.check()?;
            let mut bytes = [0; BLOCK];
            target
                .read_exact_at(
                    (self.descriptor_base + u64::from(i)) * BLOCK as u64,
                    &mut bytes,
                )
                .map_err(|e| Error::io("APFS native recovery descriptor read", e))?;
            if &bytes[32..36] != b"NXSB" {
                continue;
            }
            match crate::fs_apfs::check_object(&bytes, Some(1), u64::MAX, None) {
                Ok(()) => {}
                Err(e) if e.kind == ErrorKind::InvalidData => continue,
                Err(e) => return Err(e),
            }
            if u32le(&bytes, 24) != 0x80000001 {
                return Err(invalid("APFS recovery NX storage type"));
            }
            if bytes[72..88] != self.uuid
                || u64le(&bytes, 40) != self.length / BLOCK as u64
                || u32le(&bytes, 36) != BLOCK as u32
                || u64le(&bytes, 112) != self.descriptor_base
                || u32le(&bytes, 104) != self.descriptor_blocks
                || u64le(&bytes, 120) != self.data_base
                || u32le(&bytes, 108) != self.data_blocks
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS recovery checkpoint/anchor geometry mismatch",
                ));
            }
            let xid = u64le(&bytes, 16);
            if xid > largest {
                largest = xid;
                best = Some(bytes);
            }
        }
        Ok((
            charge,
            best.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "APFS recovery no verified native checkpoint",
                )
            })?,
        ))
    }
}
struct Payload {
    logical: u64,
    physical: u64,
    previous: u64,
}
/// A source-bound positional replacement and a complete native COW checkpoint plan.
/// This first mutation profile retains file length and every old checkpoint allocation.
pub struct ApfsRangePlan {
    scope: u128,
    xid: u64,
    generation: u64,
    offset: u64,
    input: Arc<dyn FileRead>,
    input_identity: ObjectId,
    input_length: u64,
    eof: u64,
    zero_from: Option<u64>,
    payload: Vec<Payload>,
    metadata: Vec<(u64, Vec<u8>)>,
    ephemeral: Vec<(u64, Vec<u8>)>,
    map: (u64, Vec<u8>),
    nx: (u64, Vec<u8>),
    volume_block: u64,
    _lease: Reservation,
    resources: Resources,
    work: Arc<WorkCounter>,
}
struct Projection {
    binding: Option<(ObjectId, u64)>,
    catalog: Records,
    payload: Vec<Payload>,
    input: Arc<dyn FileRead>,
    offset: u64,
    eof: u64,
    zero_from: Option<u64>,
    lease: Reservation,
    resources: Resources,
    counters: Option<(u64, u64, u64)>,
}
/// Durable native publication outcome; payload/barrier readback is followed by a complete reopened audit.
#[derive(Debug)]
pub struct ApfsEditReceipt {
    /// Previously selected native checkpoint.
    pub previous_xid: u64,
    /// Published and reopened native transaction.
    pub xid: u64,
    /// Physical selected APSB block for independent explicit native oracle selection.
    pub volume_block: u64,
    /// Ordinary logical replacement bytes.
    pub bytes: u64,
    /// Fresh physical payload blocks.
    pub payload_blocks: usize,
    /// Old checkpoints and their allocations remain retained.
    pub retained_history: bool,
}
impl ApfsRangePlan {
    /// Planned physical APSB block for explicit independent oracle selection after verified publication/recovery.
    pub fn planned_volume_block(&self) -> u64 {
        self.volume_block
    }
    fn read_input(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        self.work.charge(out.len() as u64)?;
        let mut done = 0;
        while done < out.len() {
            self.resources.cancellation.check()?;
            r.cancellation.check()?;
            if self.input.identity() != &self.input_identity
                || self.input.len() != self.input_length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS COW deferred input changed",
                ));
            }
            let n = self.input.read_at(at + done as u64, &mut out[done..], r)?;
            if n == 0 || n > out.len() - done {
                return Err(Error::io(
                    "APFS COW deferred input short read",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            done += n;
        }
        if self.input.identity() != &self.input_identity || self.input.len() != self.input_length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS COW deferred final input changed",
            ));
        }
        Ok(())
    }
}
fn unavailable(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn records(
    c: &ApfsContainer,
    root: u64,
    storage: u32,
    kind: TreeKind,
    map: Option<&BTreeMap<u64, u64>>,
    work: &mut Work,
    r: &Resources,
) -> Result<Records> {
    let tree = index::tree(c, root, storage, kind, map, work, r)?;
    if tree.pages.len() != 1 || u16::from_le_bytes(tree.pages[0].1[34..36].try_into().unwrap()) != 0
    {
        return Err(unavailable(
            "APFS initial COW single-leaf native tree profile",
        ));
    }
    Ok(tree
        .records
        .into_iter()
        .map(|record| (record.key, record.value))
        .collect())
}
fn leaf(
    id: u64,
    storage: u32,
    subtype: u32,
    mut records: Records,
    fixed: Option<(usize, usize)>,
    xid: u64,
) -> Result<Vec<u8>> {
    if fixed.is_some() {
        records.sort_by(|a, b| {
            u64le(&a.0, 0)
                .cmp(&u64le(&b.0, 0))
                .then(u64le(&a.0, 8).cmp(&u64le(&b.0, 8)))
        });
    } else {
        records.sort_by(|a, b| disk::compare(&a.0, &b.0));
    }
    let totals = (
        records.len() as u64,
        1,
        records.iter().map(|r| r.0.len()).max().unwrap_or(0),
        records.iter().map(|r| r.1.len()).max().unwrap_or(0),
    );
    let mut b = disk::node(
        disk::NodeFields {
            id,
            storage,
            subtype,
            level: 0,
            root: true,
            fixed,
            totals,
        },
        &records,
    )?;
    q(&mut b, 16, xid);
    seal(&mut b);
    Ok(b)
}
fn omap_record(id: u64, xid: u64, address: u64) -> (Vec<u8>, Vec<u8>) {
    let mut k = id.to_le_bytes().to_vec();
    k.extend_from_slice(&xid.to_le_bytes());
    let mut v = vec![0; 16];
    d(&mut v, 4, BLOCK as u32);
    q(&mut v, 8, address);
    (k, v)
}
fn queue_records(blocks: BTreeMap<u64, u64>) -> Records {
    let mut ordered: Vec<_> = blocks
        .into_iter()
        .map(|(block, xid)| (xid, block))
        .collect();
    ordered.sort_unstable();
    let mut result = Vec::new();
    let mut entries = ordered.into_iter().peekable();
    while let Some((xid, start)) = entries.next() {
        let mut length = 1u64;
        while entries.peek() == Some(&(xid, start + length)) {
            entries.next();
            length += 1;
        }
        let mut key = xid.to_le_bytes().to_vec();
        key.extend_from_slice(&start.to_le_bytes());
        result.push((
            key,
            if length == 1 {
                Vec::new()
            } else {
                length.to_le_bytes().to_vec()
            },
        ));
    }
    result
}

impl<S: Storage> ApfsEditor<S> {
    fn pending_blocks(&self, oid: u64, r: &Resources) -> Result<BTreeMap<u64, u64>> {
        let c = self.volume.container();
        let mut work = Work {
            limits: self.limits.read,
            used: 0,
        };
        let records = records(c, oid, 0x80000000, TreeKind::FreeQueue, None, &mut work, r)?;
        self.snapshot.work.charge(work.used)?;
        let mut pending = BTreeMap::new();
        for (key, value) in records {
            r.cancellation.check()?;
            let xid = u64le(&key, 0);
            let start = u64le(&key, 8);
            let length = if value.is_empty() {
                1
            } else {
                u64le(&value, 0)
            };
            let end = start
                .checked_add(length)
                .filter(|end| *end <= c.checkpoint().blocks)
                .ok_or_else(|| invalid("APFS retained freequeue extent"))?;
            if xid == 0 || xid > self.checkpoint_xid() {
                return Err(invalid("APFS retained freequeue transaction"));
            }
            for block in start..end {
                self.snapshot.work.charge(1)?;
                if pending.insert(block, xid).is_some() {
                    return Err(invalid("APFS duplicate retained retirement"));
                }
            }
        }
        Ok(pending)
    }
    fn free_blocks(&self) -> Result<Vec<u64>> {
        let mut free = Vec::new();
        free.try_reserve_exact(self.volume.container().checkpoint().blocks as usize)
            .map_err(|_| budget("APFS COW allocation candidates"))?;
        for range in self.proof.free_ranges() {
            free.extend(range.offset / BLOCK as u64..(range.offset + range.length) / BLOCK as u64);
        }
        Ok(free)
    }
    fn copied(&self, block: u64) -> Result<Vec<u8>> {
        let index = self
            .snapshot
            .blocks
            .binary_search_by_key(&block, |entry| entry.0)
            .map_err(|_| unavailable("APFS COW uncopied native metadata"))?;
        let mut b = Vec::new();
        b.try_reserve_exact(BLOCK)
            .map_err(|_| budget("APFS COW native block"))?;
        b.extend_from_slice(self.snapshot.blocks[index].1.as_ref());
        Ok(b)
    }
    /// Create a source- and generation-bound native identity for an existing regular file.
    pub fn file_identity(&self, inode: u64, r: &Resources) -> Result<ObjectId> {
        self.revalidate(r)?;
        let node = self
            .volume
            .inner
            .nodes
            .get(&inode)
            .ok_or_else(|| invalid("APFS owned inode absent"))?;
        if node.directory {
            return Err(invalid("APFS owned regular file required"));
        }
        Ok(ObjectId {
            source: self.scope,
            generation: self.generation,
            native: inode.to_be_bytes().to_vec(),
        })
    }
    /// Read an indexed ordinary stream through the exclusive owner, including cancellation at EOF.
    pub fn read_file_at(
        &self,
        id: &ObjectId,
        at: u64,
        out: &mut [u8],
        r: &Resources,
    ) -> Result<usize> {
        if self.recovery_required {
            return Err(Error::new(
                ErrorKind::InterruptedWrite,
                "APFS native recovery required",
            ));
        }
        self.revalidate(r)?;
        let file = self.own_file(id)?;
        let stream = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == StreamKind::Data)
            .ok_or_else(|| invalid("APFS owned data absent"))?;
        if at >= stream.length || out.is_empty() {
            return Ok(0);
        }
        let length = out
            .len()
            .min(usize::try_from(stream.length - at).unwrap_or(usize::MAX));
        self.snapshot.work.charge(length as u64)?;
        let mut done = 0;
        while done < length {
            r.cancellation.check()?;
            let position = at + done as u64;
            let run = stream
                .runs
                .iter()
                .find(|run| run.logical <= position && position < run.logical + run.length)
                .ok_or_else(|| invalid("APFS owned logical run absent"))?;
            let take = (length - done).min((run.logical + run.length - position) as usize);
            if run.physical == 0 {
                out[done..done + take].fill(0);
            } else {
                self.target
                    .read_exact_at(
                        run.physical * BLOCK as u64 + position - run.logical,
                        &mut out[done..done + take],
                    )
                    .map_err(|e| Error::io("APFS owned deferred payload", e))?;
            }
            done += take;
        }
        self.revalidate(r)?;
        Ok(length)
    }
    fn own_file(&self, id: &ObjectId) -> Result<u64> {
        if id.source != self.scope || id.generation != self.generation || id.native.len() != 8 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS owned foreign/stale file",
            ));
        }
        let inode = u64::from_be_bytes(id.native[..].try_into().unwrap());
        if self
            .volume
            .inner
            .nodes
            .get(&inode)
            .is_none_or(|n| n.directory)
        {
            return Err(invalid("APFS owned regular file absent"));
        }
        Ok(inode)
    }
    /// Plan an existing-length positional replacement without reading any payload or writing the target.
    /// The initial COW profile has one volume, native single-leaf trees, inline forks and no shared data streams.
    pub fn plan_range(
        &self,
        id: &ObjectId,
        offset: u64,
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsRangePlan> {
        if self.recovery_required {
            return Err(Error::new(
                ErrorKind::InterruptedWrite,
                "APFS native recovery required",
            ));
        }
        self.revalidate(r)?;
        let file = self.own_file(id)?;
        let length = input.len();
        if length == 0 {
            return Err(invalid("APFS empty COW range"));
        }
        let c = self.volume.container();
        let blocks = c.checkpoint().blocks;
        if c.checkpoint().volumes.len() != 1 || blocks > 131073 {
            return Err(unavailable(
                "APFS initial COW single-volume/single-CIB profile",
            ));
        }
        if u32le(&self.volume.inner.nodes[&file].raw, 68) != 0 {
            return Err(unavailable(
                "APFS COW BSD write/security flags require explicit support",
            ));
        }
        self.generation
            .checked_add(2)
            .ok_or_else(|| budget("APFS owned generation exhausted"))?;
        let stream = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == StreamKind::Data)
            .ok_or_else(|| invalid("APFS unnamed data absent"))?;
        let end = offset
            .checked_add(length)
            .filter(|n| *n <= stream.length)
            .ok_or_else(|| invalid("APFS range exceeds unchanged EOF"))?;
        for node in self.volume.inner.nodes.values() {
            for stream in &node.streams {
                if stream.kind != StreamKind::Data && stream.inline.is_none() {
                    return Err(unavailable("APFS COW external resource stream"));
                }
                if stream.kind == StreamKind::Data && stream.id != node.id {
                    return Err(unavailable(
                        "APFS COW shared/clone stream profile pending exact refcount mutation",
                    ));
                }
            }
        }
        let charge = blocks
            .checked_mul(1024)
            .and_then(|n| n.checked_add((self.limits.metadata_blocks as u64).checked_mul(8192)?))
            .ok_or_else(|| budget("APFS COW reservation overflow"))?;
        let lease = self.snapshot.work.resources.memory.reserve(charge)?;
        if input.identity().native.len() > 4096 {
            return Err(budget("APFS source identity cap"));
        }
        let binding = (input.identity().clone(), length);
        self.snapshot.work.charge(
            self.limits
                .read
                .work
                .checked_add(
                    blocks
                        .checked_mul(64)
                        .ok_or_else(|| budget("APFS COW planning work"))?,
                )
                .ok_or_else(|| budget("APFS COW planning work overflow"))?,
        )?;
        let mut work = Work {
            limits: self.limits.read,
            used: 0,
        };
        let (vmap, _) = index::omap(c, u64le(&self.volume.inner.header, 128), &mut work, r)?;
        let catalog_root = u64le(&self.volume.inner.header, 136);
        let mut catalog = records(
            c,
            catalog_root,
            0,
            TreeKind::Filesystem,
            Some(&vmap),
            &mut work,
            r,
        )?;
        let old_extent = u64le(&self.volume.inner.header, 144);
        records(
            c,
            old_extent,
            0x40000000,
            TreeKind::Extent,
            None,
            &mut work,
            r,
        )?;
        let old_snapshot = u64le(&self.volume.inner.header, 152);
        if !records(
            c,
            old_snapshot,
            0x40000000,
            TreeKind::Snapshot,
            None,
            &mut work,
            r,
        )?
        .is_empty()
        {
            return Err(unavailable(
                "APFS COW snapshots require preservation mutation profile",
            ));
        }
        let old_cmap = c.checkpoint().object_map;
        let old_vmap = u64le(&self.volume.inner.header, 128);
        for address in [old_cmap, old_vmap] {
            let header = self.copied(address)?;
            records(
                c,
                u64le(&header, 48),
                0x40000000,
                TreeKind::Omap,
                None,
                &mut work,
                r,
            )?;
        }
        let mut free = Vec::new();
        free.try_reserve_exact(blocks as usize)
            .map_err(|_| budget("APFS COW allocation candidates"))?;
        for range in self.proof.free_ranges() {
            for block in range.offset / BLOCK as u64..(range.offset + range.length) / BLOCK as u64 {
                free.push(block);
            }
        }
        let first = offset / BLOCK as u64;
        let last = (end - 1) / BLOCK as u64;
        let payload_count =
            usize::try_from(last - first + 1).map_err(|_| budget("APFS COW payload count"))?;
        if free.len() < payload_count + 8 {
            return Err(budget("APFS COW native free allocations"));
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_count)
            .map_err(|_| budget("APFS COW payload map"))?;
        let mut remap = BTreeMap::new();
        for (index, logical) in (first..=last).enumerate() {
            let logical = logical * BLOCK as u64;
            let run = stream
                .runs
                .iter()
                .find(|run| run.logical <= logical && logical < run.logical + run.length)
                .ok_or_else(|| invalid("APFS COW missing indexed run"))?;
            let previous = if run.physical == 0 {
                0
            } else {
                run.physical + (logical - run.logical) / BLOCK as u64
            };
            let physical = free[index];
            remap.insert(logical, physical);
            payload.push(Payload {
                logical,
                physical,
                previous,
            });
        }
        let inode = catalog
            .iter_mut()
            .find(|record| u64le(&record.0, 0) == ((3u64 << 60) | file))
            .ok_or_else(|| invalid("APFS COW inode absent"))?;
        let generation = u32le(&inode.1, 64)
            .checked_add(1)
            .ok_or_else(|| budget("APFS native write generation exhausted"))?;
        d(&mut inode.1, 64, generation);
        let count = u16::from_le_bytes(inode.1[92..94].try_into().unwrap()) as usize;
        let mut field = 96 + count * 4;
        for index in 0..count {
            let at = 96 + index * 4;
            let size = u16::from_le_bytes(inode.1[at + 2..at + 4].try_into().unwrap()) as usize;
            if inode.1[at] == 8 {
                let written = u64le(&inode.1, field + 24)
                    .checked_add(length)
                    .ok_or_else(|| budget("APFS native byte-write counter exhausted"))?;
                q(&mut inode.1, field + 24, written);
            }
            field += size.next_multiple_of(8);
        }
        let materialized = payload.iter().filter(|p| p.previous == 0).count() as u64;
        if materialized != 0 {
            let inode = catalog
                .iter_mut()
                .find(|record| u64le(&record.0, 0) == ((3u64 << 60) | file))
                .ok_or_else(|| invalid("APFS COW inode record absent"))?;
            let count = u16::from_le_bytes(inode.1[92..94].try_into().unwrap()) as usize;
            let mut field = 96 + count * 4;
            for index in 0..count {
                let at = 96 + index * 4;
                let size = u16::from_le_bytes(inode.1[at + 2..at + 4].try_into().unwrap()) as usize;
                if inode.1[at] == 13 {
                    let remaining = u64le(&inode.1, field)
                        .checked_sub(materialized * BLOCK as u64)
                        .ok_or_else(|| invalid("APFS COW sparse accounting"))?;
                    q(&mut inode.1, field, remaining);
                    if remaining == 0 {
                        let flags = u64le(&inode.1, 48) & !0x200;
                        q(&mut inode.1, 48, flags);
                    }
                }
                field += size.next_multiple_of(8);
            }
        }
        catalog
            .try_reserve_exact(blocks as usize)
            .map_err(|_| budget("APFS COW catalog normalization"))?;
        // Split every mapped native data record into block-sized records, including beyond-EOF allocation.
        catalog.retain(|record| {
            !(u64le(&record.0, 0) >> 60 == 8 && u64le(&record.0, 0) & 0x0fffffffffffffff == file)
        });
        for run in stream.runs.iter() {
            for logical in (run.logical..run.logical + run.length).step_by(BLOCK) {
                let mut key = ((8u64 << 60) | file).to_le_bytes().to_vec();
                key.extend_from_slice(&logical.to_le_bytes());
                let mut value = vec![0; 24];
                q(
                    &mut value,
                    0,
                    (run.logical + run.length - logical).min(BLOCK as u64),
                );
                let physical = remap.get(&logical).copied().unwrap_or_else(|| {
                    if run.physical == 0 {
                        0
                    } else {
                        run.physical + (logical - run.logical) / BLOCK as u64
                    }
                });
                q(&mut value, 8, physical);
                catalog.push((key, value));
            }
        }
        self.snapshot.work.charge(work.used)?;
        self.assemble(
            Projection {
                binding: Some(binding),
                catalog,
                payload,
                input,
                offset,
                eof: stream.length,
                zero_from: None,
                lease,
                resources: r.clone(),
                counters: None,
            },
            r,
        )
    }
    fn assemble(&self, projection: Projection, r: &Resources) -> Result<ApfsRangePlan> {
        let Projection {
            binding,
            catalog,
            payload,
            input,
            offset,
            eof,
            zero_from,
            lease,
            resources,
            counters,
        } = projection;
        if input.identity().native.len() > 4096 {
            return Err(budget("APFS source identity cap"));
        }
        let (identity, length) = binding.unwrap_or_else(|| (input.identity().clone(), input.len()));
        if input.identity() != &identity || input.len() != length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS source changed during planning",
            ));
        }
        let c = self.volume.container();
        let next = self
            .checkpoint_xid()
            .checked_add(1)
            .ok_or_else(|| budget("APFS transaction exhausted"))?;
        let old_cmap = c.checkpoint().object_map;
        let old_vmap = u64le(&self.volume.inner.header, 128);
        let catalog_root = u64le(&self.volume.inner.header, 136);
        let free = self.free_blocks()?;
        let payload_count = payload.len();
        if free.len() < payload_count + 8 {
            return Err(budget("APFS COW native free allocations"));
        }
        let mut ownership: BTreeMap<u64, (u64, u32)> = BTreeMap::new();
        for (key, value) in &catalog {
            if u64le(key, 0) >> 60 != 8 {
                continue;
            }
            let owner = u64le(key, 0) & 0x0fffffffffffffff;
            let physical = u64le(value, 8);
            if physical == 0 {
                continue;
            }
            let length = u64le(value, 0) & 0x00ffffffffffffff;
            for block in physical..physical + length.div_ceil(BLOCK as u64) {
                let entry = ownership.entry(block).or_insert((owner, 0));
                if entry.0 != owner {
                    return Err(unavailable("APFS COW conflicting stream extent sharing"));
                }
                entry.1 = entry
                    .1
                    .checked_add(1)
                    .ok_or_else(|| budget("APFS COW extent refs"))?;
            }
        }
        let physical_records: Records = ownership
            .into_iter()
            .map(|(block, (owner, refs))| {
                let key = ((2u64 << 60) | block).to_le_bytes().to_vec();
                let mut value = vec![0; 20];
                q(&mut value, 0, (1u64 << 60) | 1);
                q(&mut value, 8, owner);
                d(&mut value, 16, refs);
                (key, value)
            })
            .collect();
        let mut retired_main: BTreeSet<u64> =
            self.volume.inner.pages.iter().map(|page| page.0).collect();
        let current_physical: BTreeSet<u64> = physical_records
            .iter()
            .map(|record| u64le(&record.0, 0) & 0x0fffffffffffffff)
            .collect();
        for node in self.volume.inner.nodes.values() {
            for stream in node.streams.iter().filter(|s| s.kind == StreamKind::Data) {
                for run in stream.runs.iter().filter(|run| run.physical != 0) {
                    for block in run.physical..run.physical + run.length.div_ceil(BLOCK as u64) {
                        if !current_physical.contains(&block) {
                            retired_main.insert(block);
                        }
                    }
                }
            }
        }
        let sm_mapping = c
            .inner
            .mappings
            .iter()
            .find(|m| m.oid == c.checkpoint().space_manager)
            .ok_or_else(|| invalid("APFS COW spaceman mapping"))?;
        let old_sm = self.copied(sm_mapping.address)?;
        let mut main_pending = self.pending_blocks(u64le(&old_sm, 248), r)?;
        for block in retired_main {
            if main_pending.insert(block, next).is_some() {
                return Err(invalid("APFS newly retired current owner already pending"));
            }
        }
        let retired_count = main_pending.len() as u64;
        let main_oldest = main_pending.values().copied().min().unwrap_or(0);
        let main_queue = queue_records(main_pending);
        let addresses = &free[payload_count..payload_count + 8];
        let (cm, cmroot, vol, vm, vmroot, cat, ext, snap) = (
            addresses[0],
            addresses[1],
            addresses[2],
            addresses[3],
            addresses[4],
            addresses[5],
            addresses[6],
            addresses[7],
        );
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(8)
            .map_err(|_| budget("APFS COW metadata map"))?;
        let mut cmheader = self.copied(old_cmap)?;
        q(&mut cmheader, 8, cm);
        q(&mut cmheader, 16, next);
        q(&mut cmheader, 48, cmroot);
        seal(&mut cmheader);
        metadata.push((cm, cmheader));
        metadata.push((
            cmroot,
            leaf(
                cmroot,
                0x40000000,
                11,
                vec![omap_record(self.volume.inner.oid, next, vol)],
                Some((16, 16)),
                next,
            )?,
        ));
        let mut header = self.volume.inner.header.clone();
        q(&mut header, 16, next);
        let current_allocated = 5u64
            .checked_add(current_physical.len() as u64)
            .ok_or_else(|| budget("APFS COW volume allocated overflow"))?;
        if let Some((next_oid, files, dirs)) = counters {
            q(&mut header, 176, next_oid);
            q(&mut header, 184, files);
            q(&mut header, 192, dirs);
        }
        q(&mut header, 88, current_allocated);
        q(&mut header, 128, vm);
        q(&mut header, 144, ext);
        q(&mut header, 152, snap);
        seal(&mut header);
        metadata.push((vol, header));
        let mut vmheader = self.copied(old_vmap)?;
        q(&mut vmheader, 8, vm);
        q(&mut vmheader, 16, next);
        q(&mut vmheader, 48, vmroot);
        seal(&mut vmheader);
        metadata.push((vm, vmheader));
        metadata.push((
            vmroot,
            leaf(
                vmroot,
                0x40000000,
                11,
                vec![omap_record(catalog_root, next, cat)],
                Some((16, 16)),
                next,
            )?,
        ));
        metadata.push((cat, leaf(catalog_root, 0, 14, catalog, None, next)?));
        metadata.push((
            ext,
            leaf(ext, 0x40000000, 15, physical_records, None, next)?,
        ));
        metadata.push((snap, leaf(snap, 0x40000000, 16, vec![], None, next)?));
        let h = &c.inner.header;
        let desc_base = u64le(h, 112);
        let desc_count = u32le(h, 104) as usize;
        let data_base = u64le(h, 120);
        let data_count = u32le(h, 108) as usize;
        let desc_next = u32le(h, 128) as usize;
        let data_next = u32le(h, 132) as usize;
        if c.inner.mappings.len() != 4 || desc_count < 4 || data_count < 8 {
            return Err(unavailable("APFS COW native ring capacity profile"));
        }
        let descriptor_slots = [
            desc_base + desc_next as u64,
            desc_base + ((desc_next + 1) % desc_count) as u64,
        ];
        let data_slots: Vec<_> = (0..4)
            .map(|i| data_base + ((data_next + i) % data_count) as u64)
            .collect();
        // Never overwrite any structurally retained checkpoint or one of its active mapping/data slots.
        for (at, old) in &c.inner.retained_headers {
            let di = u32le(old, 136) as usize;
            let dl = u32le(old, 140) as usize;
            let pi = u32le(old, 144) as usize;
            let pl = u32le(old, 148) as usize;
            if descriptor_slots.contains(at)
                || (0..dl).any(|i| {
                    descriptor_slots.contains(&(desc_base + ((di + i) % desc_count) as u64))
                })
                || (0..pl)
                    .any(|i| data_slots.contains(&(data_base + ((pi + i) % data_count) as u64)))
            {
                return Err(budget("APFS COW retained checkpoint ring exhaustion"));
            }
        }
        let smmap = c
            .inner
            .mappings
            .iter()
            .find(|m| m.oid == c.checkpoint().space_manager)
            .ok_or_else(|| invalid("APFS COW spaceman mapping"))?;
        let mut sm = self.copied(smmap.address)?;
        if u32le(&sm, 64) != 1 {
            return Err(unavailable("APFS COW direct single CIB"));
        }
        let ipbase = u64le(&sm, 176);
        let ipcount = u64le(&sm, 152) as usize;
        let bm_base = u64le(&sm, 168);
        let boff = u32le(&sm, 328) as usize;
        let xoff = u32le(&sm, 324) as usize;
        let foff = u32le(&sm, 332) as usize;
        let active = u16::from_le_bytes(sm[boff..boff + 2].try_into().unwrap()) as usize;
        let mut ipbits = self.copied(bm_base + active as u64)?;
        let address_offset = u32le(&sm, 80) as usize;
        let old_cib = u64le(&sm, address_offset);
        let mut cib = self.copied(old_cib)?;
        let chunks = u32le(&cib, 36) as usize;
        if chunks == 0 || chunks > 5 || chunks as u64 != c.checkpoint().blocks.div_ceil(32768) {
            return Err(unavailable("APFS COW bounded single-CIB chunk profile"));
        }
        let mut changed: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
        for block in free.iter().take(payload_count + 8) {
            let chunk = (*block / 32768) as usize;
            if chunk >= chunks {
                return Err(invalid("APFS new allocation outside CIB"));
            }
            changed.entry(chunk).or_default().push(*block);
        }
        let required = changed.len() + 1;
        let slots: Vec<_> = (0..ipcount)
            .filter(|i| ipbits[i / 8] & (1 << (i % 8)) == 0)
            .take(required)
            .collect();
        if slots.len() != required {
            return Err(budget("APFS COW retained internal-pool exhaustion"));
        }
        let cib_addr = ipbase + slots[changed.len()] as u64;
        for slot in &slots {
            ipbits[slot / 8] |= 1 << (slot % 8);
        }
        let index = u16::from_le_bytes(sm[320..322].try_into().unwrap()) as usize;
        if index >= 16 {
            return Err(budget("APFS COW IP bitmap ring exhausted"));
        }
        for (_, old) in &c.inner.retained_headers {
            let old_xid = u64le(old, 16);
            for (_, bytes) in &self.snapshot.blocks {
                if u32le(bytes.as_ref(), 24) == 0x80000005 && u64le(bytes.as_ref(), 16) == old_xid {
                    let old_bo = u32le(bytes.as_ref(), 328) as usize;
                    if u16::from_le_bytes(bytes[old_bo..old_bo + 2].try_into().unwrap()) as usize
                        == index
                    {
                        return Err(budget("APFS COW retained IP bitmap ring collision"));
                    }
                }
            }
        }
        let mut ip_pending = self.pending_blocks(u64le(&sm, 208), r)?;
        if ip_pending.insert(old_cib, next).is_some() {
            return Err(invalid("APFS newly retired CIB owner already pending"));
        }
        let mut free_count = 0u64;
        for chunk in 0..chunks {
            let at = 40 + chunk * 32;
            if let Some(allocations) = changed.get(&chunk) {
                let old_bitmap = u64le(&cib, at + 24);
                let mut bitmap = if old_bitmap == 0 {
                    let mut b = Vec::new();
                    b.try_reserve_exact(BLOCK)
                        .map_err(|_| budget("APFS fresh chunk bitmap"))?;
                    b.resize(BLOCK, 0);
                    b
                } else {
                    if ip_pending.insert(old_bitmap, next).is_some() {
                        return Err(invalid("APFS newly retired bitmap owner already pending"));
                    }
                    self.copied(old_bitmap)?
                };
                for block in allocations {
                    let relative = (*block % 32768) as usize;
                    if bitmap[relative / 8] & (1 << (relative % 8)) != 0 {
                        return Err(invalid("APFS new allocation already set in chunk bitmap"));
                    }
                    bitmap[relative / 8] |= 1 << (relative % 8);
                }
                let old_free = u32le(&cib, at + 20);
                let new_free = old_free
                    .checked_sub(allocations.len() as u32)
                    .ok_or_else(|| invalid("APFS COW chunk free count"))?;
                let slot_index = changed
                    .keys()
                    .position(|n| *n == chunk)
                    .ok_or_else(|| invalid("APFS changed chunk slot"))?;
                let bitmap_addr = ipbase + slots[slot_index] as u64;
                q(&mut cib, at, next);
                d(&mut cib, at + 20, new_free);
                q(&mut cib, at + 24, bitmap_addr);
                metadata.push((bitmap_addr, bitmap));
            }
            free_count = free_count
                .checked_add(u64::from(u32le(&cib, at + 20)))
                .ok_or_else(|| budget("APFS COW aggregate free count"))?;
        }
        if free_count
            != u64le(&sm, 72)
                .checked_sub((payload_count + 8) as u64)
                .ok_or_else(|| invalid("APFS COW free count"))?
        {
            return Err(invalid("APFS COW aggregate chunk count disagrees"));
        }
        let ip_count = ip_pending.len() as u64;
        let ip_oldest = ip_pending.values().copied().min().unwrap_or(0);
        let ip_queue = queue_records(ip_pending);
        q(&mut cib, 8, cib_addr);
        q(&mut cib, 16, next);
        seal(&mut cib);
        q(&mut sm, 16, next);
        q(&mut sm, 200, ip_count);
        q(&mut sm, 216, ip_oldest);
        q(&mut sm, 240, retired_count);
        q(&mut sm, 256, main_oldest);
        q(&mut sm, 72, free_count);
        q(&mut sm, address_offset, cib_addr);
        q(&mut sm, xoff, next);
        w(&mut sm, boff, index as u16);
        let after = u16::from_le_bytes(
            sm[foff + index * 2..foff + index * 2 + 2]
                .try_into()
                .unwrap(),
        );
        let tail = u16::from_le_bytes(sm[322..324].try_into().unwrap()) as usize;
        w(&mut sm, 320, after);
        w(&mut sm, foff + tail * 2, active as u16);
        w(&mut sm, foff + active * 2, 65535);
        w(&mut sm, foff + index * 2, 65535);
        w(&mut sm, 322, active as u16);
        seal(&mut sm);
        metadata.push((cib_addr, cib));
        metadata.push((bm_base + index as u64, ipbits));
        let mut ephemeral = Vec::new();
        let mut cp = self.copied(desc_base + u32le(h, 136) as u64)?;
        for (i, mapping) in c.inner.mappings.iter().enumerate() {
            let address = data_slots[i];
            let mut bytes = if mapping.oid == c.checkpoint().space_manager {
                sm.clone()
            } else if mapping.oid == u64le(&sm, 208) {
                leaf(
                    mapping.oid,
                    0x80000000,
                    9,
                    ip_queue.clone(),
                    Some((16, 8)),
                    next,
                )?
            } else if mapping.oid == u64le(&sm, 248) {
                leaf(
                    mapping.oid,
                    0x80000000,
                    9,
                    main_queue.clone(),
                    Some((16, 8)),
                    next,
                )?
            } else {
                self.copied(mapping.address)?
            };
            q(&mut bytes, 16, next);
            seal(&mut bytes);
            ephemeral.push((address, bytes));
            q(&mut cp, 40 + i * 40 + 32, address);
        }
        q(&mut cp, 8, descriptor_slots[0]);
        q(&mut cp, 16, next);
        seal(&mut cp);
        let mut nx = h.clone();
        q(&mut nx, 16, next);
        q(
            &mut nx,
            96,
            next.checked_add(1)
                .ok_or_else(|| budget("APFS next transaction exhausted"))?,
        );
        q(&mut nx, 160, cm);
        d(&mut nx, 136, desc_next as u32);
        d(&mut nx, 140, 2);
        d(&mut nx, 128, ((desc_next + 2) % desc_count) as u32);
        d(&mut nx, 144, data_next as u32);
        d(&mut nx, 148, 4);
        d(&mut nx, 132, ((data_next + 4) % data_count) as u32);
        seal(&mut nx);
        let plan = ApfsRangePlan {
            scope: self.scope,
            xid: self.checkpoint_xid(),
            generation: self.generation,
            offset,
            input,
            input_identity: identity,
            input_length: length,
            eof,
            zero_from,
            payload,
            metadata,
            ephemeral,
            map: (descriptor_slots[0], cp),
            nx: (descriptor_slots[1], nx),
            volume_block: vol,
            _lease: lease,
            resources,
            work: self.snapshot.work.clone(),
        };
        self.validate_prepared(&plan, r)?;
        Ok(plan)
    }
    fn validate_prepared(&self, plan: &ApfsRangePlan, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.snapshot.work.charge(
            self.limits
                .read
                .work
                .checked_add(self.limits.audit.work)
                .ok_or_else(|| budget("APFS prepared proof work"))?,
        )?;
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(self.limits.metadata_blocks)
            .map_err(|_| budget("APFS prepared immutable index"))?;
        blocks.extend(self.snapshot.blocks.iter().cloned());
        for (at, bytes) in plan
            .metadata
            .iter()
            .chain(&plan.ephemeral)
            .chain(std::iter::once(&plan.map))
            .chain(std::iter::once(&plan.nx))
        {
            let copied: [u8; BLOCK] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid("APFS prepared block length"))?;
            match blocks.binary_search_by_key(at, |entry| entry.0) {
                Ok(index) => blocks[index].1 = Arc::new(copied),
                Err(index) => {
                    if blocks.len() == self.limits.metadata_blocks {
                        return Err(budget("APFS prepared metadata ceiling"));
                    }
                    blocks.insert(index, (*at, Arc::new(copied)));
                }
            }
        }
        let owner_resources = self.snapshot.work.resources.clone();
        let source = Arc::new(Snapshot {
            length: self.snapshot.length,
            blocks,
            work: self.snapshot.work.clone(),
            _lease: self.snapshot._lease.clone(),
        });
        let c = ApfsContainer::open(source, self.limits.read, &owner_resources)?;
        if c.checkpoint().xid != plan.xid + 1 {
            return Err(invalid("APFS prepared terminal checkpoint not selected"));
        }
        let volume = ApfsVolume::open(c, self.volume.inner.oid, &owner_resources)?;
        let proof = audit_apfs(&volume, self.limits.audit, &owner_resources)?;
        if !proof.is_complete() || !proof.is_clean() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "APFS prepared COW allocation/reference defects: {:?}",
                    proof.findings()
                ),
            ));
        }
        Ok(())
    }
    fn write_block(&mut self, address: u64, bytes: &[u8], r: &Resources) -> Result<()> {
        self.snapshot.work.charge(bytes.len() as u64)?;
        let at = address
            .checked_mul(BLOCK as u64)
            .ok_or_else(|| invalid("APFS COW write address"))?;
        let mut done = 0;
        while done < bytes.len() {
            r.cancellation.check()?;
            let n = self
                .target
                .write_at(at + done as u64, &bytes[done..])
                .map_err(|e| Error::io("APFS COW positional write", e))?;
            if n == 0 || n > bytes.len() - done {
                return Err(Error::io(
                    "APFS COW short write",
                    io::ErrorKind::WriteZero.into(),
                ));
            }
            done += n;
        }
        Ok(())
    }
    fn verify_blocks(&self, blocks: &[(u64, Vec<u8>)], r: &Resources) -> Result<()> {
        let mut actual = [0; BLOCK];
        for (at, expected) in blocks {
            r.cancellation.check()?;
            self.snapshot.work.charge(BLOCK as u64)?;
            self.target
                .read_exact_at(at * BLOCK as u64, &mut actual)
                .map_err(|e| Error::io("APFS COW readback", e))?;
            if actual.as_slice() != expected {
                return Err(Error::new(
                    ErrorKind::UncertainDurability,
                    "APFS COW readback mismatch",
                ));
            }
        }
        Ok(())
    }
    /// Publish a fresh native checkpoint. Any failure after a write requires consuming the owner through `recover`.
    pub fn commit_range(
        &mut self,
        plan: ApfsRangePlan,
        anchor: &ApfsRecoveryAnchor,
        r: &Resources,
    ) -> Result<ApfsEditReceipt> {
        if self.recovery_required {
            return Err(Error::new(
                ErrorKind::InterruptedWrite,
                "APFS COW recovery required",
            ));
        }
        plan.resources.cancellation.check()?;
        if anchor != &self.recovery_anchor() {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS commit recovery anchor binding",
            ));
        }
        self.revalidate(r)?;
        if plan.scope != self.scope
            || plan.xid != self.checkpoint_xid()
            || plan.generation != self.generation
            || plan.input.identity() != &plan.input_identity
            || plan.input.len() != plan.input_length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS foreign/stale COW range",
            ));
        }
        self.snapshot.work.charge(
            (plan.payload.len() as u64)
                .checked_mul(4 * BLOCK as u64)
                .ok_or_else(|| budget("APFS COW positional work"))?,
        )?;
        self.recovery_required = true;
        let result = (|| {
            let eof = plan.eof;
            for payload in &plan.payload {
                plan.resources.cancellation.check()?;
                r.cancellation.check()?;
                let mut bytes = [0; BLOCK];
                if payload.previous != 0 {
                    self.target
                        .read_exact_at(payload.previous * BLOCK as u64, &mut bytes)
                        .map_err(|e| Error::io("APFS COW old payload", e))?;
                }
                if let Some(zero) = plan.zero_from
                    && zero < payload.logical + BLOCK as u64
                {
                    bytes[zero.saturating_sub(payload.logical).min(BLOCK as u64) as usize..]
                        .fill(0);
                }
                let start = payload.logical.max(plan.offset);
                let end = (payload.logical + BLOCK as u64).min(plan.offset + plan.input_length);
                if plan.input.identity() != &plan.input_identity
                    || plan.input.len() != plan.input_length
                {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "APFS COW deferred input changed",
                    ));
                }
                if start < end {
                    plan.read_input(
                        start - plan.offset,
                        &mut bytes
                            [(start - payload.logical) as usize..(end - payload.logical) as usize],
                        r,
                    )?;
                }
                if payload.logical + BLOCK as u64 > eof {
                    bytes[(eof - payload.logical) as usize..].fill(0);
                }
                self.write_block(payload.physical, &bytes, r)?;
            }
            self.target
                .flush()
                .map_err(|e| Error::io("APFS COW payload barrier", e))?;
            // Verify the same source-bound byte model before any root publication.
            for payload in &plan.payload {
                let mut expected = [0; BLOCK];
                let mut actual = [0; BLOCK];
                if payload.previous != 0 {
                    self.target
                        .read_exact_at(payload.previous * BLOCK as u64, &mut expected)
                        .map_err(|e| Error::io("APFS COW old verification payload", e))?;
                }
                if let Some(zero) = plan.zero_from
                    && zero < payload.logical + BLOCK as u64
                {
                    expected[zero.saturating_sub(payload.logical).min(BLOCK as u64) as usize..]
                        .fill(0);
                }
                let start = payload.logical.max(plan.offset);
                let end = (payload.logical + BLOCK as u64).min(plan.offset + plan.input_length);
                if start < end {
                    plan.read_input(
                        start - plan.offset,
                        &mut expected
                            [(start - payload.logical) as usize..(end - payload.logical) as usize],
                        r,
                    )?;
                }
                if payload.logical + BLOCK as u64 > eof {
                    expected[(eof - payload.logical) as usize..].fill(0);
                }
                self.target
                    .read_exact_at(payload.physical * BLOCK as u64, &mut actual)
                    .map_err(|e| Error::io("APFS COW payload readback", e))?;
                if actual != expected {
                    return Err(Error::new(
                        ErrorKind::UncertainDurability,
                        "APFS COW payload prerequisite mismatch",
                    ));
                }
            }
            for (at, bytes) in &plan.metadata {
                self.write_block(*at, bytes, r)?;
            }
            self.target
                .flush()
                .map_err(|e| Error::io("APFS COW metadata barrier", e))?;
            self.verify_blocks(&plan.metadata, r)?;
            for (at, bytes) in &plan.ephemeral {
                self.write_block(*at, bytes, r)?;
            }
            self.write_block(plan.map.0, &plan.map.1, r)?;
            self.target
                .flush()
                .map_err(|e| Error::io("APFS COW ephemeral barrier", e))?;
            self.verify_blocks(&plan.ephemeral, r)?;
            self.verify_blocks(std::slice::from_ref(&plan.map), r)?;
            plan.resources.cancellation.check()?;
            if self
                .target
                .len()
                .map_err(|e| Error::io("APFS COW terminal length", e))?
                != self.snapshot.length
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS COW target length changed",
                ));
            }
            self.write_block(plan.nx.0, &plan.nx.1, r)?;
            self.target
                .flush()
                .map_err(|e| Error::io("APFS COW checkpoint barrier", e))?;
            self.verify_blocks(std::slice::from_ref(&plan.nx), r)?;
            self.refresh_owned(plan.xid + 1, r)?;
            self.recovery_required = true;
            let boot = self.volume.container().inner.header.clone();
            self.write_block(0, &boot, r)?;
            self.target
                .flush()
                .map_err(|e| Error::io("APFS COW terminal boot-hint barrier", e))?;
            self.verify_blocks(&[(0, boot)], r)?;
            self.refresh_owned(plan.xid + 1, r)?;
            Ok(ApfsEditReceipt {
                previous_xid: plan.xid,
                xid: plan.xid + 1,
                volume_block: plan.volume_block,
                bytes: plan.input_length,
                payload_blocks: plan.payload.len(),
                retained_history: true,
            })
        })();
        // Mutated owner must reopen the native checkpoint and prove all retained allocations before reuse.
        result.map_err(|mut error| {
            if error.kind != ErrorKind::UncertainDurability {
                error.kind = ErrorKind::InterruptedWrite;
            }
            error
        })
    }
    fn refresh_owned(&mut self, expected_xid: u64, r: &Resources) -> Result<()> {
        struct Borrowed<'a>(&'a dyn Storage);
        impl Storage for Borrowed<'_> {
            fn len(&self) -> io::Result<u64> {
                self.0.len()
            }
            fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
                self.0.read_exact_at(at, out)
            }
            fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        let prior = self.snapshot.work.used.load(Ordering::Acquire);
        let mut limits = self.limits;
        limits.work = limits
            .work
            .checked_sub(prior)
            .ok_or_else(|| budget("APFS COW reopen work"))?;
        r.cancellation.check()?;
        let owner_resources = self.snapshot.work.resources.clone();
        let fresh = ApfsEditor::open(
            Borrowed(&self.target),
            self.volume.inner.oid,
            limits,
            &owner_resources,
        )?;
        if fresh.checkpoint_xid() != expected_xid {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "APFS terminal checkpoint not selected on reopen",
            ));
        }
        let ApfsEditor {
            snapshot,
            volume,
            proof,
            ..
        } = fresh;
        let total = prior
            .checked_add(snapshot.work.used.load(Ordering::Acquire))
            .ok_or_else(|| budget("APFS COW total work"))?;
        snapshot.work.used.store(total, Ordering::Release);
        snapshot
            .work
            .ceiling
            .store(self.limits.work, Ordering::Release);
        self.snapshot = snapshot;
        self.volume = volume;
        self.proof = proof;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| budget("APFS owned generation exhausted"))?;
        self.recovery_required = false;
        Ok(())
    }
    /// Retain this native geometry anchor durably before any mutation, for torn boot-hint recovery.
    pub fn recovery_anchor(&self) -> ApfsRecoveryAnchor {
        let c = self.volume.container();
        let h = &c.inner.header;
        ApfsRecoveryAnchor {
            length: self.snapshot.length,
            uuid: c.checkpoint().uuid,
            descriptor_base: u64le(h, 112),
            descriptor_blocks: u32le(h, 104),
            data_base: u64le(h, 120),
            data_blocks: u32le(h, 108),
            volume_oid: self.volume.inner.oid,
        }
    }
    /// Cold native recovery from a caller-retained anchor; complete candidate/history proof precedes boot repair.
    /// Interrupted boot restoration can be retried with the same anchor and reopened exclusive storage.
    pub fn recover_with_anchor(
        target: S,
        anchor: &ApfsRecoveryAnchor,
        limits: ApfsEditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let seed = anchor.candidate(&target, limits, r)?;
        let mut owner = Self::open_seeded(target, anchor.volume_oid, limits, r, Some(seed))?;
        owner.revalidate_subset(r, false)?;
        owner.recovery_required = true;
        let xid = owner.checkpoint_xid();
        let boot = owner.volume.container().inner.header.clone();
        owner.write_block(0, &boot, r)?;
        owner.target.flush().map_err(|e| {
            let mut e = Error::io("APFS recovery boot barrier", e);
            e.kind = ErrorKind::UncertainDurability;
            e
        })?;
        owner.verify_blocks(&[(0, boot)], r)?;
        owner.refresh_owned(xid, r)?;
        Ok(owner)
    }
    /// Consume an owner after native publication or interruption and select/prove its highest complete checkpoint.
    /// No external undo bytes are applied. Unsupported higher checkpoints still fail the complete proof.
    pub fn recover(self, r: &Resources) -> Result<Self> {
        let scope = self.scope;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| budget("APFS recovery generation exhausted"))?;
        let limits = self.limits;
        let anchor = self.recovery_anchor();
        let target = self.into_storage();
        let mut recovered = Self::recover_with_anchor(target, &anchor, limits, r)?;
        recovered.scope = scope;
        recovered.generation = generation;
        Ok(recovered)
    }
}
