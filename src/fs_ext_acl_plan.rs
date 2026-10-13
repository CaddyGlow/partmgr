//! Private classic ACL COW planning over a complete bounded source snapshot.
//! Publication and durable recovery require the separate typed controller/capsule.
use super::{
    ExtDecodeRead, ExtDecoder, acl, acl_container, acl_semantics, acl_write, invalid, u16le, u32le,
    unsupported, xattr, xattr_write,
};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use crate::platform::prelude::*;
use crate::{
    fs_core::{NativeName, Reservation, Resources},
    fs_ext_audit::{ExtAuditLimits, audit_decoder},
    platform::io,
    storage::Storage,
};
const MAX: usize = 4096;
#[path = "fs_ext_acl_birth.rs"]
pub(super) mod birth;
#[derive(Clone, Copy)]
pub(super) enum Operation<'a> {
    Access(Option<&'a [u8]>),
    Default(Option<&'a [u8]>),
    Chmod(u16),
    Create(birth::Request<'a>),
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub source_bytes: u64,
    pub work: usize,
    pub records: usize,
    pub affected_bytes: u64,
    pub path_depth: usize,
    pub directory_entries: usize,
    pub audit: ExtAuditLimits,
    pub encoding: xattr_write::Limits,
}
pub(super) struct Home {
    pub block: u32,
    pub original: [u8; MAX],
    pub replacement: [u8; MAX],
}
pub(super) struct Plan {
    scope: u128,
    generation: u64,
    block_bytes: usize,
    source: Vec<u8>,
    homes: Vec<Home>,
    journal: Vec<u32>,
    pub inode: u32,
    pub old_external: u32,
    pub new_external: u32,
    pub changed: bool,
    intent: [u8; 32],
    original_digest: [u8; 32],
    _source: Reservation,
    _homes: Reservation,
    _journal: Reservation,
}
struct Slice<'a>(&'a [u8]);
impl ExtDecodeRead for Slice<'_> {
    fn decode_len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn decode_read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or_else(|| invalid("xattr snapshot read overflow"))?;
        out.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
struct Work<'a> {
    used: usize,
    maximum: usize,
    r: &'a Resources,
}
impl Work<'_> {
    fn charge(&mut self, n: usize) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        self.used = self
            .used
            .checked_add(n)
            .filter(|v| *v <= self.maximum)
            .ok_or_else(|| unsupported("classic xattr planning work ceiling"))?;
        Ok(())
    }
}
fn copy(bytes: &[u8], r: &Resources) -> io::Result<(Vec<u8>, Reservation)> {
    let lease = r
        .memory
        .reserve(bytes.len() as u64)
        .map_err(io::Error::other)?;
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len()).map_err(io::Error::other)?;
    if v.capacity() > bytes.len() {
        return Err(unsupported("xattr snapshot copy capacity"));
    }
    v.extend_from_slice(bytes);
    Ok((v, lease))
}
fn patch<'a>(
    homes: &'a mut Vec<Home>,
    source: &[u8],
    block: u32,
    bs: usize,
    limit: usize,
) -> io::Result<&'a mut [u8]> {
    let slot = if let Some(i) = homes.iter().position(|h| h.block == block) {
        i
    } else {
        if homes.len() == limit {
            return Err(unsupported("xattr COW home record ceiling"));
        }
        let at = block as usize * bs;
        let original = source
            .get(at..at + bs)
            .ok_or_else(|| invalid("xattr COW home outside source"))?;
        let mut h = Home {
            block,
            original: [0; MAX],
            replacement: [0; MAX],
        };
        h.original[..bs].copy_from_slice(original);
        h.replacement[..bs].copy_from_slice(original);
        homes.push(h);
        homes.len() - 1
    };
    Ok(&mut homes[slot].replacement[..bs])
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn bitmap(
    decoder: &ExtDecoder<Slice<'_>>,
    homes: &mut Vec<Home>,
    source: &[u8],
    block: u32,
    allocate: bool,
    limit: usize,
    work: &mut Work<'_>,
) -> io::Result<()> {
    work.charge(1)?;
    let g = decoder.geometry();
    let bs = g.block_size as usize;
    let index = block
        .checked_sub(g.first)
        .ok_or_else(|| invalid("xattr bitmap block underflow"))?;
    let group = index / g.blocks_per_group;
    let bit = index % g.blocks_per_group;
    let descriptor = decoder.group(group)?;
    let bytes = patch(homes, source, descriptor[0], bs, limit)?;
    let at = (bit / 8) as usize;
    let mask = 1u8 << (bit % 8);
    if (bytes[at] & mask != 0) == allocate {
        return Err(invalid("xattr bitmap source state differs"));
    }
    if allocate {
        bytes[at] |= mask;
    } else {
        bytes[at] &= !mask;
    }
    let gdt_offset = (u64::from(g.first) + 1) * bs as u64 + u64::from(group) * 32;
    let home = (gdt_offset / bs as u64) as u32;
    let inside = (gdt_offset % bs as u64) as usize;
    let gd = patch(homes, source, home, bs, limit)?;
    let before = u16le(gd, inside + 12);
    let after = if allocate {
        before.checked_sub(1)
    } else {
        before.checked_add(1)
    }
    .ok_or_else(|| invalid("xattr group free counter overflow"))?;
    gd[inside + 12..inside + 14].copy_from_slice(&after.to_le_bytes());
    let primary = u32::from(bs == 1024);
    let sb = patch(homes, source, primary, bs, limit)?;
    let inside = 1024usize % bs;
    let before = u32le(sb, inside + 12);
    let after = if allocate {
        before.checked_sub(1)
    } else {
        before.checked_add(1)
    }
    .ok_or_else(|| invalid("xattr primary free counter overflow"))?;
    put32(sb, inside + 12, after);
    Ok(())
}
impl Plan {
    pub fn original_digest(&self) -> &[u8; 32] {
        &self.original_digest
    }
    pub fn intent(&self) -> &[u8; 32] {
        &self.intent
    }
    pub fn binding(&self) -> (u128, u64) {
        (self.scope, self.generation)
    }
    pub fn homes(&self) -> &[Home] {
        &self.homes
    }
    pub fn original_source(&self) -> &[u8] {
        &self.source
    }
    pub fn journal_blocks(&self) -> &[u32] {
        &self.journal
    }
    pub fn block_bytes(&self) -> usize {
        self.block_bytes
    }
    pub fn source_bytes(&self) -> u64 {
        self.source.len() as u64
    }
    /// Ephemeral both-phase guards; only this controller's primary RECOVER bit
    /// may differ after preparation. Journal bytes belong to the typed WAL path.
    pub fn source_guards(&self, prepared: bool) -> impl Iterator<Item = (u64, &[u8])> {
        let bs = self.block_bytes;
        self.source
            .chunks_exact(bs)
            .enumerate()
            .filter(move |(i, _)| !prepared || !self.journal.contains(&(*i as u32)))
            .map(move |(i, b)| ((i * bs) as u64, b))
    }
    pub fn check_source(
        &self,
        storage: &dyn Storage,
        prepared: bool,
        maximum_work: usize,
        r: &Resources,
    ) -> io::Result<()> {
        let mut work = Work {
            used: 0,
            maximum: maximum_work,
            r,
        };
        work.charge(1)?;
        let observed = storage.len()?;
        r.cancellation.check().map_err(io::Error::other)?;
        if observed != self.source.len() as u64 {
            return Err(invalid("ACL sealed source length changed"));
        }
        let _scratch = r
            .memory
            .reserve(self.block_bytes as u64)
            .map_err(io::Error::other)?;
        let mut raw = [0; MAX];
        for (index, expected) in self.source.chunks_exact(self.block_bytes).enumerate() {
            work.charge(if prepared {
                self.journal
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| unsupported("ACL journal guard work overflow"))?
            } else {
                1
            })?;
            if prepared && self.journal.contains(&(index as u32)) {
                continue;
            }
            let at = (index * self.block_bytes) as u64;
            work.charge(
                self.block_bytes
                    .checked_mul(2)
                    .ok_or_else(|| unsupported("xattr guard work overflow"))?,
            )?;
            storage.read_exact_at(at, &mut raw[..self.block_bytes])?;
            r.cancellation.check().map_err(io::Error::other)?;
            for (i, (&actual, &old)) in raw[..self.block_bytes].iter().zip(expected).enumerate() {
                let want = if prepared && at + i as u64 == 1120 {
                    old | 4
                } else {
                    old
                };
                if actual != want {
                    return Err(io::Error::other(crate::fs_core::Error::new(
                        crate::fs_core::ErrorKind::StalePlan,
                        "xattr sealed nonjournal source changed",
                    )));
                }
            }
        }
        work.charge(1)?;
        let observed = storage.len()?;
        r.cancellation.check().map_err(io::Error::other)?;
        if observed != self.source.len() as u64 {
            return Err(invalid("ACL sealed source length changed"));
        }
        r.cancellation.check().map_err(io::Error::other)
    }
}
/// Private only: source must be an exclusively owned stable storage capability.
/// All derived data/path/free candidates come from the captured original bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan(
    storage: &dyn Storage,
    scope: u128,
    generation: u64,
    path: &[NativeName],
    operation: Operation<'_>,
    ctime: u32,
    limits: Limits,
    r: &Resources,
) -> io::Result<Plan> {
    if let Operation::Create(request) = operation {
        return birth::plan(storage, scope, generation, path, request, ctime, limits, r);
    }
    let mut work = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    work.charge(1)?;
    let length = storage.len()?;
    if length > limits.source_bytes {
        return Err(unsupported("xattr source snapshot byte ceiling"));
    }
    let size = usize::try_from(length).map_err(io::Error::other)?;
    // Refuse before O(source) initialization, with a checked envelope for capture,
    // prospective copy, and both separately bounded complete ownership audits.
    let path_work = limits
        .audit
        .directory_blocks
        .checked_mul(MAX + 16)
        .and_then(|n| {
            limits
                .directory_entries
                .checked_mul(256)
                .and_then(|e| n.checked_add(e))
        })
        .and_then(|n| n.checked_add(MAX * 258 * 2))
        .and_then(|n| n.checked_mul(limits.path_depth))
        .ok_or_else(|| unsupported("xattr path work envelope overflow"))?;
    let envelope = size
        .checked_mul(9)
        .and_then(|v| {
            limits
                .audit
                .work
                .checked_mul(2)
                .and_then(|a| v.checked_add(a))
        })
        .and_then(|v| {
            limits
                .encoding
                .work
                .checked_mul(5)
                .and_then(|n| v.checked_add(n))
        })
        .and_then(|v| v.checked_add(path_work))
        .ok_or_else(|| unsupported("xattr planning work envelope overflow"))?;
    if envelope > limits.work {
        return Err(unsupported("xattr planning work envelope ceiling"));
    }
    let source_lease = r.memory.reserve(length).map_err(io::Error::other)?;
    let mut source = Vec::new();
    source.try_reserve_exact(size).map_err(io::Error::other)?;
    if source.capacity() > size {
        return Err(unsupported("xattr source snapshot capacity"));
    }
    work.charge(size)?;
    source.resize(size, 0);
    for (at, chunk) in source.chunks_mut(65536).enumerate() {
        work.charge(chunk.len())?;
        storage.read_exact_at(at as u64 * 65536, chunk)?;
        r.cancellation.check().map_err(io::Error::other)?;
    }
    if storage.len()? != length {
        return Err(invalid("xattr source length changed while capturing"));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    work.charge(size)?;
    let decoder = ExtDecoder::open_reader(Slice(&source), scope, r, true)?;
    let g = decoder.geometry();
    let bs = g.block_size as usize;
    if g.modern.is_some()
        || g.extent_profile
        || g.inode_size != 128
        || !g.has_journal
        || !g.external_xattrs
        || length != u64::from(g.blocks) * bs as u64
    {
        return Err(unsupported(
            "xattr COW requires complete classic journal EXT_ATTR volume",
        ));
    }
    if path.len() > limits.path_depth {
        return Err(unsupported("xattr path depth ceiling"));
    }
    work.charge(limits.audit.work)?;
    let audit = audit_decoder(&decoder, limits.audit, r).map_err(io::Error::other)?;
    if !audit.is_clean() {
        return Err(invalid(
            "xattr COW requires complete clean original ownership",
        ));
    }
    let mut number = 2;
    for name in path {
        work.charge(1)?;
        let NativeName::Bytes(name) = name else {
            return Err(unsupported("xattr path native bytes required"));
        };
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(invalid("xattr path component"));
        }
        work.charge(
            limits
                .audit
                .directory_blocks
                .checked_mul(bs + 16)
                .and_then(|n| {
                    limits
                        .directory_entries
                        .checked_mul(256)
                        .and_then(|e| n.checked_add(e))
                })
                .and_then(|n| n.checked_add(bs * 258 * 2))
                .ok_or_else(|| unsupported("xattr path decoder work overflow"))?,
        )?;
        let entries = decoder.directory(
            number,
            limits.audit.directory_blocks,
            limits.directory_entries,
            r,
        )?;
        let entry = entries
            .entries()
            .iter()
            .find(|e| matches!(&e.name,NativeName::Bytes(n)if n==name))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "xattr path absent"))?;
        number = entry.inode;
    }
    work.charge(bs * 259)?;
    let inode = decoder.inode(number, r)?;
    if !matches!(inode.mode() & 0xf000, 0x8000 | 0x4000)
        || number == g.journal_inode
        || u32le(inode.raw_metadata(), 32) != 0
    {
        return Err(unsupported(
            "xattr user namespace requires ordinary classic file/directory",
        ));
    }
    let external = u32le(inode.raw_metadata(), 104);
    let old = if external == 0 {
        None
    } else {
        let at = external as usize * bs;
        Some(&source[at..at + bs])
    };
    work.charge(
        limits
            .encoding
            .work
            .checked_mul(5)
            .ok_or_else(|| unsupported("ACL planning work overflow"))?,
    )?;
    let acl_limits = acl::Limits {
        bytes: limits.encoding.value_bytes,
        entries: limits.encoding.entries,
        work: limits.encoding.work,
    };
    let requested = match operation {
        Operation::Access(Some(bytes)) | Operation::Default(Some(bytes)) => {
            Some(acl::decode(bytes, acl_limits, r)?)
        }
        _ => None,
    };
    let current_view = if let Some(old) = old {
        Some(xattr::observe(
            old,
            0,
            true,
            xattr::ObservationLimits {
                bytes: bs,
                entries: limits.encoding.entries,
                value_bytes: limits.encoding.value_bytes,
                work: limits.encoding.work,
            },
            r,
        )?)
    } else {
        None
    };
    let current_bytes = current_view
        .as_ref()
        .filter(|_| matches!(operation, Operation::Chmod(_)))
        .and_then(|view| {
            view.entries()
                .find(|entry| entry.index == 2 && entry.name.is_empty())
                .map(|entry| entry.value)
        });
    let current = if let Some(bytes) = current_bytes {
        Some(acl::decode(bytes, acl_limits, r)?)
    } else {
        None
    };
    let request = match operation {
        Operation::Access(_) => acl_write::Request::Access(requested.as_ref()),
        Operation::Default(_) => acl_write::Request::Default(requested.as_ref()),
        Operation::Create(_) => return Err(invalid("ACL birth dispatch")),
        Operation::Chmod(permissions) => acl_write::Request::Chmod {
            permissions,
            current_access: current.as_ref(),
        },
    };
    let kind = if inode.mode() & 0xf000 == 0x4000 {
        acl_semantics::ChildKind::Directory
    } else {
        acl_semantics::ChildKind::Regular
    };
    let prepared = acl_write::prepare(
        request,
        kind,
        inode.mode(),
        acl_write::Limits {
            bytes: limits.encoding.value_bytes,
            entries: limits.encoding.entries,
            work: limits.encoding.work,
        },
        r,
    )?;
    let rewritten = acl_container::rewrite(
        old,
        bs,
        &prepared,
        acl_container::Limits {
            entries: limits.encoding.entries,
            value_bytes: limits.encoding.value_bytes,
            work: limits.encoding.work,
        },
        r,
    )?;
    let metadata_changed = prepared.mode != inode.mode();
    let changed = rewritten.changed || metadata_changed;
    let home_bytes = limits
        .records
        .checked_mul(core::mem::size_of::<Home>())
        .ok_or_else(|| unsupported("xattr home inventory overflow"))?;
    let homes_lease = r
        .memory
        .reserve(home_bytes as u64)
        .map_err(io::Error::other)?;
    let mut homes = Vec::new();
    homes
        .try_reserve_exact(limits.records)
        .map_err(io::Error::other)?;
    if homes.capacity() > limits.records {
        return Err(unsupported("xattr home inventory capacity"));
    }
    work.charge(bs * 259)?;
    let journal_inode = decoder.inode(g.journal_inode, r)?;
    let journal_count =
        usize::try_from(journal_inode.len() / bs as u64).map_err(io::Error::other)?;
    work.charge(
        journal_count
            .checked_mul(journal_count)
            .ok_or_else(|| unsupported("xattr journal alias work overflow"))?,
    )?;
    let journal_lease = r
        .memory
        .reserve(
            journal_count
                .checked_mul(4)
                .ok_or_else(|| unsupported("xattr journal map overflow"))? as u64,
        )
        .map_err(io::Error::other)?;
    let mut journal = Vec::new();
    journal
        .try_reserve_exact(journal_count)
        .map_err(io::Error::other)?;
    if journal.capacity() > journal_count {
        return Err(unsupported("xattr journal map capacity"));
    }
    work.charge(
        journal_count
            .checked_mul(bs + 16)
            .ok_or_else(|| unsupported("xattr journal decoder work overflow"))?,
    )?;
    let map = decoder.file_map(g.journal_inode, journal_count, r, false)?;
    for e in &map.extents {
        work.charge(1)?;
        let super::ExtentKind::Data(at) = e.kind else {
            return Err(invalid("xattr journal mapping must be dense data"));
        };
        if !at.is_multiple_of(bs as u64)
            || !e.length.is_multiple_of(bs as u64)
            || e.offset != journal.len() as u64 * bs as u64
        {
            return Err(invalid("xattr journal mapping framing"));
        }
        for relative in (0..e.length).step_by(bs) {
            work.charge(1)?;
            let block = u32::try_from((at + relative) / bs as u64).map_err(io::Error::other)?;
            if journal.len() >= journal_count || journal.contains(&block) {
                return Err(invalid("xattr journal mapping alias/length"));
            }
            journal.push(block);
        }
    }
    if journal_inode.is_empty() || !journal_inode.len().is_multiple_of(bs as u64) {
        return Err(invalid("xattr original journal length"));
    }
    if journal.len() != journal_count {
        return Err(invalid("xattr original journal coverage"));
    }
    work.charge(2048)?;
    let primary: &[u8; 1024] = source[1024..2048].try_into().map_err(io::Error::other)?;
    let journal_at = journal[0] as usize * bs;
    let header: &[u8; 1024] = source[journal_at..journal_at + 1024]
        .try_into()
        .map_err(io::Error::other)?;
    super::jbd::xattr::clean_geometry(primary, header, journal.len())?;
    let mut new_external = external;
    if rewritten.changed {
        if let Some(encoded) = rewritten.block.as_ref() {
            let candidate = audit
                .free_ranges()
                .iter()
                .find(|range| range.length >= bs as u64)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::StorageFull, "ACL COW no audited free block")
                })?;
            new_external = (candidate.offset / bs as u64) as u32;
            patch(&mut homes, &source, new_external, bs, limits.records)?
                .copy_from_slice(encoded.bytes());
            bitmap(
                &decoder,
                &mut homes,
                &source,
                new_external,
                true,
                limits.records,
                &mut work,
            )?;
        } else {
            new_external = 0;
        }
        if external != 0 {
            let refs = u32le(
                old.ok_or_else(|| invalid("xattr original external container missing"))?,
                4,
            );
            if refs == 1 {
                bitmap(
                    &decoder,
                    &mut homes,
                    &source,
                    external,
                    false,
                    limits.records,
                    &mut work,
                )?;
            } else {
                let b = patch(&mut homes, &source, external, bs, limits.records)?;
                put32(
                    b,
                    4,
                    refs.checked_sub(1)
                        .ok_or_else(|| invalid("xattr reference underflow"))?,
                );
            }
        }
        let descriptor = decoder.group((number - 1) / g.inodes_per_group)?;
        let at = u64::from(descriptor[2]) * bs as u64
            + u64::from((number - 1) % g.inodes_per_group) * 128;
        let block = (at / bs as u64) as u32;
        let inside = (at % bs as u64) as usize;
        let home = patch(&mut homes, &source, block, bs, limits.records)?;
        put32(home, inside + 104, new_external);
        if external == 0 && new_external != 0 {
            let sectors = u32le(home, inside + 28)
                .checked_add(g.block_size / 512)
                .ok_or_else(|| invalid("xattr inode sector overflow"))?;
            put32(home, inside + 28, sectors);
        } else if external != 0 && new_external == 0 {
            let sectors = u32le(home, inside + 28)
                .checked_sub(g.block_size / 512)
                .ok_or_else(|| invalid("ACL released inode sector underflow"))?;
            put32(home, inside + 28, sectors);
        }
    }
    if changed {
        // Durable OLD primary is required even for a mode-only transaction.
        patch(
            &mut homes,
            &source,
            u32::from(bs == 1024),
            bs,
            limits.records,
        )?;
        let descriptor = decoder.group((number - 1) / g.inodes_per_group)?;
        let at = u64::from(descriptor[2]) * bs as u64
            + u64::from((number - 1) % g.inodes_per_group) * 128;
        let home = patch(
            &mut homes,
            &source,
            (at / bs as u64) as u32,
            bs,
            limits.records,
        )?;
        let inside = (at % bs as u64) as usize;
        home[inside..inside + 2].copy_from_slice(&prepared.mode.to_le_bytes());
        put32(home, inside + 12, ctime);
        let physical = (homes.len() as u64)
            .checked_mul(bs as u64)
            .ok_or_else(|| unsupported("xattr physical home footprint overflow"))?;
        if physical > limits.affected_bytes {
            return Err(unsupported("xattr affected home byte ceiling"));
        }
        work.charge(
            size.checked_mul(2)
                .ok_or_else(|| unsupported("xattr prospective copy work overflow"))?,
        )?;
        let (mut prospective, _lease) = copy(&source, r)?;
        for h in &homes {
            work.charge(bs)?;
            let at = h.block as usize * bs;
            prospective[at..at + bs].copy_from_slice(&h.replacement[..bs]);
        }
        work.charge(limits.audit.work)?;
        work.charge(size)?;
        let next = ExtDecoder::open_reader(Slice(&prospective), scope, r, true)?;
        let proof = audit_decoder(&next, limits.audit, r).map_err(io::Error::other)?;
        if !proof.is_clean() {
            return Err(invalid("xattr COW prospective ownership is not clean"));
        }
    }
    drop((audit, map, decoder));
    // Native scan_owned exposes redo in destination order. Seal ORIGINAL homes
    // in the same canonical order so cold reconstruction is byte-exact.
    work.charge(
        homes
            .len()
            .checked_mul(homes.len())
            .ok_or_else(|| unsupported("xattr canonical home ordering work overflow"))?,
    )?;
    homes.sort_unstable_by_key(|home| home.block);
    let intent_ceiling = limits
        .path_depth
        .checked_mul(259)
        .and_then(|n| n.checked_add(255))
        .and_then(|n| n.checked_add(limits.encoding.value_bytes))
        .ok_or_else(|| unsupported("xattr sealed intent ceiling overflow"))?;
    work.charge(
        limits
            .path_depth
            .checked_mul(8)
            .and_then(|n| n.checked_add(intent_ceiling))
            .and_then(|n| n.checked_add(64))
            .ok_or_else(|| unsupported("xattr intent work overflow"))?,
    )?;
    let intent = intent_digest(path, operation, ctime, intent_ceiling, r)?;
    work.charge(size)?;
    use sha2::{Digest, Sha256};
    let mut original_hash = Sha256::new();
    original_hash.update(b"partmgr-acl-exact-plan-source-v4");
    for chunk in source.chunks(65536) {
        r.cancellation.check().map_err(io::Error::other)?;
        original_hash.update(chunk);
    }
    r.cancellation.check().map_err(io::Error::other)?;
    let original_digest = original_hash.finalize().into();
    let result = Plan {
        scope,
        generation,
        block_bytes: bs,
        source,
        homes,
        journal,
        inode: number,
        old_external: external,
        new_external,
        changed,
        intent,
        original_digest,
        _source: source_lease,
        _homes: homes_lease,
        _journal: journal_lease,
    };
    result.check_source(storage, false, limits.work.saturating_sub(work.used), r)?;
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(result)
}

/// Exact operation identity is retained even when no homes change.
pub(super) fn intent_digest(
    path: &[NativeName],
    operation: Operation<'_>,
    ctime: u32,
    maximum_bytes: usize,
    r: &Resources,
) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    r.cancellation.check().map_err(io::Error::other)?;
    let (opcode, value, permissions) = match operation {
        Operation::Access(None) => (0, &[][..], 0),
        Operation::Access(Some(value)) => (1, value, 0),
        Operation::Default(None) => (2, &[][..], 0),
        Operation::Default(Some(value)) => (3, value, 0),
        Operation::Chmod(mode) => (4, &[][..], mode),
        Operation::Create(request) => {
            let (value, _lease) = birth::encode(request, maximum_bytes, r)?;
            return birth::intent(path, &value, ctime, maximum_bytes, r);
        }
    };
    let mut size = value.len();
    let mut hash = Sha256::new();
    hash.update(b"partmgr-acl-exact-intent-v4");
    hash.update([opcode]);
    hash.update(ctime.to_le_bytes());
    hash.update(permissions.to_le_bytes());
    hash.update((path.len() as u64).to_le_bytes());
    for component in path {
        r.cancellation.check().map_err(io::Error::other)?;
        let NativeName::Bytes(name) = component else {
            return Err(unsupported("ACL intent native path"));
        };
        size = size
            .checked_add(name.len() + 8)
            .filter(|n| *n <= maximum_bytes)
            .ok_or_else(|| unsupported("ACL intent byte ceiling"))?;
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
    }
    if size > maximum_bytes {
        return Err(unsupported("ACL intent value ceiling"));
    }
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(hash.finalize().into())
}
