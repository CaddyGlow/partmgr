//! Private native unwritten KEEP_SIZE reservation; no payload initialization.
use super::*;
use crate::storage::Storage;
use core::cell::Cell;

pub(super) struct SourceGuards {
    bytes: Vec<(u64, Vec<u8>)>,
    remaining: Cell<u8>,
    scope: u128,
    generation: Option<u64>,
    owner: u32,
    block_size: usize,
    inode_size: usize,
    length: u64,
    _lease: Reservation,
}
impl SourceGuards {
    pub(super) fn bind(&mut self, scope: u128, generation: u64) -> io::Result<()> {
        if self.scope != scope || self.generation.is_some() {
            return Err(invalid("modern guard source binding"));
        }
        self.generation = Some(generation);
        Ok(())
    }
    pub(super) fn guards(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.bytes.iter().map(|(at, bytes)| (*at, bytes.as_slice()))
    }
    pub(super) fn validate(
        &self,
        scope: u128,
        generation: u64,
        decoder: &ExtStorageDecoder<'_>,
        r: &Resources,
        work_limit: usize,
    ) -> io::Result<usize> {
        let mut work = 1usize;
        if work > work_limit {
            return Err(budget("modern guard validation work"));
        }
        r.cancellation.check().map_err(io::Error::other)?;
        let g = &decoder.geometry;
        if self.scope != scope
            || self.generation != Some(generation)
            || decoder.source_id != scope
            || self.block_size != g.block_size as usize
            || self.inode_size != usize::from(g.inode_size)
            || !matches!(self.inode_size, 128 | 256)
            || self.owner < 11
            || self.owner > g.inodes
            || decoder.source.len()? != self.length
        {
            return Err(invalid("modern guard controller source geometry"));
        }
        let modern = g
            .modern
            .as_ref()
            .ok_or_else(|| invalid("modern guards require modern owner"))?;
        let descriptor = &modern.descriptors[((self.owner - 1) / g.inodes_per_group) as usize];
        let inode_at = u64::from(super::super::super::u32le(descriptor, 8))
            * u64::from(g.block_size)
            + u64::from((self.owner - 1) % g.inodes_per_group) * u64::from(g.inode_size);
        if self.bytes.is_empty() {
            return Err(invalid("modern guard missing owner"));
        }
        for (index, (at, bytes)) in self.bytes.iter().enumerate() {
            work = work
                .checked_add(1)
                .filter(|n| *n <= work_limit)
                .ok_or_else(|| budget("modern guard validation work"))?;
            r.cancellation.check().map_err(io::Error::other)?;
            if at
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.length)
                || if index == 0 {
                    *at != inode_at || bytes.len() != self.inode_size
                } else {
                    bytes.len() != self.block_size || !at.is_multiple_of(self.block_size as u64)
                }
            {
                return Err(invalid("modern guard owner or range"));
            }
        }
        r.cancellation.check().map_err(io::Error::other)?;
        Ok(work)
    }
    pub(super) fn inode_guard_geometry(&self, at: u64, size: usize) -> bool {
        self.bytes.first().is_some_and(|(owner, bytes)| {
            *owner == at && bytes.len() == size && size == self.inode_size
        })
    }

    pub(super) fn check(&self, storage: &dyn Storage, r: &Resources) -> io::Result<()> {
        if self.remaining.get() == 0 {
            return Err(budget("reservation source guard pass ceiling"));
        }
        self.remaining.set(self.remaining.get() - 1);
        let mut scratch = [0u8; MAX_BLOCK];
        for (offset, expected) in &self.bytes {
            r.cancellation.check().map_err(io::Error::other)?;
            if expected.len() > scratch.len() {
                return Err(invalid("reservation guard size"));
            }
            storage.read_exact_at(*offset, &mut scratch[..expected.len()])?;
            r.cancellation.check().map_err(io::Error::other)?;
            if storage.len()? != self.length {
                return Err(invalid("modern guard source length changed"));
            }
            r.cancellation.check().map_err(io::Error::other)?;
            if &scratch[..expected.len()] != expected.as_slice() {
                return Err(invalid("reservation exact source guard changed"));
            }
        }
        Ok(())
    }
}
struct Projection<'a> {
    source: &'a dyn Storage,
    patches: &'a [WriteRange],
    work: Cell<usize>,
    limit: usize,
    resources: &'a Resources,
}
impl Projection<'_> {
    fn tick(&self, count: usize) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.work.set(
            self.work
                .get()
                .checked_add(count)
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| budget("modern reservation projection work"))?,
        );
        Ok(())
    }
}
impl Storage for Projection<'_> {
    fn len(&self) -> io::Result<u64> {
        self.tick(1)?;
        self.source.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.tick(out.len())?;
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or_else(|| invalid("reservation projection offset"))?;
        self.source.read_exact_at(offset, out)?;
        // Finite charged linear lookup, including misses; no uncharged sort/search.
        for patch in self.patches {
            self.tick(1)?;
            let patch_end = patch
                .offset()
                .checked_add(patch.replacement().len() as u64)
                .ok_or_else(|| invalid("reservation projection patch end"))?;
            let start = offset.max(patch.offset());
            let stop = end.min(patch_end);
            if start < stop {
                self.tick((stop - start) as usize)?;
                out[(start - offset) as usize..(stop - offset) as usize].copy_from_slice(
                    &patch.replacement()
                        [(start - patch.offset()) as usize..(stop - patch.offset()) as usize],
                );
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(unsupported("read-only reservation projection"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(unsupported("read-only reservation projection"))
    }
}

/// Reserve every missing native logical block intersecting the byte range as
/// unwritten, without changing i_size or writing any regular payload block.
/// This reserves native blocks; it does not guarantee future COW writes or
/// extent-tree splits can succeed without additional free metadata allocation.
pub(in super::super) fn keep_size(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    inode: &ExtInode,
    offset: u64,
    length: u64,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    resources.cancellation.check().map_err(io::Error::other)?;
    if inode.mode & 0xf000 != 0x8000
        || inode.number < 11
        || super::super::super::u32le(&inode.raw, 32) & 0x80000 == 0
        || super::super::super::u32le(&inode.raw, 32) & !0x80000 != 0
        || super::super::super::u16le(&inode.raw, 116) != 0
    {
        return Err(unsupported(
            "KEEP_SIZE reservation requires ordinary extent inode without special flags/huge sectors",
        ));
    }
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let current = decoder.inode(inode.number, resources)?;
    context.tick(256)?;
    if current.raw != inode.raw || current.extra != inode.extra {
        return Err(invalid("reservation inode source changed"));
    }
    let bs = u64::from(decoder.geometry.block_size);
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("reservation byte range overflow"))?;
    let first = offset / bs;
    let last = if length == 0 { first } else { end.div_ceil(bs) };
    if last > u64::from(u32::MAX) + 1 || last > limits.file_blocks as u64 {
        return Err(budget("reservation logical block ceiling"));
    }
    let decoded = context.allocation_map(inode)?;
    let guard_count = decoded
        .metadata
        .len()
        .checked_add(1)
        .ok_or_else(|| budget("reservation guard count"))?;
    let guard_bytes = decoded
        .metadata
        .len()
        .checked_mul(bs as usize)
        .and_then(|n| n.checked_add(usize::from(decoder.geometry.inode_size)))
        .ok_or_else(|| budget("reservation guard bytes"))?;
    let guard_charge = guard_bytes
        .checked_add(
            guard_count
                .checked_mul(64)
                .ok_or_else(|| budget("reservation guard inventory"))?,
        )
        .ok_or_else(|| budget("reservation guard charge"))?;
    let guard_lease = resources
        .memory
        .reserve(guard_charge as u64)
        .map_err(io::Error::other)?;
    // Prepay up to two local guard read+compare passes for no-op/private checks.
    // Publication guards are independently charged by the controller.
    context.tick(
        guard_bytes
            .checked_mul(4)
            .ok_or_else(|| budget("reservation guard work"))?,
    )?;
    let mut guards = Vec::new();
    guards
        .try_reserve_exact(guard_count)
        .map_err(|_| budget("reservation guard vector"))?;
    if guards.capacity() > guard_count {
        return Err(budget("reservation guard vector capacity"));
    }
    let g = &decoder.geometry;
    let descriptor =
        &g.modern.as_ref().unwrap().descriptors[((inode.number - 1) / g.inodes_per_group) as usize];
    let inode_at = u64::from(super::super::super::u32le(descriptor, 8)) * bs
        + u64::from((inode.number - 1) % g.inodes_per_group) * u64::from(g.inode_size);
    let mut inode_bytes = Vec::new();
    inode_bytes
        .try_reserve_exact(usize::from(g.inode_size))
        .map_err(|_| budget("reservation inode guard"))?;
    if inode_bytes.capacity() > usize::from(g.inode_size) {
        return Err(budget("reservation inode guard capacity"));
    }
    inode_bytes.extend_from_slice(&inode.raw);
    inode_bytes.extend_from_slice(&inode.extra[..usize::from(g.inode_size) - 128]);
    guards.push((inode_at, inode_bytes));
    for physical in &decoded.metadata {
        context.tick(bs as usize)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(bs as usize)
            .map_err(|_| budget("reservation tree guard"))?;
        if bytes.capacity() > bs as usize {
            return Err(budget("reservation tree guard capacity"));
        }
        bytes.resize(bs as usize, 0);
        decoder.read_exact_at(u64::from(*physical) * bs, &mut bytes)?;
        guards.push((u64::from(*physical) * bs, bytes));
    }
    let again = context.allocation_map(inode)?;
    context.tick(
        decoded
            .allocations
            .len()
            .checked_add(decoded.metadata.len())
            .ok_or_else(|| budget("reservation coherent map work"))?,
    )?;
    if again.allocations.len() != decoded.allocations.len()
        || again.metadata != decoded.metadata
        || !again
            .allocations
            .iter()
            .zip(&decoded.allocations)
            .all(|(a, b)| {
                a.logical == b.logical
                    && a.physical == b.physical
                    && a.blocks == b.blocks
                    && a.unwritten == b.unwritten
            })
    {
        return Err(invalid("reservation source tree changed during capture"));
    }
    drop(again);
    let source_guards = SourceGuards {
        bytes: guards,
        remaining: Cell::new(2),
        scope: decoder.source_id,
        generation: None,
        owner: inode.number,
        block_size: bs as usize,
        inode_size: usize::from(g.inode_size),
        length: decoder.source.len()?,
        _lease: guard_lease,
    };
    let mut count = last as usize;
    for allocation in &decoded.allocations {
        context.tick(1)?;
        count = count.max(
            usize::try_from(
                allocation
                    .logical
                    .checked_add(u64::from(allocation.blocks))
                    .ok_or_else(|| invalid("reservation original logical end"))?,
            )
            .map_err(|_| budget("reservation original map size"))?,
        );
    }
    if count > limits.file_blocks {
        return Err(budget("reservation complete allocation ceiling"));
    }
    // Context's file_blocks*256 reservation covers both dense maps, extent rows,
    // and writer index temporaries; retained through Plan extraction/publication.
    let mut data = Vec::<Option<(u32, bool)>>::new();
    data.try_reserve_exact(count)
        .map_err(|_| budget("reservation complete map"))?;
    if data.capacity() > count {
        return Err(budget("reservation map capacity"));
    }
    context.tick(count)?;
    data.resize(count, None);
    for allocation in &decoded.allocations {
        for relative in 0..allocation.blocks {
            context.tick(1)?;
            let slot = allocation.logical as usize + relative as usize;
            if data[slot]
                .replace((allocation.physical + relative, allocation.unwritten))
                .is_some()
            {
                return Err(invalid("reservation original overlap"));
            }
        }
    }
    let mut changed = false;
    if length != 0 {
        for logical in first..last {
            context.tick(1)?;
            if data[logical as usize].is_none() {
                let physical = context.allocate()?;
                // allocate() has not seen releases; assert native original-free
                // provenance independently of its mutable bitmap projection.
                if decoder
                    .geometry
                    .modern
                    .as_ref()
                    .unwrap()
                    .is_allocated(physical, false)
                {
                    return Err(invalid("reservation allocation reused original ownership"));
                }
                data[logical as usize] = Some((physical, true));
                changed = true;
            }
        }
    }
    if !changed {
        // Native idempotent/no-op: no dirty fence, journal or home writes required.
        return Ok(Plan {
            patches: Vec::new(),
            _reservation: context.reservation,
            source_guards: Some(source_guards),
        });
    }
    let mut allocations = Vec::<super::super::super::extent::ExtentAllocation>::new();
    allocations
        .try_reserve_exact(count)
        .map_err(|_| budget("reservation extent rows"))?;
    if allocations.capacity() > count {
        return Err(budget("reservation extent row capacity"));
    }
    for (logical, entry) in data.iter().copied().enumerate() {
        context.tick(1)?;
        let Some((physical, unwritten)) = entry else {
            continue;
        };
        let maximum = if unwritten { 32767 } else { 32768 };
        if let Some(previous) = allocations.last_mut()
            && previous.logical + u64::from(previous.blocks) == logical as u64
            && previous.physical.checked_add(previous.blocks) == Some(physical)
            && previous.unwritten == unwritten
            && previous.blocks < maximum
        {
            previous.blocks += 1;
        } else {
            allocations.push(super::super::super::extent::ExtentAllocation {
                logical: logical as u64,
                physical,
                blocks: 1,
                unwritten,
            });
        }
    }
    // Build replacement tree from original-free blocks BEFORE freeing old tree.
    // Old tree stays readable at every prepublication cut; no same-plan reuse.
    extent_writer::write_inode(&mut context, inode, inode.length, &allocations)?;
    for physical in &decoded.metadata {
        context.release(*physical)?;
    }
    // Do not let patch() adopt drifted bytes as new expected values. Inode patch
    // must carry the exact original guard, and old tree guards remain exact.
    for (offset, expected) in &source_guards.bytes {
        context.tick(
            expected
                .len()
                .checked_mul(2)
                .ok_or_else(|| budget("reservation final guard work"))?,
        )?;
        let mut scratch = [0u8; MAX_BLOCK];
        decoder.read_exact_at(*offset, &mut scratch[..expected.len()])?;
        if &scratch[..expected.len()] != expected.as_slice() {
            return Err(invalid("reservation source changed before finish"));
        }
        for index in 0..context.patches.len() {
            context.tick(1)?;
            let patch = &context.patches[index];
            if patch.offset() == *offset && patch.expected() != expected.as_slice() {
                return Err(invalid("reservation patch adopted changed source"));
            }
        }
    }
    let (mut plan, planning_work) = context.finish_with_work()?;
    let projection = Projection {
        source: decoder.source,
        patches: &plan.patches,
        work: Cell::new(planning_work),
        limit: limits.work,
        resources,
    };
    let (projected, proof) = super::super::super::ExtDecoder::open_native_clean(
        &projection as &dyn Storage,
        decoder.source_id,
        resources,
    )?;
    let after_audit = crate::fs_ext_audit::audit_decoder(&projected, limits.audit, resources)
        .map_err(io::Error::other)?;
    if !after_audit.is_clean() {
        return Err(invalid(
            "reservation prospective complete ownership audit rejected",
        ));
    }
    let after = projected.inode(inode.number, resources)?;
    if after.length != inode.length {
        return Err(invalid("KEEP_SIZE reservation changed visible length"));
    }
    // All unmanaged inode bytes and external xattr identity remain exact. Extent
    // tree, i_blocks and inode checksums are the only permitted changes.
    for index in 0..usize::from(decoder.geometry.inode_size) {
        projection.tick(1)?;
        let managed = (28..32).contains(&index)
            || (40..100).contains(&index)
            || (124..126).contains(&index)
            || (130..132).contains(&index);
        let before = if index < 128 {
            inode.raw[index]
        } else {
            inode.extra[index - 128]
        };
        let actual = if index < 128 {
            after.raw[index]
        } else {
            after.extra[index - 128]
        };
        if !managed && before != actual {
            return Err(invalid("reservation changed unrelated inode field"));
        }
    }
    let actual = projected.extent_allocations(&after, limits.file_blocks, resources)?;
    let mut observed = Vec::<Option<(u32, bool)>>::new();
    observed
        .try_reserve_exact(count)
        .map_err(|_| budget("reservation semantic map"))?;
    if observed.capacity() > count {
        return Err(budget("reservation semantic map capacity"));
    }
    projection.tick(count)?;
    observed.resize(count, None);
    for allocation in &actual.allocations {
        for relative in 0..allocation.blocks {
            projection.tick(1)?;
            let slot = usize::try_from(allocation.logical + u64::from(relative))
                .map_err(|_| budget("reservation final logical index"))?;
            if slot >= count
                || observed[slot]
                    .replace((allocation.physical + relative, allocation.unwritten))
                    .is_some()
            {
                return Err(invalid("reservation final overlap/range"));
            }
        }
    }
    for logical in 0..count {
        projection.tick(1)?;
        if observed[logical] != data[logical] {
            return Err(invalid("reservation final allocation proof differs"));
        }
    }
    // No regular data writes, including stale backing of fresh unwritten blocks.
    projection.tick(data.len())?;
    for entry in data.iter().flatten() {
        let lo = u64::from(entry.0) * bs;
        let hi = lo + bs;
        for patch in &plan.patches {
            projection.tick(1)?;
            if patch.offset() < hi && patch.offset() + patch.replacement().len() as u64 > lo {
                return Err(invalid("reservation plan contains regular payload write"));
            }
        }
    }
    drop((actual, after, after_audit, projected, proof));
    plan.source_guards = Some(source_guards);
    Ok(plan)
}

#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_jbd_modern_preallocate_tests.rs"]
mod tests;
