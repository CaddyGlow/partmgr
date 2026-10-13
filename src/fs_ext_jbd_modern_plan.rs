//! Borrowed same-owner modern extent mutation planning; publication belongs to JBD2.
use super::*;
use crate::platform::collections::BTreeMap;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_ext::{ExtInode, ExtStorageDecoder},
    fs_ext_audit::ExtAuditReport,
    fs_ext_edit::ExtEditLimits,
    storage::WriteRange,
};
#[path = "fs_ext_jbd_modern_extent.rs"]
mod extent_writer;
#[path = "fs_ext_jbd_modern_indirect.rs"]
mod indirect_writer;
#[path = "fs_ext_jbd_modern_preallocate.rs"]
mod preallocate;
pub(super) use preallocate::keep_size;
fn write_inode(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    length: u64,
    allocations: &[super::super::extent::ExtentAllocation],
) -> io::Result<()> {
    if super::super::u32le(&inode.raw, 32) & 0x80000 != 0 {
        extent_writer::write_inode(context, inode, length, allocations)
    } else {
        indirect_writer::write_inode(context, inode, length, allocations)
    }
}
#[path = "fs_ext_jbd_modern_htree.rs"]
mod htree;
#[path = "fs_ext_jbd_modern_inode.rs"]
mod inode_writer;
#[path = "fs_ext_jbd_modern_namespace.rs"]
mod namespace;
pub(super) use namespace::{Create, Delete, Rename, create, delete, rename};

pub(super) struct Plan {
    pub(super) patches: Vec<WriteRange>,
    _reservation: Reservation,
    source_guards: Option<preallocate::SourceGuards>,
}
impl Plan {
    pub(super) fn bind_source_guards(&mut self, scope: u128, generation: u64) -> io::Result<()> {
        if let Some(guards) = &mut self.source_guards {
            guards.bind(scope, generation)?;
        }
        Ok(())
    }
    pub(super) fn source_guards(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.source_guards.iter().flat_map(|g| g.guards())
    }
    pub(super) fn validate_source_guards(
        &self,
        scope: u128,
        generation: u64,
        decoder: &ExtStorageDecoder<'_>,
        r: &Resources,
        work_limit: usize,
    ) -> io::Result<usize> {
        match &self.source_guards {
            Some(guards) => guards.validate(scope, generation, decoder, r, work_limit),
            None => Ok(0),
        }
    }
    pub(super) fn inode_guard_geometry(&self, at: u64, size: usize) -> bool {
        self.source_guards
            .as_ref()
            .is_some_and(|g| g.inode_guard_geometry(at, size))
    }

    pub(super) fn check_source_guards(
        &self,
        storage: &dyn crate::storage::Storage,
        resources: &Resources,
    ) -> io::Result<()> {
        if let Some(guards) = &self.source_guards {
            guards.check(storage, resources)?;
        }
        Ok(())
    }
}
struct Group {
    bitmap: Vec<u8>,
    inode_bitmap: Option<Vec<u8>>,
    block_dirty: bool,
    descriptor: [u8; 64],
}
struct Context<'a, 's> {
    decoder: &'a ExtStorageDecoder<'s>,
    limits: ExtEditLimits,
    resources: &'a Resources,
    groups: BTreeMap<u32, Group>,
    patches: Vec<WriteRange>,
    bytes: u64,
    work: usize,
    released: u32,
    allocated: u32,
    allocated_inodes: u32,
    released_inodes: u32,
    cursor: u32,
    reservation: Reservation,
}
impl<'a, 's> Context<'a, 's> {
    fn allocation_map(
        &mut self,
        inode: &ExtInode,
    ) -> io::Result<super::super::extent::DecodedExtents> {
        if super::super::u32le(&inode.raw, 32) & 0x80000 != 0 {
            self.decoder
                .extent_allocations(inode, self.limits.file_blocks, self.resources)
        } else {
            indirect_writer::decode(self, inode)
        }
    }

    fn new(
        decoder: &'a ExtStorageDecoder<'s>,
        audit: &ExtAuditReport,
        limits: ExtEditLimits,
        resources: &'a Resources,
    ) -> io::Result<Self> {
        if !audit.is_clean() || decoder.geometry.modern.is_none() {
            return Err(unsupported(
                "modern mutation requires same-owner clean complete audit",
            ));
        }
        let charge = limits
            .affected_bytes
            .checked_mul(2)
            .and_then(|n| {
                n.checked_add(u64::from(decoder.geometry.groups) * (2 * MAX_BLOCK as u64 + 1536))
            })
            .and_then(|n| {
                n.checked_add(
                    u64::from(limits.undo.patches)
                        * (crate::platform::mem::size_of::<WriteRange>() as u64 + 128),
                )
            })
            .and_then(|n| {
                (limits.file_blocks as u64)
                    .checked_mul(256)
                    .and_then(|charge| n.checked_add(charge))
            })
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| budget("modern mutation planning accounting"))?;
        let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(limits.undo.patches as usize)
            .map_err(|_| budget("modern mutation patch vector"))?;
        if patches.capacity() > limits.undo.patches as usize {
            return Err(budget("modern mutation patch capacity"));
        }
        Ok(Self {
            decoder,
            limits,
            resources,
            groups: BTreeMap::new(),
            patches,
            bytes: 0,
            work: 0,
            released: 0,
            allocated: 0,
            allocated_inodes: 0,
            released_inodes: 0,
            cursor: decoder.geometry.first,
            reservation,
        })
    }
    fn tick(&mut self, count: usize) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.work = self
            .work
            .checked_add(count)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("modern mutation work ceiling"))?;
        Ok(())
    }
    fn patch(&mut self, offset: u64, after: &[u8]) -> io::Result<()> {
        self.tick(after.len())?;
        self.bytes = self
            .bytes
            .checked_add(after.len() as u64)
            .filter(|n| *n <= self.limits.affected_bytes)
            .ok_or_else(|| budget("modern mutation affected bytes"))?;
        if self.patches.len() >= self.limits.undo.patches as usize {
            return Err(budget("modern mutation patch ceiling"));
        }
        let mut before = Vec::new();
        before
            .try_reserve_exact(after.len())
            .map_err(|_| budget("modern mutation expected bytes"))?;
        before.resize(after.len(), 0);
        self.decoder.read_exact_at(offset, &mut before)?;
        let mut new = Vec::new();
        new.try_reserve_exact(after.len())
            .map_err(|_| budget("modern mutation replacement bytes"))?;
        new.extend_from_slice(after);
        self.patches.push(WriteRange::new(offset, before, new)?);
        Ok(())
    }
    fn ensure_group(&mut self, group: u32) -> io::Result<()> {
        let g = &self.decoder.geometry;
        let proof = g.modern.as_ref().unwrap();
        if let crate::platform::collections::btree_map::Entry::Vacant(entry) =
            self.groups.entry(group)
        {
            let descriptor = *proof
                .descriptors
                .get(group as usize)
                .ok_or_else(|| invalid("modern release group bounds"))?;
            let mut bitmap = Vec::new();
            bitmap
                .try_reserve_exact(g.block_size as usize)
                .map_err(|_| budget("modern bitmap projection"))?;
            if bitmap.capacity() > g.block_size as usize {
                return Err(budget("modern bitmap capacity"));
            }
            bitmap.resize(g.block_size as usize, 0);
            let offset = group as usize * 2 * g.block_size as usize;
            bitmap[..g.block_size as usize]
                .copy_from_slice(&proof.bitmaps[offset..offset + g.block_size as usize]);
            entry.insert(Group {
                bitmap,
                inode_bitmap: None,
                block_dirty: false,
                descriptor,
            });
        }
        Ok(())
    }
    fn allocate(&mut self) -> io::Result<u32> {
        let g = &self.decoder.geometry;
        let blocks = g.blocks;
        let first = g.first;
        let per = g.blocks_per_group;
        while self.cursor < blocks {
            self.tick(1)?;
            let physical = self.cursor;
            self.cursor += 1;
            let group = (physical - first) / per;
            let bit = ((physical - first) % per) as usize;
            let mask = 1 << (bit % 8);
            let current = self.groups.get(&group).map_or_else(
                || {
                    self.decoder.geometry.modern.as_ref().unwrap().bitmaps
                        [group as usize * 2 * self.decoder.geometry.block_size as usize + bit / 8]
                },
                |row| row.bitmap[bit / 8],
            );
            if current & mask != 0 {
                continue;
            }
            self.ensure_group(group)?;
            let row = self.groups.get_mut(&group).unwrap();
            row.block_dirty = true;
            row.bitmap[bit / 8] |= mask;
            let flags = super::super::u16le(&row.descriptor, 18) & !2;
            row.descriptor[18..20].copy_from_slice(&flags.to_le_bytes());
            let mut count = u32::from(super::super::u16le(&row.descriptor, 12));
            if self
                .decoder
                .geometry
                .modern
                .as_ref()
                .unwrap()
                .descriptor_size
                == 64
            {
                count |= u32::from(super::super::u16le(&row.descriptor, 44)) << 16;
            }
            count = count
                .checked_sub(1)
                .ok_or_else(|| invalid("modern allocation free count underflow"))?;
            row.descriptor[12..14].copy_from_slice(&(count as u16).to_le_bytes());
            if self
                .decoder
                .geometry
                .modern
                .as_ref()
                .unwrap()
                .descriptor_size
                == 64
            {
                row.descriptor[44..46].copy_from_slice(&((count >> 16) as u16).to_le_bytes());
            }
            self.allocated = self
                .allocated
                .checked_add(1)
                .ok_or_else(|| budget("modern allocation count"))?;
            return Ok(physical);
        }
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "modern native allocation has no free block",
        ))
    }
    fn release(&mut self, physical: u32) -> io::Result<()> {
        self.tick(1)?;
        let g = &self.decoder.geometry;
        let proof = g.modern.as_ref().unwrap();
        if !proof.is_allocated(physical, false) || proof.metadata_block(physical) {
            return Err(invalid("modern release outside audited payload ownership"));
        }
        let index = physical
            .checked_sub(g.first)
            .ok_or_else(|| invalid("modern release first block"))?;
        let group = index / g.blocks_per_group;
        let bit = (index % g.blocks_per_group) as usize;
        self.ensure_group(group)?;
        let row = self.groups.get_mut(&group).unwrap();
        row.block_dirty = true;
        let mask = 1 << (bit % 8);
        if row.bitmap[bit / 8] & mask == 0 {
            return Err(invalid("modern duplicate block release"));
        }
        row.bitmap[bit / 8] &= !mask;
        let mut count = u32::from(super::super::u16le(&row.descriptor, 12));
        if proof.descriptor_size == 64 {
            count |= u32::from(super::super::u16le(&row.descriptor, 44)) << 16;
        }
        count = count
            .checked_add(1)
            .filter(|n| *n <= g.blocks_per_group)
            .ok_or_else(|| invalid("modern group free count overflow"))?;
        row.descriptor[12..14].copy_from_slice(&(count as u16).to_le_bytes());
        if proof.descriptor_size == 64 {
            row.descriptor[44..46].copy_from_slice(&((count >> 16) as u16).to_le_bytes());
        }
        self.cursor = self.cursor.min(physical);
        self.released = self
            .released
            .checked_add(1)
            .ok_or_else(|| budget("modern release count overflow"))?;
        Ok(())
    }
    fn finish(self) -> io::Result<Plan> {
        self.finish_with_work().map(|(plan, _)| plan)
    }
    fn finish_with_work(mut self) -> io::Result<(Plan, usize)> {
        let g = &self.decoder.geometry;
        let proof = g.modern.as_ref().unwrap();
        for (number, mut row) in crate::platform::mem::take(&mut self.groups) {
            self.tick(g.blocks_per_group as usize / 8 + usize::from(proof.descriptor_size))?;
            if row.block_dirty {
                if proof.checksums.has_metadata() {
                    let checksum = super::super::checksum::crc32c(
                        proof.checksums.seed,
                        &row.bitmap[..g.blocks_per_group as usize / 8],
                    );
                    row.descriptor[24..26].copy_from_slice(&(checksum as u16).to_le_bytes());
                    if proof.descriptor_size == 64 {
                        row.descriptor[56..58]
                            .copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
                    }
                }
                let bitmap = super::super::u32le(&row.descriptor, 0);
                self.patch(
                    u64::from(bitmap) * u64::from(g.block_size),
                    &row.bitmap[..g.block_size as usize],
                )?;
            }
            if let Some(bitmap) = row.inode_bitmap {
                if proof.checksums.has_metadata() {
                    let checksum = super::super::checksum::crc32c(
                        proof.checksums.seed,
                        &bitmap[..g.inodes_per_group as usize / 8],
                    );
                    row.descriptor[26..28].copy_from_slice(&(checksum as u16).to_le_bytes());
                    if proof.descriptor_size == 64 {
                        row.descriptor[58..60]
                            .copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
                    }
                }
                let physical = super::super::u32le(&row.descriptor, 4);
                self.patch(u64::from(physical) * u64::from(g.block_size), &bitmap)?;
            }
            proof.checksums.stamp_descriptor(
                number,
                &mut row.descriptor[..usize::from(proof.descriptor_size)],
            )?;
            self.patch(
                (u64::from(g.first) + 1) * u64::from(g.block_size)
                    + u64::from(number) * u64::from(proof.descriptor_size),
                &row.descriptor[..usize::from(proof.descriptor_size)],
            )?;
        }
        let mut superblock = [0; 1024];
        self.decoder.read_exact_at(1024, &mut superblock)?;
        let free = super::super::u32le(&superblock, 12)
            .checked_add(self.released)
            .and_then(|n| n.checked_sub(self.allocated))
            .filter(|n| *n < g.blocks)
            .ok_or_else(|| invalid("modern superblock free count overflow"))?;
        superblock[12..16].copy_from_slice(&free.to_le_bytes());
        let free = super::super::u32le(&superblock, 16)
            .checked_add(self.released_inodes)
            .and_then(|n| n.checked_sub(self.allocated_inodes))
            .filter(|n| *n <= g.inodes)
            .ok_or_else(|| invalid("modern superblock free inode count underflow"))?;
        superblock[16..20].copy_from_slice(&free.to_le_bytes());
        if proof.checksums.has_metadata() {
            let checksum = super::super::checksum::crc32c(!0, &superblock[..1020]);
            superblock[1020..].copy_from_slice(&checksum.to_le_bytes());
        }
        self.patch(1024, &superblock)?;
        // Explicit finite insertion sort: every comparison and swap is charged.
        // Reservation operations must not inherit an uncharged library sort.
        for index in 1..self.patches.len() {
            let mut at = index;
            while at > 0 {
                self.tick(1)?;
                if self.patches[at - 1].offset() <= self.patches[at].offset() {
                    break;
                }
                self.tick(1)?;
                self.patches.swap(at - 1, at);
                at -= 1;
            }
        }
        self.tick(self.patches.len().saturating_sub(1))?;
        for pair in self.patches.windows(2) {
            if pair[0]
                .offset()
                .checked_add(pair[0].expected().len() as u64)
                .is_none_or(|end| end > pair[1].offset())
            {
                return Err(invalid("modern mutation patches overlap"));
            }
        }
        Ok((
            Plan {
                patches: self.patches,
                _reservation: self.reservation,
                source_guards: None,
            },
            self.work,
        ))
    }
}

pub(super) fn truncate(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    inode: &ExtInode,
    length: u64,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    if length >= inode.length
        || inode.mode & 0xf000 != 0x8000
        || inode.number < 11
        || super::super::u32le(&inode.raw, 32) & 0x40030 != 0
        || super::super::u16le(&inode.raw, 116) != 0
    {
        return Err(unsupported(
            "modern truncate requires mutable ordinary extent file and smaller size",
        ));
    }
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let g = &decoder.geometry;
    let decoded = context.allocation_map(inode)?;
    let end = length.div_ceil(u64::from(g.block_size));
    let mut kept = Vec::new();
    kept.try_reserve_exact(limits.file_blocks)
        .map_err(|_| budget("modern inline extent projection"))?;
    if kept.capacity() > limits.file_blocks {
        return Err(budget("modern retained extent capacity"));
    }

    for allocation in &decoded.allocations {
        context.tick(1)?;
        let count = end
            .saturating_sub(allocation.logical)
            .min(u64::from(allocation.blocks)) as u32;
        if count != 0 {
            kept.push(super::super::extent::ExtentAllocation {
                logical: allocation.logical,
                physical: allocation.physical,
                blocks: count,
                unwritten: allocation.unwritten,
            });
        }
        for relative in count..allocation.blocks {
            context.release(allocation.physical + relative)?;
        }
    }
    for &physical in &decoded.metadata {
        context.release(physical)?;
    }
    if !length.is_multiple_of(u64::from(g.block_size)) {
        let logical = length / u64::from(g.block_size);
        if let Some(allocation) = kept.iter().find(|a| {
            a.logical <= logical && logical < a.logical + u64::from(a.blocks) && !a.unwritten
        }) {
            let physical = allocation.physical + (logical - allocation.logical) as u32;
            let mut block = [0; MAX_BLOCK];
            decoder.read_exact_at(
                u64::from(physical) * u64::from(g.block_size),
                &mut block[..g.block_size as usize],
            )?;
            let inside = (length % u64::from(g.block_size)) as usize;
            block[inside..g.block_size as usize].fill(0);
            context.patch(
                u64::from(physical) * u64::from(g.block_size),
                &block[..g.block_size as usize],
            )?;
        }
    }
    write_inode(&mut context, inode, length, &kept)?;
    context.finish()
}

pub(super) fn extend(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    inode: &ExtInode,
    input: &dyn crate::fs_core::FileRead,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    if inode.mode & 0xf000 != 0x8000
        || inode.number < 11
        || super::super::u32le(&inode.raw, 32) & 0x40030 != 0
        || super::super::u16le(&inode.raw, 116) != 0
    {
        return Err(unsupported(
            "modern append requires mutable ordinary extent file",
        ));
    }
    let append = input.len();
    let bs = u64::from(decoder.geometry.block_size);
    let length = inode
        .length
        .checked_add(append)
        .filter(|n| n.div_ceil(bs) <= limits.file_blocks as u64)
        .ok_or_else(|| budget("modern appended logical block ceiling"))?;
    if append == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "modern append requires nonempty input",
        ));
    }
    if input.identity().native.len() > limits.work {
        return Err(budget("modern deferred source identity ceiling"));
    }
    let identity_lease = resources
        .memory
        .reserve(input.identity().native.len() as u64 + 64)
        .map_err(io::Error::other)?;
    let identity = input.identity().clone();
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let decoded = context.allocation_map(inode)?;
    let mut count = length.div_ceil(bs) as usize;
    for allocation in &decoded.allocations {
        count = count.max(
            usize::try_from(allocation.logical + u64::from(allocation.blocks))
                .map_err(|_| budget("modern retained allocation ceiling"))?,
        );
    }
    if count > limits.file_blocks {
        return Err(budget("modern complete allocation map ceiling"));
    }
    let mut data = Vec::<Option<(u32, bool)>>::new();
    data.try_reserve_exact(count)
        .map_err(|_| budget("modern append block map"))?;
    if data.capacity() > count {
        return Err(budget("modern append map capacity"));
    }
    data.resize(count, None);
    for allocation in &decoded.allocations {
        for relative in 0..allocation.blocks {
            context.tick(1)?;
            data[allocation.logical as usize + relative as usize] =
                Some((allocation.physical + relative, allocation.unwritten));
        }
    }
    let mut source_offset = 0;
    for logical in inode.length / bs..length.div_ceil(bs) {
        context.tick(1)?;
        let start = logical * bs;
        let within = inode.length.saturating_sub(start) as usize;
        let end = (length - start).min(bs) as usize;
        let old = data[logical as usize];
        let physical = match old {
            Some((physical, _)) => physical,
            None => context.allocate()?,
        };
        let mut block = [0; MAX_BLOCK];
        if old.is_some_and(|(_, unwritten)| !unwritten) {
            decoder.read_exact_at(u64::from(physical) * bs, &mut block[..bs as usize])?;
        }
        block[end..bs as usize].fill(0);
        let mut filled = within;
        while filled < end {
            context.tick(1)?;
            if input.identity() != &identity || input.len() != append {
                return Err(invalid("modern deferred source identity or length changed"));
            }
            let n = input
                .read_at(source_offset, &mut block[filled..end], resources)
                .map_err(io::Error::other)?;
            if n == 0 || n > end - filled {
                return Err(invalid("modern deferred source short or oversized read"));
            }
            filled += n;
            source_offset += n as u64;
            if input.identity() != &identity || input.len() != append {
                return Err(invalid("modern deferred source changed during read"));
            }
        }
        data[logical as usize] = Some((physical, false));
        context.patch(u64::from(physical) * bs, &block[..bs as usize])?;
    }
    if source_offset != append {
        return Err(invalid("modern deferred append accounting"));
    }
    let mut allocations = Vec::<super::super::extent::ExtentAllocation>::new();
    allocations
        .try_reserve_exact(count)
        .map_err(|_| budget("modern append extent rows"))?;
    if allocations.capacity() > count {
        return Err(budget("modern append extent capacity"));
    }
    for (logical, entry) in data.into_iter().enumerate() {
        let Some((physical, unwritten)) = entry else {
            continue;
        };
        let maximum = if unwritten { 32767 } else { 32768 };
        if let Some(previous) = allocations.last_mut()
            && previous.logical + u64::from(previous.blocks) == logical as u64
            && previous.physical + previous.blocks == physical
            && previous.unwritten == unwritten
            && previous.blocks < maximum
        {
            previous.blocks += 1;
            continue;
        }
        allocations.push(super::super::extent::ExtentAllocation {
            logical: logical as u64,
            physical,
            blocks: 1,
            unwritten,
        });
    }
    for &physical in &decoded.metadata {
        context.release(physical)?;
    }
    write_inode(&mut context, inode, length, &allocations)?;
    drop(identity_lease);
    context.finish()
}

#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_jbd_modern_tests.rs"]
mod tests;
