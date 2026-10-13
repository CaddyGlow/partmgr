//! Classic ext2 filesystem growth inside the already existing final group.
use super::*;
use crate::storage::WriteRange;
use core::cell::Cell;
fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors allocation types supplied by the std prelude.
use crate::platform::prelude::*;
const STATE: u64 = 1082;
fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn vector(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| budget("ext2 growth payload allocation"))?;
    if v.capacity() > bytes.len() {
        return Err(budget("ext2 growth payload capacity"));
    }
    v.extend_from_slice(bytes);
    Ok(v)
}
/// Observations accompanying an owner/generation-bound growth batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtFilesystemGrowReport {
    /// Existing native filesystem blocks, excluding extra backend capacity.
    pub old_blocks: u32,
    /// New native filesystem blocks; no new block group is created.
    pub new_blocks: u32,
    /// Newly admitted free native blocks.
    pub added_free_blocks: u32,
    /// Existing block-group count, unchanged by this operation.
    pub groups: u32,
    /// Native allocation unit, unchanged.
    pub block_size: u32,
    /// Existing backup superblocks/GDT copies updated.
    pub backup_groups: u32,
}
struct Patches<'a> {
    target: &'a dyn Storage,
    patches: Vec<WriteRange>,
    bytes: u64,
    work: usize,
    limits: ExtEditLimits,
    r: &'a Resources,
}
impl Patches<'_> {
    fn tick(&mut self) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(1)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("ext2 geometry planning work"))?;
        Ok(())
    }
    fn add(&mut self, at: u64, after: &[u8]) -> Result<()> {
        self.tick()?;
        if self.patches.len() >= self.limits.undo.patches as usize {
            return Err(budget("ext2 geometry patch ceiling"));
        }
        self.bytes = self
            .bytes
            .checked_add(after.len() as u64)
            .filter(|n| *n <= self.limits.affected_bytes)
            .ok_or_else(|| budget("ext2 geometry affected bytes"))?;
        let mut before = vector(after)?;
        self.target.read_exact_at(at, &mut before).map_err(native)?;
        self.patches
            .push(WriteRange::new(at, before, vector(after)?).map_err(native)?);
        Ok(())
    }
}
struct Projected<'a> {
    target: &'a dyn Storage,
    patches: &'a [WriteRange],
    work: &'a Cell<usize>,
    limit: usize,
    r: &'a Resources,
}
impl Storage for Projected<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        self.target.read_exact_at(at, out)?;
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        for patch in self.patches {
            self.r.cancellation.check().map_err(io::Error::other)?;
            let used = self
                .work
                .get()
                .checked_add(1)
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| {
                    io::Error::other(budget("ext2 projected patch comparison ceiling"))
                })?;
            self.work.set(used);
            let start = at.max(patch.offset());
            let stop = end.min(patch.offset() + patch.replacement().len() as u64);
            if start < stop {
                out[(start - at) as usize..(stop - at) as usize].copy_from_slice(
                    &patch.replacement()
                        [(start - patch.offset()) as usize..(stop - patch.offset()) as usize],
                );
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
impl<S: Storage, J: Storage> ExtEditor<S, J> {
    /// Plan real native geometry growth inside the existing final block group.
    /// The owned backend/region must already cover the requested size. No backend
    /// resize, partition change, metadata relocation, new inode or group is made.
    /// Reserved blocks retain their original absolute count. Every affected
    /// backup field retains its own actual original bytes for exact undo.
    /// Backup free counters are normalized to the new primary totals. Planning,
    /// including every prospective-overlay patch comparison and final source
    /// check, shares limits.work; full audits additionally retain audit limits.
    pub fn plan_grow_filesystem(
        &self,
        new_blocks: u32,
        r: &Resources,
    ) -> Result<(ExtEditBatch, ExtFilesystemGrowReport)> {
        self.ready(r)?;
        let decoder =
            ExtStorageDecoder::open_storage(&self.target, self.scope, r).map_err(native)?;
        let g = decoder.geometry().clone();
        if !g.is_classic() || ![1024, 2048, 4096].contains(&g.block_size) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 classic geometry growth profile",
            ));
        }
        let old = &self.geometry;
        if g.blocks != old.blocks
            || g.inodes != old.inodes
            || g.uuid != old.uuid
            || g.block_size != old.block_size
            || g.first != old.first
            || g.groups != old.groups
            || g.blocks_per_group != old.blocks_per_group
            || g.inodes_per_group != old.inodes_per_group
            || g.inode_size != old.inode_size
            || g.minimum_extra_size != old.minimum_extra_size
            || g.filetype != old.filetype
            || g.sparse_super != old.sparse_super
            || g.extent_profile != old.extent_profile
            || g.has_journal != old.has_journal
            || g.journal_inode != old.journal_inode
            || g.modern.is_some() != old.modern.is_some()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 growth session geometry/profile changed",
            ));
        }
        if !audit_ext_storage(&self.target, self.limits.audit, r)?.is_clean() {
            return Err(bad("ext2 growth requires complete clean audit"));
        }
        let bs = u64::from(g.block_size);
        let start = u64::from(g.first)
            + u64::from(
                g.groups
                    .checked_sub(1)
                    .ok_or_else(|| bad("ext2 empty group geometry"))?,
            ) * u64::from(g.blocks_per_group);
        let end = start
            .checked_add(u64::from(g.blocks_per_group))
            .ok_or_else(|| bad("ext2 group-end overflow"))?;
        let new_bytes = u64::from(new_blocks)
            .checked_mul(bs)
            .ok_or_else(|| bad("ext2 growth byte overflow"))?;
        if new_blocks <= g.blocks
            || u64::from(new_blocks) > end
            || new_bytes > self.target.bounds.length
            || g.blocks_per_group > g.block_size * 8
            || new_blocks > u32::MAX - g.blocks_per_group - 1
        {
            return Err(bad(
                "ext2 growth must fit existing last group and owned region",
            ));
        }
        let delta = new_blocks - g.blocks;
        let mut primary = [0; 1024];
        self.target
            .read_exact_at(1024, &mut primary)
            .map_err(native)?;
        // Conservative initial allowlist excludes resize-inode and all compatible
        // extensions, not merely journal/extent flags exposed by is_classic().
        if u32le(&primary, 92) != 0
            || u32le(&primary, 96) & !2 != 0
            || u32le(&primary, 100) & !1 != 0
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 geometry growth feature allowlist",
            ));
        }
        let new_free = u32le(&primary, 12)
            .checked_add(delta)
            .filter(|n| *n <= new_blocks)
            .ok_or_else(|| bad("ext2 free block counter overflow"))?;
        let group = g.groups - 1;
        let descriptor_at = (u64::from(g.first) + 1) * bs + u64::from(group) * 32;
        let mut descriptor = [0; 32];
        self.target
            .read_exact_at(descriptor_at, &mut descriptor)
            .map_err(native)?;
        let new_group_free = u32::from(u16le(&descriptor, 12))
            .checked_add(delta)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| bad("ext2 group free counter overflow"))?;
        let power = |group: u32, base: u32| {
            let mut n = group;
            while n > 1 && n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        let backup = |group: u32| {
            !g.sparse_super || group == 1 || power(group, 3) || power(group, 5) || power(group, 7)
        };
        // Bound group enumeration before the iterator can do uncharged work.
        if g.groups as usize > self.limits.work {
            return Err(budget("ext2 growth group work ceiling"));
        }
        let backups = (1..g.groups).filter(|group| backup(*group)).count();
        let count = backups
            .checked_mul(3)
            .and_then(|n| n.checked_add(5))
            .ok_or_else(|| budget("ext2 growth patch count"))?;
        let affected = (g.block_size as u64)
            .checked_add(12)
            .and_then(|n| n.checked_add((backups as u64).checked_mul(10)?))
            .ok_or_else(|| budget("ext2 growth byte count"))?;
        let body = affected
            .checked_mul(2)
            .and_then(|n| n.checked_add((count as u64).checked_mul(16)?))
            .ok_or_else(|| budget("ext2 growth undo size"))?;
        if count > self.limits.undo.patches as usize
            || affected > self.limits.affected_bytes
            || body > self.limits.undo.body_bytes
        {
            return Err(budget("ext2 growth transaction ceilings"));
        }
        let inventory = count
            .checked_mul(core::mem::size_of::<WriteRange>())
            .and_then(|n| n.checked_add(4 * core::mem::size_of::<usize>()))
            .ok_or_else(|| budget("ext2 growth inventory size"))?;
        // Retained before/after payloads + bitmap scratch + bounded planning overhead.
        let charge = affected
            .checked_mul(2)
            .and_then(|n| n.checked_add(g.block_size as u64))
            .and_then(|n| n.checked_add(inventory as u64))
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| budget("ext2 growth reservation size"))?;
        let lease = r.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(count)
            .map_err(|_| budget("ext2 growth patch allocation"))?;
        if patches.capacity() > count {
            return Err(budget("ext2 growth patch capacity"));
        }
        let mut p = Patches {
            target: &self.target,
            patches,
            bytes: 0,
            work: g.groups as usize,
            limits: self.limits,
            r,
        };
        let mut bitmap = vector(&[0; 4096][..g.block_size as usize])?;
        let bitmap_at = u64::from(u32le(&descriptor, 0)) * bs;
        self.target
            .read_exact_at(bitmap_at, &mut bitmap)
            .map_err(native)?;
        let old_count = u64::from(g.blocks) - start;
        let new_count = u64::from(new_blocks) - start;
        for bit in old_count..new_count {
            p.tick()?;
            let byte = &mut bitmap[bit as usize / 8];
            let mask = 1u8 << (bit % 8);
            if *byte & mask == 0 {
                return Err(bad("ext2 growth tail was not reserved"));
            }
            *byte &= !mask;
        }
        p.add(bitmap_at, &bitmap)?;
        drop(bitmap);
        let metadata_start = p.patches.len();
        p.add(descriptor_at + 12, &new_group_free.to_le_bytes())?;
        for backup_group in 1..g.groups {
            p.tick()?;
            if !backup(backup_group) {
                continue;
            }
            let at =
                (u64::from(g.first) + u64::from(backup_group) * u64::from(g.blocks_per_group)) * bs;
            p.add(at + 4, &new_blocks.to_le_bytes())?;
            p.add(at + 12, &new_free.to_le_bytes())?;
            p.add(
                at + bs + u64::from(group) * 32 + 12,
                &new_group_free.to_le_bytes(),
            )?;
        }
        let metadata = p.patches.len() - metadata_start;
        p.add(1028, &new_blocks.to_le_bytes())?;
        p.add(1036, &new_free.to_le_bytes())?;
        p.add(STATE, &[1, 0])?;
        if p.bytes != affected || p.patches.len() != count {
            return Err(bad("ext2 growth patch accounting mismatch"));
        }
        {
            let projection_work = Cell::new(p.work);
            let projected = Projected {
                target: &self.target,
                patches: &p.patches,
                work: &projection_work,
                limit: self.limits.work,
                r,
            };
            let future =
                ExtStorageDecoder::open_storage(&projected, self.scope, r).map_err(native)?;
            if future.geometry().blocks != new_blocks
                || future.geometry().groups != g.groups
                || !audit_ext_storage(&projected, self.limits.audit, r)?.is_clean()
            {
                return Err(bad("ext2 prospective growth audit"));
            }
            // Existing audit excludes classic backup free counters; verify all planned
            // exact projected bytes, subsequently read back by UndoPlan's stages.
            let mut readback = [0; 4096];
            for patch in &p.patches {
                r.cancellation.check()?;
                let n = patch.replacement().len();
                projected
                    .read_exact_at(patch.offset(), &mut readback[..n])
                    .map_err(native)?;
                if readback[..n] != *patch.replacement() {
                    return Err(bad("ext2 prospective counter readback"));
                }
            }
            p.work = projection_work.get();
        }
        // Bind all retained mutation preconditions to the still-owned source.
        // This detects changed observations; exclusivity remains required.
        let mut original = [0u8; 4096];
        for index in 0..p.patches.len() {
            p.tick()?;
            let patch = &p.patches[index];
            let n = patch.expected().len();
            self.target
                .read_exact_at(patch.offset(), &mut original[..n])
                .map_err(native)?;
            if original[..n] != *patch.expected() {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "ext2 growth mutation precondition changed",
                ));
            }
        }
        p.tick()?;
        self.target
            .read_exact_at(1024, &mut original[..1024])
            .map_err(native)?;
        if original[..1024] != primary {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 growth primary profile changed",
            ));
        }
        p.tick()?;
        self.target
            .read_exact_at(descriptor_at, &mut original[..32])
            .map_err(native)?;
        if original[..32] != descriptor {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 growth final descriptor changed",
            ));
        }
        self.target.len().map_err(native)?;
        r.cancellation.check()?;
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(4)
            .map_err(|_| budget("ext2 growth stage allocation"))?;
        if stages.capacity() > 4 {
            return Err(budget("ext2 growth stage capacity"));
        }
        stages.extend_from_slice(&[1, metadata, 2, 1]);
        let report = ExtFilesystemGrowReport {
            old_blocks: g.blocks,
            new_blocks,
            added_free_blocks: delta,
            groups: g.groups,
            block_size: g.block_size,
            backup_groups: backups as u32,
        };
        Ok((
            ExtEditBatch {
                source: self.scope,
                generation: self.generation,
                patches: p.patches,
                stages,
                bytes: affected,
                _lease: lease,
                resize: None,
                namespace: None,
                range_allocation: None,
                ordered: None,
                symlink: Vec::new(),
            },
            report,
        ))
    }
}
