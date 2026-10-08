//! Staged COW fork allocation. No target mutation or free-space publication.
use super::super::fork_builder;
use super::*;
struct ResizeAllocation {
    fork: fork_builder::PlannedFork,
    allocated: Vec<(u32, u32)>,
    released: Vec<(u32, u32)>,
    free_blocks: u32,
    old_length: u64,
    new_length: u64,
    _lease: Reservation,
}
impl<S: Storage> Prepared<S> {
    fn plan_resize_allocation(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        length: u64,
        r: &Resources,
    ) -> Result<ResizeAllocation> {
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "HFS+ resize requires recovery",
            ));
        }
        self.revalidate(r)?;
        let id = self.volume.lookup(path, r)?;
        self.volume.verify_catalog_record(&id, r)?;
        let node = self.volume.node(&id)?;
        if node.directory {
            return Err(bad("HFS+ resize selected directory"));
        }
        let index = match kind {
            StreamKind::Data => 0,
            StreamKind::ResourceFork => 1,
            _ => return Err(bad("HFS+ resize unsupported fork")),
        };
        let old = &node.forks[index];
        let g = self.volume.geometry();
        let count = length.div_ceil(u64::from(g.block_size()));
        let blocks = u32::try_from(count).map_err(|_| budget("HFS+ resize allocation count"))?;
        if blocks > g.free {
            return Err(budget("HFS+ resize COW free-space ceiling"));
        }
        let free = self.proof.free_ranges();
        let charge = (free.len() as u64)
            .checked_add(old.extents.len() as u64)
            .and_then(|n| n.checked_mul(16))
            .ok_or_else(|| budget("HFS+ resize allocation plan charge"))?;
        let lease = r.memory.reserve(charge)?;
        let mut allocated = vector(free.len())?;
        let mut remaining = blocks;
        for range in free {
            r.cancellation.check()?;
            if remaining == 0 {
                break;
            }
            if !range.offset.is_multiple_of(u64::from(g.block_size()))
                || !range.length.is_multiple_of(u64::from(g.block_size()))
            {
                return Err(bad("HFS+ audited free range alignment"));
            }
            let start = u32::try_from(range.offset / u64::from(g.block_size()))
                .map_err(|_| bad("HFS+ free range start"))?;
            let available = u32::try_from(range.length / u64::from(g.block_size()))
                .map_err(|_| bad("HFS+ free range count"))?;
            let take = remaining.min(available);
            if take != 0 {
                allocated.push((start, take));
                remaining -= take;
            }
        }
        if remaining != 0 {
            return Err(bad(
                "HFS+ audit free ranges disagree with native free count",
            ));
        }
        let mut released = vector(old.extents.len())?;
        for extent in &old.extents {
            released.push((extent.start, extent.count));
        }
        let free_blocks = g
            .free
            .checked_add(old.blocks)
            .and_then(|n| n.checked_sub(blocks))
            .ok_or_else(|| bad("HFS+ resize final free count overflow"))?;
        let fork = fork_builder::plan(
            node.id,
            index == 1,
            length,
            (g.block_size(), g.blocks()),
            &allocated,
            r,
        )?;
        self.revalidate(r)?;
        Ok(ResizeAllocation {
            fork,
            allocated,
            released,
            free_blocks,
            old_length: old.length,
            new_length: length,
            _lease: lease,
        })
    }
}
pub(super) struct ResizePayload {
    pub(super) patches: Vec<WriteRange>,
    _lease: Reservation,
}
impl<S: Storage> Prepared<S> {
    fn stage_resize_payload(
        &self,
        allocation: &ResizeAllocation,
        offset: u64,
        replacement: &[u8],
        r: &Resources,
    ) -> Result<ResizePayload> {
        r.cancellation.check()?;
        let end = offset
            .checked_add(replacement.len() as u64)
            .filter(|end| *end <= allocation.new_length)
            .ok_or_else(|| bad("HFS+ resize replacement exceeds new EOF"))?;
        let block = u64::from(self.volume.geometry().block_size());
        let total = allocation
            .allocated
            .iter()
            .try_fold(0u64, |sum, (_, count)| {
                sum.checked_add(u64::from(*count) * block)
            })
            .ok_or_else(|| budget("HFS+ resize payload size overflow"))?;
        if total > self.range_bytes {
            return Err(budget("HFS+ resize initialized allocation ceiling"));
        }
        let chunks = allocation
            .allocated
            .iter()
            .try_fold(0usize, |sum, (_, count)| {
                sum.checked_add((u64::from(*count) * block).div_ceil(65536) as usize)
            })
            .ok_or_else(|| budget("HFS+ resize payload patch count"))?;
        let charge = total
            .checked_mul(2)
            .and_then(|n| n.checked_add(chunks as u64 * 128))
            .ok_or_else(|| budget("HFS+ resize payload charge"))?;
        let lease = r.memory.reserve(charge)?;
        self.revalidate(r)?;
        let mut patches = vector(chunks)?;
        let mut logical = 0u64;
        for &(start, count) in &allocation.allocated {
            let bytes = u64::from(count) * block;
            let mut within = 0;
            while within < bytes {
                r.cancellation.check()?;
                let size = (bytes - within).min(65536) as usize;
                let at = u64::from(start) * block + within;
                let mut old = vector(size)?;
                old.resize(size, 0);
                self.snapshot.work.charge(size as u64)?;
                self.target
                    .read_exact_at(at, &mut old)
                    .map_err(|e| Error::io("HFS+ resize free-block preimage", e))?;
                let mut new = vector(size)?;
                new.resize(size, 0);
                let copy_end = (logical + size as u64)
                    .min(allocation.old_length)
                    .min(allocation.new_length);
                let mut old_logical = 0u64;
                for &(old_start, old_count) in &allocation.released {
                    self.snapshot.work.charge(1)?;
                    let extent_end = old_logical + u64::from(old_count) * block;
                    let first = logical.max(old_logical);
                    let last = copy_end.min(extent_end);
                    if first < last {
                        r.cancellation.check()?;
                        self.snapshot.work.charge(last - first)?;
                        self.target
                            .read_exact_at(
                                u64::from(old_start) * block + first - old_logical,
                                &mut new[(first - logical) as usize..(last - logical) as usize],
                            )
                            .map_err(|e| Error::io("HFS+ resize retained payload", e))?;
                    }
                    old_logical = extent_end;
                }
                let first = logical.max(offset);
                let last = (logical + size as u64).min(end);
                if first < last {
                    new[(first - logical) as usize..(last - logical) as usize].copy_from_slice(
                        &replacement[(first - offset) as usize..(last - offset) as usize],
                    );
                }
                patches.push(
                    WriteRange::new(at, old, new)
                        .map_err(|e| Error::io("HFS+ resize payload patch", e))?,
                );
                within += size as u64;
                logical += size as u64;
            }
        }
        self.revalidate(r)?;
        Ok(ResizePayload {
            patches,
            _lease: lease,
        })
    }
}

#[test]
fn resize_cow_allocations_use_only_audited_free_and_preserve_other_fork() {
    struct ReadOnly(Vec<u8>);
    impl Storage for ReadOnly {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(&self.0[at..at + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("resize allocation planning wrote")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("resize allocation planning flushed")
        }
    }
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let image = super::super::independent::hfsplus_seed(binary);
        let prepared = Prepared::open(ReadOnly(image.clone()), limits, &r).unwrap();
        let path = [NativeName::Utf16(super::super::independent::native_name(
            binary,
        ))];
        for length in [0, 7, 4097, 70000] {
            let plan = prepared
                .plan_resize_allocation(&path, &StreamKind::Data, length, &r)
                .unwrap();
            assert_eq!(
                u64::from_be_bytes(plan.fork.header[..8].try_into().unwrap()),
                length
            );
            assert_eq!(plan.released.len(), 9);
            assert_eq!(plan.released.iter().map(|e| e.1).sum::<u32>(), 9);
            let blocks = length.div_ceil(4096) as u32;
            assert_eq!(plan.allocated.iter().map(|e| e.1).sum::<u32>(), blocks);
            assert_eq!(
                plan.free_blocks,
                prepared.volume.geometry().free + 9 - blocks
            );
            for &(start, count) in &plan.allocated {
                for block in start..start + count {
                    assert_eq!(
                        prepared.volume.inner.bitmap[block as usize / 8] & (0x80 >> (block % 8)),
                        0
                    );
                    assert!(
                        !plan
                            .released
                            .iter()
                            .any(|&(old, n)| block >= old && block < old + n)
                    );
                    assert_ne!(block, 32, "resource fork reused");
                }
            }
            assert!(plan.fork.overflow.len() <= plan.allocated.len().div_ceil(8));
            let payload = prepared.stage_resize_payload(&plan, 0, &[], &r).unwrap();
            let mut actual = Vec::new();
            for patch in &payload.patches {
                actual.extend_from_slice(patch.replacement());
            }
            let mut expected = Vec::new();
            for &(start, count) in &plan.released {
                expected.extend_from_slice(
                    &image[start as usize * 4096..(start + count) as usize * 4096],
                );
            }
            expected.truncate(plan.old_length as usize);
            expected.resize(length as usize, 0);
            let padded = length.div_ceil(4096) * 4096;
            expected.resize(padded as usize, 0);
            assert_eq!(actual, expected);
            let metadata = prepared
                .stage_resize_metadata(&path, &StreamKind::Data, &plan, &r)
                .unwrap();
            let mut projected = image.clone();
            for patch in payload.patches.iter().chain(metadata.patches.iter()) {
                let at = patch.offset() as usize;
                assert_eq!(
                    &projected[at..at + patch.expected().len()],
                    patch.expected()
                );
                projected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
            }
            drop(Prepared::open(ReadOnly(projected), limits, &r).unwrap());
            if length >= 7 {
                let edited = prepared.stage_resize_payload(&plan, 3, b"XYZ", &r).unwrap();
                let actual: Vec<u8> = edited
                    .patches
                    .iter()
                    .flat_map(|p| p.replacement().iter().copied())
                    .collect();
                expected[3..6].copy_from_slice(b"XYZ");
                assert_eq!(actual, expected);
            }
            assert!(
                prepared
                    .stage_resize_payload(&plan, length, b"x", &r)
                    .is_err()
            );
            assert_eq!(prepared.target.0, image);
        }
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fs_hfsplus_owned_resize_metadata.rs"]
pub(super) mod metadata;

#[path = "fs_hfsplus_owned_resize_commit.rs"]
pub(crate) mod commit;

#[path = "fs_hfsplus_owned_resize_recovery.rs"]
pub(crate) mod recovery;

#[cfg(test)]
#[path = "fs_hfsplus_owned_resize_cuts.rs"]
mod cuts;

#[cfg(all(test, target_os = "linux"))]
#[path = "fs_hfsplus_owned_resize_native.rs"]
mod native_gate;

#[cfg(all(test, target_os = "linux"))]
#[path = "fs_hfsplus_owned_resize_forks_native.rs"]
mod native_forks_gate;

impl<S: Storage> Prepared<S> {
    pub(super) fn stage_zero_fork(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        r: &Resources,
    ) -> Result<metadata::ResizeMetadata> {
        let allocation = self.plan_resize_allocation(path, kind, 0, r)?;
        self.stage_resize_metadata(path, kind, &allocation, r)
    }
}

impl<S: Storage> Prepared<S> {
    pub(super) fn stage_birth_fork(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<(ResizePayload, metadata::ResizeMetadata)> {
        let allocation = self.plan_resize_allocation(path, kind, bytes.len() as u64, r)?;
        if allocation.old_length != 0 || !allocation.released.is_empty() {
            return Err(bad("HFS+ birth fork requires empty original fork"));
        }
        let payload = self.stage_resize_payload(&allocation, 0, bytes, r)?;
        let metadata = self.stage_resize_metadata(path, kind, &allocation, r)?;
        Ok((payload, metadata))
    }
}
