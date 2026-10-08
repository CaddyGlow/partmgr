//! Bounded classic-header ext4 extent trees without metadata checksums or 64-bit groups.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
/// Complete allocation references retained separately from logical zero/read semantics.
pub(crate) struct ExtentAllocation {
    pub(crate) logical: u64,
    pub(crate) physical: u32,
    pub(crate) blocks: u32,
    pub(crate) unwritten: bool,
}
pub(crate) struct DecodedExtents {
    pub(crate) map: Vec<FileExtent>,
    pub(crate) allocations: Vec<ExtentAllocation>,
    pub(crate) metadata: Vec<u32>,
    pub(crate) reservation: Reservation,
}
struct Walk<'a, R> {
    decoder: &'a ExtDecoder<R>,
    resources: &'a Resources,
    cap: usize,
    work: usize,
    allocated: usize,
    allocations: Vec<ExtentAllocation>,
    metadata: Vec<u32>,
    seen: crate::platform::collections::BTreeSet<u32>,
    inode: &'a ExtInode,
}
fn budget(message: &str) -> io::Error {
    io::Error::other(fs_core::Error::new(
        fs_core::ErrorKind::BudgetExhausted,
        message,
    ))
}
impl<R: ExtDecodeRead> Walk<'_, R> {
    fn step(&mut self, n: usize) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.work = self
            .work
            .checked_add(n)
            .filter(|n| *n <= self.cap.saturating_mul(8).saturating_add(64))
            .ok_or_else(|| budget("ext4 extent work ceiling"))?;
        Ok(())
    }
    fn node(
        &mut self,
        bytes: &[u8],
        expected_depth: Option<u16>,
        low: u64,
        high: u64,
    ) -> io::Result<()> {
        self.step(1)?;
        if bytes.len() < 12 || u16le(bytes, 0) != 0xf30a {
            return Err(invalid("ext4 extent header magic"));
        }
        let entries = usize::from(u16le(bytes, 2));
        let maximum = usize::from(u16le(bytes, 4));
        let depth = u16le(bytes, 6);
        let capacity = (bytes.len() - 12) / 12;
        if maximum == 0
            || maximum > capacity
            || entries > maximum
            || depth > 5
            || expected_depth.is_some_and(|d| d != depth)
            || (depth != 0 && entries == 0)
        {
            return Err(invalid("ext4 extent header capacity/depth"));
        }
        let mut previous = None;
        for i in 0..entries {
            self.step(1)?;
            let at = 12 + i * 12;
            let logical = u64::from(u32le(bytes, at));
            if logical < low || logical >= high || previous.is_some_and(|p| logical <= p) {
                return Err(invalid("ext4 extent keys out of order or index bounds"));
            }
            previous = Some(logical);
            if depth == 0 {
                let raw_length = u16le(bytes, at + 4);
                let unwritten = raw_length > 32768;
                let blocks = u32::from(if unwritten {
                    raw_length - 32768
                } else {
                    raw_length
                });
                if blocks == 0 || u16le(bytes, at + 6) != 0 {
                    return Err(invalid(
                        "ext4 zero extent or physical address outside 32-bit profile",
                    ));
                }
                let end = logical
                    .checked_add(u64::from(blocks))
                    .filter(|n| *n <= high && *n <= 1u64 << 32)
                    .ok_or_else(|| invalid("ext4 extent logical overflow"))?;
                if self
                    .allocations
                    .last()
                    .is_some_and(|p| p.logical + u64::from(p.blocks) > logical)
                {
                    return Err(invalid("ext4 overlapping logical extents"));
                }
                let physical = u32le(bytes, at + 8);
                let physical_end = physical
                    .checked_add(blocks)
                    .filter(|n| *n <= self.decoder.geometry.blocks)
                    .ok_or_else(|| invalid("ext4 extent physical overflow"))?;
                self.allocated = self
                    .allocated
                    .checked_add(blocks as usize)
                    .filter(|n| *n <= self.cap)
                    .ok_or_else(|| budget("ext4 extent allocation ceiling"))?;
                for block in physical..physical_end {
                    self.step(1)?;
                    self.decoder.block(block)?;
                }
                if self.allocations.len() >= self.cap {
                    return Err(budget("ext4 extent leaf ceiling"));
                }
                self.allocations.push(ExtentAllocation {
                    logical,
                    physical,
                    blocks,
                    unwritten,
                });
                let _ = end;
            } else {
                if u16le(bytes, at + 8) != 0 || u16le(bytes, at + 10) != 0 {
                    return Err(invalid("ext4 index physical high bits or reserved field"));
                }
                let block = u32le(bytes, at + 4);
                self.decoder.block(block)?;
                if !self.seen.insert(block) {
                    return Err(invalid("ext4 extent metadata alias or cycle"));
                }
                if self.metadata.len() >= self.cap {
                    return Err(budget("ext4 extent metadata ceiling"));
                }
                self.metadata.push(block);
                let child_high = if i + 1 < entries {
                    u64::from(u32le(bytes, at + 12))
                } else {
                    high
                };
                if child_high <= logical || child_high > high {
                    return Err(invalid("ext4 index child key bounds"));
                }
                let bs = self.decoder.geometry.block_size as usize;
                let _scratch = self
                    .resources
                    .memory
                    .reserve(bs as u64)
                    .map_err(io::Error::other)?;
                let mut child = Vec::new();
                child.try_reserve_exact(bs).map_err(io::Error::other)?;
                child.resize(bs, 0);
                self.decoder
                    .read_exact_at(u64::from(block) * bs as u64, &mut child)?;
                if let Some(proof) = &self.decoder.geometry.modern {
                    proof
                        .checksums
                        .extent(self.inode.number, self.inode.generation, &child)?;
                }
                self.node(&child, Some(depth - 1), logical, child_high)?;
                if u32le(&child, 12) as u64 != logical || u16le(&child, 2) == 0 {
                    return Err(invalid("ext4 index key does not match child first extent"));
                }
            }
        }
        Ok(())
    }
}
impl<R: ExtDecodeRead> ExtDecoder<R> {
    pub(crate) fn extent_map(
        &self,
        inode: &ExtInode,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<DecodedExtents> {
        self.decode_extents(inode, max_blocks, resources, true)
    }
    pub(crate) fn extent_allocations(
        &self,
        inode: &ExtInode,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<DecodedExtents> {
        self.decode_extents(inode, max_blocks, resources, false)
    }
    fn decode_extents(
        &self,
        inode: &ExtInode,
        max_blocks: usize,
        resources: &Resources,
        logical_map: bool,
    ) -> io::Result<DecodedExtents> {
        let bs = u64::from(self.geometry.block_size);
        if logical_map && inode.length.div_ceil(bs) > max_blocks as u64 {
            return Err(budget("ext4 logical block ceiling"));
        }
        let charge = (max_blocks as u64)
            .checked_mul(384_u64)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| budget("ext4 extent reservation overflow"))?;
        let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut walk = Walk {
            inode,
            decoder: self,
            resources,
            cap: max_blocks,
            work: 0,
            allocated: 0,
            allocations: Vec::new(),
            metadata: Vec::new(),
            seen: crate::platform::collections::BTreeSet::new(),
        };
        walk.allocations
            .try_reserve_exact(max_blocks)
            .map_err(io::Error::other)?;
        walk.metadata
            .try_reserve_exact(max_blocks)
            .map_err(io::Error::other)?;
        walk.node(&inode.raw[40..100], None, 0, 1u64 << 32)?;
        // Physical ranges must be disjoint even when logical ranges are ordered.
        let _physical = resources
            .memory
            .reserve(max_blocks as u64 * 16)
            .map_err(io::Error::other)?;
        let mut physical: Vec<(u32, u32)> = Vec::new();
        physical
            .try_reserve_exact(walk.allocations.len())
            .map_err(io::Error::other)?;
        for allocation in &walk.allocations {
            physical.push((allocation.physical, allocation.physical + allocation.blocks));
        }
        physical.sort_unstable();
        if physical.windows(2).any(|p| p[0].1 > p[1].0)
            || walk.metadata.iter().any(|b| {
                let i = physical.partition_point(|(start, _)| start <= b);
                i > 0 && *b < physical[i - 1].1
            })
        {
            return Err(invalid("ext4 physical extent or metadata alias"));
        }
        if self.geometry.modern.is_some() {
            let xattr = u32le(&inode.raw, 104);
            if xattr != 0
                && (walk.metadata.contains(&xattr)
                    || physical
                        .iter()
                        .any(|(start, end)| *start <= xattr && xattr < *end))
            {
                return Err(invalid("ext4 inode map aliases its external xattrs"));
            }
        }
        if !logical_map {
            return Ok(DecodedExtents {
                map: Vec::new(),
                allocations: walk.allocations,
                metadata: walk.metadata,
                reservation,
            });
        }
        let mut map = Vec::new();
        map.try_reserve_exact(max_blocks.saturating_add(1))
            .map_err(io::Error::other)?;
        let mut position = 0;
        for allocation in &walk.allocations {
            let start = allocation.logical * bs;
            if start >= inode.length {
                continue;
            }
            if start > position {
                map.push(FileExtent {
                    offset: position,
                    length: start - position,
                    kind: ExtentKind::Hole,
                });
            }
            let length = (u64::from(allocation.blocks) * bs).min(inode.length - start);
            map.push(FileExtent {
                offset: start,
                length,
                kind: if allocation.unwritten {
                    ExtentKind::Unwritten
                } else {
                    ExtentKind::Data(u64::from(allocation.physical) * bs)
                },
            });
            position = start + length;
        }
        if position < inode.length {
            map.push(FileExtent {
                offset: position,
                length: inode.length - position,
                kind: ExtentKind::Hole,
            });
        }
        Ok(DecodedExtents {
            map,
            allocations: walk.allocations,
            metadata: walk.metadata,
            reservation,
        })
    }
}
