//! Bounded checksum-aware inode authoring with unchanged native indirect-map profile.
use super::*;

pub(super) fn decode(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
) -> io::Result<super::super::super::extent::DecodedExtents> {
    let cap = context.limits.file_blocks;
    let charge = cap
        .checked_mul(128)
        .and_then(|n| n.checked_add(16384))
        .ok_or_else(|| budget("native indirect decoding charge"))?;
    let reservation = context
        .resources
        .memory
        .reserve(charge as u64)
        .map_err(io::Error::other)?;
    let end = inode
        .length
        .div_ceil(u64::from(context.decoder.geometry.block_size));
    let mut walk = Walk {
        context,
        end,
        allocations: Vec::new(),
        metadata: Vec::new(),
        seen: std::collections::BTreeSet::new(),
        cap,
    };
    if walk.end > cap as u64 {
        return Err(budget("native indirect logical block ceiling"));
    }
    walk.allocations
        .try_reserve_exact(cap)
        .map_err(|_| budget("native indirect data references"))?;
    walk.metadata
        .try_reserve_exact(cap)
        .map_err(|_| budget("native indirect metadata references"))?;
    if walk.allocations.capacity() > cap || walk.metadata.capacity() > cap {
        return Err(budget("native indirect actual references capacity"));
    }
    for index in 0..12 {
        walk.pointer(
            super::super::super::u32le(&inode.raw, 40 + index * 4),
            0,
            index as u64,
        )?;
    }
    let width = u64::from(walk.context.decoder.geometry.block_size / 4);
    let mut logical = 12;
    for depth in 1..=3 {
        walk.pointer(
            super::super::super::u32le(&inode.raw, 84 + depth as usize * 4),
            depth,
            logical,
        )?;
        logical += width.pow(depth);
    }
    Ok(super::super::super::extent::DecodedExtents {
        map: Vec::new(),
        allocations: walk.allocations,
        metadata: walk.metadata,
        reservation,
    })
}
struct Walk<'a, 'd, 's> {
    context: &'a mut Context<'d, 's>,
    end: u64,
    allocations: Vec<super::super::super::extent::ExtentAllocation>,
    metadata: Vec<u32>,
    seen: std::collections::BTreeSet<u32>,
    cap: usize,
}
impl Walk<'_, '_, '_> {
    fn pointer(&mut self, physical: u32, depth: u32, logical: u64) -> io::Result<()> {
        self.context.tick(1)?;
        if physical == 0 {
            return Ok(());
        }
        if logical >= self.end {
            return Err(invalid("native indirect allocation beyond logical EOF"));
        }
        self.context.decoder.block(physical)?;
        if self.seen.len() >= self.cap {
            return Err(budget("native indirect complete allocation ceiling"));
        }
        if !self.seen.insert(physical) {
            return Err(invalid("native indirect cycle/alias"));
        }
        if depth == 0 {
            if let Some(last) = self.allocations.last_mut()
                && last.logical + u64::from(last.blocks) == logical
                && last.physical + last.blocks == physical
            {
                last.blocks += 1;
                return Ok(());
            }
            self.allocations
                .push(super::super::super::extent::ExtentAllocation {
                    logical,
                    physical,
                    blocks: 1,
                    unwritten: false,
                });
            return Ok(());
        }
        self.metadata.push(physical);
        let bs = self.context.decoder.geometry.block_size as usize;
        let width = (bs / 4) as u64;
        let stride = width.pow(depth - 1);
        let mut bytes = [0; MAX_BLOCK];
        self.context
            .decoder
            .read_exact_at(u64::from(physical) * (bs as u64), &mut bytes[..bs])?;
        for slot in 0..bs / 4 {
            self.pointer(
                super::super::super::u32le(&bytes, slot * 4),
                depth - 1,
                logical + (slot as u64) * stride,
            )?;
        }
        Ok(())
    }
}

pub(super) fn write_inode(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    length: u64,
    allocations: &[super::super::super::extent::ExtentAllocation],
) -> io::Result<()> {
    let bs = context.decoder.geometry.block_size as usize;
    let count = usize::try_from(length.div_ceil(bs as u64))
        .map_err(|_| budget("native indirect length"))?;
    if count > context.limits.file_blocks {
        return Err(budget("native indirect authored logical blocks"));
    }
    let charge = count
        .checked_mul(4)
        .and_then(|n| n.checked_add(3 * MAX_BLOCK + 512))
        .ok_or_else(|| budget("native indirect authoring charge"))?;
    let _reservation = context
        .resources
        .memory
        .reserve(charge as u64)
        .map_err(io::Error::other)?;
    let mut data = Vec::new();
    data.try_reserve_exact(count)
        .map_err(|_| budget("native indirect authored pointers"))?;
    if data.capacity() > count {
        return Err(budget("native indirect actual pointer capacity"));
    }
    data.resize(count, 0u32);
    for allocation in allocations {
        if allocation.unwritten || allocation.logical + u64::from(allocation.blocks) > count as u64
        {
            return Err(unsupported(
                "native indirect map cannot encode uninitialized/beyond-EOF allocation",
            ));
        }
        for relative in 0..allocation.blocks {
            context.tick(1)?;
            let slot = (allocation.logical + u64::from(relative)) as usize;
            if data[slot] != 0 {
                return Err(invalid("native indirect authored logical alias"));
            }
            data[slot] = allocation.physical + relative;
        }
    }
    let mut pointers = [0u32; 15];
    let direct = count.min(12);
    pointers[..direct].copy_from_slice(&data[..direct]);
    let mut begin = direct;
    let width = bs / 4;
    let mut metadata = 0u32;
    for depth in 1..=3 {
        let capacity = width
            .checked_pow(depth)
            .ok_or_else(|| budget("native indirect authored fanout"))?;
        let end = begin.saturating_add(capacity).min(count);
        pointers[11 + depth as usize] = node(context, depth, &data[begin..end], &mut metadata)?;
        begin = end;
    }
    if begin != count {
        return Err(budget("native indirect triple fanout ceiling"));
    }
    let sectors = (data.iter().filter(|physical| **physical != 0).count() as u64)
        .checked_add(u64::from(metadata))
        .and_then(|n| n.checked_add(u64::from(super::super::super::u32le(&inode.raw, 104) != 0)))
        .and_then(|n| n.checked_mul((bs / 512) as u64))
        .filter(|n| *n <= u64::from(u32::MAX))
        .ok_or_else(|| budget("native indirect sector count"))? as u32;
    super::inode_writer::patch_inode(context, inode, |bytes| {
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[108..112].copy_from_slice(&((length >> 32) as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&sectors.to_le_bytes());
        bytes[116..118].fill(0);
        bytes[40..100].fill(0);
        for (index, physical) in pointers.iter().enumerate() {
            bytes[40 + index * 4..44 + index * 4].copy_from_slice(&physical.to_le_bytes());
        }
        Ok(())
    })
}
fn node(
    context: &mut Context<'_, '_>,
    depth: u32,
    data: &[u32],
    metadata: &mut u32,
) -> io::Result<u32> {
    context.tick(1)?;
    if data.iter().all(|physical| *physical == 0) {
        return Ok(0);
    }
    let bs = context.decoder.geometry.block_size as usize;
    let width = bs / 4;
    let mut bytes = [0; MAX_BLOCK];
    if depth == 1 {
        for (slot, physical) in data.iter().enumerate() {
            bytes[slot * 4..slot * 4 + 4].copy_from_slice(&physical.to_le_bytes());
        }
    } else {
        let stride = width
            .checked_pow(depth - 1)
            .ok_or_else(|| budget("native indirect node fanout"))?;
        for (slot, chunk) in data.chunks(stride).enumerate() {
            let physical = node(context, depth - 1, chunk, metadata)?;
            bytes[slot * 4..slot * 4 + 4].copy_from_slice(&physical.to_le_bytes());
        }
    }
    let physical = context.allocate()?;
    *metadata = metadata
        .checked_add(1)
        .ok_or_else(|| budget("native indirect node count"))?;
    context.patch(u64::from(physical) * (bs as u64), &bytes[..bs])?;
    Ok(physical)
}
