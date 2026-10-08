//! Bounded canonical checksum-aware extent-tree authoring for the owned modern planner.
use super::*;

pub(super) fn write_inode(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    length: u64,
    allocations: &[super::super::super::extent::ExtentAllocation],
) -> io::Result<()> {
    let g = &context.decoder.geometry;
    let proof = g.modern.as_ref().unwrap();
    let block_size = g.block_size;
    let inode_size = g.inode_size;
    let inode_seed = proof.checksums.inode_seed(inode.number, inode.generation);
    let descriptor = proof.descriptors[((inode.number - 1) / g.inodes_per_group) as usize];
    let inode_offset = u64::from(super::super::super::u32le(&descriptor, 8))
        * u64::from(block_size)
        + u64::from((inode.number - 1) % g.inodes_per_group) * u64::from(inode_size);
    let capacity = (block_size as usize - 12) / 12;
    let mut bytes = [0; 256];
    bytes[..128].copy_from_slice(&inode.raw);
    bytes[128..].copy_from_slice(&inode.extra);
    let generation: [u8; 4] = bytes[48..52].try_into().unwrap();
    bytes[40..100].fill(0);
    bytes[40..42].copy_from_slice(&0xf30au16.to_le_bytes());
    bytes[44..46].copy_from_slice(&4u16.to_le_bytes());
    bytes[48..52].copy_from_slice(&generation);
    let mut metadata = 0u32;
    let mut root = Vec::<(u64, u32)>::new();
    root.try_reserve_exact(allocations.len())
        .map_err(|_| budget("modern extent index rows"))?;
    if root.capacity() > allocations.len() {
        return Err(budget("modern extent index capacity"));
    }
    let encode_extent = |out: &mut [u8],
                         allocation: &super::super::super::extent::ExtentAllocation|
     -> io::Result<()> {
        let logical = u32::try_from(allocation.logical)
            .map_err(|_| unsupported("modern logical extent high word"))?;
        let maximum = if allocation.unwritten { 32767 } else { 32768 };
        if allocation.blocks == 0 || allocation.blocks > maximum {
            return Err(invalid("modern extent run length"));
        }
        out[..4].copy_from_slice(&logical.to_le_bytes());
        let count = allocation.blocks as u16 + if allocation.unwritten { 32768 } else { 0 };
        out[4..6].copy_from_slice(&count.to_le_bytes());
        out[8..12].copy_from_slice(&allocation.physical.to_le_bytes());
        Ok(())
    };
    if allocations.len() <= 4 {
        bytes[42..44].copy_from_slice(&(allocations.len() as u16).to_le_bytes());
        for (index, allocation) in allocations.iter().enumerate() {
            encode_extent(&mut bytes[52 + index * 12..64 + index * 12], allocation)?;
        }
    } else {
        for chunk in allocations.chunks(capacity) {
            let physical = context.allocate()?;
            metadata = metadata
                .checked_add(1)
                .ok_or_else(|| budget("modern extent metadata count"))?;
            let mut block = [0; MAX_BLOCK];
            block[..2].copy_from_slice(&0xf30au16.to_le_bytes());
            block[2..4].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
            block[4..6].copy_from_slice(&(capacity as u16).to_le_bytes());
            block[8..12].copy_from_slice(&generation);
            for (index, allocation) in chunk.iter().enumerate() {
                encode_extent(&mut block[12 + index * 12..24 + index * 12], allocation)?;
            }
            let tail = 12 + capacity * 12;
            if proof.checksums.has_metadata() {
                let checksum = super::super::super::checksum::crc32c(inode_seed, &block[..tail]);
                block[tail..tail + 4].copy_from_slice(&checksum.to_le_bytes());
            }
            context.patch(
                u64::from(physical) * u64::from(block_size),
                &block[..block_size as usize],
            )?;
            root.push((chunk[0].logical, physical));
        }
        let mut depth = 1u16;
        while root.len() > 4 {
            if depth >= 5 {
                return Err(unsupported("modern extent depth exceeds native maximum"));
            }
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(root.len().div_ceil(capacity))
                .map_err(|_| budget("modern extent parent rows"))?;
            if parents.capacity() > root.len().div_ceil(capacity) {
                return Err(budget("modern extent parent capacity"));
            }
            for chunk in root.chunks(capacity) {
                let physical = context.allocate()?;
                metadata = metadata
                    .checked_add(1)
                    .ok_or_else(|| budget("modern extent metadata count"))?;
                let mut block = [0; MAX_BLOCK];
                block[..2].copy_from_slice(&0xf30au16.to_le_bytes());
                block[2..4].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
                block[4..6].copy_from_slice(&(capacity as u16).to_le_bytes());
                block[6..8].copy_from_slice(&depth.to_le_bytes());
                block[8..12].copy_from_slice(&generation);
                for (index, (logical, physical)) in chunk.iter().enumerate() {
                    let at = 12 + index * 12;
                    block[at..at + 4].copy_from_slice(&(*logical as u32).to_le_bytes());
                    block[at + 4..at + 8].copy_from_slice(&physical.to_le_bytes());
                }
                let tail = 12 + capacity * 12;
                if proof.checksums.has_metadata() {
                    let checksum =
                        super::super::super::checksum::crc32c(inode_seed, &block[..tail]);
                    block[tail..tail + 4].copy_from_slice(&checksum.to_le_bytes());
                }
                context.patch(
                    u64::from(physical) * u64::from(block_size),
                    &block[..block_size as usize],
                )?;
                parents.push((chunk[0].0, physical));
            }
            root = parents;
            depth += 1;
        }
        bytes[42..44].copy_from_slice(&(root.len() as u16).to_le_bytes());
        bytes[46..48].copy_from_slice(&depth.to_le_bytes());
        for (index, (logical, physical)) in root.iter().enumerate() {
            let at = 52 + index * 12;
            bytes[at..at + 4].copy_from_slice(&(*logical as u32).to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&physical.to_le_bytes());
        }
    }
    let data = allocations.iter().try_fold(0u32, |n, a| {
        n.checked_add(a.blocks)
            .ok_or_else(|| budget("modern data sector count"))
    })?;
    let sectors = data
        .checked_add(metadata)
        .and_then(|n| n.checked_add(u32::from(super::super::super::u32le(&inode.raw, 104) != 0)))
        .and_then(|n| n.checked_mul(block_size / 512))
        .ok_or_else(|| budget("modern native sector count"))?;
    bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[108..112].copy_from_slice(&((length >> 32) as u32).to_le_bytes());
    bytes[28..32].copy_from_slice(&sectors.to_le_bytes());
    bytes[116..118].fill(0);
    context.tick(usize::from(inode_size))?;
    proof.checksums.stamp_inode(
        inode.number,
        inode.generation,
        &mut bytes[..usize::from(inode_size)],
    )?;
    context.patch(inode_offset, &bytes[..usize::from(inode_size)])
}
