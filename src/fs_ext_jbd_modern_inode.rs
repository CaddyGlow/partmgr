//! Bounded inode bitmap/counter projection and exact native inode checksum updates.
use super::*;

impl Context<'_, '_> {
    pub(super) fn allocate_inode(&mut self, directory: bool) -> io::Result<(u32, u32)> {
        let g = &self.decoder.geometry;
        let proof = g.modern.as_ref().unwrap();
        for number in 11..=g.inodes {
            self.tick(1)?;
            let group = (number - 1) / g.inodes_per_group;
            let bit = ((number - 1) % g.inodes_per_group) as usize;
            let mask = 1 << (bit % 8);
            let current = self
                .groups
                .get(&group)
                .and_then(|row| row.inode_bitmap.as_ref())
                .map_or(
                    proof.bitmaps[(group as usize * 2 + 1) * g.block_size as usize + bit / 8],
                    |bitmap| bitmap[bit / 8],
                );
            if current & mask != 0 {
                continue;
            }
            self.ensure_group(group)?;
            let row = self.groups.get_mut(&group).unwrap();
            if row.inode_bitmap.is_none() {
                let mut bitmap = Vec::new();
                bitmap
                    .try_reserve_exact(g.block_size as usize)
                    .map_err(|_| budget("modern inode bitmap allocation"))?;
                if bitmap.capacity() > g.block_size as usize {
                    return Err(budget("modern inode bitmap capacity"));
                }
                let at = (group as usize * 2 + 1) * g.block_size as usize;
                bitmap.extend_from_slice(&proof.bitmaps[at..at + g.block_size as usize]);
                row.inode_bitmap = Some(bitmap);
            }
            row.inode_bitmap.as_mut().unwrap()[bit / 8] |= mask;
            let flags = super::super::super::u16le(&row.descriptor, 18) & !1;
            row.descriptor[18..20].copy_from_slice(&flags.to_le_bytes());
            let read = |lo, hi| {
                u32::from(super::super::super::u16le(&row.descriptor, lo))
                    | if proof.descriptor_size == 64 {
                        u32::from(super::super::super::u16le(&row.descriptor, hi)) << 16
                    } else {
                        0
                    }
            };
            let free = read(14, 46)
                .checked_sub(1)
                .ok_or_else(|| invalid("modern free inode count underflow"))?;
            let directories = read(16, 48)
                .checked_add(u32::from(directory))
                .filter(|n| *n <= g.inodes_per_group)
                .ok_or_else(|| invalid("modern directory count overflow"))?;
            let unused = read(28, 50).min(g.inodes_per_group - bit as u32 - 1);
            for (lo, hi, count) in [(14, 46, free), (16, 48, directories), (28, 50, unused)] {
                row.descriptor[lo..lo + 2].copy_from_slice(&(count as u16).to_le_bytes());
                if proof.descriptor_size == 64 {
                    row.descriptor[hi..hi + 2]
                        .copy_from_slice(&((count >> 16) as u16).to_le_bytes());
                }
            }
            self.allocated_inodes = self
                .allocated_inodes
                .checked_add(1)
                .ok_or_else(|| budget("modern allocated inode count"))?;
            let offset = u64::from(super::super::super::u32le(&row.descriptor, 8))
                * u64::from(g.block_size)
                + bit as u64 * u64::from(g.inode_size);
            let mut old_generation = [0; 4];
            self.decoder
                .read_exact_at(offset + 100, &mut old_generation)?;
            let generation = u32::from_le_bytes(old_generation)
                .checked_add(1)
                .ok_or_else(|| budget("modern native inode generation exhausted"))?;
            return Ok((number, generation));
        }
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "modern native allocation has no free inode",
        ))
    }
    pub(super) fn release_inode(&mut self, number: u32, directory: bool) -> io::Result<()> {
        self.tick(1)?;
        let g = &self.decoder.geometry;
        let proof = g.modern.as_ref().unwrap();
        if number < 11 || number == proof.orphan_inode || !proof.is_allocated(number, true) {
            return Err(invalid("modern release outside ordinary inode ownership"));
        }
        let group = (number - 1) / g.inodes_per_group;
        let bit = ((number - 1) % g.inodes_per_group) as usize;
        self.ensure_group(group)?;
        let row = self.groups.get_mut(&group).unwrap();
        if row.inode_bitmap.is_none() {
            let mut bitmap = Vec::new();
            bitmap
                .try_reserve_exact(g.block_size as usize)
                .map_err(|_| budget("modern released inode bitmap"))?;
            if bitmap.capacity() > g.block_size as usize {
                return Err(budget("modern released inode bitmap capacity"));
            }
            let at = (group as usize * 2 + 1) * g.block_size as usize;
            bitmap.extend_from_slice(&proof.bitmaps[at..at + g.block_size as usize]);
            row.inode_bitmap = Some(bitmap);
        }
        let bitmap = row.inode_bitmap.as_mut().unwrap();
        let mask = 1 << (bit % 8);
        if bitmap[bit / 8] & mask == 0 {
            return Err(invalid("modern duplicate inode release"));
        }
        bitmap[bit / 8] &= !mask;
        let read = |lo, hi| {
            u32::from(super::super::super::u16le(&row.descriptor, lo))
                | if proof.descriptor_size == 64 {
                    u32::from(super::super::super::u16le(&row.descriptor, hi)) << 16
                } else {
                    0
                }
        };
        let free = read(14, 46)
            .checked_add(1)
            .filter(|n| *n <= g.inodes_per_group)
            .ok_or_else(|| invalid("modern free inode count overflow"))?;
        let directories = read(16, 48)
            .checked_sub(u32::from(directory))
            .ok_or_else(|| invalid("modern directory count underflow"))?;
        for (lo, hi, count) in [(14, 46, free), (16, 48, directories)] {
            row.descriptor[lo..lo + 2].copy_from_slice(&(count as u16).to_le_bytes());
            if proof.descriptor_size == 64 {
                row.descriptor[hi..hi + 2].copy_from_slice(&((count >> 16) as u16).to_le_bytes());
            }
        }
        self.released_inodes = self
            .released_inodes
            .checked_add(1)
            .ok_or_else(|| budget("modern released inode count"))?;
        Ok(())
    }
}

pub(super) fn patch_inode(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    edit: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> io::Result<()> {
    let g = &context.decoder.geometry;
    let proof = g.modern.as_ref().unwrap();
    let descriptor = proof.descriptors[((inode.number - 1) / g.inodes_per_group) as usize];
    let offset = u64::from(super::super::super::u32le(&descriptor, 8)) * u64::from(g.block_size)
        + u64::from((inode.number - 1) % g.inodes_per_group) * u64::from(g.inode_size);
    let size = usize::from(g.inode_size);
    let mut bytes = [0; 256];
    bytes[..128].copy_from_slice(&inode.raw);
    bytes[128..].copy_from_slice(&inode.extra);
    if let Some(index) = context
        .patches
        .iter()
        .position(|patch| patch.offset() == offset && patch.expected().len() == size)
    {
        let old = context.patches.swap_remove(index);
        bytes[..size].copy_from_slice(old.replacement());
        context.bytes -= size as u64;
        drop(old);
    }
    edit(&mut bytes[..size])?;
    proof
        .checksums
        .stamp_inode(inode.number, inode.generation, &mut bytes[..size])?;
    context.patch(offset, &bytes[..size])
}
