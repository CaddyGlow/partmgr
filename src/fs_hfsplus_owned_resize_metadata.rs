//! Projected resize metadata; caller still must establish commit/recovery authority.
use super::*;
use crate::fs_hfsplus as native;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
pub(in super::super) struct ResizeMetadata {
    pub(in super::super) patches: Vec<WriteRange>,
    _lease: Reservation,
}
impl<S: Storage> Prepared<S> {
    pub(super) fn stage_resize_metadata(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        allocation: &ResizeAllocation,
        r: &Resources,
    ) -> Result<ResizeMetadata> {
        self.revalidate(r)?;
        let id = self.volume.lookup(path, r)?;
        let node = self.volume.node(&id)?;
        let index = match kind {
            StreamKind::Data => 0,
            StreamKind::ResourceFork => 1,
            _ => return Err(bad("HFS+ resize metadata fork")),
        };
        let inner = &self.volume.inner;
        let g = self.volume.geometry();
        let block = u64::from(g.block_size());
        let size = inner.system[1]
            .length
            .checked_add(inner.bitmap.len() as u64)
            .and_then(|n| n.checked_add(88))
            .ok_or_else(|| budget("HFS+ resize metadata size"))?;
        if size > self.range_bytes {
            return Err(budget("HFS+ resize metadata ceiling"));
        }
        let lease = r.memory.reserve(
            size.checked_mul(5)
                .and_then(|n| n.checked_add(self.limits.read.extents as u64 * 256))
                .ok_or_else(|| budget("HFS+ resize metadata charge"))?,
        )?;
        let mut bitmap = vector(inner.bitmap.len())?;
        bitmap.extend_from_slice(&inner.bitmap);
        for (&set, runs) in [(false, &allocation.released), (true, &allocation.allocated)]
            .iter()
            .map(|(set, runs)| (set, *runs))
        {
            for &(start, count) in runs {
                for b in start..start + count {
                    self.snapshot.work.charge(1)?;
                    let mask = 0x80 >> (b % 8);
                    let byte = &mut bitmap[b as usize / 8];
                    if set {
                        if *byte & mask != 0 {
                            return Err(bad("HFS+ resize allocated block is not free"));
                        }
                        *byte |= mask;
                    } else {
                        if *byte & mask == 0 {
                            return Err(bad("HFS+ resize released block is not allocated"));
                        }
                        *byte &= !mask;
                    }
                }
            }
        }
        let extmap = native::map(
            self.snapshot.clone(),
            &inner.system[1],
            g,
            self.limits.read.extents,
        )?;
        let mut work = native::Work {
            limits: self.limits.read,
            work: 0,
            nodes: 0,
            records: 0,
            extents: 0,
        };
        let tree = native::tree(&extmap, 1, false, &mut work, r)?;
        let mut records = vector(tree.records.len() + allocation.fork.overflow.len())?;
        for record in tree.records {
            if native::be32(&record.key, 2) == node.id
                && record.key[0] == if index == 0 { 0 } else { 255 }
            {
                continue;
            }
            let mut bytes = vector(2 + record.key.len() + record.data.len())?;
            bytes.extend_from_slice(&(record.key.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&record.key);
            bytes.extend_from_slice(&record.data);
            records.push(bytes);
        }
        for record in &allocation.fork.overflow {
            let mut bytes = vector(record.len())?;
            bytes.extend_from_slice(record);
            records.push(bytes);
        }
        records.sort_unstable_by_key(|record| {
            (native::be32(record, 4), record[2], native::be32(record, 8))
        });
        let mut header = [0; 40];
        native::mapped_read(&extmap, 0, &mut header, r)?;
        let node_size = usize::from(native::be16(&header, 32));
        let nodes = native::be32(&header, 36);
        let mut refs = vector(records.len())?;
        refs.extend(records.iter().map(Vec::as_slice));
        let (mut overflow, _overflow_lease) = super::super::super::keyed_tree(
            node_size,
            nodes,
            usize::MAX,
            super::super::super::TreeKind::Extents,
            &refs,
            r,
        )?;
        // Preserve native header policy/reserved fields and the opaque user record.
        // Only tree topology, record counts and the node bitmap are regenerated.
        let mut old_header = vector(node_size)?;
        old_header.resize(node_size, 0);
        self.snapshot.work.charge(node_size as u64)?;
        native::mapped_read(&extmap, 0, &mut old_header, r)?;
        let old_ranges = native::offsets(&old_header)?;
        let new_ranges = native::offsets(&overflow[..node_size])?;
        let old_record = old_ranges[0].0;
        let new_record = new_ranges[0].0;
        overflow[new_record + 30..new_record + 106]
            .copy_from_slice(&old_header[old_record + 30..old_record + 106]);
        overflow[new_ranges[1].0..new_ranges[1].1]
            .copy_from_slice(&old_header[old_ranges[1].0..old_ranges[1].1]);
        overflow[12..14].copy_from_slice(&old_header[12..14]);
        let mut patches = vector(self.limits.read.extents.saturating_mul(3).saturating_add(2))?;
        let mut patch_fork = |fork: &native::Fork, offset: u64, bytes: &[u8]| -> Result<()> {
            let end = offset
                .checked_add(bytes.len() as u64)
                .filter(|end| *end <= fork.length)
                .ok_or_else(|| bad("HFS+ resize metadata fork range"))?;
            let mut logical = 0;
            let mut covered = 0;
            for extent in &fork.extents {
                let last = logical + u64::from(extent.count) * block;
                let first = offset.max(logical);
                let limit = end.min(last);
                if first < limit {
                    let at = u64::from(extent.start) * block + first - logical;
                    let n = (limit - first) as usize;
                    let mut old = vector(n)?;
                    old.resize(n, 0);
                    self.snapshot.work.charge(n as u64)?;
                    self.target
                        .read_exact_at(at, &mut old)
                        .map_err(|e| Error::io("HFS+ resize metadata preimage", e))?;
                    let mut new = vector(n)?;
                    new.extend_from_slice(
                        &bytes[(first - offset) as usize..(limit - offset) as usize],
                    );
                    patches.push(
                        WriteRange::new(at, old, new)
                            .map_err(|e| Error::io("HFS+ resize metadata patch", e))?,
                    );
                    covered += n;
                }
                logical = last;
            }
            if covered != bytes.len() {
                return Err(bad("HFS+ resize metadata incomplete mapping"));
            }
            Ok(())
        };
        patch_fork(&inner.system[0], 0, &bitmap)?;
        patch_fork(&inner.system[1], 0, &overflow)?;
        let mut fork = allocation.fork.header;
        fork[8..12].copy_from_slice(&node.raw[96 + index * 80..100 + index * 80]);
        patch_fork(
            &inner.system[2],
            node.catalog_offset + 88 + index as u64 * 80,
            &fork,
        )?;
        for at in [1024 + 48, g.volume_bytes() - 1024 + 48] {
            let mut old = vec![0; 4];
            self.target
                .read_exact_at(at, &mut old)
                .map_err(|e| Error::io("HFS+ resize free count preimage", e))?;
            patches.push(
                WriteRange::new(at, old, allocation.free_blocks.to_be_bytes().to_vec())
                    .map_err(|e| Error::io("HFS+ resize free count", e))?,
            );
        }
        self.revalidate(r)?;
        Ok(ResizeMetadata {
            patches,
            _lease: lease,
        })
    }
}
