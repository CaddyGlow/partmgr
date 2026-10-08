//! Bounded native-hash-preserving HTree namespace reconstruction.
use super::namespace::EntryEdit;
use super::*;
use crate::fs_core::NativeName;

struct Row {
    hash: u32,
    inode: u32,
    kind: u8,
    name: Vec<u8>,
}

pub(super) fn edit(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    edit: EntryEdit<'_>,
) -> io::Result<()> {
    let decoder = context.decoder;
    let bs = decoder.geometry.block_size as usize;
    let max_blocks = context.limits.audit.directory_blocks;
    let max_entries = context.limits.directory_entries;
    if max_blocks < 2 || max_entries < 2 {
        return Err(budget("HTree minimum inventory ceilings"));
    }
    let charge = max_entries
        .checked_mul(512)
        .and_then(|n| {
            max_blocks
                .checked_mul(bs + 128)
                .and_then(|blocks| n.checked_add(blocks))
        })
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| budget("HTree planner scratch charge overflow"))?;
    let _scratch = context
        .resources
        .memory
        .reserve(charge as u64)
        .map_err(io::Error::other)?;
    let map = decoder.file_map(inode.number, max_blocks, context.resources, false)?;
    let mut root = [0; MAX_BLOCK];
    decoder.read_map(&map, 0, &mut root[..bs], context.resources)?;
    let proof = decoder.geometry.modern.as_ref().unwrap();
    let stored_version = root[28];
    let version = stored_version
        + if stored_version <= 2 && proof.unsigned_hash {
            3
        } else {
            0
        };
    let inventory = decoder.directory(inode.number, max_blocks, max_entries, context.resources)?;
    let mut rows = Vec::<Row>::new();
    rows.try_reserve_exact(max_entries)
        .map_err(|_| budget("HTree planner entry capacity"))?;
    if rows.capacity() > max_entries {
        return Err(budget("HTree planner actual entry capacity"));
    }
    let mut parent = None;
    let mut found = false;
    for entry in inventory.entries() {
        context.tick(1)?;
        let NativeName::Bytes(name) = &entry.name else {
            return Err(invalid("HTree native byte names"));
        };
        if name == b"." {
            if entry.inode != inode.number {
                return Err(invalid("HTree dot owner"));
            }
            continue;
        }
        if name == b".." {
            let number = if let EntryEdit::Reparent { old, new } = edit {
                if entry.inode != old {
                    return Err(invalid("HTree stale parent"));
                }
                found = true;
                new
            } else {
                entry.inode
            };
            if parent.replace(number).is_some() {
                return Err(invalid("HTree duplicate parent"));
            }
            continue;
        }
        if let EntryEdit::Rename {
            inode: object,
            old,
            new,
        } = edit
        {
            if name == new && name != old {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "HTree rename collision",
                ));
            }
            if name == old && entry.inode == object {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(new.len())
                    .map_err(|_| budget("HTree renamed name copy"))?;
                if bytes.capacity() > new.len() {
                    return Err(budget("HTree renamed name capacity"));
                }
                bytes.extend_from_slice(new);
                rows.push(Row {
                    hash: super::super::super::dir_hash::hash(version, new, proof.hash_seed)?,
                    inode: entry.inode,
                    kind: entry.file_type.unwrap_or(0),
                    name: bytes,
                });
                found = true;
                continue;
            }
        }
        if let EntryEdit::Remove {
            inode,
            name: removed,
        } = edit
            && name == removed
            && entry.inode == inode
        {
            found = true;
            continue;
        }
        if let EntryEdit::Insert { name: inserted, .. } = edit
            && name == inserted
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "HTree insertion collision",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(name.len())
            .map_err(|_| budget("HTree name copy"))?;
        if bytes.capacity() > name.len() {
            return Err(budget("HTree actual name capacity"));
        }
        bytes.extend_from_slice(name);
        rows.push(Row {
            hash: super::super::super::dir_hash::hash(version, name, proof.hash_seed)?,
            inode: entry.inode,
            kind: entry.file_type.unwrap_or(0),
            name: bytes,
        });
    }
    if let EntryEdit::Insert { inode, name, kind } = edit {
        if rows.len() >= max_entries {
            return Err(budget("HTree inserted entry ceiling"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(name.len())
            .map_err(|_| budget("HTree inserted name copy"))?;
        if bytes.capacity() > name.len() {
            return Err(budget("HTree inserted name capacity"));
        }
        bytes.extend_from_slice(name);
        rows.push(Row {
            hash: super::super::super::dir_hash::hash(version, name, proof.hash_seed)?,
            inode,
            kind,
            name: bytes,
        });
        found = true;
    }
    if !found {
        return Err(invalid("HTree mutation entry disappeared"));
    }
    let parent = parent.ok_or_else(|| invalid("HTree missing parent"))?;
    context
        .resources
        .cancellation
        .check()
        .map_err(io::Error::other)?;
    rows.sort_unstable_by(|a, b| (a.hash, &a.name, a.inode).cmp(&(b.hash, &b.name, b.inode)));
    let mut spans = Vec::<(usize, usize, u32)>::new();
    spans
        .try_reserve_exact(max_blocks)
        .map_err(|_| budget("HTree leaf spans"))?;
    if spans.capacity() > max_blocks {
        return Err(budget("HTree actual leaf-span capacity"));
    }
    let leaf_usable = bs
        - if proof.checksums.has_metadata() {
            12
        } else {
            0
        };
    let mut start = 0;
    while start < rows.len() {
        let mut end = start;
        let mut used = 0;
        while end < rows.len() {
            let size = (8 + rows[end].name.len()).next_multiple_of(4);
            if used + size > leaf_usable {
                break;
            }
            used += size;
            end += 1;
        }
        if end == start || spans.len() >= max_blocks {
            return Err(budget("HTree leaf block ceiling"));
        }
        let key = if start == 0 {
            0
        } else {
            rows[start].hash | u32::from(rows[start - 1].hash == rows[start].hash)
        };
        spans.push((start, end, key));
        start = end;
    }
    if spans.is_empty() {
        spans.push((0, 0, 0));
    }
    let checksum_tail = if proof.checksums.has_metadata() { 8 } else { 0 };
    let root_limit = (bs - 32 - checksum_tail) / 8;
    let node_limit = (bs - 8 - checksum_tail) / 8;
    let nodes = if spans.len() <= root_limit {
        0
    } else {
        spans.len().div_ceil(node_limit)
    };
    if nodes > root_limit {
        return Err(budget("HTree supported index-depth ceiling"));
    }
    let blocks = 1 + spans.len() + nodes;
    if blocks > max_blocks || blocks > context.limits.file_blocks {
        return Err(budget("HTree total directory block ceiling"));
    }
    let decoded = context.allocation_map(inode)?;
    for allocation in &decoded.allocations {
        if allocation.unwritten
            || allocation.logical + u64::from(allocation.blocks) > inode.length / (bs as u64)
        {
            return Err(unsupported("HTree uninitialized/beyond-length allocation"));
        }
        for relative in 0..allocation.blocks {
            context.release(allocation.physical + relative)?;
        }
    }
    for &physical in &decoded.metadata {
        context.release(physical)?;
    }
    let mut allocations = Vec::new();
    allocations
        .try_reserve_exact(blocks)
        .map_err(|_| budget("HTree extent rows"))?;
    if allocations.capacity() > blocks {
        return Err(budget("HTree actual extent-row capacity"));
    }
    let inode_seed = proof
        .checksums
        .has_metadata()
        .then(|| proof.checksums.inode_seed(inode.number, inode.generation));
    for logical in 0..blocks {
        let mut block = [0; MAX_BLOCK];
        if logical == 0 {
            block[..24].copy_from_slice(&root[..24]);
            block[12..16].copy_from_slice(&parent.to_le_bytes());
            block[28] = stored_version;
            block[29] = 8;
            block[30] = u8::from(nodes != 0);
            index(
                &mut block[..bs],
                32,
                root_limit,
                if nodes == 0 { spans.len() } else { nodes },
                inode_seed,
                |slot| {
                    if nodes == 0 {
                        (spans[slot].2, (slot + 1) as u32)
                    } else {
                        (spans[slot * node_limit].2, (1 + spans.len() + slot) as u32)
                    }
                },
            );
        } else if logical <= spans.len() {
            let (start, end, _) = spans[logical - 1];
            let mut at = 0;
            for (position, row) in rows[start..end].iter().enumerate() {
                let size = if position + 1 == end - start {
                    leaf_usable - at
                } else {
                    (8 + row.name.len()).next_multiple_of(4)
                };
                block[at..at + 4].copy_from_slice(&row.inode.to_le_bytes());
                block[at + 4..at + 6].copy_from_slice(&(size as u16).to_le_bytes());
                block[at + 6] = row.name.len() as u8;
                block[at + 7] = row.kind;
                block[at + 8..at + 8 + row.name.len()].copy_from_slice(&row.name);
                at += size;
            }
            if start == end {
                block[4..6].copy_from_slice(&(leaf_usable as u16).to_le_bytes());
            }
            proof.checksums.stamp_directory_leaf(
                inode.number,
                inode.generation,
                &mut block[..bs],
            )?;
        } else {
            block[4..6].copy_from_slice(&(bs as u16).to_le_bytes());
            let first = (logical - 1 - spans.len()) * node_limit;
            let count = (spans.len() - first).min(node_limit);
            index(&mut block[..bs], 8, node_limit, count, inode_seed, |slot| {
                let leaf = first + slot;
                (spans[leaf].2, (leaf + 1) as u32)
            });
        }
        let physical = context.allocate()?;
        context.patch(u64::from(physical) * (bs as u64), &block[..bs])?;
        allocations.push(super::super::super::extent::ExtentAllocation {
            logical: logical as u64,
            physical,
            blocks: 1,
            unwritten: false,
        });
    }
    write_inode(context, inode, (blocks * bs) as u64, &allocations)
}

fn index(
    bytes: &mut [u8],
    offset: usize,
    limit: usize,
    count: usize,
    seed: Option<u32>,
    mut child: impl FnMut(usize) -> (u32, u32),
) {
    bytes[offset..offset + 2].copy_from_slice(&(limit as u16).to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&(count as u16).to_le_bytes());
    for slot in 0..count {
        let (key, logical) = child(slot);
        let at = offset + slot * 8;
        if slot != 0 {
            bytes[at..at + 4].copy_from_slice(&key.to_le_bytes());
        }
        bytes[at + 4..at + 8].copy_from_slice(&logical.to_le_bytes());
    }
    if let Some(seed) = seed {
        let tail = offset + limit * 8;
        let crc = super::super::super::checksum::crc32c(seed, &bytes[..offset + count * 8]);
        let crc = super::super::super::checksum::crc32c(crc, &[0; 8]);
        bytes[tail + 4..tail + 8].copy_from_slice(&crc.to_le_bytes());
    }
}
