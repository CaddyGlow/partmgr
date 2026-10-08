//! Bounded checksum, topology and native hash-range validation for indexed directories.
use super::{dir_hash, integrity::Integrity, invalid, u16le, u32le, unsupported};
use crate::fs_core::{Reservation, Resources};
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct IndexNode {
    pub kind: u8, // 1=root, 2=index, 3=leaf.
    pub low: u32,
    pub high: u64,
    pub high_inclusive: bool,
}
pub(super) struct DirectoryIndex {
    pub nodes: Vec<IndexNode>,
    _reservation: Reservation,
}
pub(super) struct IndexOptions {
    pub inode: u32,
    pub generation: u32,
    pub block_size: usize,
    pub logical_blocks: usize,
    pub maximum_entries: usize,
    pub hash_seed: [u32; 4],
    pub unsigned_hash: bool,
}
pub(super) fn validate(
    checksums: &Integrity,
    options: IndexOptions,
    resources: &Resources,
    mut read: impl FnMut(usize, &mut [u8]) -> io::Result<()>,
) -> io::Result<DirectoryIndex> {
    let IndexOptions {
        inode,
        generation,
        block_size: bs,
        logical_blocks: blocks,
        maximum_entries,
        hash_seed,
        unsigned_hash,
    } = options;
    resources.cancellation.check().map_err(io::Error::other)?;
    if !matches!(bs, 1024 | 2048 | 4096) || blocks < 2 || maximum_entries < 2 {
        return Err(invalid("ext indexed directory geometry"));
    }
    let charge = blocks
        .checked_mul(128)
        .and_then(|bytes| bytes.checked_add(4608))
        .ok_or_else(|| invalid("ext indexed directory accounting overflow"))?;
    let reservation = resources
        .memory
        .reserve(charge as u64)
        .map_err(io::Error::other)?;
    let mut nodes = Vec::new();
    nodes.try_reserve_exact(blocks).map_err(io::Error::other)?;
    nodes.resize(blocks, IndexNode::default());
    let mut queue = Vec::new();
    queue.try_reserve_exact(blocks).map_err(io::Error::other)?;
    if nodes
        .capacity()
        .checked_mul(crate::platform::mem::size_of::<IndexNode>())
        .and_then(|bytes| {
            bytes.checked_add(
                queue
                    .capacity()
                    .checked_mul(crate::platform::mem::size_of::<(usize, u8)>())?,
            )
        })
        .and_then(|bytes| bytes.checked_add(4608))
        .is_none_or(|bytes| bytes > charge)
    {
        return Err(io::Error::other(crate::fs_core::Error::new(
            crate::fs_core::ErrorKind::BudgetExhausted,
            "ext directory index actual vector capacity",
        )));
    }
    let mut buffer = [0; 4096];
    read(0, &mut buffer[..bs])?;
    if u32le(&buffer, 0) != inode
        || u16le(&buffer, 4) != 12
        || buffer[6] != 1
        || !matches!(buffer[7], 0 | 2)
        || buffer[8] != b'.'
        || u32le(&buffer, 12) == 0
        || usize::from(u16le(&buffer, 16)) != bs - 12
        || buffer[18] != 2
        || !matches!(buffer[19], 0 | 2)
        || &buffer[20..22] != b".."
        || u32le(&buffer, 24) != 0
        || buffer[29] != 8
        || buffer[31] != 0
    {
        return Err(invalid("ext indexed directory root encoding"));
    }
    if buffer[30] > 1 || buffer[28] > 5 {
        return Err(unsupported("ext directory index depth/hash profile"));
    }
    let version = buffer[28]
        + if buffer[28] <= 2 && unsigned_hash {
            3
        } else {
            0
        };
    nodes[0] = IndexNode {
        kind: 1,
        low: 0,
        high: 1u64 << 32,
        high_inclusive: false,
    };
    queue.push((0usize, buffer[30] + 1));
    let mut cursor = 0;
    let mut entries = 2usize;
    while cursor < queue.len() {
        resources.cancellation.check().map_err(io::Error::other)?;
        let (logical, depth) = queue[cursor];
        cursor += 1;
        read(logical, &mut buffer[..bs])?;
        let parent = nodes[logical];
        let offset = if logical == 0 { 32 } else { 8 };
        if logical != 0
            && (u32le(&buffer, 0) != 0
                || usize::from(u16le(&buffer, 4)) != bs
                || buffer[6..8] != [0; 2])
        {
            return Err(invalid("ext internal directory index encoding"));
        }
        let limit = usize::from(u16le(&buffer, offset));
        let count = usize::from(u16le(&buffer, offset + 2));
        let checksum_tail = if checksums.has_metadata() { 8 } else { 0 };
        if limit != (bs - offset - checksum_tail) / 8 || count == 0 || count > limit {
            return Err(invalid("ext directory index count/capacity"));
        }
        checksums.directory_index(inode, generation, &buffer[..bs], offset)?;
        let mut previous = parent.low;
        for slot in 0..count {
            let key = if slot == 0 {
                parent.low
            } else {
                u32le(&buffer, offset + slot * 8)
            };
            let low = key & !1;
            if low < previous
                || u64::from(low) > parent.high
                || (slot != 0 && low == previous && key & 1 == 0)
            {
                return Err(invalid("ext directory index key order/parent range"));
            }
            let (high, inclusive) = if slot + 1 < count {
                let next = u32le(&buffer, offset + (slot + 1) * 8);
                (u64::from(next & !1), next & 1 != 0)
            } else {
                (parent.high, parent.high_inclusive)
            };
            if high < u64::from(low) || high > parent.high {
                return Err(invalid("ext directory index child hash interval"));
            }
            let child = u32le(&buffer, offset + slot * 8 + 4) as usize;
            if child >= blocks || nodes[child].kind != 0 {
                return Err(invalid("ext directory index cycle/alias/child bounds"));
            }
            nodes[child] = IndexNode {
                kind: if depth == 1 { 3 } else { 2 },
                low,
                high,
                high_inclusive: inclusive,
            };
            if depth != 1 {
                queue.push((child, depth - 1));
            }
            previous = low;
        }
    }
    for (logical, &node) in nodes.iter().enumerate().skip(1) {
        if node.kind == 0 {
            return Err(invalid("ext directory logical block absent from index"));
        }
        if node.kind != 3 {
            continue;
        }
        resources.cancellation.check().map_err(io::Error::other)?;
        read(logical, &mut buffer[..bs])?;
        let end = checksums.directory_leaf(inode, generation, &buffer[..bs])?;
        let mut at = 0;
        while at < end {
            resources.cancellation.check().map_err(io::Error::other)?;
            if end - at < 8 {
                return Err(invalid("ext indexed leaf directory header bounds"));
            }
            let number = u32le(&buffer, at);
            let record = usize::from(u16le(&buffer, at + 4));
            let length = usize::from(buffer[at + 6]);
            if record < 8 || !record.is_multiple_of(4) || record > end - at || length > record - 8 {
                return Err(invalid("ext indexed leaf directory record"));
            }
            if number != 0 {
                let name = &buffer[at + 8..at + 8 + length];
                if name.is_empty()
                    || name.contains(&0)
                    || name.contains(&b'/')
                    || matches!(name, b"." | b"..")
                {
                    return Err(invalid("ext indexed leaf native name"));
                }
                entries = entries
                    .checked_add(1)
                    .filter(|count| *count <= maximum_entries)
                    .ok_or_else(|| {
                        io::Error::other(crate::fs_core::Error::new(
                            crate::fs_core::ErrorKind::BudgetExhausted,
                            "ext indexed directory entry ceiling",
                        ))
                    })?;
                let hash = u64::from(dir_hash::hash(version, name, hash_seed)?);
                if hash < u64::from(node.low)
                    || hash > node.high
                    || hash == node.high && !node.high_inclusive
                {
                    return Err(invalid(
                        "ext indexed directory native name outside hash interval",
                    ));
                }
            }
            at += record;
        }
    }
    Ok(DirectoryIndex {
        nodes,
        _reservation: reservation,
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::metadata::MetadataChecksums;
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn r(bytes: u64) -> Resources {
        Resources {
            memory: Budget::new(bytes),
            cancellation: Cancellation::default(),
        }
    }
    fn w(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn d(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn crc(mut state: u32, bytes: &[u8]) -> u32 {
        state = state.reverse_bits();
        for &byte in bytes {
            state ^= u32::from(byte.reverse_bits()) << 24;
            for _ in 0..8 {
                let top = state & 0x80000000 != 0;
                state <<= 1;
                if top {
                    state ^= 0x1edc6f41;
                }
            }
        }
        state.reverse_bits()
    }
    fn seed() -> u32 {
        crc(crc(0x12345678, &2u32.to_le_bytes()), &0u32.to_le_bytes())
    }
    fn checksum_root(b: &mut [u8; 1024]) {
        let count = usize::from(u16le(b, 34));
        let value = crc(crc(seed(), &b[..32 + count * 8]), &[0; 8]);
        d(b, 1020, value);
    }
    fn checksum_leaf(b: &mut [u8; 1024]) {
        let value = crc(seed(), &b[..1012]);
        d(b, 1020, value);
    }
    fn fixture() -> [[u8; 1024]; 3] {
        let mut b = [[0; 1024]; 3];
        let root = &mut b[0];
        d(root, 0, 2);
        w(root, 4, 12);
        root[6] = 1;
        root[7] = 2;
        root[8] = b'.';
        d(root, 12, 2);
        w(root, 16, 1012);
        root[18] = 2;
        root[19] = 2;
        root[20..22].copy_from_slice(b"..");
        root[28] = 1;
        root[29] = 8;
        w(root, 32, 123);
        w(root, 34, 2);
        d(root, 36, 1);
        d(root, 40, 0x80000000);
        d(root, 44, 2);
        checksum_root(root);
        for leaf in &mut b[1..] {
            w(leaf, 4, 1012);
            w(leaf, 1016, 12);
            leaf[1019] = 0xde;
        }
        d(&mut b[2], 0, 11);
        b[2][6] = 8;
        b[2][7] = 1;
        b[2][8..16].copy_from_slice(b"filename");
        checksum_leaf(&mut b[1]);
        checksum_leaf(&mut b[2]);
        b
    }
    fn options() -> IndexOptions {
        IndexOptions {
            inode: 2,
            generation: 0,
            block_size: 1024,
            logical_blocks: 3,
            maximum_entries: 8,
            hash_seed: [0x67452301, 0xefcdab89, 0x67452301, 0xefcdab89],
            unsigned_hash: false,
        }
    }
    fn inspect(b: &[[u8; 1024]; 3], resources: &Resources) -> io::Result<DirectoryIndex> {
        validate(
            &MetadataChecksums { seed: 0x12345678 }.into(),
            options(),
            resources,
            |logical, bytes| {
                bytes.copy_from_slice(&b[logical]);
                Ok(())
            },
        )
    }
    #[cfg(feature = "std")]
    #[test]
    fn absent_checksum_native_index_capacity_topology_and_cancel() {
        // Raw native directory layout is assembled independently; no checksum
        // tail exists and each leaf's final record reaches the whole block end.
        let mut image = [[0; 1024]; 3];
        d(&mut image[0], 0, 2);
        w(&mut image[0], 4, 12);
        image[0][6..9].copy_from_slice(&[1, 2, b'.']);
        d(&mut image[0], 12, 2);
        w(&mut image[0], 16, 1012);
        image[0][18..22].copy_from_slice(&[2, 2, b'.', b'.']);
        image[0][28..30].copy_from_slice(&[1, 8]);
        w(&mut image[0], 32, 124);
        w(&mut image[0], 34, 2);
        d(&mut image[0], 36, 1);
        d(&mut image[0], 40, 0x80000000);
        d(&mut image[0], 44, 2);
        w(&mut image[1], 4, 1024);
        d(&mut image[2], 0, 11);
        w(&mut image[2], 4, 1024);
        image[2][6..16].copy_from_slice(b"\x08\x01filename");
        let policy = Integrity::superblock(&[0; 1024]).unwrap();
        let resources = r(32768);
        let inspect = |bytes: &[[u8; 1024]; 3], r: &Resources| {
            validate(&policy, options(), r, |logical, buffer| {
                buffer.copy_from_slice(&bytes[logical]);
                Ok(())
            })
        };
        let proof = inspect(&image, &resources).unwrap();
        assert_eq!(
            proof.nodes.iter().map(|n| n.kind).collect::<Vec<_>>(),
            vec![1, 3, 3]
        );
        drop(proof);
        for mutation in 0..4 {
            let mut bad = image;
            match mutation {
                0 => d(&mut bad[0], 44, 1),
                1 => w(&mut bad[0], 32, 123),
                2 => w(&mut bad[2], 4, 1012),
                _ => bad[2][8] = 0,
            }
            assert!(inspect(&bad, &resources).is_err());
            assert_eq!(resources.memory.used(), 0);
        }
        let tiny = r(0);
        assert!(inspect(&image, &tiny).is_err());
        assert_eq!(tiny.memory.used(), 0);
        let mut reads = 0;
        let cancelled = validate(&policy, options(), &resources, |logical, buffer| {
            reads += 1;
            buffer.copy_from_slice(&image[logical]);
            resources.cancellation.cancel();
            Ok(())
        });
        assert!(cancelled.is_err());
        assert_eq!(reads, 1);
        assert_eq!(resources.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn complete_index_rechecksummed_key_alias_cycle_and_leaf_defects_are_bounded() {
        let image = fixture();
        let resources = r(32768);
        let proof = inspect(&image, &resources).unwrap();
        assert_eq!(
            proof.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
            vec![1, 3, 3]
        );
        drop(proof);
        assert_eq!(resources.memory.used(), 0);
        for mutation in 0..5 {
            let mut bad = image;
            match mutation {
                0 => d(&mut bad[0], 44, 1),
                1 => d(&mut bad[0], 44, 0),
                2 => d(&mut bad[0], 44, 3),
                3 => d(&mut bad[0], 40, 0xc0000000),
                _ => bad[2][8] = 0,
            }
            checksum_root(&mut bad[0]);
            checksum_leaf(&mut bad[2]);
            assert!(inspect(&bad, &resources).is_err(), "mutation{mutation}");
            assert_eq!(resources.memory.used(), 0);
        }
        let low = r(1);
        assert!(inspect(&image, &low).is_err());
        assert_eq!(low.memory.used(), 0);
        resources.cancellation.cancel();
        assert!(inspect(&image, &resources).is_err());
        assert_eq!(resources.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn internal_index_depth_collision_ranges_and_unreferenced_blocks() {
        let base = fixture();
        let mut image = [base[0], [0; 1024], base[1], base[2]];
        image[0][30] = 1;
        w(&mut image[0], 34, 1);
        d(&mut image[0], 36, 1);
        checksum_root(&mut image[0]);
        w(&mut image[1], 4, 1024);
        w(&mut image[1], 8, 126);
        w(&mut image[1], 10, 2);
        d(&mut image[1], 12, 2);
        d(&mut image[1], 16, 0x80000000);
        d(&mut image[1], 20, 3);
        let sign = |block: &mut [u8; 1024]| {
            let count = usize::from(u16le(block, 10));
            let value = crc(crc(seed(), &block[..8 + count * 8]), &[0; 8]);
            d(block, 1020, value);
        };
        sign(&mut image[1]);
        let inspect = |blocks: &[[u8; 1024]; 4], r: &Resources| {
            let mut opts = options();
            opts.logical_blocks = 4;
            validate(
                &MetadataChecksums { seed: 0x12345678 }.into(),
                opts,
                r,
                |n, dst| {
                    dst.copy_from_slice(&blocks[n]);
                    Ok(())
                },
            )
        };
        let resources = r(32768);
        let index = inspect(&image, &resources).unwrap();
        assert_eq!(
            index.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
            [1, 2, 3, 3]
        );
        drop(index);
        for mutation in 0..4 {
            let mut bad = image;
            match mutation {
                0 => d(&mut bad[1], 20, 1),
                1 => w(&mut bad[1], 10, 1),
                2 => d(&mut bad[1], 16, 0),
                _ => d(&mut bad[1], 16, 0x80000001),
            }
            // A collision bit is valid; this exercises the inclusive upper bound.
            sign(&mut bad[1]);
            assert_eq!(inspect(&bad, &resources).is_ok(), mutation == 3);
            assert_eq!(resources.memory.used(), 0);
        }
    }
}
