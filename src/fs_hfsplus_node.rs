//! Staged native B-tree node assembly for HFS+ authoring and owned mutation.
//! This codec supplies bytes only; it grants no allocation or publication authority.
use super::{bad, budget, vector};
use crate::fs_core::{Reservation, Resources, Result};
#[path = "fs_hfsplus_allocation_builder.rs"]
mod allocation_builder;
#[path = "fs_hfsplus_builder_inventory.rs"]
pub(crate) mod builder_inventory;
#[path = "fs_hfsplus_builder_layout.rs"]
mod builder_layout;
#[path = "fs_hfsplus_fork_builder.rs"]
mod fork_builder;
#[cfg(test)]
#[path = "../tests/fixtures/hfsplus_clean.rs"]
mod independent;
#[path = "fs_hfsplus_metadata_builder.rs"]
pub(crate) mod metadata_builder;
#[path = "fs_hfsplus_owned_prepare.rs"]
pub(crate) mod owned_prepare;

#[derive(Clone, Copy)]
enum Kind {
    Leaf,
    Header,
    #[cfg(test)]
    Map,
    Index {
        height: u8,
    },
}

pub(super) fn leaf(
    node_bytes: usize,
    forward: u32,
    backward: u32,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    assemble(node_bytes, forward, backward, Kind::Leaf, records, r)
}

fn assemble(
    node_bytes: usize,
    forward: u32,
    backward: u32,
    kind: Kind,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    r.cancellation.check()?;
    let (native_kind, height) = match kind {
        Kind::Leaf => (0xff, 1),
        Kind::Header => (1, 0),
        #[cfg(test)]
        Kind::Map => (2, 0),
        Kind::Index {
            height: height @ 2..=64,
        } => (0, height),
        Kind::Index { .. } => return Err(bad("HFS+ authoring index height")),
    };
    match kind {
        Kind::Header if backward != 0 || records.len() != 3 => {
            return Err(bad("HFS+ authoring header descriptor"));
        }
        Kind::Header
            if records[0].len() != 106 || records[1].len() != 128 || records[2].is_empty() =>
        {
            return Err(bad("HFS+ authoring header records"));
        }
        #[cfg(test)]
        Kind::Map if records.len() != 1 || records[0].is_empty() => {
            return Err(bad("HFS+ authoring map records"));
        }
        _ => {}
    }
    if matches!(kind, Kind::Index { .. }) {
        if records.is_empty() {
            return Err(bad("HFS+ authoring empty index"));
        }
        for record in records {
            if record.len() < 8 {
                return Err(bad("HFS+ authoring short index record"));
            }
            let key_bytes = usize::from(super::be16(record, 0)) + 2;
            if key_bytes + 4 != record.len()
                || !key_bytes.is_multiple_of(2)
                || super::be32(record, key_bytes) == 0
            {
                return Err(bad("HFS+ authoring index key/child encoding"));
            }
        }
    }
    if !(512..=32768).contains(&node_bytes) || !node_bytes.is_power_of_two() {
        return Err(bad("HFS+ authoring node size"));
    }
    let count: u16 = records
        .len()
        .try_into()
        .map_err(|_| budget("HFS+ authoring record count"))?;
    let table = node_bytes
        .checked_sub((usize::from(count) + 1) * 2)
        .filter(|at| *at >= 14)
        .ok_or_else(|| budget("HFS+ authoring offset table"))?;
    let mut end = 14usize;
    for record in records {
        r.cancellation.check()?;
        if record.is_empty() || !record.len().is_multiple_of(2) {
            return Err(bad("HFS+ authoring empty or unaligned record"));
        }
        end = end
            .checked_add(record.len())
            .filter(|end| *end <= table)
            .ok_or_else(|| budget("HFS+ authoring node capacity"))?;
    }
    let lease = r.memory.reserve(node_bytes as u64)?;
    let mut bytes = vector(node_bytes)?;
    bytes.resize(node_bytes, 0);
    bytes[..4].copy_from_slice(&forward.to_be_bytes());
    bytes[4..8].copy_from_slice(&backward.to_be_bytes());
    bytes[8] = native_kind;
    bytes[9] = height;
    bytes[10..12].copy_from_slice(&count.to_be_bytes());
    let mut at = 14;
    for (i, record) in records.iter().enumerate() {
        let slot = node_bytes - (i + 1) * 2;
        bytes[slot..slot + 2].copy_from_slice(&(at as u16).to_be_bytes());
        bytes[at..at + record.len()].copy_from_slice(record);
        at += record.len();
    }
    let slot = node_bytes - (records.len() + 1) * 2;
    bytes[slot..slot + 2].copy_from_slice(&(at as u16).to_be_bytes());
    Ok((bytes, lease))
}

#[test]
fn native_leaf_layout_capacity_and_prewrite_rejections() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(512),
        cancellation: Cancellation::default(),
    };
    let first = [0x12; 242];
    let second = [0x34; 250];
    let (bytes, lease) = leaf(512, 0x10203040, 7, &[&first, &second], &r).unwrap();
    assert_eq!(
        &bytes[..14],
        &[0x10, 0x20, 0x30, 0x40, 0, 0, 0, 7, 255, 1, 0, 2, 0, 0]
    );
    assert_eq!(&bytes[506..], &[1, 250, 1, 0, 0, 14]);
    assert_eq!(super::offsets(&bytes).unwrap(), [(14, 256), (256, 506)]);
    assert_eq!(&bytes[14..256], first);
    assert_eq!(&bytes[256..506], second);
    assert_eq!(r.memory.used(), 512);
    drop((bytes, lease));
    assert_eq!(r.memory.used(), 0);
    assert!(leaf(512, 0, 0, &[&first, &[0; 252]], &r).is_err());
    assert!(leaf(512, 0, 0, &[&[1]], &r).is_err());
    assert!(leaf(513, 0, 0, &[], &r).is_err());
    r.cancellation.cancel();
    assert!(leaf(512, 0, 0, &[], &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_index_key_child_layout_and_invalid_targets() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(512),
        cancellation: Cancellation::default(),
    };
    let record = [0, 2, 0x12, 0x34, 0, 0, 0, 9];
    let (bytes, lease) = assemble(512, 0, 0, Kind::Index { height: 2 }, &[&record], &r).unwrap();
    assert_eq!(&bytes[8..14], &[0, 2, 0, 1, 0, 0]);
    assert_eq!(&bytes[14..22], &record);
    assert_eq!(&bytes[508..], &[0, 22, 0, 14]);
    assert_eq!(super::offsets(&bytes).unwrap(), [(14, 22)]);
    drop((bytes, lease));
    for height in [0, 1, 65, 255] {
        assert!(assemble(512, 0, 0, Kind::Index { height }, &[&record], &r).is_err());
    }
    for invalid in [[0, 2, 0, 0, 0, 0, 0, 0], [0, 4, 0, 0, 0, 0, 0, 9]] {
        assert!(assemble(512, 0, 0, Kind::Index { height: 2 }, &[&invalid], &r).is_err());
    }
    assert!(assemble(512, 0, 0, Kind::Index { height: 2 }, &[], &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_header_and_continuation_map_layout() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(1024),
        cancellation: Cancellation::default(),
    };
    let header = [0; 106];
    let user = [0; 128];
    let mut map = [0; 256];
    map[0] = 0xc0;
    let (bytes, lease) = assemble(512, 2, 0, Kind::Header, &[&header, &user, &map], &r).unwrap();
    assert_eq!(&bytes[..14], &[0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0]);
    assert_eq!(
        super::offsets(&bytes).unwrap(),
        [(14, 120), (120, 248), (248, 504)]
    );
    assert_eq!(&bytes[504..], &[1, 248, 0, 248, 0, 120, 0, 14]);
    assert_eq!(bytes[248], 0xc0);
    let (next, next_lease) = assemble(512, 3, 0, Kind::Map, &[&map], &r).unwrap();
    assert_eq!(&next[..14], &[0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0]);
    assert_eq!(super::offsets(&next).unwrap(), [(14, 270)]);
    assert_eq!(r.memory.used(), 1024);
    drop((bytes, lease, next, next_lease));
    assert!(assemble(512, 0, 1, Kind::Header, &[&header, &user, &map], &r).is_err());
    assert!(assemble(512, 0, 0, Kind::Header, &[&user, &user, &map], &r).is_err());
    assert!(assemble(512, 0, 0, Kind::Header, &[], &r).is_err());
    assert!(assemble(512, 0, 0, Kind::Map, &[], &r).is_err());
    assert!(assemble(512, 0, 0, Kind::Map, &[&map, &map], &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

fn catalog_key(
    parent: u32,
    name: &[u16],
    binary: bool,
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    r.cancellation.check()?;
    if name.len() > 255 {
        return Err(bad("HFS+ authoring catalog name length"));
    }
    let length = 8 + name.len() * 2;
    let lease = r.memory.reserve(length as u64)?;
    let scratch = r.memory.reserve((4 * (name.len() + 1)) as u64)?;
    let mut bytes = vector(length)?;
    bytes.extend_from_slice(&((length - 2) as u16).to_be_bytes());
    bytes.extend_from_slice(&parent.to_be_bytes());
    bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
    for unit in name {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    super::key(&bytes[2..], 0, binary)?;
    drop(scratch);
    Ok((bytes, lease))
}

#[cfg(test)]
fn catalog_leaf(
    node_bytes: usize,
    forward: u32,
    backward: u32,
    binary: bool,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    keyed_leaf(
        node_bytes,
        forward,
        backward,
        TreeKind::Catalog { binary },
        records,
        r,
    )
}

#[derive(Clone, Copy)]
enum TreeKind {
    Catalog { binary: bool },
    Extents,
}
impl TreeKind {
    fn native(self) -> u8 {
        if matches!(self, Self::Extents) { 1 } else { 0 }
    }
    fn binary(self) -> bool {
        matches!(self, Self::Catalog { binary: true })
    }
}

fn keyed_leaf(
    node_bytes: usize,
    forward: u32,
    backward: u32,
    kind: TreeKind,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    r.cancellation.check()?;
    // At most two decoded native keys survive simultaneously.
    let _scratch = r.memory.reserve(2 * 256 * 4)?;
    let mut previous = None;
    for record in records {
        r.cancellation.check()?;
        if record.len() < 8 {
            return Err(bad("HFS+ authoring short catalog record"));
        }
        let end = usize::from(super::be16(record, 0)) + 2;
        if end > record.len() || end < 8 {
            return Err(bad("HFS+ authoring catalog key bounds"));
        }
        let key = super::key(&record[2..end], kind.native(), kind.binary())?;
        if previous.as_ref().is_some_and(|old| old >= &key) {
            return Err(bad("HFS+ authoring catalog order or collision"));
        }
        previous = Some(key);
    }
    leaf(node_bytes, forward, backward, records, r)
}

#[test]
fn native_catalog_keys_and_case_profile_collisions() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    };
    let (upper, upper_lease) = catalog_key(2, &[65], false, &r).unwrap();
    let (lower, lower_lease) = catalog_key(2, &[97], false, &r).unwrap();
    assert_eq!(upper, [0, 8, 0, 0, 0, 2, 0, 1, 0, 65]);
    let (thread, thread_lease) = catalog_key(2, &[], false, &r).unwrap();
    assert_eq!(thread, [0, 6, 0, 0, 0, 2, 0, 0]);
    assert!(catalog_leaf(512, 0, 0, false, &[&upper, &lower], &r).is_err());
    let (node, node_lease) = catalog_leaf(512, 0, 0, true, &[&thread, &upper, &lower], &r).unwrap();
    assert_eq!(
        super::offsets(&node).unwrap(),
        [(14, 22), (22, 32), (32, 42)]
    );
    assert!(catalog_leaf(512, 0, 0, true, &[&lower, &upper], &r).is_err());
    assert!(catalog_key(2, &[0xe9], false, &r).is_err());
    let (unicode, unicode_lease) = catalog_key(2, &[0xe9], true, &r).unwrap();
    assert_eq!(&unicode[8..], &[0, 0xe9]);
    assert!(catalog_key(2, &[65; 256], true, &r).is_err());
    drop((
        upper,
        upper_lease,
        lower,
        lower_lease,
        thread,
        thread_lease,
        node,
        node_lease,
        unicode,
        unicode_lease,
    ));
    assert_eq!(r.memory.used(), 0);
}

fn catalog_tree(
    node_bytes: usize,
    total_nodes: u32,
    max_leaf_records: usize,
    binary: bool,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    keyed_tree(
        node_bytes,
        total_nodes,
        max_leaf_records,
        TreeKind::Catalog { binary },
        records,
        r,
    )
}

fn keyed_tree(
    node_bytes: usize,
    total_nodes: u32,
    max_leaf_records: usize,
    kind: TreeKind,
    records: &[&[u8]],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    r.cancellation.check()?;
    if !(if kind.native() == 0 { 4096 } else { 512 }..=32768).contains(&node_bytes)
        || !node_bytes.is_power_of_two()
        || total_nodes < if records.is_empty() { 1 } else { 2 }
        || u64::from(total_nodes) > ((node_bytes - 256) * 8) as u64
        || records.is_empty() && kind.native() == 0
        || max_leaf_records == 0
    {
        return Err(bad("HFS+ staged catalog tree geometry"));
    }
    let count: u32 = records
        .len()
        .try_into()
        .map_err(|_| budget("HFS+ tree record count"))?;
    let scratch_bytes = (records.len() as u64)
        .checked_mul(2000)
        .and_then(|n| n.checked_add(2048))
        .ok_or_else(|| budget("HFS+ tree planning charge"))?;
    let _scratch = r.memory.reserve(scratch_bytes)?;
    let mut groups = vector(records.len())?;
    let mut previous = None;
    let mut start = 0;
    let mut body = 14usize;
    for (i, record) in records.iter().enumerate() {
        r.cancellation.check()?;
        if record.len() < 8 || !record.len().is_multiple_of(2) {
            return Err(bad("HFS+ tree catalog record encoding"));
        }
        let end = usize::from(super::be16(record, 0)) + 2;
        if end < 8 || end > record.len() {
            return Err(bad("HFS+ tree catalog key bounds"));
        }
        if kind.native() == 1 && record.len() - end != 64 {
            return Err(bad("HFS+ authoring overflow extent body size"));
        }
        let key = super::key(&record[2..end], kind.native(), kind.binary())?;
        if previous.as_ref().is_some_and(|old| old >= &key) {
            return Err(bad("HFS+ tree catalog order or collision"));
        }
        previous = Some(key);
        if record.len() > node_bytes - 18 {
            return Err(budget("HFS+ tree record exceeds leaf"));
        }
        if i > start
            && (i - start >= max_leaf_records
                || body + record.len() + 2 * (i - start + 2) > node_bytes)
        {
            groups.push((start, i));
            start = i;
            body = 14;
        }
        body += record.len();
    }
    if !records.is_empty() {
        groups.push((start, records.len()));
    }
    let leaves: u32 = groups
        .len()
        .try_into()
        .map_err(|_| budget("HFS+ tree leaf count"))?;
    let mut used = leaves
        .checked_add(1)
        .ok_or_else(|| budget("HFS+ tree node count"))?;
    if used > total_nodes {
        return Err(budget("HFS+ tree node allocation capacity"));
    }
    let length = node_bytes
        .checked_mul(total_nodes as usize)
        .ok_or_else(|| budget("HFS+ tree byte count"))?;
    let lease = r.memory.reserve(length as u64)?;
    let mut bytes = vector(length)?;
    bytes.resize(length, 0);
    let mut index_records = vector(groups.len())?;
    for (i, (start, end)) in groups.iter().copied().enumerate() {
        r.cancellation.check()?;
        let id = i as u32 + 1;
        let (node, node_lease) = keyed_leaf(
            node_bytes,
            if id < leaves { id + 1 } else { 0 },
            id - 1,
            kind,
            &records[start..end],
            r,
        )?;
        let at = id as usize * node_bytes;
        bytes[at..at + node_bytes].copy_from_slice(&node);
        drop((node, node_lease));
        {
            let key_end = usize::from(super::be16(records[start], 0)) + 2;
            let mut record = vector(key_end + 4)?;
            record.extend_from_slice(&records[start][..key_end]);
            record.extend_from_slice(&id.to_be_bytes());
            index_records.push(record);
        }
    }
    let mut height = if leaves == 0 { 0u8 } else { 1u8 };
    while index_records.len() > 1 {
        r.cancellation.check()?;
        height = height
            .checked_add(1)
            .filter(|h| *h <= 64)
            .ok_or_else(|| budget("HFS+ tree height"))?;
        let mut ranges = vector(index_records.len())?;
        let mut start = 0;
        let mut body = 14usize;
        for (i, record) in index_records.iter().enumerate() {
            if i > start && body + record.len() + 2 * (i - start + 2) > node_bytes {
                ranges.push((start, i));
                start = i;
                body = 14;
            }
            body += record.len();
        }
        ranges.push((start, index_records.len()));
        // The checked native profile requires at least two children per index.
        if ranges.len() > 1 && ranges.last().is_some_and(|(a, b)| b - a == 1) {
            let last = ranges.len() - 1;
            if ranges[last - 1].1 - ranges[last - 1].0 < 3 {
                return Err(budget("HFS+ index rebalance capacity"));
            }
            ranges[last - 1].1 -= 1;
            ranges[last].0 -= 1;
        }
        if ranges.len() >= index_records.len() {
            return Err(budget("HFS+ tree index fanout"));
        }
        let count =
            u32::try_from(ranges.len()).map_err(|_| budget("HFS+ tree index node count"))?;
        let after = used
            .checked_add(count)
            .filter(|n| *n <= total_nodes)
            .ok_or_else(|| budget("HFS+ tree index allocation capacity"))?;
        let mut next = vector(ranges.len())?;
        for (i, (start, end)) in ranges.iter().copied().enumerate() {
            r.cancellation.check()?;
            let id = used + i as u32;
            let refs: Vec<_> = index_records[start..end]
                .iter()
                .map(Vec::as_slice)
                .collect();
            let (node, node_lease) = assemble(
                node_bytes,
                if i + 1 < ranges.len() { id + 1 } else { 0 },
                if i > 0 { id - 1 } else { 0 },
                Kind::Index { height },
                &refs,
                r,
            )?;
            let at = id as usize * node_bytes;
            bytes[at..at + node_bytes].copy_from_slice(&node);
            drop((node, node_lease));
            let first = &index_records[start];
            let mut record = vector(first.len())?;
            record.extend_from_slice(&first[..first.len() - 4]);
            record.extend_from_slice(&id.to_be_bytes());
            next.push(record);
        }
        used = after;
        index_records = next;
    }
    let root = if index_records.is_empty() {
        0
    } else {
        super::be32(&index_records[0], index_records[0].len() - 4)
    };
    let mut header = [0; 106];
    header[..2].copy_from_slice(&u16::from(height).to_be_bytes());
    for (at, value) in [
        (2, root),
        (6, count),
        (10, if leaves == 0 { 0 } else { 1 }),
        (14, leaves),
        (22, total_nodes),
        (26, total_nodes - used),
        (38, if kind.native() == 0 { 6 } else { 2 }),
    ] {
        header[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    header[18..20].copy_from_slice(&(node_bytes as u16).to_be_bytes());
    header[20..22]
        .copy_from_slice(&(if kind.native() == 0 { 516u16 } else { 10u16 }).to_be_bytes());
    header[37] = if kind.binary() { 0xbc } else { 0xcf };
    let map_lease = r.memory.reserve((node_bytes - 256) as u64)?;
    let mut bitmap = vector(node_bytes - 256)?;
    bitmap.resize(node_bytes - 256, 0);
    for id in 0..used {
        bitmap[id as usize / 8] |= 0x80 >> (id % 8);
    }
    let (node, node_lease) = assemble(
        node_bytes,
        0,
        0,
        Kind::Header,
        &[&header, &[0; 128], &bitmap],
        r,
    )?;
    bytes[..node_bytes].copy_from_slice(&node);
    drop((node, node_lease, bitmap, map_lease));
    Ok((bytes, lease))
}

#[test]
fn assembled_catalog_tree_passes_existing_volume_decoder_and_ownership_audit() {
    use crate::{
        fs_core::{Budget, Cancellation},
        fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
        fs_hfsplus_audit::{HfsPlusAuditLimits, audit_hfsplus},
    };
    use std::{io, sync::Arc};
    struct Bytes(Vec<u8>);
    impl virtdisk::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let start = usize::try_from(at).map_err(io::Error::other)?;
            let end = start
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(start..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    for (binary, max_leaf_records) in [(false, 64), (true, 64), (false, 4), (true, 4)] {
        let r = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let mut image = independent::hfsplus_seed(binary);
        let mut records = Vec::new();
        for block in [6, 7] {
            let node = &image[block * 4096..(block + 1) * 4096];
            for (a, b) in super::offsets(node).unwrap() {
                records.push(node[a..b].to_vec());
            }
        }
        let extents: Vec<_> = (0..9).map(|i| (12 + i * 2, 1)).collect();
        let planned_data =
            fork_builder::plan(16, false, 9 * 4096 - 7, (4096, 256), &extents, &r).unwrap();
        let planned_resource =
            fork_builder::plan(16, true, 5, (4096, 256), &[(32, 1)], &r).unwrap();
        for record in &mut records {
            let key_end = usize::from(super::be16(record, 0)) + 2;
            if super::be16(record, key_end) == 2 && super::be32(record, key_end + 8) == 16 {
                assert_eq!(&record[key_end + 88..key_end + 168], &planned_data.header);
                assert_eq!(
                    &record[key_end + 168..key_end + 248],
                    &planned_resource.header
                );
                record[key_end + 88..key_end + 168].copy_from_slice(&planned_data.header);
                record[key_end + 168..key_end + 248].copy_from_slice(&planned_resource.header);
            }
        }
        let retained = r.memory.used();
        let refs: Vec<_> = records.iter().map(Vec::as_slice).collect();
        assert!(catalog_tree(4096, 4, 1, binary, &refs, &r).is_err());
        assert!(catalog_tree(4096, 4, 0, binary, &refs, &r).is_err());
        assert_eq!(r.memory.used(), retained);
        let (tree, lease) = catalog_tree(4096, 4, max_leaf_records, binary, &refs, &r).unwrap();
        image[4 * 4096..8 * 4096].copy_from_slice(&tree);
        drop((tree, lease));
        let overflow_refs: Vec<_> = planned_data.overflow.iter().map(Vec::as_slice).collect();
        let (overflow, overflow_lease) =
            keyed_tree(1024, 4, 1, TreeKind::Extents, &overflow_refs, &r).unwrap();
        image[2 * 4096..3 * 4096].copy_from_slice(&overflow);
        drop((overflow, overflow_lease, planned_data, planned_resource));
        let volume = HfsPlusVolume::open(
            Arc::new(Bytes(image)),
            HfsPlusReadLimits {
                blocks: 256,
                nodes: 32,
                records: 64,
                extents: 128,
                work: 4 << 20,
            },
            &r,
        )
        .unwrap();
        let proof = audit_hfsplus(
            &volume,
            HfsPlusAuditLimits {
                blocks: 256,
                objects: 64,
                depth: 16,
                findings: 64,
                work: 4 << 20,
            },
            &r,
        )
        .unwrap();
        assert!(proof.is_clean() && proof.is_complete());
        drop((proof, volume));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn deep_catalog_indexes_reopen_with_exact_child_minima_and_sibling_topology() {
    use crate::{
        fs_core::{Budget, Cancellation},
        fs_file::{ExtentFile, ExtentKind, FileExtent},
    };
    use std::{io, sync::Arc};
    struct Bytes(Vec<u8>);
    impl virtdisk::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let mut records = Vec::new();
    let mut leases = Vec::new();
    for i in 0..100u16 {
        let mut name = [65; 250];
        name[249] = 1000 + i;
        let (mut key, lease) = catalog_key(2, &name, true, &r).unwrap();
        key.extend_from_slice(&[0, 3]);
        records.push(key);
        leases.push(lease);
    }
    let refs: Vec<_> = records.iter().map(Vec::as_slice).collect();
    let (bytes, lease) = catalog_tree(4096, 128, 1, true, &refs, &r).unwrap();
    assert_eq!(super::be16(&bytes, 14), 4);
    let file = ExtentFile::new(
        Arc::new(Bytes(bytes)),
        128 * 4096,
        vec![FileExtent {
            offset: 0,
            length: 128 * 4096,
            kind: ExtentKind::Data(0),
        }],
        1,
    )
    .unwrap();
    let mut work = super::Work {
        limits: super::HfsPlusReadLimits {
            blocks: 128,
            nodes: 128,
            records: 100,
            extents: 1,
            work: 8 << 20,
        },
        work: 0,
        nodes: 0,
        records: 0,
        extents: 0,
    };
    let tree = super::tree(&file, 0, true, &mut work, &r).unwrap();
    assert_eq!(tree.records.len(), 100);
    for (record, original) in tree.records.iter().zip(records.iter()) {
        assert_eq!(&record.key, &original[2..original.len() - 2]);
        assert_eq!(record.data, [0, 3]);
    }
    drop((tree, file, lease, records, leases));
    assert_eq!(r.memory.used(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit native HFS+ catalog assembly gate requires immutable inputs and fresh evidence"]
fn native_catalog_assembly_fsck_and_complete_fork_models() {
    use crate::fs_core::{Budget, Cancellation};
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let input = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_CATALOG_INPUT").expect("explicit native input required"),
    );
    let output = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_CATALOG_EVIDENCE").expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let mut receipt = String::new();
    for tool in [checker, icat] {
        receipt.push_str(&format!(
            "tool={tool} sha256={:x}\n",
            Sha256::digest(fs::read(tool).unwrap())
        ));
    }
    for binary in [false, true] {
        let profile = if binary { "hfsx" } else { "hfsplus" };
        let source = input.join(format!("{profile}-independent-tree.img"));
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let source_lease = r
            .memory
            .reserve(fs::metadata(&source).unwrap().len())
            .unwrap();
        let original = fs::read(&source).unwrap();
        let bs = super::be32(&original, 1024 + 40) as usize;
        let catalog = super::be32(&original, 1024 + 272 + 16) as usize * bs;
        let length =
            u64::from_be_bytes(original[1024 + 272..1024 + 280].try_into().unwrap()) as usize;
        let ns = usize::from(super::be16(&original, catalog + 32));
        let total = super::be32(&original, catalog + 36);
        assert_eq!(length, ns * total as usize);
        let records_lease = r.memory.reserve((length as u64) * 2).unwrap();
        let mut records = Vec::new();
        let mut leaf = super::be32(&original, catalog + 24);
        let mut visited = std::collections::BTreeSet::new();
        while leaf != 0 {
            assert!(leaf < total && visited.insert(leaf));
            let at = catalog + leaf as usize * ns;
            let node = &original[at..at + ns];
            assert_eq!(&node[8..10], &[255, 1]);
            for (a, b) in super::offsets(node).unwrap() {
                records.push(node[a..b].to_vec());
            }
            leaf = super::be32(node, 0);
        }
        let refs: Vec<_> = records.iter().map(Vec::as_slice).collect();
        let extents = super::be32(&original, 1024 + 192 + 16) as usize * bs;
        let extents_length =
            u64::from_be_bytes(original[1024 + 192..1024 + 200].try_into().unwrap()) as usize;
        let extents_ns = usize::from(super::be16(&original, extents + 32));
        let extents_total = super::be32(&original, extents + 36);
        assert_eq!(extents_length, extents_ns * extents_total as usize);
        assert!(extents + extents_length <= catalog);
        let mut overflow_records = Vec::new();
        let mut leaf = super::be32(&original, extents + 24);
        let mut seen = std::collections::BTreeSet::new();
        while leaf != 0 {
            assert!(leaf < extents_total && seen.insert(leaf));
            let at = extents + leaf as usize * extents_ns;
            let node = &original[at..at + extents_ns];
            for (a, b) in super::offsets(node).unwrap() {
                overflow_records.push(node[a..b].to_vec());
            }
            leaf = super::be32(node, 0);
        }
        let overflow_refs: Vec<_> = overflow_records.iter().map(Vec::as_slice).collect();
        for max_records in [64, 2] {
            let label = format!("{profile}-leafcap{max_records}");
            let (tree, tree_lease) =
                catalog_tree(ns, total, max_records, binary, &refs, &r).unwrap();
            let image_lease = r.memory.reserve(original.len() as u64).unwrap();
            let mut image = original.clone();
            image[catalog..catalog + length].copy_from_slice(&tree);
            let (overflow, overflow_lease) = keyed_tree(
                extents_ns,
                extents_total,
                max_records,
                TreeKind::Extents,
                &overflow_refs,
                &r,
            )
            .unwrap();
            image[extents..extents + extents_length].copy_from_slice(&overflow);
            assert_eq!(&image[..extents], &original[..extents]);
            assert_eq!(
                &image[extents + extents_length..catalog],
                &original[extents + extents_length..catalog]
            );
            drop((overflow, overflow_lease));
            assert_eq!(&image[catalog + length..], &original[catalog + length..]);
            let path = output.join(format!("{label}.img"));
            fs::write(&path, &image).unwrap();
            let check = Command::new(checker)
                .arg("-fn")
                .arg(&path)
                .output()
                .unwrap();
            fs::write(output.join(format!("{label}-fsck.stdout")), &check.stdout).unwrap();
            fs::write(output.join(format!("{label}-fsck.stderr")), &check.stderr).unwrap();
            assert!(check.status.success(), "native checker {check:?}");
            let text = String::from_utf8_lossy(&check.stdout);
            assert!(text.contains("appears to be OK"), "{text}");
            for (id, expected) in [
                (
                    "16",
                    (0..9 * bs - 17)
                        .map(|i| (i * 31 % 251) as u8)
                        .collect::<Vec<_>>(),
                ),
                ("18", b"nested!".to_vec()),
                ("16-4353-1", b"RSRC!".to_vec()),
            ] {
                let data = Command::new(icat)
                    .args(["-f", "hfs"])
                    .arg(&path)
                    .arg(id)
                    .output()
                    .unwrap();
                assert!(data.status.success());
                assert_eq!(data.stdout, expected);
                fs::write(output.join(format!("{label}-{id}.stdout")), data.stdout).unwrap();
                fs::write(output.join(format!("{label}-{id}.stderr")), data.stderr).unwrap();
            }
            assert_eq!(fs::read(&path).unwrap(), image);
            receipt.push_str(&format!("case={label} image_sha256={:x} input_sha256={:x} records={} tree_depth={} outside_catalog_and_extents_unchanged=true\n",Sha256::digest(&image),Sha256::digest(&original),records.len(),super::be16(&tree,14)));
            drop((image, image_lease, tree, tree_lease));
        }
        assert_eq!(fs::read(&source).unwrap(), original);
        drop((original, source_lease, records, records_lease));
        assert_eq!(r.memory.used(), 0);
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

#[test]
fn empty_and_indexed_extent_overflow_trees_have_native_geometry() {
    use crate::{
        fs_core::{Budget, Cancellation},
        fs_file::{ExtentFile, ExtentKind, FileExtent},
    };
    use std::{io, sync::Arc};
    struct Bytes(Vec<u8>);
    impl virtdisk::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let mut records = Vec::new();
    for i in 0..40u32 {
        let mut record = vec![0; 76];
        record[..2].copy_from_slice(&10u16.to_be_bytes());
        record[4..8].copy_from_slice(&16u32.to_be_bytes());
        record[8..12].copy_from_slice(&(i * 8).to_be_bytes());
        records.push(record);
    }
    for empty in [true, false] {
        let refs: Vec<_> = if empty {
            Vec::new()
        } else {
            records.iter().map(Vec::as_slice).collect()
        };
        let (bytes, lease) = keyed_tree(512, 64, 1, TreeKind::Extents, &refs, &r).unwrap();
        assert_eq!(super::be16(&bytes, 14), if empty { 0 } else { 3 });
        let file = ExtentFile::new(
            Arc::new(Bytes(bytes)),
            64 * 512,
            vec![FileExtent {
                offset: 0,
                length: 64 * 512,
                kind: ExtentKind::Data(0),
            }],
            1,
        )
        .unwrap();
        let mut work = super::Work {
            limits: super::HfsPlusReadLimits {
                blocks: 64,
                nodes: 64,
                records: 40,
                extents: 1,
                work: 1 << 20,
            },
            work: 0,
            nodes: 0,
            records: 0,
            extents: 0,
        };
        let tree = super::tree(&file, 1, false, &mut work, &r).unwrap();
        assert_eq!(tree.records.len(), if empty { 0 } else { 40 });
        for (record, original) in tree.records.iter().zip(records.iter()) {
            assert_eq!(&record.key, &original[2..12]);
            assert_eq!(&record.data, &original[12..]);
        }
        drop((tree, file, lease));
        assert_eq!(r.memory.used(), 0);
    }
    let mut invalid = records[0].clone();
    invalid.pop();
    assert!(keyed_tree(512, 4, 1, TreeKind::Extents, &[&invalid], &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
