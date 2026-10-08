//! Checked fork bytes for the staged HFS+ builder; no allocation ownership grant.
use super::{bad, budget, vector};
use crate::fs_core::{Reservation, Resources, Result};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) struct PlannedFork {
    pub(super) header: [u8; 80],
    pub(super) overflow: Vec<Vec<u8>>,
    _lease: Reservation,
}

pub(super) fn plan(
    object: u32,
    resource: bool,
    length: u64,
    geometry: (u32, u32),
    extents: &[(u32, u32)],
    r: &Resources,
) -> Result<PlannedFork> {
    r.cancellation.check()?;
    let (block_size, volume_blocks) = geometry;
    if object == 0 || block_size < 512 || !block_size.is_power_of_two() || volume_blocks == 0 {
        return Err(bad("HFS+ planned fork geometry/identity"));
    }
    let scratch_bytes = (extents.len() as u64)
        .checked_mul(8)
        .ok_or_else(|| budget("HFS+ fork extent planning charge"))?;
    let _scratch = r.memory.reserve(scratch_bytes)?;
    let mut sorted = vector(extents.len())?;
    let mut blocks = 0u32;
    for &(start, count) in extents {
        r.cancellation.check()?;
        if count == 0
            || start
                .checked_add(count)
                .is_none_or(|end| end > volume_blocks)
        {
            return Err(bad("HFS+ planned physical extent bounds"));
        }
        blocks = blocks
            .checked_add(count)
            .ok_or_else(|| bad("HFS+ planned fork block count"))?;
        sorted.push((start, count));
    }
    if length > u64::from(blocks) * u64::from(block_size) {
        return Err(bad("HFS+ planned fork EOF exceeds allocation"));
    }
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        r.cancellation.check()?;
        if pair[0].0 + pair[0].1 > pair[1].0 {
            return Err(bad("HFS+ planned fork physical overlap"));
        }
    }
    let overflow_count = extents.len().saturating_sub(8).div_ceil(8);
    let retained = (overflow_count as u64)
        .checked_mul(100)
        .and_then(|n| n.checked_add(80))
        .ok_or_else(|| budget("HFS+ fork result charge"))?;
    let lease = r.memory.reserve(retained)?;
    let mut header = [0; 80];
    header[..8].copy_from_slice(&length.to_be_bytes());
    header[12..16].copy_from_slice(&blocks.to_be_bytes());
    let mut logical_start = 0u32;
    for (i, &(start, count)) in extents.iter().take(8).enumerate() {
        header[16 + i * 8..20 + i * 8].copy_from_slice(&start.to_be_bytes());
        header[20 + i * 8..24 + i * 8].copy_from_slice(&count.to_be_bytes());
        logical_start += count;
    }
    let mut overflow = vector(overflow_count)?;
    for group in extents.get(8..).unwrap_or_default().chunks(8) {
        r.cancellation.check()?;
        let mut record = vector(76)?;
        record.resize(76, 0);
        record[..2].copy_from_slice(&10u16.to_be_bytes());
        record[2] = if resource { 255 } else { 0 };
        record[4..8].copy_from_slice(&object.to_be_bytes());
        record[8..12].copy_from_slice(&logical_start.to_be_bytes());
        for (i, &(start, count)) in group.iter().enumerate() {
            record[12 + i * 8..16 + i * 8].copy_from_slice(&start.to_be_bytes());
            record[16 + i * 8..20 + i * 8].copy_from_slice(&count.to_be_bytes());
            logical_start += count;
        }
        overflow.push(record);
    }
    Ok(PlannedFork {
        header,
        overflow,
        _lease: lease,
    })
}

#[cfg(feature = "std")]
#[test]
fn fragmented_fork_bytes_overflow_keys_and_invalid_ranges() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    };
    let extents: Vec<_> = (0..17).map(|i| (50 - i * 2, 1)).collect();
    let fork = plan(16, false, 17 * 4096 - 7, (4096, 256), &extents, &r).unwrap();
    assert_eq!(
        u64::from_be_bytes(fork.header[..8].try_into().unwrap()),
        17 * 4096 - 7
    );
    assert_eq!(&fork.header[8..16], &[0, 0, 0, 0, 0, 0, 0, 17]);
    assert_eq!(fork.overflow.len(), 2);
    assert_eq!(
        &fork.overflow[0][..12],
        &[0, 10, 0, 0, 0, 0, 0, 16, 0, 0, 0, 8]
    );
    assert_eq!(
        &fork.overflow[1][..12],
        &[0, 10, 0, 0, 0, 0, 0, 16, 0, 0, 0, 16]
    );
    assert_eq!(&fork.overflow[1][12..20], &[0, 0, 0, 18, 0, 0, 0, 1]);
    assert!(fork.overflow[1][20..].iter().all(|b| *b == 0));
    let resource = plan(16, true, 0, (4096, 256), &extents, &r).unwrap();
    assert_eq!(resource.overflow[0][2], 255);
    drop((fork, resource));
    assert_eq!(r.memory.used(), 0);
    for extents in [&[(1, 0)][..], &[(255, 2)][..], &[(3, 2), (4, 1)][..]] {
        assert!(plan(16, false, 1, (4096, 256), extents, &r).is_err());
    }
    assert!(plan(16, false, 4097, (4096, 256), &[(1, 1)], &r).is_err());
    let empty = plan(16, false, 0, (4096, 256), &[], &r).unwrap();
    assert_eq!(empty.header, [0; 80]);
    assert!(empty.overflow.is_empty());
    drop(empty);
    r.cancellation.cancel();
    assert!(plan(16, false, 0, (4096, 256), &[], &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
