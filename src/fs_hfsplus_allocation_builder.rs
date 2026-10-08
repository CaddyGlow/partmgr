//! Fresh-volume layout only. This bitmap never authorizes reuse in an existing image.
use super::{bad, budget, vector};
use crate::fs_core::{Reservation, Resources, Result};

pub(super) struct FreshAllocation {
    block_size: u32,
    blocks: u32,
    next: u32,
    tail: u32,
    used: u32,
    bitmap: Vec<u8>,
    bitmap_extent: (u32, u32),
    _lease: Reservation,
}

fn mark(bitmap: &mut [u8], start: u32, count: u32) {
    let end = u64::from(start) + u64::from(count);
    let first = u64::from(start) / 8;
    let last = (end - 1) / 8;
    if first == last {
        for bit in u64::from(start)..end {
            bitmap[first as usize] |= 0x80 >> (bit % 8);
        }
        return;
    }
    bitmap[first as usize] |= 0xff >> (start % 8);
    bitmap[first as usize + 1..last as usize].fill(0xff);
    bitmap[last as usize] |= 0xff << (7 - ((end - 1) % 8));
}

impl FreshAllocation {
    pub(super) fn plan(block_size: u32, blocks: u32, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        if block_size < 512 || !block_size.is_power_of_two() || blocks < 8 {
            return Err(bad("HFS+ fresh allocation geometry"));
        }
        let bytes = u64::from(block_size) * u64::from(blocks);
        let first = 1536u64.div_ceil(u64::from(block_size)) as u32;
        let tail = ((bytes - 1024) / u64::from(block_size)) as u32;
        let bitmap_bytes = u64::from(blocks).div_ceil(8);
        let bitmap_blocks = bitmap_bytes.div_ceil(u64::from(block_size)) as u32;
        let next = first
            .checked_add(bitmap_blocks)
            .filter(|n| *n <= tail)
            .ok_or_else(|| budget("HFS+ fresh bitmap allocation capacity"))?;
        let lease = r.memory.reserve(bitmap_bytes)?;
        let mut bitmap = vector(bitmap_bytes as usize)?;
        bitmap.resize(bitmap_bytes as usize, 0);
        mark(&mut bitmap, 0, next);
        mark(&mut bitmap, tail, blocks - tail);
        Ok(Self {
            block_size,
            blocks,
            next,
            tail,
            used: next + (blocks - tail),
            bitmap,
            bitmap_extent: (first, bitmap_blocks),
            _lease: lease,
        })
    }
    pub(super) fn allocate(&mut self, count: u32, r: &Resources) -> Result<(u32, u32)> {
        r.cancellation.check()?;
        if count == 0 {
            return Err(bad("HFS+ zero fresh allocation request"));
        }
        let end = self
            .next
            .checked_add(count)
            .filter(|end| *end <= self.tail)
            .ok_or_else(|| budget("HFS+ fresh volume allocation capacity"))?;
        let start = self.next;
        mark(&mut self.bitmap, start, count);
        self.next = end;
        self.used += count;
        Ok((start, count))
    }
    pub(super) fn geometry(&self) -> (u32, u32) {
        (self.block_size, self.blocks)
    }
    pub(super) fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }
    pub(super) fn bitmap_extent(&self) -> (u32, u32) {
        self.bitmap_extent
    }
    pub(super) fn free_blocks(&self) -> u32 {
        self.blocks - self.used
    }
}

#[test]
fn fresh_layout_header_bitmap_payload_tail_accounting_and_failures() {
    use crate::fs_core::{Budget, Cancellation};
    for size in [512, 4096] {
        let r = Resources {
            memory: Budget::new(4096),
            cancellation: Cancellation::default(),
        };
        let mut a = FreshAllocation::plan(size, 257, &r).unwrap();
        assert_eq!(a.geometry(), (size, 257));
        assert_eq!(a.bitmap_extent(), (if size == 512 { 3 } else { 1 }, 1));
        let used = if size == 512 { 6 } else { 3 };
        assert_eq!(a.free_blocks(), 257 - used);
        assert_eq!(a.bitmap().iter().map(|b| b.count_ones()).sum::<u32>(), used);
        assert_eq!(a.bitmap()[32] & 0x7f, 0);
        let (start, count) = a.allocate(17, &r).unwrap();
        assert_eq!(start, if size == 512 { 4 } else { 2 });
        assert_eq!(count, 17);
        assert_eq!(a.free_blocks(), 257 - used - 17);
        for block in start..start + count {
            assert_ne!(a.bitmap()[block as usize / 8] & (0x80 >> (block % 8)), 0);
        }
        let before = a.bitmap().to_vec();
        let free = a.free_blocks();
        assert!(a.allocate(free + 1, &r).is_err());
        assert!(a.allocate(0, &r).is_err());
        assert_eq!(a.bitmap(), before);
        assert_eq!(a.free_blocks(), free);
        a.allocate(free, &r).unwrap();
        assert_eq!(a.free_blocks(), 0);
        assert_eq!(a.bitmap().iter().map(|b| b.count_ones()).sum::<u32>(), 257);
        r.cancellation.cancel();
        assert!(a.allocate(1, &r).is_err());
        drop(a);
        assert_eq!(r.memory.used(), 0);
    }
    let r = Resources {
        memory: Budget::new(0),
        cancellation: Cancellation::default(),
    };
    assert!(FreshAllocation::plan(4096, 257, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
