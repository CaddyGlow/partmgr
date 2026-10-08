//! Independent direct two-CIB geometry. No production construction/serialization is called.
use super::{fixture, independent};
const B: usize = 4096;
pub const BLOCKS: u64 = 126 * 32768 + 2048;
pub const LENGTH: u64 = BLOCKS * B as u64;
pub const PREFIX: usize = 4 * 1024 * 1024;
pub fn seed() -> Vec<u8> {
    let mut image = independent::seed();
    image.resize(PREFIX, 0);
    for at in [0, 301] {
        fixture::p64(&mut image, at * B + 40, BLOCKS);
        fixture::p32(
            &mut image,
            at * B + 180,
            BLOCKS.div_ceil(131072).min(100) as u32,
        );
        fixture::p64(&mut image, at * B + 1312, (8u64 << 32) | (4u64 << 16) | 1);
        fixture::seal(&mut image[at * B..(at + 1) * B]);
    }
    // Native control fields are explicitly authored rather than inherited
    // from the older decoder-only fixture's deliberately minimal headers.
    fixture::p32(&mut image, 17 * B + 32, 1); // Container OMAP is manually managed.
    fixture::seal(&mut image[17 * B..18 * B]);
    fixture::p32(&mut image, 128 * B + 108, 3984); // Empty reaper state-buffer capacity.
    fixture::seal(&mut image[128 * B..129 * B]);
    fixture::p32(&mut image, 19 * B + 960, 16); // First available document ID.
    image[19 * B + 272..19 * B + 283].copy_from_slice(b"independent");
    fixture::p64(&mut image, 19 * B + 304, 123456789);
    fixture::p64(&mut image, 19 * B + 312, 1);
    fixture::seal(&mut image[19 * B..20 * B]);
    for block in [130, 131] {
        fixture::p32(&mut image, block * B + 4072, 16);
        fixture::p32(&mut image, block * B + 4076, 8);
        fixture::seal(&mut image[block * B..(block + 1) * B]);
    }
    for block in 400..787 {
        image[400 * B + block / 8] |= 1 << (block % 8);
    }
    image[25 * B..26 * B].fill(0);
    image[25 * B] = 7;
    let allocated = image[400 * B..401 * B]
        .iter()
        .map(|v| u64::from(v.count_ones()))
        .sum::<u64>();
    for ci in 0..2 {
        let address = 401 + ci;
        let mut cib = fixture::object(address as u64, 1, 0x40000007, 0);
        fixture::p32(&mut cib, 32, ci as u32);
        let count = if ci == 0 { 126 } else { 1 };
        fixture::p32(&mut cib, 36, count);
        for entry in 0..count as usize {
            let chunk = ci * 126 + entry;
            let start = chunk as u64 * 32768;
            let n = (BLOCKS - start).min(32768);
            let p = 40 + entry * 32;
            fixture::p64(&mut cib, p, 1);
            fixture::p64(&mut cib, p + 8, start);
            fixture::p32(&mut cib, p + 16, n as u32);
            fixture::p32(
                &mut cib,
                p + 20,
                (n - if chunk == 0 { allocated } else { 0 }) as u32,
            );
            fixture::p64(&mut cib, p + 24, if chunk == 0 { 400 } else { 0 });
        }
        fixture::seal(&mut cib);
        image[address * B..(address + 1) * B].copy_from_slice(&cib);
    }
    let p = 129 * B;
    fixture::p64(&mut image, p + 48, BLOCKS);
    fixture::p64(&mut image, p + 56, 127);
    fixture::p32(&mut image, p + 64, 2);
    fixture::p64(&mut image, p + 72, BLOCKS - allocated);
    fixture::p64(&mut image, p + 152, 387);
    fixture::p64(&mut image, p + 392, 402);
    fixture::p16(&mut image, p + 264, 512);
    fixture::seal(&mut image[p..p + B]);
    image
}
/// Real allocated zero-filled bulk stream ends at the CIB boundary. Fresh payloads cross into CIB1.
pub fn crossing_seed() -> Vec<u8> {
    const START: u64 = 2000;
    const COUNT: u64 = 126 * 32768 - START;
    let mut image = seed();
    let mut records = fixture::fs_records();
    for (k, v) in &mut records {
        if k == &fixture::key(2, 3) {
            fixture::p32(v, 56, 3);
        }
    }
    records.insert(5, fixture::drec(2, 47, b"Bulk", false));
    records.push((
        fixture::key(47, 3),
        fixture::inode(2, 47, b"Bulk", false, 1, Some((COUNT * 4096, COUNT * 4096))),
    ));
    records.push((fixture::key(47, 6), 1u32.to_le_bytes().to_vec()));
    let mut k = fixture::key(47, 8);
    k.extend_from_slice(&0u64.to_le_bytes());
    let mut v = vec![0; 24];
    fixture::p64(&mut v, 0, COUNT * 4096);
    fixture::p64(&mut v, 8, START);
    records.push((k, v));
    image[22 * B..23 * B].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &records, false));
    let mut records = fixture::extent_records();
    let mut v = vec![0; 20];
    fixture::p64(&mut v, 0, (1u64 << 60) | COUNT);
    fixture::p64(&mut v, 8, 47);
    fixture::p32(&mut v, 16, 1);
    records.push((fixture::key(START, 2), v));
    image[23 * B..24 * B].copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &records, false));
    let mut allocated = 0;
    for chunk in 0..126 {
        let address = if chunk == 0 { 400 } else { 402 + chunk };
        let bitmap = &mut image[address * B..(address + 1) * B];
        if chunk == 0 {
            for n in START as usize..32768 {
                bitmap[n / 8] |= 1 << (n % 8);
            }
        } else {
            bitmap.fill(255);
        }
        let used = bitmap.iter().map(|v| v.count_ones()).sum::<u32>();
        allocated += u64::from(used);
        let p = 401 * B + 40 + chunk * 32;
        fixture::p32(&mut image, p + 20, 32768 - used);
        fixture::p64(&mut image, p + 24, address as u64);
    }
    image[25 * B..26 * B].fill(0);
    for bit in 0..128 {
        image[25 * B + bit / 8] |= 1 << (bit % 8);
    }
    fixture::seal(&mut image[401 * B..402 * B]);
    fixture::p64(&mut image, 129 * B + 72, BLOCKS - allocated);
    fixture::seal(&mut image[129 * B..130 * B]);
    fixture::p64(&mut image, 19 * B + 88, 9 + COUNT);
    fixture::p64(&mut image, 19 * B + 176, 48);
    fixture::p64(&mut image, 19 * B + 184, 3);
    fixture::seal(&mut image[19 * B..20 * B]);
    image
}
