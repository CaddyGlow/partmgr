//! Independent five-chunk raw fixture: production builder/encoder is never called.
use super::fixture;
pub const LENGTH: u64 = fixture::MULTIVOLUME_LENGTH;
pub fn seed() -> Vec<u8> {
    const B: usize = 4096;
    let mut image = fixture::apfs_seed();
    fixture::multivolume_geometry(&mut image);
    for source in 9..13 {
        let bytes = image[source * B..(source + 1) * B].to_vec();
        image[(source + 119) * B..(source + 120) * B].copy_from_slice(&bytes);
    }
    let mut nx = image[2 * B..3 * B].to_vec();
    fixture::p32(&mut nx, 180, 2);
    fixture::p32(&mut nx, 104, 32);
    fixture::p32(&mut nx, 108, 64);
    fixture::p64(&mut nx, 112, 300);
    fixture::p64(&mut nx, 120, 128);
    fixture::seal(&mut nx);
    image[..B].copy_from_slice(&nx);
    image[301 * B..302 * B].copy_from_slice(&nx);
    let mut map = image[B..2 * B].to_vec();
    fixture::p64(&mut map, 8, 300);
    for i in 0..4 {
        fixture::p64(&mut map, 40 + i * 40 + 32, 128 + i as u64);
    }
    fixture::seal(&mut map);
    image[300 * B..301 * B].copy_from_slice(&map);
    let bitmap = &mut image[400 * B..401 * B];
    for n in 1..17 {
        bitmap[n / 8] &= !(1 << (n % 8));
    }
    for n in 128..192 {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    for n in 300..332 {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    let allocated = bitmap
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum::<u64>();
    fixture::p64(&mut image, 129 * B + 72, LENGTH / 4096 - allocated);
    fixture::seal(&mut image[129 * B..130 * B]);
    fixture::p32(&mut image, 401 * B + 60, 32768 - allocated as u32);
    fixture::seal(&mut image[401 * B..402 * B]);
    image[B..17 * B].fill(0);
    image[41 * B..47 * B].fill(0);
    image
}

/// Bulk native owned allocation occupies the end of chunk0; replacement then crosses chunk0/1.
pub fn crossing_seed() -> Vec<u8> {
    const B: usize = 4096;
    const START: u64 = 2000;
    const COUNT: u64 = 32768 - START;
    let mut image = seed();
    let mut catalog = fixture::fs_records();
    for (k, v) in &mut catalog {
        if k == &fixture::key(2, 3) {
            fixture::p32(v, 56, 3);
        }
    }
    catalog.insert(5, fixture::drec(2, 47, b"Bulk", false));
    catalog.push((
        fixture::key(47, 3),
        fixture::inode(2, 47, b"Bulk", false, 1, Some((COUNT * 4096, COUNT * 4096))),
    ));
    catalog.push((fixture::key(47, 6), 1u32.to_le_bytes().to_vec()));
    let mut k = fixture::key(47, 8);
    k.extend_from_slice(&0u64.to_le_bytes());
    let mut v = vec![0; 24];
    fixture::p64(&mut v, 0, COUNT * 4096);
    fixture::p64(&mut v, 8, START);
    catalog.push((k, v));
    image[22 * B..23 * B].copy_from_slice(&fixture::leaf(1027, 1, 0, 14, &catalog, false));
    let mut refs = fixture::extent_records();
    let mut v = vec![0; 20];
    fixture::p64(&mut v, 0, (1u64 << 60) | COUNT);
    fixture::p64(&mut v, 8, 47);
    fixture::p32(&mut v, 16, 1);
    refs.push((fixture::key(START, 2), v));
    image[23 * B..24 * B].copy_from_slice(&fixture::leaf(23, 1, 0x40000000, 15, &refs, false));
    for n in START as usize..32768 {
        image[400 * B + n / 8] |= 1 << (n % 8);
    }
    let allocated = image[400 * B..401 * B]
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum::<u64>();
    fixture::p64(&mut image, 129 * B + 72, LENGTH / 4096 - allocated);
    fixture::seal(&mut image[129 * B..130 * B]);
    fixture::p32(&mut image, 401 * B + 60, 32768 - allocated as u32);
    fixture::seal(&mut image[401 * B..402 * B]);
    fixture::p64(&mut image, 19 * B + 88, 9 + COUNT);
    fixture::p64(&mut image, 19 * B + 176, 48);
    fixture::p64(&mut image, 19 * B + 184, 3);
    fixture::seal(&mut image[19 * B..20 * B]);
    image
}

/// Independently split the raw catalog into a two-child virtual index.
/// This constructor uses raw Apple node fields, never the production authoring codec.
pub fn indexed_seed() -> Vec<u8> {
    const B: usize = 4096;
    let mut image = seed();
    let records = fixture::fs_records();
    let split = records.len() / 2;
    for (oid, at, part) in [
        (1100, 450, &records[..split]),
        (1101, 451, &records[split..]),
    ] {
        let mut child = fixture::leaf(oid, 1, 0, 14, part, false);
        let values: usize = part.iter().map(|p| p.1.len()).sum();
        child.copy_within(B - 40 - values..B - 40, B - values);
        child[B - 40 - values..B - values].fill(0);
        fixture::p32(&mut child, 24, 3);
        fixture::p16(&mut child, 32, 2);
        let free = u16::from_le_bytes(child[46..48].try_into().unwrap());
        fixture::p16(&mut child, 46, free + 40);
        fixture::seal(&mut child);
        image[at * B..(at + 1) * B].copy_from_slice(&child);
        image[400 * B + at / 8] |= 1 << (at % 8);
    }
    let parents = vec![
        (records[0].0.clone(), 1100u64.to_le_bytes().to_vec()),
        (records[split].0.clone(), 1101u64.to_le_bytes().to_vec()),
    ];
    let mut root = fixture::leaf(1027, 1, 0, 14, &parents, false);
    fixture::p16(&mut root, 32, 1);
    fixture::p16(&mut root, 34, 1);
    fixture::p32(
        &mut root,
        B - 24,
        records.iter().map(|p| p.0.len()).max().unwrap() as u32,
    );
    fixture::p32(
        &mut root,
        B - 20,
        records.iter().map(|p| p.1.len()).max().unwrap() as u32,
    );
    fixture::p64(&mut root, B - 16, records.len() as u64);
    fixture::p64(&mut root, B - 8, 3);
    fixture::seal(&mut root);
    image[22 * B..23 * B].copy_from_slice(&root);
    let maps: Vec<_> = [(1027u64, 22u64), (1100, 450), (1101, 451)]
        .into_iter()
        .map(|(oid, at)| {
            let mut k = oid.to_le_bytes().to_vec();
            k.extend_from_slice(&1u64.to_le_bytes());
            let mut v = vec![0; 16];
            fixture::p32(&mut v, 4, 4096);
            fixture::p64(&mut v, 8, at);
            (k, v)
        })
        .collect();
    image[21 * B..22 * B].copy_from_slice(&fixture::leaf(21, 1, 0x40000000, 11, &maps, true));
    let old = u64::from_le_bytes(image[19 * B + 88..19 * B + 96].try_into().unwrap());
    fixture::p64(&mut image, 19 * B + 88, old + 2);
    fixture::p64(&mut image, 19 * B + 176, 1102);
    fixture::seal(&mut image[19 * B..20 * B]);
    let allocated = image[400 * B..401 * B]
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum::<u64>();
    fixture::p64(&mut image, 129 * B + 72, LENGTH / 4096 - allocated);
    fixture::seal(&mut image[129 * B..130 * B]);
    fixture::p32(&mut image, 401 * B + 60, 32768 - allocated as u32);
    fixture::seal(&mut image[401 * B..402 * B]);
    image
}
