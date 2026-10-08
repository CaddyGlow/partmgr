//! Independent external resource descriptor/run/reference construction.
use super::fixture::*;
fn raw(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
/// Unique xattr stream IDs24/25; optionally share physical allocation113.
/// No DATA_STREAM_ID record is authored for either xattr stream.
pub fn records(shared: bool, defect: u8) -> (Records, Records) {
    let (mut fs, mut ext) = shared_records(true);
    for (key, value) in &mut fs {
        if raw(key, 0) >> 60 == 4 && key[10..] == *b"com.apple.ResourceFork\0" {
            let inode = raw(key, 0) & 0x0fff_ffff_ffff_ffff;
            let mut v = vec![0; 52];
            p16(&mut v, 0, 1);
            p16(&mut v, 2, if defect == 6 { u16::MAX } else { 48 });
            p64(&mut v, 4, if inode == 16 { 24 } else { 25 });
            p64(&mut v, 12, 8);
            p64(&mut v, 20, 4096);
            p64(&mut v, 36, 8);
            if defect == 1 && inode == 21 {
                p64(&mut v, 4, 24);
            }
            if defect == 2 && inode == 16 {
                p64(&mut v, 28, 1);
            }
            *value = v;
        }
    }
    for (stream, physical) in [(24u64, 113u64), (25, if shared { 113 } else { 114 })] {
        let mut key = (8u64 << 60 | stream).to_le_bytes().to_vec();
        key.extend_from_slice(&0u64.to_le_bytes());
        let mut value = vec![0; 24];
        p64(&mut value, 0, 4096);
        p64(
            &mut value,
            8,
            if defect == 3 && stream == 24 {
                0
            } else {
                physical
            },
        );
        fs.push((key, value));
    }
    if defect == 4 {
        fs.push((
            (6u64 << 60 | 24).to_le_bytes().to_vec(),
            1u32.to_le_bytes().to_vec(),
        ));
    }
    for (physical, owner, refs) in if shared {
        vec![(113, 16, 2)]
    } else {
        vec![(113, 16, 1), (114, 21, 1)]
    } {
        let mut value = vec![0; 20];
        p64(&mut value, 0, 1u64 << 60 | 1);
        p64(&mut value, 8, owner);
        p32(&mut value, 16, if defect == 5 { 3 } else { refs });
        ext.push(((2u64 << 60 | physical).to_le_bytes().to_vec(), value));
    }
    fs.sort_by(|a, b| {
        let x = raw(&a.0, 0);
        let y = raw(&b.0, 0);
        (x & 0x0fff_ffff_ffff_ffff)
            .cmp(&(y & 0x0fff_ffff_ffff_ffff))
            .then((x >> 60).cmp(&(y >> 60)))
            .then_with(|| match x >> 60 {
                4 | 9 => a.0[10..].cmp(&b.0[10..]),
                5 | 8 => raw(&a.0, 8).cmp(&raw(&b.0, 8)),
                _ => a.0[8..].cmp(&b.0[8..]),
            })
    });
    ext.sort_by_key(|record| raw(&record.0, 0));
    (fs, ext)
}
pub fn seed(shared: bool, defect: u8) -> Vec<u8> {
    let mut image = shared_seed(true);
    let (fs, ext) = records(shared, defect);
    image[22 * BLOCK..23 * BLOCK].copy_from_slice(&leaf(1027, 1, 0, 14, &fs, false));
    image[23 * BLOCK..24 * BLOCK].copy_from_slice(&leaf(23, 1, 0x40000000, 15, &ext, false));
    let count = if shared { 1 } else { 2 };
    for physical in 113..113 + count {
        image[41 * BLOCK + physical / 8] |= 1 << (physical % 8);
        image[physical * BLOCK..physical * BLOCK + 8].copy_from_slice(b"resource");
    }
    p64(&mut image, 10 * BLOCK + 72, 461 - count as u64);
    seal(&mut image[10 * BLOCK..11 * BLOCK]);
    p32(&mut image, 42 * BLOCK + 60, 461 - count as u32);
    seal(&mut image[42 * BLOCK..43 * BLOCK]);
    p64(&mut image, 19 * BLOCK + 88, 9 + count as u64);
    p64(&mut image, 19 * BLOCK + 176, 26);
    seal(&mut image[19 * BLOCK..20 * BLOCK]);
    image
}
/// Independent generic external UTF8 xattr conversion of the complete seed.
pub fn generic_seed(shared: bool, defect: u8) -> Vec<u8> {
    let mut image = seed(shared, defect);
    let (mut fs, _) = records(shared, defect);
    for (key, value) in &mut fs {
        let kind = raw(key, 0) >> 60;
        if kind == 4 && key[10..] == *b"com.apple.ResourceFork\0" {
            key.truncate(8);
            let name = "user/external.é\0".as_bytes();
            key.extend_from_slice(&(name.len() as u16).to_le_bytes());
            key.extend_from_slice(name);
        }
        if kind == 3 {
            let flags = raw(value, 48);
            p64(value, 48, (flags & !0x4000) | 0x8000);
        }
    }
    image[22 * BLOCK..23 * BLOCK].copy_from_slice(&leaf(1027, 1, 0, 14, &fs, false));
    image
}
