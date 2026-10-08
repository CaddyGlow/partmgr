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
