//! Independent raw checkpoint-data ring construction, without the production authoring encoder.
use super::fixture;
pub fn repeated_seed() -> Vec<u8> {
    let mut image = fixture::apfs_seed();
    for old in 9..13 {
        let bytes = image[old * 4096..(old + 1) * 4096].to_vec();
        image[(128 + old - 9) * 4096..(129 + old - 9) * 4096].copy_from_slice(&bytes);
    }
    for at in [0, 2] {
        let nx = &mut image[at * 4096..(at + 1) * 4096];
        fixture::p32(nx, 108, 16);
        fixture::p64(nx, 120, 128);
        fixture::seal(nx);
    }
    let cp = &mut image[4096..8192];
    for i in 0..4 {
        fixture::p64(cp, 40 + i * 40 + 32, 128 + i as u64);
    }
    fixture::seal(cp);
    for bit in 9..17 {
        image[41 * 4096 + bit / 8] &= !(1 << (bit % 8));
    }
    for bit in 128..144 {
        image[41 * 4096 + bit / 8] |= 1 << (bit % 8);
    }
    let sm = &mut image[129 * 4096..130 * 4096];
    fixture::p64(sm, 72, 453);
    fixture::seal(sm);
    let cib = &mut image[42 * 4096..43 * 4096];
    fixture::p32(cib, 60, 453);
    fixture::seal(cib);
    image
}
