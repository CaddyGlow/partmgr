//! Independent native queue construction; no production encoder is invoked.
use super::fixture;
pub fn queue(entries: &[(u64, u64, u64)], oid: u64) -> Vec<u8> {
    let rows: Vec<_> = entries
        .iter()
        .map(|(xid, address, length)| {
            let mut key = xid.to_le_bytes().to_vec();
            key.extend_from_slice(&address.to_le_bytes());
            (
                key,
                if *length == 1 {
                    Vec::new()
                } else {
                    length.to_le_bytes().to_vec()
                },
            )
        })
        .collect();
    let mut block = fixture::leaf(oid, 1, 0x80000000, 9, &rows, true);
    for (i, (_, _, length)) in entries.iter().enumerate() {
        if *length == 1 {
            fixture::p16(&mut block, 56 + i * 4 + 2, 65535);
        }
    }
    fixture::seal(&mut block);
    block
}
pub fn queued_seed() -> Vec<u8> {
    let mut image = fixture::apfs_seed();
    let b = &mut image[12 * 4096..13 * 4096];
    b.copy_from_slice(&queue(&[(1, 200, 1), (1, 202, 2)], 1029));
    let sm = &mut image[10 * 4096..11 * 4096];
    fixture::p64(sm, 240, 3);
    fixture::p64(sm, 256, 1);
    fixture::p64(sm, 72, 458);
    fixture::seal(sm);
    let cib = &mut image[42 * 4096..43 * 4096];
    fixture::p32(cib, 60, 458);
    fixture::seal(cib);
    let bitmap = &mut image[41 * 4096..42 * 4096];
    for bit in [200, 202, 203] {
        bitmap[bit / 8] |= 1 << (bit % 8);
    }
    image[11 * 4096..12 * 4096].copy_from_slice(&queue(&[(1, 43, 1)], 1028));
    let sm = &mut image[10 * 4096..11 * 4096];
    fixture::p64(sm, 200, 1);
    fixture::p64(sm, 216, 1);
    fixture::seal(sm);
    image[25 * 4096] |= 4;
    image
}
