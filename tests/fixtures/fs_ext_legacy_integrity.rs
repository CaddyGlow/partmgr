// Independent legacy profile field assembly; included alongside fs_ext_modern.rs.
// No production reader, authoring or checksum helper generates this fixture.
pub fn without_metadata_checksums(extents: bool, gdt16: bool) -> (Vec<u8>, Vec<u8>) {
    let (mut image, payload) = if extents {
        fixture()
    } else {
        without_extents()
    };
    d(&mut image, 1120, if extents { 0xc2 } else { 0x82 });
    d(&mut image, 1124, 0x43 | if gdt16 { 0x10 } else { 0 });
    image[1397] = 0;
    d(&mut image, 1648, 0);
    d(&mut image, 2044, 0);
    for number in [2usize, 12] {
        let at = 5 * 1024 + (number - 1) * 256;
        w(&mut image, at + 124, 0);
        w(&mut image, at + 130, 0);
    }
    w(&mut image, 9 * 1024 + 28, 1000);
    image[9 * 1024 + 1012..10 * 1024].fill(0);
    d(&mut image, 12 * 1024 + 16, 0);
    for at in [24, 26, 30, 56, 58] {
        w(&mut image, 2048 + at, 0);
    }
    if gdt16 {
        // Independent forward CRC16 polynomial; production uses reflected 0xa001.
        let mut crc = 0xffffu16;
        let mut data = image[1128..1144].to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&image[2048..2078]);
        data.extend_from_slice(&image[2080..2112]);
        for byte in data {
            crc ^= u16::from(byte.reverse_bits()) << 8;
            for _ in 0..8 {
                let high = crc & 0x8000 != 0;
                crc <<= 1;
                if high {
                    crc ^= 0x8005;
                }
            }
        }
        w(&mut image, 2078, crc.reverse_bits());
    }
    (image, payload)
}
