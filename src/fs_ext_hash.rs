//! Bounded native ext directory hash algorithms; no Unicode/casefold transformation.
use super::{invalid, unsupported};
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
pub(super) fn hash(version: u8, name: &[u8], seed: [u32; 4]) -> io::Result<u32> {
    if version > 5 {
        return Err(unsupported("ext directory hash version"));
    }
    if name.is_empty() || name.len() > 255 {
        return Err(invalid("ext directory hash native name length"));
    }
    let unsigned = version >= 3;
    let algorithm = version % 3;
    let byte_word = |byte: u8| {
        if unsigned {
            u32::from(byte)
        } else {
            (i32::from(byte as i8)) as u32
        }
    };
    let mut state = if seed == [0; 4] {
        [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    } else {
        seed
    };
    let raw = if algorithm == 0 {
        let mut previous = 0x37abe8f9u32;
        let mut current = 0x12a3fe2du32;
        for &byte in name {
            let mut next = previous.wrapping_add(current ^ byte_word(byte).wrapping_mul(7152373));
            if next & 0x80000000 != 0 {
                next = next.wrapping_sub(0x7fffffff);
            }
            previous = current;
            current = next;
        }
        current << 1
    } else {
        let width = if algorithm == 1 { 32 } else { 16 };
        for start in (0..name.len()).step_by(width) {
            let remaining = name.len() - start;
            let pad = (remaining as u32).wrapping_mul(0x01010101);
            let mut words = [pad; 8];
            for (word, bytes) in name[start..(start + width).min(name.len())]
                .chunks(4)
                .enumerate()
            {
                let mut value = if bytes.len() == 4 { 0 } else { pad };
                for &byte in bytes {
                    value = (value << 8).wrapping_add(byte_word(byte));
                }
                words[word] = value;
            }
            if algorithm == 2 {
                let (mut left, mut right) = (state[0], state[1]);
                let mut sum = 0u32;
                for _ in 0..16 {
                    sum = sum.wrapping_add(0x9e3779b9);
                    left = left.wrapping_add(
                        (right << 4).wrapping_add(words[0])
                            ^ right.wrapping_add(sum)
                            ^ (right >> 5).wrapping_add(words[1]),
                    );
                    right = right.wrapping_add(
                        (left << 4).wrapping_add(words[2])
                            ^ left.wrapping_add(sum)
                            ^ (left >> 5).wrapping_add(words[3]),
                    );
                }
                state[0] = state[0].wrapping_add(left);
                state[1] = state[1].wrapping_add(right);
            } else {
                let mut registers = state;
                for (round, order, rotations, constant) in [
                    (0, [0, 1, 2, 3, 4, 5, 6, 7], [3, 7, 11, 19], 0u32),
                    (1, [1, 3, 5, 7, 0, 2, 4, 6], [3, 5, 9, 13], 0x5a827999),
                    (2, [3, 7, 2, 6, 1, 5, 0, 4], [3, 9, 11, 15], 0x6ed9eba1),
                ] {
                    for (step, word) in order.into_iter().enumerate() {
                        let target = [0, 3, 2, 1][step % 4];
                        let x = registers[(target + 1) % 4];
                        let y = registers[(target + 2) % 4];
                        let z = registers[(target + 3) % 4];
                        let mix = match round {
                            0 => (x & y) | (!x & z),
                            1 => (x & y) | (x & z) | (y & z),
                            _ => x ^ y ^ z,
                        };
                        registers[target] = registers[target]
                            .wrapping_add(mix)
                            .wrapping_add(words[word])
                            .wrapping_add(constant)
                            .rotate_left(rotations[step % 4]);
                    }
                }
                for slot in 0..4 {
                    state[slot] = state[slot].wrapping_add(registers[slot]);
                }
            }
        }
        state[if algorithm == 1 { 1 } else { 0 }]
    } & !1;
    Ok(if raw == 0xfffffffe { 0xfffffffc } else { raw })
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    #[test]
    fn independent_debugfs_half_md4_vector_and_profile_bounds() {
        // e2fsprogs debugfs 1.47.4: dx_hash -h half_md4 -s
        // 01234567-89ab-cdef-0123-456789abcdef filename => af3e3244.
        assert_eq!(
            hash(
                1,
                b"filename",
                [0x67452301, 0xefcdab89, 0x67452301, 0xefcdab89]
            )
            .unwrap(),
            0xaf3e3244
        );
        assert!(hash(6, b"filename", [0; 4]).is_err());
        assert!(hash(1, &[], [0; 4]).is_err());
        assert!(hash(1, &[1; 256], [0; 4]).is_err());
        // Same independent command with numeric -h 0..5 and exact native
        // bytes, including 0xff and a name spanning multiple hash blocks.
        let expected = [
            [0x2719a80c, 0x30b36080, 0x552c4fd0],
            [0xaf3e3244, 0x90bb3f5e, 0xb9dd3cb6],
            [0x6ef9c730, 0x8e813bde, 0x77a86708],
            [0x2719a80c, 0xf4d96278, 0x552c4fd0],
            [0xaf3e3244, 0x4f28a27c, 0xb9dd3cb6],
            [0x6ef9c730, 0xc0726ff6, 0x77a86708],
        ];
        for (version, expected) in expected.iter().enumerate() {
            for (name, expected) in [
                b"filename".as_slice(),
                b"x\xffname".as_slice(),
                b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO".as_slice(),
            ]
            .into_iter()
            .zip(expected)
            {
                assert_eq!(
                    hash(
                        version as u8,
                        name,
                        [0x67452301, 0xefcdab89, 0x67452301, 0xefcdab89]
                    )
                    .unwrap(),
                    *expected
                );
            }
        }
    }
}
