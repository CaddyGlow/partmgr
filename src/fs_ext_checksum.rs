//! Linux ext/JBD2 CRC32C state: reflected Castagnoli polynomial, no final xor.
pub(super) fn crc32c(mut state: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        state ^= u32::from(byte);
        for _ in 0..8 {
            state = (state >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(state & 1));
        }
    }
    state
}

#[cfg(test)]
mod tests {
    #[test]
    fn castagnoli_standard_vector_and_incremental_state() {
        assert_eq!(super::crc32c(!0, b"123456789"), 0x1cf96d7c);
        assert_eq!(
            super::crc32c(super::crc32c(!0, b"1234"), b"56789"),
            0x1cf96d7c
        );
    }
}
