//! Staged bounded ext4 metadata checksums. Feature acceptance remains closed until
//! descriptor/bitmap, hidden-allocation, directory and xattr ownership validators
//! are connected to both the immutable decoder and the complete audit.
use super::{checksum::crc32c, invalid, u16le, u32le, unsupported};
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
fn bounded_block(bytes: &[u8]) -> io::Result<()> {
    if !matches!(bytes.len(), 1024 | 2048 | 4096) {
        return Err(unsupported("ext metadata block size"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MetadataChecksums {
    pub seed: u32,
}
impl MetadataChecksums {
    pub fn superblock(bytes: &[u8; 1024]) -> io::Result<Self> {
        if u32le(bytes, 100) & 0x400 == 0 {
            return Err(unsupported("ext metadata checksum feature absent"));
        }
        if bytes[373] != 1 {
            return Err(unsupported("ext metadata checksum algorithm"));
        }
        if crc32c(!0, &bytes[..1020]) != u32le(bytes, 1020) {
            return Err(invalid("ext superblock checksum"));
        }
        let seed = if u32le(bytes, 96) & 0x2000 != 0 {
            u32le(bytes, 624)
        } else {
            crc32c(!0, &bytes[104..120])
        };
        Ok(Self { seed })
    }
    pub fn inode_seed(&self, number: u32, generation: u32) -> u32 {
        crc32c(
            crc32c(self.seed, &number.to_le_bytes()),
            &generation.to_le_bytes(),
        )
    }
    pub fn descriptor(&self, group: u32, bytes: &[u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 32 | 64) {
            return Err(unsupported("ext metadata descriptor size"));
        }
        let crc = crc32c(self.seed, &group.to_le_bytes());
        let crc = crc32c(crc, &bytes[..30]);
        let crc = crc32c(crc32c(crc, &[0; 2]), &bytes[32..]);
        if crc as u16 != u16le(bytes, 30) {
            return Err(invalid("ext group descriptor checksum"));
        }
        Ok(())
    }
    pub fn bitmap(
        &self,
        bytes: &[u8],
        bits: u32,
        descriptor: &[u8],
        inode: bool,
    ) -> io::Result<()> {
        bounded_block(bytes)?;
        if !bits.is_multiple_of(8)
            || bits as usize / 8 > bytes.len()
            || !matches!(descriptor.len(), 32 | 64)
        {
            return Err(invalid("ext checksum bitmap geometry"));
        }
        let mut recorded = u32::from(u16le(descriptor, if inode { 26 } else { 24 }));
        let mut computed = crc32c(self.seed, &bytes[..bits as usize / 8]);
        if descriptor.len() == 64 {
            recorded |= u32::from(u16le(descriptor, if inode { 58 } else { 56 })) << 16;
        } else {
            computed &= 0xffff;
        }
        if computed != recorded {
            return Err(invalid("ext allocation bitmap checksum"));
        }
        Ok(())
    }
    pub fn inode(&self, number: u32, bytes: &[u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 128 | 256) {
            return Err(unsupported("ext checksum inode size"));
        }
        let high = bytes.len() == 256 && u16le(bytes, 128) >= 4;
        let crc = self.inode_seed(number, u32le(bytes, 100));
        let crc = crc32c(crc32c(crc, &bytes[..124]), &[0; 2]);
        let mut crc = crc32c(crc, &bytes[126..128]);
        if bytes.len() == 256 {
            crc = crc32c(crc, &bytes[128..130]);
            if high {
                crc = crc32c(crc32c(crc, &[0; 2]), &bytes[132..]);
            } else {
                crc = crc32c(crc, &bytes[130..]);
            }
        }
        let mut recorded = u32::from(u16le(bytes, 124));
        if high {
            recorded |= u32::from(u16le(bytes, 130)) << 16;
        } else {
            crc &= 0xffff;
        }
        if recorded != crc {
            return Err(invalid("ext inode checksum"));
        }
        Ok(())
    }
    pub fn extent(&self, number: u32, generation: u32, bytes: &[u8]) -> io::Result<()> {
        bounded_block(bytes)?;
        if bytes.len() < 16 {
            return Err(invalid("ext checksum extent header truncated"));
        }
        let tail = 12usize
            .checked_add(usize::from(u16le(bytes, 4)) * 12)
            .filter(|tail| *tail <= bytes.len() - 4)
            .ok_or_else(|| invalid("ext checksum extent tail bounds"))?;
        if crc32c(self.inode_seed(number, generation), &bytes[..tail]) != u32le(bytes, tail) {
            return Err(invalid("ext extent block checksum"));
        }
        Ok(())
    }
    pub fn directory_leaf(&self, number: u32, generation: u32, bytes: &[u8]) -> io::Result<usize> {
        bounded_block(bytes)?;
        let tail = bytes
            .len()
            .checked_sub(12)
            .ok_or_else(|| invalid("ext directory checksum tail bounds"))?;
        if u32le(bytes, tail) != 0
            || u16le(bytes, tail + 4) != 12
            || bytes[tail + 6] != 0
            || bytes[tail + 7] != 0xde
        {
            return Err(invalid("ext directory checksum tail encoding"));
        }
        if crc32c(self.inode_seed(number, generation), &bytes[..tail]) != u32le(bytes, tail + 8) {
            return Err(invalid("ext directory leaf checksum"));
        }
        Ok(tail)
    }
    pub fn directory_index(
        &self,
        number: u32,
        generation: u32,
        bytes: &[u8],
        count_offset: usize,
    ) -> io::Result<()> {
        bounded_block(bytes)?;
        if count_offset
            .checked_add(4)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(invalid("ext directory index checksum count bounds"));
        }
        let limit = usize::from(u16le(bytes, count_offset));
        let count = usize::from(u16le(bytes, count_offset + 2));
        let tail = count_offset
            .checked_add(limit * 8)
            .filter(|tail| bytes.len() >= 8 && *tail <= bytes.len() - 8)
            .ok_or_else(|| invalid("ext directory index checksum tail bounds"))?;
        if count == 0 || count > limit || u32le(bytes, tail) != 0 {
            return Err(invalid("ext directory index checksum count/tail encoding"));
        }
        let crc = crc32c(
            self.inode_seed(number, generation),
            &bytes[..count_offset + count * 8],
        );
        let crc = crc32c(crc32c(crc, &bytes[tail..tail + 4]), &[0; 4]);
        if crc != u32le(bytes, tail + 4) {
            return Err(invalid("ext directory index checksum"));
        }
        Ok(())
    }
    pub fn orphan(
        &self,
        number: u32,
        generation: u32,
        physical: u64,
        bytes: &[u8],
    ) -> io::Result<()> {
        bounded_block(bytes)?;
        let tail = bytes
            .len()
            .checked_sub(8)
            .ok_or_else(|| invalid("ext orphan checksum tail bounds"))?;
        if !tail.is_multiple_of(4) || u32le(bytes, tail) != 0x0b10ca04 {
            return Err(invalid("ext orphan tail encoding"));
        }
        let crc = crc32c(self.inode_seed(number, generation), &physical.to_le_bytes());
        if crc32c(crc, &bytes[..tail]) != u32le(bytes, tail + 4) {
            return Err(invalid("ext orphan block checksum"));
        }
        if bytes[..tail].iter().any(|byte| *byte != 0) {
            return Err(unsupported("ext orphan file requires recovery"));
        }
        Ok(())
    }
    pub fn xattr(&self, physical: u64, bytes: &[u8]) -> io::Result<()> {
        bounded_block(bytes)?;
        if bytes.len() < 32 || u32le(bytes, 0) != 0xea020000 {
            return Err(invalid("ext xattr header magic/bounds"));
        }
        let crc = crc32c(self.seed, &physical.to_le_bytes());
        let crc = crc32c(crc32c(crc, &bytes[..16]), &[0; 4]);
        if crc32c(crc, &bytes[20..]) != u32le(bytes, 16) {
            return Err(invalid("ext xattr block checksum"));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    fn w(b: &mut [u8], at: usize, value: u16) {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn d(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    // Independent forward Castagnoli polynomial; fixtures never call production
    // checksum/encoding helpers to produce their expected on-disk checksums.
    fn forward(state: u32, bytes: &[u8]) -> u32 {
        let mut state = state.reverse_bits();
        for &byte in bytes {
            state ^= u32::from(byte.reverse_bits()) << 24;
            for _ in 0..8 {
                let high = state & 0x80000000 != 0;
                state <<= 1;
                if high {
                    state ^= 0x1edc6f41;
                }
            }
        }
        state.reverse_bits()
    }
    fn inode_seed(seed: u32, inode: u32, generation: u32) -> u32 {
        forward(
            forward(seed, &inode.to_le_bytes()),
            &generation.to_le_bytes(),
        )
    }
    fn header(seeded: bool) -> [u8; 1024] {
        let mut b = [0; 1024];
        d(&mut b, 100, 0x400);
        d(&mut b, 96, if seeded { 0x2000 } else { 0 });
        b[104..120].copy_from_slice(b"0123456789abcdef");
        b[373] = 1;
        d(&mut b, 624, 0x87654321);
        let crc = forward(!0, &b[..1020]);
        d(&mut b, 1020, crc);
        b
    }
    #[cfg(feature = "std")]
    #[test]
    fn super_descriptor_bitmap_inode_bindings_and_corruption() {
        for seeded in [false, true] {
            let sb = header(seeded);
            let profile = MetadataChecksums::superblock(&sb).unwrap();
            let seed = if seeded {
                0x87654321
            } else {
                forward(!0, b"0123456789abcdef")
            };
            assert_eq!(profile.seed, seed);
            assert_eq!(profile.inode_seed(17, 91), inode_seed(seed, 17, 91));
            for descriptor_size in [32, 64] {
                let mut desc = vec![0; descriptor_size];
                d(&mut desc, 0, 37);
                d(&mut desc, 4, 39);
                d(&mut desc, 8, 41);
                let bitmap = [0x35; 1024];
                let crc = forward(seed, &bitmap[..512]);
                w(&mut desc, 24, crc as u16);
                w(&mut desc, 26, crc as u16);
                if descriptor_size == 64 {
                    w(&mut desc, 56, (crc >> 16) as u16);
                    w(&mut desc, 58, (crc >> 16) as u16);
                }
                let crc = forward(forward(seed, &3u32.to_le_bytes()), &desc);
                w(&mut desc, 30, crc as u16);
                profile.descriptor(3, &desc).unwrap();
                assert!(profile.descriptor(4, &desc).is_err());
                for inode in [false, true] {
                    profile.bitmap(&bitmap, 4096, &desc, inode).unwrap();
                }
                let mut altered = bitmap;
                altered[123] ^= 1;
                assert!(profile.bitmap(&altered, 4096, &desc, false).is_err());
                assert!(profile.bitmap(&bitmap, 4097, &desc, false).is_err());
                desc[10] ^= 1;
                assert!(profile.descriptor(3, &desc).is_err());
            }
            for (size, extra_size) in [(128, 0), (256, 0), (256, 32)] {
                let mut inode = vec![0; size];
                w(&mut inode, 0, 0x81a4);
                d(&mut inode, 100, 91);
                if size == 256 {
                    w(&mut inode, 128, extra_size);
                }
                let crc = forward(inode_seed(seed, 17, 91), &inode);
                w(&mut inode, 124, crc as u16);
                if extra_size >= 4 {
                    w(&mut inode, 130, (crc >> 16) as u16);
                }
                profile.inode(17, &inode).unwrap();
                assert!(profile.inode(18, &inode).is_err());
                inode[size - 1] ^= 1;
                assert!(profile.inode(17, &inode).is_err());
            }
            let mut damaged = sb;
            damaged[777] ^= 1;
            assert!(MetadataChecksums::superblock(&damaged).is_err());
            assert!(profile.inode(17, &[0; 127]).is_err());
            assert!(profile.descriptor(0, &[0; 33]).is_err());
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn extent_leaf_index_orphan_and_xattr_have_distinct_seeds_and_bounds() {
        let seed = 0x12345678;
        let profile = MetadataChecksums { seed };
        let native_seed = inode_seed(seed, 17, 91);
        let mut extent = [0; 1024];
        w(&mut extent, 0, 0xf30a);
        w(&mut extent, 4, 84);
        let crc = forward(native_seed, &extent[..1020]);
        d(&mut extent, 1020, crc);
        profile.extent(17, 91, &extent).unwrap();
        assert!(profile.extent(17, 92, &extent).is_err());
        let mut bad = extent;
        w(&mut bad, 4, 85);
        assert!(profile.extent(17, 91, &bad).is_err());
        for offset in [8, 32] {
            let mut index = [0; 1024];
            let limit = (1024 - offset - 8) / 8;
            w(&mut index, offset, limit as u16);
            w(&mut index, offset + 2, 1);
            d(&mut index, offset + 4, 7);
            let tail = offset + limit * 8;
            let crc = forward(forward(native_seed, &index[..offset + 8]), &[0; 8]);
            d(&mut index, tail + 4, crc);
            profile.directory_index(17, 91, &index, offset).unwrap();
            assert!(profile.directory_index(18, 91, &index, offset).is_err());
            w(&mut index, offset + 2, (limit + 1) as u16);
            assert!(profile.directory_index(17, 91, &index, offset).is_err());
        }
        let mut leaf = [0; 1024];
        w(&mut leaf, 1016, 12);
        leaf[1019] = 0xde;
        let crc = forward(native_seed, &leaf[..1012]);
        d(&mut leaf, 1020, crc);
        assert_eq!(profile.directory_leaf(17, 91, &leaf).unwrap(), 1012);
        leaf[42] ^= 1;
        assert!(profile.directory_leaf(17, 91, &leaf).is_err());
        let mut orphan = [0; 1024];
        d(&mut orphan, 1016, 0x0b10ca04);
        let physical_seed = forward(native_seed, &177u64.to_le_bytes());
        let crc = forward(physical_seed, &orphan[..1016]);
        d(&mut orphan, 1020, crc);
        profile.orphan(17, 91, 177, &orphan).unwrap();
        assert!(profile.orphan(17, 91, 178, &orphan).is_err());
        d(&mut orphan, 0, 25);
        let crc = forward(physical_seed, &orphan[..1016]);
        d(&mut orphan, 1020, crc);
        assert_eq!(
            profile.orphan(17, 91, 177, &orphan).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let mut xattr = [0; 1024];
        d(&mut xattr, 0, 0xea020000);
        d(&mut xattr, 4, 1);
        d(&mut xattr, 8, 1);
        let crc = forward(forward(seed, &377u64.to_le_bytes()), &xattr);
        d(&mut xattr, 16, crc);
        profile.xattr(377, &xattr).unwrap();
        assert!(profile.xattr(378, &xattr).is_err());
        xattr[200] ^= 1;
        assert!(profile.xattr(377, &xattr).is_err());
        assert!(profile.extent(17, 91, &[0; 8]).is_err());
        assert!(
            profile
                .directory_index(17, 91, &[0; 8], usize::MAX)
                .is_err()
        );
        assert!(profile.directory_leaf(17, 91, &[0; 8]).is_err());
        assert!(profile.orphan(17, 91, 177, &[0; 4]).is_err());
        assert!(profile.xattr(177, &[0; 4]).is_err());
    }
}
