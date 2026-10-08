//! Read-only inactive internal JBD/JBD2 validation. No replay or writable journal authority.
use super::*;
const MAX_JOURNAL_BLOCKS: usize = 65536;
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
impl<R: ExtDecodeRead> ExtDecoder<R> {
    pub(crate) fn validate_journal(&self, resources: &Resources) -> io::Result<()> {
        if !self.geometry.has_journal {
            return Ok(());
        }
        let inode = self.inode(self.geometry.journal_inode, resources)?;
        let bs = u64::from(self.geometry.block_size);
        if inode.mode & 0xf000 != 0x8000
            || inode.length < bs * 1024
            || !inode.length.is_multiple_of(bs)
            || u16le(&inode.raw, 26) != 1
        {
            return Err(invalid("ext internal journal inode geometry/kind"));
        }
        let blocks = usize::try_from(inode.length / bs)
            .ok()
            .filter(|n| *n <= MAX_JOURNAL_BLOCKS)
            .ok_or_else(|| {
                io::Error::other(fs_core::Error::new(
                    fs_core::ErrorKind::BudgetExhausted,
                    "ext journal block ceiling",
                ))
            })?;
        let map = self.file_map(self.geometry.journal_inode, blocks, resources, false)?;
        if map
            .extents
            .iter()
            .any(|e| !matches!(e.kind, ExtentKind::Data(_)))
        {
            return Err(invalid(
                "ext internal journal has sparse or unwritten storage",
            ));
        }
        let mut journal = [0u8; 1024];
        self.read_map(&map, 0, &mut journal, resources)?;
        if be32(&journal, 0) != 0xc03b3998
            || !matches!(be32(&journal, 4), 3 | 4)
            || be32(&journal, 8) != 0
        {
            return Err(invalid("ext journal superblock magic/type/sequence"));
        }
        let length = inode.length / bs;
        if be32(&journal, 12) != self.geometry.block_size
            || u64::from(be32(&journal, 16)) != length
            || be32(&journal, 20) == 0
            || u64::from(be32(&journal, 20)) + 1023 > length
        {
            return Err(invalid("ext journal superblock size/first-block geometry"));
        }
        // s_start==0 is only one condition: ext s_state clean and RECOVER absent
        // have already been enforced by opening, and abort state is checked here.
        if be32(&journal, 28) != 0 || be32(&journal, 32) != 0 {
            return Err(unsupported(
                "ext journal active/aborted; immutable profile cannot replay",
            ));
        }
        if be32(&journal, 4) == 4 {
            let features = be32(&journal, 40);
            let checksummed = features & 0x18 != 0;
            if be32(&journal, 36) != 0
                || features & !0x19 != 0
                || be32(&journal, 44) != 0
                || be32(&journal, 84) != 0
                || be32(&journal, 68) != 0
            {
                return Err(unsupported(
                    "ext journal checksum-v1/64-bit/async/fast-commit/dynamic or unknown feature",
                ));
            }
            if features & 0x18 == 0x18 {
                return Err(invalid("ext journal checksum-v2 and checksum-v3 conflict"));
            }
            if checksummed {
                if journal[80] != 4 {
                    return Err(unsupported("ext journal checksum algorithm"));
                }
                let saved = be32(&journal, 252);
                journal[252..256].fill(0);
                if checksum::crc32c(!0, &journal) != saved {
                    return Err(invalid("ext journal superblock checksum"));
                }
            } else if journal[80] != 0 {
                return Err(unsupported("ext journal checksum type without feature"));
            }
            if journal[48..64] != self.geometry.uuid || be32(&journal, 64) != 1 {
                return Err(invalid("ext internal journal UUID/user binding"));
            }
        }
        Ok(())
    }
}
