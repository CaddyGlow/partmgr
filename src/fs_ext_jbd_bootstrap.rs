//! Bounded candidate journal mapping for restart; it grants no write authority.
//! The committed preparation and complete final-redo ownership audit close this
//! candidate before any filesystem home block may be restored.
use super::*;
use crate::platform::collections::BTreeSet;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::storage::Storage;
pub(crate) struct Bootstrap {
    pub(crate) geometry: Geometry,
    pub(crate) primary: [u8; 1024],
    pub(crate) journal: [u8; 1024],
    pub(crate) inode: [u8; 256],
    #[cfg(test)]
    pub(crate) inode_bytes: usize,
    pub(crate) physical_blocks: Vec<u32>,
    pub(crate) metadata_blocks: Vec<u32>,
    volume_blocks: u32,
    _reservation: Reservation,
}
struct Walk<'a> {
    storage: &'a dyn Storage,
    resources: &'a Resources,
    length: u64,
    block_bytes: usize,
    volume_blocks: u32,
    map: Vec<u32>,
    metadata: Vec<u32>,
    seen: BTreeSet<u32>,
    work: usize,
    ceiling: usize,
    checksums: Option<super::super::metadata::MetadataChecksums>,
    generation: u32,
}
impl Walk<'_> {
    fn step(&mut self, count: usize) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.work = self
            .work
            .checked_add(count)
            .filter(|n| *n <= self.ceiling)
            .ok_or_else(|| budget("JBD2 bootstrap work ceiling"))?;
        if self.storage.len()? != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "JBD2 bootstrap source length changed",
            )));
        }
        Ok(())
    }
    fn reference(&mut self, physical: u32, metadata: bool) -> io::Result<()> {
        self.step(1)?;
        if physical == 0 || physical >= self.volume_blocks || !self.seen.insert(physical) {
            return Err(invalid("JBD2 bootstrap block bounds/alias/cycle"));
        }
        if metadata {
            if self.metadata.len() >= self.map.len() {
                return Err(budget("JBD2 bootstrap metadata ceiling"));
            }
            self.metadata.push(physical);
        }
        Ok(())
    }
    fn block(&mut self, physical: u32, out: &mut [u8]) -> io::Result<()> {
        self.step(1)?;
        if physical >= self.volume_blocks {
            return Err(invalid("JBD2 bootstrap read outside filesystem"));
        }
        self.storage
            .read_exact_at(u64::from(physical) * self.block_bytes as u64, out)
    }
    fn data(&mut self, logical: usize, physical: u32) -> io::Result<()> {
        self.reference(physical, false)?;
        if logical >= self.map.len() || self.map[logical] != u32::MAX {
            return Err(invalid("JBD2 bootstrap logical alias/outside journal"));
        }
        self.map[logical] = physical;
        Ok(())
    }
    fn indirect(&mut self, physical: u32, depth: u32, logical: usize) -> io::Result<()> {
        if depth == 0 {
            return self.data(logical, physical);
        }
        let span = (self.block_bytes / 4).pow(depth - 1);
        if physical == 0 {
            return if logical >= self.map.len() {
                Ok(())
            } else {
                Err(invalid("JBD2 bootstrap sparse journal"))
            };
        }
        if logical >= self.map.len() {
            return Err(unsupported("JBD2 bootstrap journal allocation beyond EOF"));
        }
        self.reference(physical, true)?;
        let mut bytes = [0u8; MAX_BLOCK];
        self.block(physical, &mut bytes[..self.block_bytes])?;
        for index in 0..self.block_bytes / 4 {
            self.step(1)?;
            let pointer = super::super::u32le(&bytes, index * 4);
            let offset = logical
                .checked_add(index * span)
                .ok_or_else(|| invalid("JBD2 bootstrap indirect offset overflow"))?;
            if depth == 1 {
                if offset < self.map.len() {
                    if pointer == 0 {
                        return Err(invalid("JBD2 bootstrap sparse indirect journal"));
                    }
                    self.data(offset, pointer)?;
                } else if pointer != 0 {
                    return Err(unsupported("JBD2 bootstrap indirect allocation beyond EOF"));
                }
            } else {
                self.indirect(pointer, depth - 1, offset)?;
            }
        }
        Ok(())
    }
    fn extents(
        &mut self,
        bytes: &[u8],
        expected: Option<u16>,
        low: usize,
        high: usize,
    ) -> io::Result<()> {
        self.step(1)?;
        if bytes.len() < 12 || super::super::u16le(bytes, 0) != 0xf30a {
            return Err(invalid("JBD2 bootstrap extent header"));
        }
        let count = usize::from(super::super::u16le(bytes, 2));
        let maximum = usize::from(super::super::u16le(bytes, 4));
        let depth = super::super::u16le(bytes, 6);
        if maximum == 0
            || maximum > (bytes.len() - 12) / 12
            || count > maximum
            || depth > 5
            || expected.is_some_and(|value| value != depth)
            || depth != 0 && count == 0
        {
            return Err(invalid("JBD2 bootstrap extent depth/capacity"));
        }
        let mut prior = None;
        for index in 0..count {
            self.step(1)?;
            let at = 12 + index * 12;
            let logical = super::super::u32le(bytes, at) as usize;
            if logical < low || logical >= high || prior.is_some_and(|p| logical <= p) {
                return Err(invalid("JBD2 bootstrap extent parent ordering"));
            }
            prior = Some(logical);
            let next = if index + 1 < count {
                super::super::u32le(bytes, at + 12) as usize
            } else {
                high
            };
            if depth == 0 {
                let length = usize::from(super::super::u16le(bytes, at + 4));
                if length == 0
                    || length > 32768
                    || super::super::u16le(bytes, at + 6) != 0
                    || logical
                        .checked_add(length)
                        .is_none_or(|end| end > next || end > high)
                {
                    return Err(invalid("JBD2 bootstrap unwritten/high/overlapping extent"));
                }
                let physical = super::super::u32le(bytes, at + 8);
                for delta in 0..length {
                    self.data(
                        logical + delta,
                        physical
                            .checked_add(delta as u32)
                            .ok_or_else(|| invalid("JBD2 bootstrap physical overflow"))?,
                    )?;
                }
            } else {
                if super::super::u16le(bytes, at + 8) != 0 {
                    return Err(unsupported("JBD2 bootstrap high extent node"));
                }
                let physical = super::super::u32le(bytes, at + 4);
                self.reference(physical, true)?;
                let mut child = [0; MAX_BLOCK];
                self.block(physical, &mut child[..self.block_bytes])?;
                if let Some(checksums) = self.checksums {
                    checksums.extent(8, self.generation, &child[..self.block_bytes])?;
                }
                self.extents(&child[..self.block_bytes], Some(depth - 1), logical, next)?;
            }
        }
        Ok(())
    }
}
impl Bootstrap {
    /// Close raw mapping geometry against the checksum-validated preparation.
    /// Only the journal's sequence, start and CRC are publication fields;
    /// every other byte must retain the original native header exactly.
    pub(crate) fn validate_preparation(
        &self,
        preparation: &Preparation,
        next_sequence: u32,
    ) -> io::Result<()> {
        let inside = if self.geometry.block_bytes == 1024 {
            0
        } else {
            1024
        };
        let primary = &preparation.superblock[inside..inside + 1024];
        for range in [
            0..8,
            20..44,
            76..96,
            100..120,
            208..232,
            254..256,
            336..340,
            624..628,
        ] {
            if self.primary[range.clone()] != primary[range] {
                return Err(invalid("JBD2 preparation changed bootstrap geometry"));
            }
        }
        if super::super::u32le(&self.primary, 96) & !4 != super::super::u32le(primary, 96) & !4 {
            return Err(invalid("JBD2 preparation changed filesystem features"));
        }
        let original = &preparation.journal_superblock;
        let mut active = *original;
        put32(&mut active, 28, self.geometry.first);
        journal_checksum(&self.geometry, &mut active);
        let mut empty = *original;
        put32(&mut empty, 24, next_sequence);
        journal_checksum(&self.geometry, &mut empty);
        if self
            .journal
            .iter()
            .enumerate()
            .any(|(at, byte)| *byte != original[at] && *byte != active[at] && *byte != empty[at])
        {
            return Err(invalid(
                "JBD2 preparation changed native journal static fields",
            ));
        }
        Ok(())
    }

    pub(crate) fn read(
        storage: &dyn Storage,
        maximum_blocks: usize,
        maximum_work: usize,
        resources: &Resources,
    ) -> io::Result<Self> {
        resources.cancellation.check().map_err(io::Error::other)?;
        // Charge fixed decoding scratch before inspecting attacker-controlled
        // geometry; the later map reservation covers retained candidate state.
        let scratch = resources.memory.reserve(4096).map_err(io::Error::other)?;
        let length = storage.len()?;
        let mut primary = [0; 1024];
        storage.read_exact_at(1024, &mut primary)?;
        let log = super::super::u32le(&primary, 24);
        if log > 2
            || super::super::u16le(&primary, 56) != 0xef53
            || super::super::u32le(&primary, 92) & 4 == 0
            || super::super::u32le(&primary, 224) != 8
            || super::super::u32le(&primary, 228) != 0
            || primary[208..224].iter().any(|b| *b != 0)
        {
            return Err(unsupported("JBD2 bootstrap internal journal/block profile"));
        }
        let block_bytes = 1024usize << log;
        let volume_blocks = super::super::u32le(&primary, 4);
        let first = super::super::u32le(&primary, 20);
        let inode_bytes = usize::from(super::super::u16le(&primary, 88));
        let ipg = super::super::u32le(&primary, 40);
        if first != u32::from(block_bytes == 1024)
            || volume_blocks <= first
            || u64::from(volume_blocks) * block_bytes as u64 > length
            || ipg < 8
            || !matches!(inode_bytes, 128 | 256)
            || super::super::u32le(&primary, 336) != 0
        {
            return Err(invalid("JBD2 bootstrap bounded filesystem geometry"));
        }
        let descriptor_bytes = if super::super::u32le(&primary, 96) & 0x80 != 0 {
            64
        } else {
            32
        };
        let mut descriptor = [0; 64];
        storage.read_exact_at(
            u64::from(first + 1) * block_bytes as u64,
            &mut descriptor[..descriptor_bytes],
        )?;
        if descriptor_bytes == 64 && super::super::u32le(&descriptor, 40) != 0 {
            return Err(unsupported("JBD2 bootstrap high inode table"));
        }
        let table = super::super::u32le(&descriptor, 8);
        let position = u64::from(table) * block_bytes as u64 + (7 * inode_bytes) as u64;
        if table >= volume_blocks
            || position + inode_bytes as u64 > u64::from(volume_blocks) * block_bytes as u64
        {
            return Err(invalid("JBD2 bootstrap journal inode bounds"));
        }
        let mut inode = [0; 256];
        storage.read_exact_at(position, &mut inode[..inode_bytes])?;
        let raw: [u8; 128] = inode[..128].try_into().unwrap();
        let decoded = super::super::ExtInode::decode_profile(
            8,
            raw,
            super::super::u32le(&primary, 96) & 0x40 != 0,
        )?;
        if decoded.mode & 0xf000 != 0x8000
            || super::super::u16le(&inode, 26) != 1
            || decoded.length < 1024 * block_bytes as u64
            || !decoded.length.is_multiple_of(block_bytes as u64)
        {
            return Err(invalid("JBD2 bootstrap journal inode kind/length"));
        }
        let blocks = usize::try_from(decoded.length / block_bytes as u64)
            .ok()
            .filter(|n| *n <= maximum_blocks && *n <= 65536)
            .ok_or_else(|| budget("JBD2 bootstrap journal block ceiling"))?;
        let charged = blocks
            .checked_mul(384)
            .and_then(|n| n.checked_add(32768))
            .ok_or_else(|| budget("JBD2 bootstrap reservation overflow"))?;
        let reservation = resources
            .memory
            .reserve(charged as u64)
            .map_err(io::Error::other)?;
        drop(scratch);
        let checksums = if super::super::u32le(&primary, 100) & 0x400 != 0 {
            let seed = if super::super::u32le(&primary, 96) & 0x2000 != 0 {
                super::super::u32le(&primary, 624)
            } else {
                crc32c(!0, &primary[104..120])
            };
            let checksums = super::super::metadata::MetadataChecksums { seed };
            checksums.inode(8, &inode[..inode_bytes])?;
            Some(checksums)
        } else {
            None
        };
        let mut map = Vec::new();
        map.try_reserve_exact(blocks)
            .map_err(|_| budget("JBD2 bootstrap map allocation"))?;
        map.resize(blocks, u32::MAX);
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(blocks)
            .map_err(|_| budget("JBD2 bootstrap node allocation"))?;
        if map.capacity() > blocks || metadata.capacity() > blocks {
            return Err(budget("JBD2 bootstrap allocator capacity"));
        }
        let mut walk = Walk {
            storage,
            resources,
            length,
            block_bytes,
            volume_blocks,
            map,
            metadata,
            seen: BTreeSet::new(),
            work: 0,
            ceiling: maximum_work,
            checksums,
            generation: decoded.generation,
        };
        if super::super::u32le(&inode, 32) & 0x80000 != 0 {
            walk.extents(&inode[40..100], None, 0, blocks)?;
        } else {
            for index in 0..12 {
                if index < blocks {
                    walk.data(index, decoded.pointers[index])?;
                }
            }
            let per = block_bytes / 4;
            walk.indirect(decoded.pointers[12], 1, 12)?;
            walk.indirect(decoded.pointers[13], 2, 12 + per)?;
            walk.indirect(decoded.pointers[14], 3, 12 + per + per * per)?;
        }
        if walk.map.contains(&u32::MAX) {
            return Err(invalid("JBD2 bootstrap sparse mapped journal"));
        }
        let mut journal = [0; 1024];
        walk.block(walk.map[0], &mut journal)?;
        let features = be32(&journal, 40);
        if features & !0x19 != 0 || be32(&journal, 36) != 0 || be32(&journal, 44) != 0 {
            return Err(unsupported(
                "JBD2 bootstrap unsupported native feature profile",
            ));
        }
        let checksums = match features & 0x18 {
            8 => Checksums::V2,
            16 => Checksums::V3,
            0 => Checksums::None,
            _ => return Err(unsupported("JBD2 bootstrap checksum profile")),
        };
        if be32(&journal, 0) != MAGIC
            || be32(&journal, 4) != 4
            || be32(&journal, 8) != 0
            || be32(&journal, 12) as usize != block_bytes
            || be32(&journal, 16) as usize != blocks
            || journal[48..64] != primary[104..120]
            || be32(&journal, 64) != 1
            || be32(&journal, 68) != 0
            || journal[80]
                != if matches!(checksums, Checksums::None) {
                    0
                } else {
                    4
                }
            || be32(&journal, 84) != 0
            || be32(&journal, 32) != 0
        {
            return Err(invalid("JBD2 bootstrap native header profile/binding"));
        }
        let geometry = Geometry {
            block_bytes,
            first: be32(&journal, 20),
            maximum: blocks as u32,
            start: be32(&journal, 28),
            sequence: be32(&journal, 24),
            uuid: primary[104..120].try_into().unwrap(),
            checksums,
            revoke: features & 1 != 0,
        };
        // Dynamic start/sequence/checksum may be torn; the preparation closes them.
        if geometry.first == 0 || geometry.first >= geometry.maximum {
            return Err(invalid("JBD2 bootstrap native first block"));
        }
        Ok(Self {
            geometry,
            primary,
            journal,
            inode,
            #[cfg(test)]
            inode_bytes,
            physical_blocks: walk.map,
            metadata_blocks: walk.metadata,
            volume_blocks,
            _reservation: reservation,
        })
    }
    pub(crate) fn physical(&self, logical: u32) -> io::Result<u64> {
        self.physical_blocks
            .get(logical as usize)
            .map(|block| u64::from(*block) * self.geometry.block_bytes as u64)
            .ok_or_else(|| invalid("JBD2 bootstrap logical block outside journal"))
    }
    pub(crate) fn destination(&self, physical: u32) -> io::Result<()> {
        if physical >= self.volume_blocks
            || self.physical_blocks.contains(&physical)
            || self.metadata_blocks.contains(&physical)
        {
            return Err(invalid(
                "JBD2 bootstrap replay destination outside volume or aliases journal",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
pub(super) mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    pub(crate) struct Owned(pub(crate) Vec<u8>);
    impl Storage for Owned {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            out.copy_from_slice(
                self.0
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("bootstrap preflight writes")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("bootstrap preflight flushes")
        }
    }
    fn le(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn short(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn raw_crc(mut state: u32, bytes: &[u8]) -> u32 {
        state = state.reverse_bits();
        for byte in bytes {
            state ^= u32::from(byte.reverse_bits()) << 24;
            for _ in 0..8 {
                state = (state << 1)
                    ^ if state & 0x80000000 != 0 {
                        0x1edc6f41
                    } else {
                        0
                    };
            }
        }
        state.reverse_bits()
    }
    // Independently assembled ext3 layout, including packed bitmaps, inode table,
    // direct/single/double journal references and a forward-polynomial JBD CRC.
    pub(crate) fn fixture() -> Owned {
        let mut image = vec![0; 2048 * 1024];
        let sb = &mut image[1024..2048];
        le(sb, 0, 128);
        le(sb, 4, 2048);
        le(sb, 12, 997);
        le(sb, 16, 118);
        le(sb, 20, 1);
        le(sb, 32, 2048);
        le(sb, 36, 2048);
        le(sb, 40, 128);
        short(sb, 56, 0xef53);
        short(sb, 58, 1);
        le(sb, 76, 1);
        le(sb, 84, 11);
        short(sb, 88, 128);
        le(sb, 92, 4);
        le(sb, 96, 2);
        le(sb, 100, 1);
        sb[104..120].fill(0x39);
        le(sb, 224, 8);
        let gd = &mut image[2048..2080];
        le(gd, 0, 3);
        le(gd, 4, 4);
        le(gd, 8, 5);
        short(gd, 12, 997);
        short(gd, 14, 118);
        short(gd, 16, 1);
        let mut allocated: Vec<usize> = (1..21).collect();
        allocated.push(30);
        allocated.extend(50..55);
        allocated.extend(100..1124);
        for physical in allocated {
            let bit = physical - 1;
            image[3 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        for bit in 2047..8192 {
            image[3 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        for bit in (0..10).chain(128..8192) {
            image[4 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        let root = &mut image[5 * 1024 + 128..5 * 1024 + 256];
        short(root, 0, 0o40755);
        le(root, 4, 1024);
        short(root, 26, 2);
        le(root, 28, 2);
        le(root, 40, 30);
        let journal = &mut image[5 * 1024 + 7 * 128..5 * 1024 + 8 * 128];
        short(journal, 0, 0o100600);
        le(journal, 4, 1024 * 1024);
        short(journal, 26, 1);
        le(journal, 28, 2058);
        for index in 0..12 {
            le(journal, 40 + index * 4, 100 + index as u32);
        }
        le(journal, 88, 50);
        le(journal, 92, 51);
        for index in 0..256 {
            le(&mut image, 50 * 1024 + index * 4, 112 + index as u32);
        }
        for node in 0..3 {
            le(&mut image, 51 * 1024 + node * 4, 52 + node as u32);
            for index in 0..256 {
                let logical = 268 + node * 256 + index;
                if logical < 1024 {
                    le(
                        &mut image,
                        (52 + node) * 1024 + index * 4,
                        100 + logical as u32,
                    );
                }
            }
        }
        let directory = &mut image[30 * 1024..31 * 1024];
        le(directory, 0, 2);
        short(directory, 4, 12);
        directory[6] = 1;
        directory[7] = 2;
        directory[8] = b'.';
        le(directory, 12, 2);
        short(directory, 16, 1012);
        directory[18] = 2;
        directory[19] = 2;
        directory[20..22].copy_from_slice(b"..");
        let journal = &mut image[100 * 1024..101 * 1024];
        put32(journal, 0, MAGIC);
        put32(journal, 4, 4);
        put32(journal, 12, 1024);
        put32(journal, 16, 1024);
        put32(journal, 20, 1);
        put32(journal, 24, 37);
        put32(journal, 40, 17);
        journal[48..64].fill(0x39);
        put32(journal, 64, 1);
        journal[80] = 4;
        let sum = raw_crc(!0, journal);
        put32(journal, 252, sum);
        Owned(image)
    }
    #[cfg(feature = "std")]
    #[test]
    fn independent_complete_classic_journal_bootstrap_cycles_limits_cancel_and_refunds() {
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let owned = fixture();
        let boot = Bootstrap::read(&owned, 1024, 100000, &r).unwrap();
        assert_eq!(boot.inode_bytes, 128);
        assert_eq!(boot.metadata_blocks.len(), 5);
        assert_eq!(boot.physical_blocks.len(), 1024);
        for logical in 0..1024 {
            assert_eq!(
                boot.physical(logical).unwrap(),
                (100 + u64::from(logical)) * 1024
            );
        }
        assert!(boot.destination(50).is_err());
        assert!(boot.destination(101).is_err());
        assert!(boot.destination(2048).is_err());
        assert!(boot.destination(30).is_ok());
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(&owned, 18u128 << 64, &r).unwrap();
        for logical in 0..1024 {
            assert_eq!(
                boot.physical(logical).unwrap(),
                proof.physical(logical).unwrap()
            );
        }
        let audit = crate::fs_ext_audit::audit_decoder(
            &decoder,
            crate::fs_ext_audit::ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 100000,
                directory_blocks: 8,
                directory_entries: 32,
                findings: 8,
            },
            &r,
        )
        .unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        drop((audit, decoder, proof, boot));
        assert_eq!(r.memory.used(), 0);
        assert!(Bootstrap::read(&owned, 1023, 100000, &r).is_err());
        assert!(Bootstrap::read(&owned, 1024, 1, &r).is_err());
        let mut cycle = fixture();
        le(&mut cycle.0, 51 * 1024, 51);
        assert!(Bootstrap::read(&cycle, 1024, 100000, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        r.cancellation.cancel();
        assert!(Bootstrap::read(&owned, 1024, 100000, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}
