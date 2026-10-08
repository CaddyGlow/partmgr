//! Explicit checksum policy, separate from complete structural ownership checks.
//! Absent checksums never supply an integrity proof. GDT_CSUM protects descriptors
//! only; bitmap, inode, extent and directory checksums require METADATA_CSUM.
use super::{invalid, metadata::MetadataChecksums, u16le, u32le, unsupported};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Absent { uuid: [u8; 16] },
    Group16 { uuid: [u8; 16], wide: bool },
    Metadata { uuid: [u8; 16] },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Integrity {
    // Existing checksum writers may use this only in the metadata profile. It
    // is deliberately zero in the two profiles without metadata checksums.
    pub seed: u32,
    kind: Kind,
}

fn block(bytes: &[u8]) -> io::Result<()> {
    if !matches!(bytes.len(), 1024 | 2048 | 4096) {
        return Err(unsupported("ext integrity block size"));
    }
    Ok(())
}

fn crc16(mut crc: u16, bytes: &[u8]) -> u16 {
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    crc
}

impl From<MetadataChecksums> for Integrity {
    fn from(checksums: MetadataChecksums) -> Self {
        Self {
            seed: checksums.seed,
            kind: Kind::Metadata { uuid: [0; 16] },
        }
    }
}

impl Integrity {
    pub fn superblock(bytes: &[u8; 1024]) -> io::Result<Self> {
        if u32le(bytes, 100) & 0x400 != 0 {
            let checked = MetadataChecksums::superblock(bytes)?;
            return Ok(Self {
                seed: checked.seed,
                kind: Kind::Metadata {
                    uuid: bytes[104..120].try_into().unwrap(),
                },
            });
        }
        if u32le(bytes, 96) & 0x2000 != 0 || bytes[373] != 0 || u32le(bytes, 624) != 0 {
            return Err(unsupported(
                "ext checksum seed/algorithm without metadata checksums",
            ));
        }
        let kind = if u32le(bytes, 100) & 0x10 != 0 {
            Kind::Group16 {
                uuid: bytes[104..120].try_into().unwrap(),
                wide: u32le(bytes, 96) & 0x80 != 0,
            }
        } else {
            Kind::Absent {
                uuid: bytes[104..120].try_into().unwrap(),
            }
        };
        Ok(Self { seed: 0, kind })
    }
    pub fn has_metadata(&self) -> bool {
        matches!(self.kind, Kind::Metadata { .. })
    }
    pub fn has_group_checksum(&self) -> bool {
        !matches!(self.kind, Kind::Absent { .. })
    }
    pub fn same_policy(&self, other: &Self) -> bool {
        self.kind == other.kind && self.seed == other.seed
    }
    fn metadata(&self) -> Option<MetadataChecksums> {
        self.has_metadata()
            .then_some(MetadataChecksums { seed: self.seed })
    }
    // Native checksum writing remains in the private journal qualification module.
    #[cfg(test)]
    pub fn inode_seed(&self, number: u32, generation: u32) -> u32 {
        self.metadata()
            .map_or(0, |c| c.inode_seed(number, generation))
    }
    #[cfg(test)]
    pub fn stamp_directory_leaf(
        &self,
        number: u32,
        generation: u32,
        bytes: &mut [u8],
    ) -> io::Result<()> {
        block(bytes)?;
        if !self.has_metadata() {
            return Ok(());
        }
        let tail = bytes.len() - 12;
        bytes[tail..tail + 12].fill(0);
        bytes[tail + 4..tail + 6].copy_from_slice(&12u16.to_le_bytes());
        bytes[tail + 7] = 0xde;
        let checksum = super::checksum::crc32c(self.inode_seed(number, generation), &bytes[..tail]);
        bytes[tail + 8..tail + 12].copy_from_slice(&checksum.to_le_bytes());
        self.directory_leaf(number, generation, bytes).map(|_| ())
    }
    #[cfg(test)]
    pub fn stamp_inode(&self, number: u32, generation: u32, bytes: &mut [u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 128 | 256) {
            return Err(unsupported("ext integrity inode size"));
        }
        if !self.has_metadata() {
            return Ok(());
        }
        let high = bytes.len() == 256 && u16le(bytes, 128) >= 4;
        bytes[124..126].fill(0);
        if high {
            bytes[130..132].fill(0);
        }
        let checksum = super::checksum::crc32c(self.inode_seed(number, generation), bytes);
        bytes[124..126].copy_from_slice(&(checksum as u16).to_le_bytes());
        if high {
            bytes[130..132].copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
        }
        self.inode(number, bytes)
    }
    // Native writers remain private until their full profile qualification.
    #[cfg(test)]
    pub fn stamp_descriptor(&self, group: u32, bytes: &mut [u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 32 | 64) {
            return Err(unsupported("ext integrity descriptor size"));
        }
        let checksum = match self.kind {
            Kind::Absent { .. } => return Ok(()),
            Kind::Group16 { uuid, wide } => {
                if wide != (bytes.len() == 64) {
                    return Err(invalid("ext CRC16 descriptor width"));
                }
                let crc = crc16(crc16(crc16(!0, &uuid), &group.to_le_bytes()), &bytes[..30]);
                if wide { crc16(crc, &bytes[32..]) } else { crc }
            }
            Kind::Metadata { .. } => {
                bytes[30..32].fill(0);
                super::checksum::crc32c(
                    super::checksum::crc32c(self.seed, &group.to_le_bytes()),
                    bytes,
                ) as u16
            }
        };
        bytes[30..32].copy_from_slice(&checksum.to_le_bytes());
        self.descriptor(group, bytes)
    }
    pub fn descriptor(&self, group: u32, bytes: &[u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 32 | 64) {
            return Err(unsupported("ext integrity descriptor size"));
        }
        if let Some(c) = self.metadata() {
            return c.descriptor(group, bytes);
        }
        if let Kind::Group16 { uuid, wide } = self.kind {
            if wide != (bytes.len() == 64) {
                return Err(invalid("ext CRC16 descriptor width"));
            }
            let crc = crc16(crc16(crc16(!0, &uuid), &group.to_le_bytes()), &bytes[..30]);
            let crc = if wide { crc16(crc, &bytes[32..]) } else { crc };
            if crc != u16le(bytes, 30) {
                return Err(invalid("ext CRC16 group descriptor checksum"));
            }
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
        block(bytes)?;
        if !bits.is_multiple_of(8)
            || bits as usize / 8 > bytes.len()
            || !matches!(descriptor.len(), 32 | 64)
        {
            return Err(invalid("ext integrity bitmap geometry"));
        }
        if let Some(c) = self.metadata() {
            c.bitmap(bytes, bits, descriptor, inode)?;
        }
        Ok(())
    }
    pub fn inode(&self, number: u32, bytes: &[u8]) -> io::Result<()> {
        if !matches!(bytes.len(), 128 | 256) {
            return Err(unsupported("ext integrity inode size"));
        }
        if let Some(c) = self.metadata() {
            c.inode(number, bytes)?;
        }
        Ok(())
    }
    pub fn extent(&self, number: u32, generation: u32, bytes: &[u8]) -> io::Result<()> {
        block(bytes)?;
        if let Some(c) = self.metadata() {
            c.extent(number, generation, bytes)?;
        }
        Ok(())
    }
    pub fn directory_leaf(&self, number: u32, generation: u32, bytes: &[u8]) -> io::Result<usize> {
        block(bytes)?;
        self.metadata().map_or(Ok(bytes.len()), |c| {
            c.directory_leaf(number, generation, bytes)
        })
    }
    pub fn directory_index(
        &self,
        number: u32,
        generation: u32,
        bytes: &[u8],
        offset: usize,
    ) -> io::Result<()> {
        block(bytes)?;
        if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("ext integrity directory index count bounds"));
        }
        if let Some(c) = self.metadata() {
            c.directory_index(number, generation, bytes, offset)?;
        }
        Ok(())
    }
    pub fn xattr(&self, physical: u64, bytes: &[u8]) -> io::Result<()> {
        block(bytes)?;
        if u32le(bytes, 0) != 0xea020000 {
            return Err(invalid("ext xattr header magic"));
        }
        if let Some(c) = self.metadata() {
            c.xattr(physical, bytes)?;
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
        self.metadata()
            .ok_or_else(|| unsupported("ext orphan file without metadata checksums"))?
            .orphan(number, generation, physical, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn native_crc16_descriptors_and_absent_integrity() {
        // Independently authored mke2fs ext4 16MiB/1KiB/I256 fixture, -O
        // ^metadata_csum,^orphan_file,uninit_bg; archived probe command/hash.
        let mut sb = [0; 1024];
        sb[96..100].copy_from_slice(&0x80u32.to_le_bytes());
        sb[100..104].copy_from_slice(&0x10u32.to_le_bytes());
        sb[104..120].copy_from_slice(&unhex("0781c67d1943450c8c7f1ac601621542"));
        let c = Integrity::superblock(&sb).unwrap();
        assert!(!c.has_metadata());
        assert!(c.has_group_checksum());
        for (group, text) in [
            (
                0,
                "8200000084000000860000006d1bf507020004000000000000000000f5073d540000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                1,
                "8300000085000000860200007e1b00080000050000000000000000000008c3290000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let descriptor = unhex(text);
            c.descriptor(group, &descriptor).unwrap();
            let mut restamped = descriptor.clone();
            restamped[30..32].fill(0);
            c.stamp_descriptor(group, &mut restamped).unwrap();
            assert_eq!(restamped, descriptor);
            for at in 0..descriptor.len() {
                let mut damaged = descriptor.clone();
                damaged[at] ^= 1;
                assert!(c.descriptor(group, &damaged).is_err());
            }
            assert!(c.descriptor(group + 2, &descriptor).is_err());
        }
        assert_eq!(crc16(0, b"123456789"), 0xbb3d);
        assert_eq!(crc16(!0, b"123456789"), 0x4b37);
        sb[96..104].fill(0);
        let absent = Integrity::superblock(&sb).unwrap();
        assert!(!absent.has_group_checksum());
        let mut opaque = [0xa5; 64];
        absent.stamp_descriptor(0, &mut opaque).unwrap();
        assert_eq!(opaque, [0xa5; 64]);
        let mut opaque_inode = [0xa5; 256];
        absent.stamp_inode(12, 5, &mut opaque_inode).unwrap();
        assert_eq!(opaque_inode, [0xa5; 256]);
        let mut opaque_directory = [0xa5; 1024];
        absent
            .stamp_directory_leaf(2, 5, &mut opaque_directory)
            .unwrap();
        assert_eq!(opaque_directory, [0xa5; 1024]);
        let mut foreign = sb;
        foreign[104] ^= 1;
        assert!(!absent.same_policy(&Integrity::superblock(&foreign).unwrap()));
        assert_eq!(absent.directory_leaf(2, 0, &[0; 1024]).unwrap(), 1024);
        assert!(absent.orphan(12, 0, 100, &[0; 1024]).is_err());
        sb[373] = 1;
        assert!(Integrity::superblock(&sb).is_err());
        sb[373] = 0;
        sb[96..100].copy_from_slice(&0x2000u32.to_le_bytes());
        assert!(Integrity::superblock(&sb).is_err());
    }
}
