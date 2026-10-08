//! Borrowed final-redo decoding; no immutable payload capability is constructed.
use super::*;
use crate::fs_ext_audit::{ExtAuditLimits, ExtAuditReport};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::storage::Storage;

pub(crate) struct JournalControl {
    pub(crate) physical: u64,
    pub(crate) original: [u8; 1024],
    pub(crate) geometry: Geometry,
    pub(crate) next_sequence: u32,
}
pub(crate) struct Overlay<'a> {
    storage: &'a dyn Storage,
    blocks: &'a [ReplayBlock],
    block_bytes: usize,
    source_length: u64,
    volume_length: u64,
    superblock: [u8; 1024],
    journal: Option<(u64, [u8; 1024])>,
    resources: Resources,
    _reservation: Reservation,
}
fn apply(
    records: &[ReplayBlock],
    block_bytes: usize,
    offset: u64,
    out: &mut [u8],
) -> io::Result<()> {
    let end = offset
        .checked_add(out.len() as u64)
        .ok_or_else(|| invalid("redo overlay range overflow"))?;
    let first = records
        .partition_point(|r| u64::from(r.destination) * block_bytes as u64 <= offset)
        .saturating_sub(1);
    for record in &records[first..] {
        let start = u64::from(record.destination) * block_bytes as u64;
        if start >= end {
            break;
        }
        let left = offset.max(start);
        let right = end.min(start + block_bytes as u64);
        if left < right {
            out[(left - offset) as usize..(right - offset) as usize]
                .copy_from_slice(&record.bytes[(left - start) as usize..(right - start) as usize]);
        }
    }
    Ok(())
}
fn control(offset: u64, bytes: &[u8], at: u64, out: &mut [u8]) {
    let left = at.max(offset);
    let right = (at + out.len() as u64).min(offset + bytes.len() as u64);
    if left < right {
        out[(left - at) as usize..(right - at) as usize]
            .copy_from_slice(&bytes[(left - offset) as usize..(right - offset) as usize]);
    }
}
impl<'a> Overlay<'a> {
    pub(crate) fn new(
        storage: &'a dyn Storage,
        blocks: &'a [ReplayBlock],
        block_bytes: usize,
        journal: Option<JournalControl>,
        resources: &Resources,
    ) -> io::Result<Self> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if !matches!(block_bytes, 1024 | 2048 | 4096) {
            return Err(invalid("redo overlay block size"));
        }
        let reservation = resources.memory.reserve(4096).map_err(io::Error::other)?;
        let source_length = storage.len()?;
        let mut superblock = [0; 1024];
        storage.read_exact_at(1024, &mut superblock)?;
        for pair in blocks.windows(2) {
            resources.cancellation.check().map_err(io::Error::other)?;
            if pair[0].destination >= pair[1].destination {
                return Err(invalid("redo overlay destinations unordered/duplicated"));
            }
        }
        apply(blocks, block_bytes, 1024, &mut superblock)?;
        if super::super::u16le(&superblock, 56) != 0xef53
            || super::super::u16le(&superblock, 58) != 1
            || super::super::u32le(&superblock, 24) > 2
            || 1024usize << super::super::u32le(&superblock, 24) != block_bytes
        {
            return Err(invalid("redo overlay filesystem superblock geometry/state"));
        }
        let volume_length = u64::from(super::super::u32le(&superblock, 4)) * block_bytes as u64;
        if volume_length > source_length || volume_length < 2048 {
            return Err(invalid("redo overlay volume bounds"));
        }
        for record in blocks {
            resources.cancellation.check().map_err(io::Error::other)?;
            if (u64::from(record.destination) + 1) * block_bytes as u64 > volume_length {
                return Err(invalid("redo overlay destination outside filesystem"));
            }
        }
        if super::super::u32le(&superblock, 100) & 0x400 != 0 {
            super::super::metadata::MetadataChecksums::superblock(&superblock)?;
        }
        let features = super::super::u32le(&superblock, 96) & !4;
        superblock[96..100].copy_from_slice(&features.to_le_bytes());
        if super::super::u32le(&superblock, 100) & 0x400 != 0 {
            let sum = crc32c(!0, &superblock[..1020]);
            superblock[1020..].copy_from_slice(&sum.to_le_bytes());
        }
        let journal = if let Some(mut control) = journal {
            original_journal(&control.geometry, &control.original)?;
            if control.geometry.block_bytes != block_bytes
                || control.geometry.uuid != superblock[104..120]
                || control
                    .physical
                    .checked_add(1024)
                    .is_none_or(|end| end > volume_length)
            {
                return Err(invalid("redo overlay journal binding/bounds"));
            }
            put32(&mut control.original, 24, control.next_sequence);
            put32(&mut control.original, 28, 0);
            journal_checksum(&control.geometry, &mut control.original);
            Some((control.physical, control.original))
        } else {
            None
        };
        Ok(Self {
            storage,
            blocks,
            block_bytes,
            source_length,
            volume_length,
            superblock,
            journal,
            resources: resources.clone(),
            _reservation: reservation,
        })
    }
    pub(crate) fn verify(
        self,
        scope: u128,
        limits: ExtAuditLimits,
        expected_journal: Option<&bootstrap::Bootstrap>,
    ) -> io::Result<(super::super::ExtGeometry, ExtAuditReport)> {
        let resources = self.resources.clone();
        if let Some(expected) = expected_journal {
            for record in self.blocks {
                expected.destination(record.destination)?;
            }
        }
        let decoder =
            super::super::ExtDecoder::open_owned_profile_qualification(self, scope, &resources)?;
        if let Some(expected) = expected_journal {
            let inode = decoder.inode(8, &resources)?;
            if inode.raw != expected.inode[..128] || inode.extra != expected.inode[128..256] {
                return Err(invalid("redo overlay changes immutable journal inode"));
            }
            let map = decoder.file_map(8, expected.physical_blocks.len(), &resources, false)?;
            if map.length
                != expected.physical_blocks.len() as u64 * expected.geometry.block_bytes as u64
            {
                return Err(invalid("redo overlay changes journal length"));
            }
            for logical in 0..expected.geometry.maximum {
                resources.cancellation.check().map_err(io::Error::other)?;
                let position = u64::from(logical) * expected.geometry.block_bytes as u64;
                let index = map
                    .extents
                    .partition_point(|e| e.offset <= position)
                    .checked_sub(1)
                    .ok_or_else(|| invalid("redo overlay missing journal map"))?;
                let extent = &map.extents[index];
                let super::super::ExtentKind::Data(physical) = extent.kind else {
                    return Err(invalid("redo overlay sparse journal map"));
                };
                if physical + position - extent.offset != expected.physical(logical)? {
                    return Err(invalid("redo overlay changes journal allocation"));
                }
            }
        }
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, &resources)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(invalid("redo overlay complete ownership audit rejected"));
        }
        Ok((decoder.geometry, audit))
    }
}
impl super::super::ExtDecodeRead for Overlay<'_> {
    fn decode_len(&self) -> io::Result<u64> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        if self.storage.len()? != self.source_length {
            return Err(invalid("redo overlay source length changed"));
        }
        Ok(self.volume_length)
    }
    fn decode_read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let end = at
            .checked_add(out.len() as u64)
            .ok_or_else(|| invalid("redo overlay read overflow"))?;
        if end > self.decode_len()? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.storage.read_exact_at(at, out)?;
        apply(self.blocks, self.block_bytes, at, out)?;
        control(1024, &self.superblock, at, out);
        if let Some((offset, bytes)) = &self.journal {
            control(*offset, bytes, at, out);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use crate::fs_ext::ExtDecodeRead;
    mod independent {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fs_ext_modern.rs"
        ));
    }
    struct Owned(Vec<u8>);
    impl Storage for Owned {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(
                self.0
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("redo preflight writes")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("redo preflight flushes")
        }
    }
    fn limits() -> ExtAuditLimits {
        ExtAuditLimits {
            blocks: 64,
            inodes: 16,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn complete_borrowed_overlay_rejects_checksum_valid_semantic_defect_before_writes() {
        let resources = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        for image in [independent::fixture().0, independent::without_extents().0] {
            let owned = Owned(image);
            let mut replacement = [0; MAX_BLOCK];
            replacement[..1024].copy_from_slice(&owned.0[10 * 1024..11 * 1024]);
            replacement[37..51].fill(0xfe);
            let records = [ReplayBlock {
                destination: 10,
                bytes: replacement,
            }];
            let view = Overlay::new(&owned, &records, 1024, None, &resources).unwrap();
            let mut range = [0; 80];
            view.decode_read_exact_at(10 * 1024 + 9, &mut range)
                .unwrap();
            assert_eq!(range, replacement[9..89]);
            let checked = view.verify(18u128 << 64, limits(), None).unwrap();
            assert!(checked.1.is_clean());
            drop(checked);
            assert_eq!(resources.memory.used(), 0);
            let malformed = independent::mutation_seeds().remove(0);
            let mut bad = [0; MAX_BLOCK];
            bad[..1024].copy_from_slice(&malformed[12 * 1024..13 * 1024]);
            let records = [ReplayBlock {
                destination: 12,
                bytes: bad,
            }];
            let view = Overlay::new(&owned, &records, 1024, None, &resources).unwrap();
            assert!(view.verify(18u128 << 64, limits(), None).is_err());
            assert_eq!(resources.memory.used(), 0);
            let tiny = Resources {
                memory: Budget::new(1),
                cancellation: Cancellation::default(),
            };
            assert!(Overlay::new(&owned, &[], 1024, None, &tiny).is_err());
            assert_eq!(tiny.memory.used(), 0);
        }
        resources.cancellation.cancel();
        assert!(
            Overlay::new(
                &Owned(independent::fixture().0),
                &[],
                1024,
                None,
                &resources
            )
            .is_err()
        );
        assert_eq!(resources.memory.used(), 0);
    }
}
