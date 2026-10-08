//! Bounded native JBD2 transaction scan; no backend authority or replay writes.
use super::{checksum::crc32c, invalid, unsupported};
use crate::fs_core::{Error, ErrorKind, Reservation, Resources};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{cell::Cell, io};
#[path = "fs_ext_jbd_bootstrap.rs"]
mod bootstrap;
#[path = "fs_ext_jbd_legacy.rs"]
mod legacy;
#[path = "fs_ext_jbd_modern_plan.rs"]
mod modern_plan;
#[cfg(all(test, feature = "std", unix))]
#[path = "fs_ext_jbd_native.rs"]
mod native;
#[path = "fs_ext_jbd_overlay.rs"]
mod overlay;
#[path = "fs_ext_jbd_recovery.rs"]
mod recovery;
#[path = "fs_ext_jbd_session.rs"]
mod session;
#[path = "fs_ext_jbd_transaction.rs"]
mod transaction;

pub(crate) struct NativeJournalProof {
    pub(crate) geometry: Geometry,
    map: super::ExtDecodedFileMap,
}
impl NativeJournalProof {
    pub(crate) fn physical(&self, logical: u32) -> io::Result<u64> {
        if logical >= self.geometry.maximum {
            return Err(invalid("JBD2 logical block outside journal"));
        }
        let position = u64::from(logical) * self.geometry.block_bytes as u64;
        let index = self
            .map
            .extents
            .partition_point(|extent| extent.offset <= position)
            .checked_sub(1)
            .ok_or_else(|| invalid("JBD2 missing mapped block"))?;
        let extent = &self.map.extents[index];
        let relative = position - extent.offset;
        if relative
            .checked_add(self.geometry.block_bytes as u64)
            .is_none_or(|end| end > extent.length)
        {
            return Err(invalid("JBD2 partial mapped block"));
        }
        match extent.kind {
            super::ExtentKind::Data(physical) => physical
                .checked_add(relative)
                .ok_or_else(|| invalid("JBD2 mapped offset overflow")),
            _ => Err(invalid("JBD2 non-data journal allocation")),
        }
    }
}
impl<'a> super::ExtDecoder<&'a dyn crate::storage::Storage> {
    /// Distinct borrowed-storage decoder; this never grants immutable ReadAt authority.
    pub(crate) fn open_native_clean(
        storage: &'a dyn crate::storage::Storage,
        scope: u128,
        resources: &Resources,
    ) -> io::Result<(Self, NativeJournalProof)> {
        let decoder = Self::open_owned_profile_qualification(storage, scope, resources)?;
        if !decoder.geometry.has_journal {
            return Err(unsupported(
                "native ext editor requires internal JBD2 journal",
            ));
        }
        let inode = decoder.inode(decoder.geometry.journal_inode, resources)?;
        let blocks = usize::try_from(inode.length / u64::from(decoder.geometry.block_size))
            .map_err(|_| budget("native JBD2 mapping size"))?;
        let map = decoder.file_map(decoder.geometry.journal_inode, blocks, resources, false)?;
        let mut header = [0u8; 1024];
        decoder.read_map(&map, 0, &mut header, resources)?;
        let checksums = match be32(&header, 40) & 0x18 {
            8 => Checksums::V2,
            16 => Checksums::V3,
            0 => Checksums::None,
            _ => return Err(unsupported("native editor JBD2 checksum profile")),
        };
        let geometry = Geometry {
            block_bytes: decoder.geometry.block_size as usize,
            first: be32(&header, 20),
            maximum: be32(&header, 16),
            start: be32(&header, 28),
            sequence: be32(&header, 24),
            uuid: header[48..64].try_into().unwrap(),
            checksums,
            revoke: be32(&header, 40) & 1 != 0,
        };
        geometry.check()?;
        Ok((decoder, NativeJournalProof { geometry, map }))
    }
}

const MAGIC: u32 = 0xc03b3998;
const MAX_BLOCK: usize = 4096;
fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn budget(message: &str) -> io::Error {
    io::Error::other(Error::new(ErrorKind::BudgetExhausted, message))
}
#[derive(Clone, Copy)]
pub(crate) enum Checksums {
    None,
    V2,
    V3,
}
#[derive(Clone, Copy)]
pub(crate) struct Geometry {
    pub(crate) block_bytes: usize,
    pub(crate) first: u32,
    pub(crate) maximum: u32,
    pub(crate) start: u32,
    pub(crate) sequence: u32,
    pub(crate) uuid: [u8; 16],
    pub(crate) checksums: Checksums,
    pub(crate) revoke: bool,
}
pub(crate) struct ReplayBlock {
    pub(crate) destination: u32,
    pub(crate) bytes: [u8; MAX_BLOCK],
}
pub(crate) struct ReplayPlan {
    pub(crate) blocks: Vec<ReplayBlock>,
    pub(crate) next_sequence: u32,
    pub(crate) committed_transactions: usize,
    pub(crate) discarded_tail: bool,
    _reservation: Reservation,
}
impl Geometry {
    fn check(&self) -> io::Result<()> {
        if !matches!(self.block_bytes, 1024 | 2048 | 4096)
            || self.first == 0
            || self.first >= self.maximum
            || self.start != 0 && !(self.first..self.maximum).contains(&self.start)
        {
            return Err(invalid("JBD2 log geometry"));
        }
        Ok(())
    }
    fn next(&self, block: u32) -> u32 {
        if block + 1 == self.maximum {
            self.first
        } else {
            block + 1
        }
    }
    fn seeded(&self) -> u32 {
        crc32c(!0, &self.uuid)
    }
    fn metadata_valid(&self, bytes: &mut [u8], offset: usize) -> bool {
        if matches!(self.checksums, Checksums::None) {
            return true;
        }
        let supplied = be32(bytes, offset);
        bytes[offset..offset + 4].fill(0);
        let actual = crc32c(self.seeded(), bytes);
        bytes[offset..offset + 4].copy_from_slice(&supplied.to_be_bytes());
        actual == supplied
    }
}

pub(crate) struct LogBlock {
    pub(crate) logical: u32,
    pub(crate) bytes: [u8; MAX_BLOCK],
}
pub(crate) struct EncodedTransaction {
    pub(crate) blocks: Vec<LogBlock>,
    pub(crate) next_logical: u32,
    _reservation: Reservation,
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn header(bytes: &mut [u8], kind: u32, sequence: u32) {
    put32(bytes, 0, MAGIC);
    put32(bytes, 4, kind);
    put32(bytes, 8, sequence);
}
fn metadata_checksum(geometry: &Geometry, bytes: &mut [u8], at: usize) {
    if matches!(geometry.checksums, Checksums::None) {
        return;
    }
    put32(bytes, at, 0);
    let checksum = crc32c(geometry.seeded(), bytes);
    put32(bytes, at, checksum);
}
fn journal_checksum(geometry: &Geometry, bytes: &mut [u8; 1024]) {
    if !matches!(geometry.checksums, Checksums::None) {
        put32(bytes, 252, 0);
        let sum = crc32c(!0, bytes);
        put32(bytes, 252, sum);
    }
}

const CAPSULE_MAGIC: &[u8; 16] = b"PMGRJBD2PREPARE1";
pub(crate) struct Preparation {
    pub(crate) superblock: [u8; MAX_BLOCK],
    pub(crate) journal_superblock: [u8; 1024],
    pub(crate) next_logical: u32,
    _reservation: Reservation,
}
fn original_journal(geometry: &Geometry, bytes: &[u8; 1024]) -> io::Result<()> {
    let features = be32(bytes, 40);
    let desired = match geometry.checksums {
        Checksums::None => 0,
        Checksums::V2 => 8,
        Checksums::V3 => 16,
    } | u32::from(geometry.revoke);
    if be32(bytes, 0) != MAGIC
        || be32(bytes, 4) != 4
        || be32(bytes, 8) != 0
        || be32(bytes, 12) as usize != geometry.block_bytes
        || be32(bytes, 16) != geometry.maximum
        || be32(bytes, 20) != geometry.first
        || be32(bytes, 24) != geometry.sequence
        || be32(bytes, 28) != 0
        || be32(bytes, 32) != 0
        || be32(bytes, 36) != 0
        || features != desired
        || be32(bytes, 44) != 0
        || bytes[48..64] != geometry.uuid
        || be32(bytes, 64) != 1
        || be32(bytes, 68) != 0
        || bytes[80]
            != if matches!(geometry.checksums, Checksums::None) {
                0
            } else {
                4
            }
        || be32(bytes, 84) != 0
    {
        return Err(invalid("JBD2 preparation original header binding"));
    }
    let mut checked = *bytes;
    let supplied = be32(&checked, 252);
    put32(&mut checked, 252, 0);
    if !matches!(geometry.checksums, Checksums::None) && crc32c(!0, &checked) != supplied {
        return Err(invalid("JBD2 preparation original header checksum"));
    }
    Ok(())
}
/// Native redo preparation stores the dirty superblock and preserves the original
/// journal header in CRC-covered padding ignored by native JBD2 parsers.
pub(crate) fn prepare(
    geometry: &Geometry,
    superblock: &[u8],
    journal_superblock: &[u8; 1024],
    resources: &Resources,
) -> io::Result<EncodedTransaction> {
    geometry.check()?;
    original_journal(geometry, journal_superblock)?;
    if superblock.len() != geometry.block_bytes {
        return Err(invalid("JBD2 preparation superblock block size"));
    }
    let inside = if geometry.block_bytes == 1024 {
        0
    } else {
        1024
    };
    let mut bytes = [0; MAX_BLOCK];
    bytes[..superblock.len()].copy_from_slice(superblock);
    let sb = &mut bytes[inside..inside + 1024];
    if super::u16le(sb, 56) != 0xef53
        || super::u16le(sb, 58) != 1
        || super::u32le(sb, 96) & 4 != 0
        || sb[104..120] != geometry.uuid
    {
        return Err(invalid("JBD2 preparation clean filesystem binding"));
    }
    if super::u32le(sb, 100) & 0x400 != 0 {
        super::metadata::MetadataChecksums::superblock((&*sb).try_into().unwrap())?;
    }
    let feature = super::u32le(sb, 96) | 4;
    sb[96..100].copy_from_slice(&feature.to_le_bytes());
    if super::u32le(sb, 100) & 0x400 != 0 {
        let sum = crc32c(!0, &sb[..1020]);
        sb[1020..].copy_from_slice(&sum.to_le_bytes());
    }
    let input = [ReplayBlock {
        destination: u32::from(geometry.block_bytes == 1024),
        bytes,
    }];
    let mut result = encode(geometry, &input, 16, resources, |_| Ok(()))?;
    assert_eq!(result.blocks.len(), 3);
    for index in [0, 2] {
        result.blocks[index].bytes[96..112].copy_from_slice(CAPSULE_MAGIC);
        put32(&mut result.blocks[index].bytes, 112, 1);
    }
    result.blocks[0].bytes[128..640].copy_from_slice(&journal_superblock[..512]);
    result.blocks[2].bytes[128..640].copy_from_slice(&journal_superblock[512..]);
    metadata_checksum(
        geometry,
        &mut result.blocks[0].bytes[..geometry.block_bytes],
        geometry.block_bytes - 4,
    );
    metadata_checksum(
        geometry,
        &mut result.blocks[2].bytes[..geometry.block_bytes],
        16,
    );
    legacy::stamp(geometry, &mut result.blocks)?;
    Ok(result)
}
pub(crate) fn preparation(
    geometry: &Geometry,
    resources: &Resources,
    mut read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
) -> io::Result<Preparation> {
    geometry.check()?;
    let scratch = resources
        .memory
        .reserve((4 * MAX_BLOCK + 2048) as u64)
        .map_err(io::Error::other)?;
    let mut descriptor = [0; MAX_BLOCK];
    let mut data = [0; MAX_BLOCK];
    let mut commit = [0; MAX_BLOCK];
    let second = geometry.next(geometry.first);
    let third = geometry.next(second);
    for (logical, out) in [
        (geometry.first, &mut descriptor),
        (second, &mut data),
        (third, &mut commit),
    ] {
        resources.cancellation.check().map_err(io::Error::other)?;
        read(logical, &mut out[..geometry.block_bytes])?;
    }
    for (block, kind, checksum_at) in [
        (&mut descriptor, 1, geometry.block_bytes - 4),
        (&mut commit, 2, 16),
    ] {
        if be32(block, 0) != MAGIC
            || be32(block, 4) != kind
            || be32(block, 8) != geometry.sequence
            || block[96..112] != *CAPSULE_MAGIC
            || be32(block, 112) != 1
            || !geometry.metadata_valid(&mut block[..geometry.block_bytes], checksum_at)
        {
            return Err(invalid(
                "JBD2 committed preparation header/capsule/checksum",
            ));
        }
    }
    let (flags, checksum, uuid_at) = match geometry.checksums {
        Checksums::V3 => (be32(&descriptor, 16), be32(&descriptor, 24), 28),
        Checksums::V2 => (
            u32::from(u16::from_be_bytes(descriptor[18..20].try_into().unwrap())),
            u32::from(u16::from_be_bytes(descriptor[16..18].try_into().unwrap())),
            22,
        ),
        Checksums::None => (be32(&descriptor, 16), 0, 20),
    };
    if commit[12..16] != [0; 4]
        || (matches!(geometry.checksums, Checksums::V3) && be32(&descriptor, 20) != 0)
        || !matches!(flags, 8 | 9)
        || be32(&descriptor, 12) != u32::from(geometry.block_bytes == 1024)
        || descriptor[uuid_at..uuid_at + 16] != geometry.uuid
    {
        return Err(invalid("JBD2 preparation single superblock tag"));
    }
    let actual = crc32c(
        crc32c(geometry.seeded(), &geometry.sequence.to_be_bytes()),
        &data[..geometry.block_bytes],
    );
    if !matches!(geometry.checksums, Checksums::None)
        && (if matches!(geometry.checksums, Checksums::V2) {
            actual & 0xffff
        } else {
            actual
        }) != checksum
    {
        return Err(invalid("JBD2 preparation superblock data checksum"));
    }
    if matches!(geometry.checksums, Checksums::None) {
        let mut integrity = legacy::Integrity::new(geometry, geometry.sequence);
        integrity.feed(geometry.first, &descriptor[..geometry.block_bytes])?;
        integrity.feed(second, &data[..geometry.block_bytes])?;
        integrity.verify(geometry, &commit[..geometry.block_bytes])?;
    }
    if flags & 1 != 0 {
        if data[..4] != [0; 4] {
            return Err(invalid("JBD2 preparation escape"));
        }
        data[..4].copy_from_slice(&MAGIC.to_be_bytes());
    }
    let mut original = [0; 1024];
    original[..512].copy_from_slice(&descriptor[128..640]);
    original[512..].copy_from_slice(&commit[128..640]);
    original_journal(geometry, &original)?;
    let inside = if geometry.block_bytes == 1024 {
        0
    } else {
        1024
    };
    let sb: &[u8; 1024] = data[inside..inside + 1024].try_into().unwrap();
    if super::u16le(sb, 56) != 0xef53
        || super::u16le(sb, 58) != 1
        || super::u32le(sb, 96) & 4 == 0
        || sb[104..120] != geometry.uuid
    {
        return Err(invalid("JBD2 preparation filesystem recovery binding"));
    }
    if super::u32le(sb, 100) & 0x400 != 0 {
        super::metadata::MetadataChecksums::superblock(sb)?;
    }
    Ok(Preparation {
        superblock: data,
        journal_superblock: original,
        next_logical: geometry.next(third),
        _reservation: scratch,
    })
}
/// Encode native redo records; publication and checkpoint ordering remain separate.
pub(crate) fn encode(
    geometry: &Geometry,
    input: &[ReplayBlock],
    maximum_work: usize,
    resources: &Resources,
    mut destination: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<EncodedTransaction> {
    geometry.check()?;
    if input.is_empty() {
        return Err(invalid("empty native JBD2 transaction"));
    }
    let tag_bytes = match geometry.checksums {
        Checksums::V3 => 16,
        Checksums::V2 => 10,
        Checksums::None => 8,
    };
    let tags_per_descriptor = (geometry.block_bytes - 4 - 12 - 16) / tag_bytes;
    let descriptors = input.len().div_ceil(tags_per_descriptor);
    let count = input
        .len()
        .checked_add(descriptors)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| budget("JBD2 encoding block count overflow"))?;
    if count >= (geometry.maximum - geometry.first) as usize {
        return Err(budget("JBD2 transaction exceeds bounded ring capacity"));
    }
    let charged = count
        .checked_mul(crate::platform::mem::size_of::<LogBlock>())
        .and_then(|n| n.checked_add(MAX_BLOCK + 128))
        .ok_or_else(|| budget("JBD2 encoding reservation overflow"))?;
    let reservation = resources
        .memory
        .reserve(charged as u64)
        .map_err(io::Error::other)?;
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(count)
        .map_err(|_| budget("JBD2 encoding allocation"))?;
    if blocks.capacity() > count {
        return Err(budget("JBD2 encoding allocator capacity"));
    }
    let mut work = 0usize;
    for (at, block) in input.iter().enumerate() {
        resources.cancellation.check().map_err(io::Error::other)?;
        work = work
            .checked_add(at + 1)
            .filter(|n| *n <= maximum_work)
            .ok_or_else(|| budget("JBD2 encoding work ceiling"))?;
        destination(block.destination)?;
        if input[..at]
            .iter()
            .any(|other| other.destination == block.destination)
        {
            return Err(invalid("duplicate native JBD2 transaction destination"));
        }
    }
    let mut logical = if geometry.start == 0 {
        geometry.first
    } else {
        geometry.start
    };
    let block_bytes = geometry.block_bytes;
    for chunk in input.chunks(tags_per_descriptor) {
        resources.cancellation.check().map_err(io::Error::other)?;
        let mut descriptor = [0u8; MAX_BLOCK];
        header(&mut descriptor, 1, geometry.sequence);
        let mut at = 12;
        for (index, block) in chunk.iter().enumerate() {
            let escaped = block.bytes[..4] == MAGIC.to_be_bytes();
            let flags = u32::from(escaped)
                | if index == 0 { 0 } else { 2 }
                | if index + 1 == chunk.len() { 8 } else { 0 };
            let mut data = block.bytes;
            if escaped {
                data[..4].fill(0);
            }
            let sum = crc32c(
                crc32c(geometry.seeded(), &geometry.sequence.to_be_bytes()),
                &data[..block_bytes],
            );
            put32(&mut descriptor, at, block.destination);
            if matches!(geometry.checksums, Checksums::V3) {
                put32(&mut descriptor, at + 4, flags);
                put32(&mut descriptor, at + 12, sum);
            } else if matches!(geometry.checksums, Checksums::None) {
                put32(&mut descriptor, at + 4, flags);
            } else {
                descriptor[at + 4..at + 6].copy_from_slice(&(sum as u16).to_be_bytes());
                descriptor[at + 6..at + 8].copy_from_slice(&(flags as u16).to_be_bytes());
            }
            at += tag_bytes;
            if index == 0 {
                descriptor[at..at + 16].copy_from_slice(&geometry.uuid);
                at += 16;
            }
        }
        metadata_checksum(geometry, &mut descriptor[..block_bytes], block_bytes - 4);
        blocks.push(LogBlock {
            logical,
            bytes: descriptor,
        });
        logical = geometry.next(logical);
        for block in chunk {
            resources.cancellation.check().map_err(io::Error::other)?;
            let mut data = block.bytes;
            if data[..4] == MAGIC.to_be_bytes() {
                data[..4].fill(0);
            }
            blocks.push(LogBlock {
                logical,
                bytes: data,
            });
            logical = geometry.next(logical);
        }
    }
    let mut commit = [0u8; MAX_BLOCK];
    header(&mut commit, 2, geometry.sequence);
    metadata_checksum(geometry, &mut commit[..block_bytes], 16);
    blocks.push(LogBlock {
        logical,
        bytes: commit,
    });
    logical = geometry.next(logical);
    legacy::stamp(geometry, &mut blocks)?;
    Ok(EncodedTransaction {
        blocks,
        next_logical: logical,
        _reservation: reservation,
    })
}

/// Durably write descriptor/data blocks before the native commit record.
/// Activating the journal and publishing the filesystem dirty fence are separate
/// owned-session steps; this helper never checkpoints filesystem home blocks.
pub(crate) fn publish_log(
    storage: &mut dyn crate::storage::Storage,
    proof: &NativeJournalProof,
    encoded: &EncodedTransaction,
    resources: &Resources,
) -> io::Result<()> {
    let length = storage.len()?;
    let block_bytes = proof.geometry.block_bytes;
    let _scratch_reservation = resources
        .memory
        .reserve((2 * MAX_BLOCK + 512) as u64)
        .map_err(io::Error::other)?;
    let mut scratch = [0u8; MAX_BLOCK];
    let write = |storage: &mut _, logical, inside: usize, bytes: &[u8]| -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if crate::storage::Storage::len(storage)? != length {
            return Err(invalid("JBD2 target length changed"));
        }
        if inside
            .checked_add(bytes.len())
            .is_none_or(|end| end > block_bytes)
        {
            return Err(invalid("JBD2 partial log range outside block"));
        }
        let mut at = proof
            .physical(logical)?
            .checked_add(inside as u64)
            .ok_or_else(|| invalid("JBD2 partial log offset overflow"))?;
        if at
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > length)
        {
            return Err(invalid("JBD2 log write outside owned storage"));
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            resources.cancellation.check().map_err(io::Error::other)?;
            let count = crate::storage::Storage::write_at(storage, at, remaining)?;
            if count == 0 || count > remaining.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            at += count as u64;
            remaining = &remaining[count..];
        }
        Ok(())
    };
    let verify = |storage: &_, logical, bytes: &[u8], scratch: &mut [u8]| -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if crate::storage::Storage::len(storage)? != length {
            return Err(invalid("JBD2 target length changed"));
        }
        crate::storage::Storage::read_exact_at(storage, proof.physical(logical)?, scratch)?;
        if bytes != scratch {
            return Err(invalid("JBD2 durable log readback mismatch"));
        }
        Ok(())
    };
    let (commit, preceding) = encoded
        .blocks
        .split_last()
        .ok_or_else(|| invalid("JBD2 empty encoded log"))?;
    if preceding.is_empty() || be32(&commit.bytes, 0) != MAGIC || be32(&commit.bytes, 4) != 2 {
        return Err(invalid("JBD2 missing encoded commit"));
    }
    // Clear both the future tail and commit header before any new descriptor/data.
    // An inactive ring may retain a valid commit with the upcoming native sequence.
    write(storage, encoded.next_logical, 0, &scratch[..block_bytes])?;
    write(storage, commit.logical, 0, &[0; 12])?;
    storage.flush()?;
    verify(storage, commit.logical, &[0; 12], &mut scratch[..12])?;
    verify(
        storage,
        encoded.next_logical,
        &[0; MAX_BLOCK][..block_bytes],
        &mut scratch[..block_bytes],
    )?;
    for block in preceding {
        write(storage, block.logical, 0, &block.bytes[..block_bytes])?;
    }
    // The complete commit body is durable while its publication header is zero.
    write(storage, commit.logical, 12, &commit.bytes[12..block_bytes])?;
    storage.flush()?;
    for block in preceding {
        verify(
            storage,
            block.logical,
            &block.bytes[..block_bytes],
            &mut scratch[..block_bytes],
        )?;
    }
    let mut unpublished = commit.bytes;
    unpublished[..12].fill(0);
    verify(
        storage,
        commit.logical,
        &unpublished[..block_bytes],
        &mut scratch[..block_bytes],
    )?;
    write(storage, commit.logical, 0, &commit.bytes[..12])?;
    storage.flush()?;
    verify(
        storage,
        commit.logical,
        &commit.bytes[..block_bytes],
        &mut scratch[..block_bytes],
    )?;
    Ok(())
}

/// Scan the whole bounded log before returning any block authorized for replay.
/// `destination` must exclude journal storage and any unsupported native targets.
pub(crate) fn scan(
    geometry: &Geometry,
    maximum_records: usize,
    maximum_work: usize,
    resources: &Resources,
    read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
    destination: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<ReplayPlan> {
    scan_profile(
        geometry,
        maximum_records,
        maximum_work,
        resources,
        read,
        destination,
        false,
    )
}
pub(crate) fn scan_owned(
    geometry: &Geometry,
    maximum_records: usize,
    maximum_work: usize,
    resources: &Resources,
    read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
    destination: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<ReplayPlan> {
    scan_profile(
        geometry,
        maximum_records,
        maximum_work,
        resources,
        read,
        destination,
        true,
    )
}
fn scan_profile(
    geometry: &Geometry,
    maximum_records: usize,
    maximum_work: usize,
    resources: &Resources,
    mut read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
    mut destination: impl FnMut(u32) -> io::Result<()>,
    owned_legacy: bool,
) -> io::Result<ReplayPlan> {
    geometry.check()?;
    resources.cancellation.check().map_err(io::Error::other)?;
    let charged = maximum_records
        .checked_mul(2 * (MAX_BLOCK + 64))
        .and_then(|n| n.checked_add(3 * MAX_BLOCK + 512))
        .ok_or_else(|| budget("JBD2 scan reservation overflow"))?;
    let reservation = resources
        .memory
        .reserve(charged as u64)
        .map_err(io::Error::other)?;
    let mut blocks: Vec<ReplayBlock> = Vec::new();
    let mut pending: Vec<ReplayBlock> = Vec::new();
    let mut revocations: Vec<u32> = Vec::new();
    blocks
        .try_reserve_exact(maximum_records)
        .map_err(|_| budget("JBD2 result allocation"))?;
    pending
        .try_reserve_exact(maximum_records)
        .map_err(|_| budget("JBD2 pending allocation"))?;
    revocations
        .try_reserve_exact(maximum_records)
        .map_err(|_| budget("JBD2 revoke allocation"))?;
    let capacity = blocks
        .capacity()
        .checked_add(pending.capacity())
        .and_then(|n| n.checked_mul(crate::platform::mem::size_of::<ReplayBlock>()))
        .and_then(|n| n.checked_add(revocations.capacity() * 4 + 3 * MAX_BLOCK + 512))
        .ok_or_else(|| budget("JBD2 actual capacity overflow"))?;
    if capacity > charged {
        return Err(budget("JBD2 allocator exceeded reservation"));
    }
    let mut sequence = geometry.sequence;
    let mut integrity = legacy::Integrity::new(geometry, sequence);
    let mut committed = 0;
    let mut pending_bad = false;
    let mut discarded = false;
    let mut log = geometry.start;
    let mut reads = 0usize;
    let block_bytes = geometry.block_bytes;
    let mut control = [0u8; MAX_BLOCK];
    let mut data = [0u8; MAX_BLOCK];
    let log_capacity = (geometry.maximum - geometry.first) as usize;
    let steps = Cell::new(0usize);
    let charge_work = |count: usize| -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let total = steps
            .get()
            .checked_add(count)
            .filter(|n| *n <= maximum_work)
            .ok_or_else(|| budget("JBD2 scan work ceiling"))?;
        steps.set(total);
        Ok(())
    };
    let mut read_block = |at: u32, bytes: &mut [u8]| -> io::Result<()> {
        charge_work(1)?;
        resources.cancellation.check().map_err(io::Error::other)?;
        if reads >= log_capacity {
            return Err(budget("JBD2 log scan work ceiling"));
        }
        reads += 1;
        read(at, bytes)
    };
    while log != 0 {
        let control_log = log;
        read_block(log, &mut control[..block_bytes])?;
        if be32(&control, 0) != MAGIC || be32(&control, 8) != sequence {
            discarded = !pending.is_empty() || !revocations.is_empty();
            break;
        }
        log = geometry.next(log);
        match be32(&control, 4) {
            1 => {
                if matches!(geometry.checksums, Checksums::None) && owned_legacy {
                    integrity.feed(control_log, &control[..block_bytes])?;
                }
                if !geometry.metadata_valid(&mut control[..block_bytes], block_bytes - 4) {
                    discarded = true;
                    break;
                }
                let checked = !matches!(geometry.checksums, Checksums::None);
                let end = block_bytes - if checked { 4 } else { 0 };
                let tag_bytes = match geometry.checksums {
                    Checksums::V3 => 16,
                    Checksums::V2 => 10,
                    Checksums::None => 8,
                };
                let mut at = 12;
                let mut first_tag = true;
                loop {
                    resources.cancellation.check().map_err(io::Error::other)?;
                    if at + tag_bytes > end {
                        return Err(invalid("JBD2 descriptor missing last tag"));
                    }
                    let target = be32(&control, at);
                    let (flags, saved) = if matches!(geometry.checksums, Checksums::V3) {
                        if be32(&control, at + 8) != 0 {
                            return Err(unsupported("JBD2 high destination block"));
                        }
                        (be32(&control, at + 4), be32(&control, at + 12))
                    } else if matches!(geometry.checksums, Checksums::None) && owned_legacy {
                        (be32(&control, at + 4), 0)
                    } else {
                        (
                            u32::from(u16::from_be_bytes(
                                control[at + 6..at + 8].try_into().unwrap(),
                            )),
                            u32::from(u16::from_be_bytes(
                                control[at + 4..at + 6].try_into().unwrap(),
                            )),
                        )
                    };
                    if flags & !0xb != 0 {
                        return Err(unsupported("JBD2 deleted/unknown tag flags"));
                    }
                    at += tag_bytes;
                    if flags & 2 == 0 {
                        if at + 16 > end || control[at..at + 16] != geometry.uuid {
                            return Err(invalid("JBD2 descriptor UUID binding"));
                        }
                        at += 16;
                    } else if first_tag {
                        return Err(invalid("JBD2 first tag omits UUID"));
                    }
                    first_tag = false;
                    destination(target)?;
                    charge_work(1 + pending.len())?;
                    if pending.len() >= maximum_records
                        || pending.iter().any(|p| p.destination == target)
                    {
                        return Err(if pending.len() >= maximum_records {
                            budget("JBD2 transaction block ceiling")
                        } else {
                            invalid("JBD2 duplicate destination in transaction")
                        });
                    }
                    read_block(log, &mut data[..block_bytes])?;
                    if matches!(geometry.checksums, Checksums::None) && owned_legacy {
                        integrity.feed(log, &data[..block_bytes])?;
                    }
                    log = geometry.next(log);
                    let actual = crc32c(
                        crc32c(geometry.seeded(), &sequence.to_be_bytes()),
                        &data[..block_bytes],
                    );
                    let good = match geometry.checksums {
                        Checksums::None => true,
                        Checksums::V2 => actual & 0xffff == saved,
                        Checksums::V3 => actual == saved,
                    };
                    pending_bad |= !good;
                    if flags & 1 != 0 {
                        if data[..4] != [0; 4] {
                            pending_bad = true;
                        }
                        data[..4].copy_from_slice(&MAGIC.to_be_bytes());
                    }
                    pending.push(ReplayBlock {
                        destination: target,
                        bytes: data,
                    });
                    if flags & 8 != 0 {
                        break;
                    }
                }
            }
            5 => {
                if matches!(geometry.checksums, Checksums::None) && owned_legacy {
                    integrity.feed(control_log, &control[..block_bytes])?;
                }
                if !geometry.revoke {
                    return Err(unsupported("JBD2 revocation feature absent"));
                }
                if !geometry.metadata_valid(&mut control[..block_bytes], block_bytes - 4) {
                    discarded = true;
                    break;
                }
                let end = be32(&control, 12) as usize;
                let maximum = block_bytes
                    - if matches!(geometry.checksums, Checksums::None) {
                        0
                    } else {
                        4
                    };
                if end < 16 || end > maximum || !end.is_multiple_of(4) {
                    return Err(invalid("JBD2 revoke count"));
                }
                for at in (16..end).step_by(4) {
                    resources.cancellation.check().map_err(io::Error::other)?;
                    let target = be32(&control, at);
                    charge_work(1)?;
                    destination(target)?;
                    if revocations.len() >= maximum_records {
                        return Err(budget("JBD2 revoke ceiling"));
                    }
                    revocations.push(target);
                }
            }
            2 => {
                if matches!(geometry.checksums, Checksums::None) && owned_legacy {
                    integrity.verify(geometry, &control[..block_bytes])?;
                }
                if !geometry.metadata_valid(&mut control[..block_bytes], 16) {
                    discarded = true;
                    break;
                }
                if !matches!(geometry.checksums, Checksums::None) && control[12..16] != [0; 4] {
                    return Err(invalid("JBD2 native checksum commit header"));
                }
                if pending_bad {
                    return Err(invalid("JBD2 committed data checksum or escape encoding"));
                }
                for target in &revocations {
                    charge_work(blocks.len() + 1)?;
                    blocks.retain(|p| p.destination != *target);
                }
                for new in pending.drain(..) {
                    charge_work(revocations.len() + blocks.len() + 1)?;
                    if revocations.contains(&new.destination) {
                        continue;
                    }
                    if let Some(old) = blocks.iter_mut().find(|p| p.destination == new.destination)
                    {
                        *old = new;
                    } else {
                        if blocks.len() >= maximum_records {
                            return Err(budget("JBD2 replay block ceiling"));
                        }
                        blocks.push(new);
                    }
                }
                revocations.clear();
                pending_bad = false;
                committed += 1;
                sequence = sequence.wrapping_add(1); // Native transaction IDs are modulo 2^32.
                integrity = legacy::Integrity::new(geometry, sequence);
            }
            _ => {
                discarded = !pending.is_empty() || !revocations.is_empty();
                break;
            }
        }
    }
    charge_work(
        blocks
            .len()
            .saturating_mul(1 + blocks.len().checked_ilog2().unwrap_or(0) as usize),
    )?;
    blocks.sort_unstable_by_key(|p| p.destination);
    Ok(ReplayPlan {
        blocks,
        next_sequence: sequence,
        committed_transactions: committed,
        discarded_tail: discarded,
        _reservation: reservation,
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources(bytes: u64) -> Resources {
        Resources {
            memory: Budget::new(bytes),
            cancellation: Cancellation::default(),
        }
    }
    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    // Independent forward-polynomial implementation, rather than codec CRC helpers.
    fn crc(mut state: u32, bytes: &[u8]) -> u32 {
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
        state
    }
    fn crc_raw(initial: u32, bytes: &[u8]) -> u32 {
        crc(initial.reverse_bits(), bytes).reverse_bits()
    }
    fn metadata(block: &mut [u8], offset: usize, uuid: &[u8; 16]) {
        put(block, offset, 0);
        let sum = crc_raw(crc_raw(!0, uuid), block);
        put(block, offset, sum);
    }
    fn header(block: &mut [u8], kind: u32, sequence: u32) {
        put(block, 0, MAGIC);
        put(block, 4, kind);
        put(block, 8, sequence);
    }
    fn fixture(format: Checksums) -> (Geometry, Vec<Vec<u8>>) {
        let uuid = [0x39; 16];
        let geometry = Geometry {
            block_bytes: 1024,
            first: 1,
            maximum: 12,
            start: 10,
            sequence: 37,
            uuid,
            checksums: format,
            revoke: true,
        };
        let mut log = vec![vec![0; 1024]; 12];
        // A transaction wraps 10(descriptor),11(data),1(commit).
        let mut data = vec![0x71; 1024];
        data[..4].fill(0); // Escaped native journal magic.
        let sum = crc_raw(crc_raw(crc_raw(!0, &uuid), &37u32.to_be_bytes()), &data);
        let descriptor = &mut log[10];
        header(descriptor, 1, 37);
        put(descriptor, 12, 99);
        match format {
            Checksums::V3 => {
                put(descriptor, 16, 9);
                put(descriptor, 24, sum);
                descriptor[28..44].copy_from_slice(&uuid);
            }
            Checksums::V2 | Checksums::None => {
                descriptor[16..18].copy_from_slice(&(sum as u16).to_be_bytes());
                descriptor[18..20].copy_from_slice(&9u16.to_be_bytes());
                let uuid_at = if matches!(format, Checksums::V2) {
                    22
                } else {
                    20
                };
                descriptor[uuid_at..uuid_at + 16].copy_from_slice(&uuid);
            }
        }
        if !matches!(format, Checksums::None) {
            metadata(descriptor, 1020, &uuid);
        }
        log[11] = data;
        header(&mut log[1], 2, 37);
        if !matches!(format, Checksums::None) {
            metadata(&mut log[1], 16, &uuid);
        }
        (geometry, log)
    }
    fn execute(
        g: &Geometry,
        log: &[Vec<u8>],
        r: &Resources,
        cap: usize,
        work: usize,
    ) -> io::Result<ReplayPlan> {
        scan(
            g,
            cap,
            work,
            r,
            |at, out| {
                out.copy_from_slice(&log[at as usize]);
                Ok(())
            },
            |target| {
                if (90..110).contains(&target) {
                    Ok(())
                } else {
                    Err(invalid("fixture destination rejected"))
                }
            },
        )
    }
    #[cfg(feature = "std")]
    #[test]
    fn independent_v2_v3_legacy_ring_escape_complete_and_refunds() {
        for format in [Checksums::None, Checksums::V2, Checksums::V3] {
            let (g, log) = fixture(format);
            let r = resources(1 << 20);
            let plan = execute(&g, &log, &r, 4, 20).unwrap();
            assert_eq!(plan.next_sequence, 38);
            assert_eq!(plan.committed_transactions, 1);
            assert!(!plan.discarded_tail);
            assert_eq!(plan.blocks.len(), 1);
            assert_eq!(plan.blocks[0].destination, 99);
            assert_eq!(&plan.blocks[0].bytes[..4], &MAGIC.to_be_bytes());
            assert!(plan.blocks[0].bytes[4..1024].iter().all(|b| *b == 0x71));
            assert!(r.memory.used() > 0);
            drop(plan);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn incomplete_commit_revoke_semantics_bad_data_and_semantic_binding() {
        let (g, mut log) = fixture(Checksums::V3);
        let r = resources(1 << 20);
        log[1][16] ^= 1;
        let p = execute(&g, &log, &r, 4, 20).unwrap();
        assert_eq!(p.committed_transactions, 0);
        assert!(p.blocks.is_empty());
        assert!(p.discarded_tail);
        drop(p);
        metadata(&mut log[1], 16, &g.uuid);
        // Later committed revoke removes earlier data from the complete replay plan.
        header(&mut log[2], 5, 38);
        put(&mut log[2], 12, 20);
        put(&mut log[2], 16, 99);
        metadata(&mut log[2], 1020, &g.uuid);
        header(&mut log[3], 2, 38);
        metadata(&mut log[3], 16, &g.uuid);
        let p = execute(&g, &log, &r, 4, 20).unwrap();
        assert_eq!(p.committed_transactions, 2);
        assert_eq!(p.next_sequence, 39);
        assert!(p.blocks.is_empty());
        drop(p);
        log[11][51] ^= 1;
        assert!(execute(&g, &log, &r, 4, 20).is_err());
        log[11][51] ^= 1;
        put(&mut log[10], 12, 1);
        metadata(&mut log[10], 1020, &g.uuid);
        assert!(execute(&g, &log, &r, 4, 20).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn bounded_work_memory_cancellation_unknown_flags_and_malformed_tags() {
        let (g, mut log) = fixture(Checksums::V3);
        let r = resources(1 << 20);
        assert!(execute(&g, &log, &r, 0, 20).is_err());
        assert!(execute(&g, &log, &r, 4, 2).is_err());
        put(&mut log[10], 16, 11); // UUID omitted on the first tag.
        metadata(&mut log[10], 1020, &g.uuid);
        assert!(execute(&g, &log, &r, 4, 20).is_err());
        put(&mut log[10], 16, 13); // Unsupported deletion flag, valid CRC.
        metadata(&mut log[10], 1020, &g.uuid);
        assert_eq!(
            execute(&g, &log, &r, 4, 20).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(r.memory.used(), 0);
        let tiny = resources(1);
        assert!(execute(&g, &log, &tiny, 4, 20).is_err());
        assert_eq!(tiny.memory.used(), 0);
        r.cancellation.cancel();
        assert!(execute(&g, &log, &r, 4, 20).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn checked_encoder_multiple_descriptors_wrap_escape_and_replay() {
        for format in [Checksums::V2, Checksums::V3] {
            let (mut geometry, _) = fixture(format);
            geometry.maximum = 100;
            geometry.start = 90;
            let r = resources(8 << 20);
            let mut input = Vec::new();
            for n in 0..70u32 {
                let mut bytes = [n as u8; MAX_BLOCK];
                if n == 0 {
                    bytes[..4].copy_from_slice(&MAGIC.to_be_bytes());
                }
                input.push(ReplayBlock {
                    destination: 1000 + n,
                    bytes,
                });
            }
            let encoded = encode(&geometry, &input, 5000, &r, |_| Ok(())).unwrap();
            assert!((geometry.first..geometry.maximum).contains(&encoded.next_logical));
            assert!(
                encoded
                    .blocks
                    .iter()
                    .filter(|b| be32(&b.bytes, 4) == 1 && be32(&b.bytes, 0) == MAGIC)
                    .count()
                    >= 1
            );
            assert_eq!(be32(&encoded.blocks.last().unwrap().bytes, 4), 2);
            let mut ring = vec![vec![0; 1024]; 100];
            for block in &encoded.blocks {
                ring[block.logical as usize].copy_from_slice(&block.bytes[..1024]);
            }
            let plan = scan(
                &geometry,
                70,
                10000,
                &r,
                |at, out| {
                    out.copy_from_slice(&ring[at as usize]);
                    Ok(())
                },
                |at| {
                    if (1000..1070).contains(&at) {
                        Ok(())
                    } else {
                        Err(invalid("writer destination"))
                    }
                },
            )
            .unwrap();
            assert_eq!(plan.blocks.len(), 70);
            assert_eq!(plan.committed_transactions, 1);
            for (got, expected) in plan.blocks.iter().zip(&input) {
                assert_eq!(got.destination, expected.destination);
                assert_eq!(got.bytes[..1024], expected.bytes[..1024]);
            }
            drop(plan);
            drop(encoded);
            assert_eq!(r.memory.used(), 0);
            assert!(encode(&geometry, &input, 1, &r, |_| Ok(())).is_err());
            assert_eq!(r.memory.used(), 0);
            geometry.checksums = Checksums::None;
            let encoded = encode(&geometry, &input, 5000, &r, |_| Ok(())).unwrap();
            assert_eq!(
                encoded.blocks.last().unwrap().bytes[640..656],
                *b"PMGRJBD2SHA256V1"
            );
            drop(encoded);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn journal_physical_map_boundaries_and_owned_constructor_no_readat_authority() {
        let r = resources(1 << 20);
        let (geometry, _) = fixture(Checksums::V3);
        let proof = NativeJournalProof {
            geometry,
            map: super::super::ExtDecodedFileMap {
                identity: crate::fs_core::ObjectId {
                    source: 18u128 << 64,
                    generation: 0,
                    native: vec![8],
                },
                length: 12 * 1024,
                extents: vec![
                    crate::fs_file::FileExtent {
                        offset: 0,
                        length: 4 * 1024,
                        kind: crate::fs_file::ExtentKind::Data(100 * 1024),
                    },
                    crate::fs_file::FileExtent {
                        offset: 4 * 1024,
                        length: 8 * 1024,
                        kind: crate::fs_file::ExtentKind::Data(300 * 1024),
                    },
                ],
                reservation: r.memory.reserve(512).unwrap(),
            },
        };
        assert_eq!(proof.physical(0).unwrap(), 100 * 1024);
        assert_eq!(proof.physical(3).unwrap(), 103 * 1024);
        assert_eq!(proof.physical(4).unwrap(), 300 * 1024);
        assert_eq!(proof.physical(11).unwrap(), 307 * 1024);
        assert!(proof.physical(12).is_err());
        drop(proof);
        // Storage implements only mutable decoder I/O; no immutable ReadAt adapter.
        struct Owned(Vec<u8>);
        impl crate::storage::Storage for Owned {
            fn len(&self) -> io::Result<u64> {
                Ok(self.0.len() as u64)
            }
            fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
                let at = at as usize;
                let bytes = self
                    .0
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                out.copy_from_slice(bytes);
                Ok(())
            }
            fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
                panic!("constructor writes")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("constructor flushes")
            }
        }
        mod independent {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/fs_ext_modern.rs"
            ));
        }
        let mut inputs = vec![independent::fixture().0, independent::without_extents().0];
        inputs.extend(independent::mutation_seeds());
        for bytes in inputs {
            let owned = Owned(bytes);
            assert!(super::super::ExtDecoder::open_native_clean(&owned, 18u128 << 64, &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn native_log_publication_write_barrier_readback_and_torn_cuts() {
        use crate::platform::cell::Cell;
        use crate::storage::Storage;
        struct Fault {
            visible: Vec<u8>,
            durable: Vec<u8>,
            events: Cell<usize>,
            cut: Option<usize>,
            immediate: bool,
            persist_failed_flush: bool,
        }
        impl Fault {
            fn hit(&self) -> bool {
                let event = self.events.get();
                self.events.set(event + 1);
                self.cut == Some(event)
            }
        }
        impl Storage for Fault {
            fn len(&self) -> io::Result<u64> {
                Ok(self.visible.len() as u64)
            }
            fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
                if self.hit() {
                    return Err(io::Error::other("readback cut"));
                }
                let at = at as usize;
                out.copy_from_slice(&self.visible[at..at + out.len()]);
                Ok(())
            }
            fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
                let fail = self.hit();
                let count = if fail { bytes.len() / 2 } else { bytes.len() };
                let at = at as usize;
                self.visible[at..at + count].copy_from_slice(&bytes[..count]);
                if self.immediate {
                    self.durable[at..at + count].copy_from_slice(&bytes[..count]);
                }
                if fail {
                    Err(io::Error::other("torn write cut"))
                } else {
                    Ok(count)
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                let fail = self.hit();
                if !fail || self.persist_failed_flush {
                    self.durable.copy_from_slice(&self.visible);
                }
                if fail {
                    Err(io::Error::other("barrier cut"))
                } else {
                    Ok(())
                }
            }
        }
        let r = resources(8 << 20);
        let (geometry, _) = fixture(Checksums::V3);
        let proof = NativeJournalProof {
            geometry,
            map: super::super::ExtDecodedFileMap {
                identity: crate::fs_core::ObjectId {
                    source: 18u128 << 64,
                    generation: 0,
                    native: vec![8],
                },
                length: 12 * 1024,
                extents: vec![crate::fs_file::FileExtent {
                    offset: 0,
                    length: 12 * 1024,
                    kind: crate::fs_file::ExtentKind::Data(4096),
                }],
                reservation: r.memory.reserve(512).unwrap(),
            },
        };
        let input: Vec<_> = (99..102)
            .map(|destination| ReplayBlock {
                destination,
                bytes: [destination as u8; MAX_BLOCK],
            })
            .collect();
        let encoded = encode(&proof.geometry, &input, 100, &r, |_| Ok(())).unwrap();
        let mut original = vec![0xa5; 20 * 1024];
        original[4096..16 * 1024].fill(0);
        let commit = encoded.blocks.last().unwrap();
        let physical = proof.physical(commit.logical).unwrap() as usize;
        original[physical..physical + 1024].copy_from_slice(&commit.bytes[..1024]);
        let make = |cut, immediate, persist_failed_flush| Fault {
            visible: original.clone(),
            durable: original.clone(),
            events: Cell::new(0),
            cut,
            immediate,
            persist_failed_flush,
        };
        let mut success = make(None, false, false);
        publish_log(&mut success, &proof, &encoded, &r).unwrap();
        let events = success.events.get();
        assert!(events >= 12);
        let mut cuts = 0;
        for immediate in [false, true] {
            for persist_failed_flush in [false, true] {
                for cut in 0..events {
                    let mut storage = make(Some(cut), immediate, persist_failed_flush);
                    assert!(publish_log(&mut storage, &proof, &encoded, &r).is_err());
                    assert_eq!(&storage.durable[..4096], &original[..4096]);
                    assert_eq!(&storage.durable[16 * 1024..], &original[16 * 1024..]);
                    let plan = scan(
                        &proof.geometry,
                        4,
                        100,
                        &r,
                        |at, out| {
                            let physical = proof.physical(at)? as usize;
                            out.copy_from_slice(&storage.durable[physical..physical + out.len()]);
                            Ok(())
                        },
                        |_| Ok(()),
                    )
                    .unwrap();
                    assert!(plan.blocks.is_empty() || plan.blocks.len() == input.len());
                    if !plan.blocks.is_empty() {
                        for (got, expected) in plan.blocks.iter().zip(&input) {
                            assert_eq!(got.destination, expected.destination);
                            assert_eq!(got.bytes[..1024], expected.bytes[..1024]);
                        }
                    }
                    cuts += 1;
                }
            }
        }
        assert_eq!(cuts, 4 * events);
        drop((encoded, proof));
        assert_eq!(r.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn preparation_capsule_preserves_native_header_and_rejects_rechecksummed_binding() {
        let r = resources(1 << 20);
        let (mut geometry, _) = fixture(Checksums::V3);
        geometry.start = geometry.first;
        let mut journal = [0u8; 1024];
        header(&mut journal, 4, 0);
        put32(&mut journal, 12, 1024);
        put32(&mut journal, 16, geometry.maximum);
        put32(&mut journal, 20, geometry.first);
        put32(&mut journal, 24, geometry.sequence);
        put32(&mut journal, 40, 17);
        journal[48..64].copy_from_slice(&geometry.uuid);
        put32(&mut journal, 64, 1);
        journal[80] = 4;
        for (index, byte) in journal[256..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let sum = crc_raw(!0, &journal);
        put32(&mut journal, 252, sum);
        let mut sb = [0; 1024];
        sb[56..58].copy_from_slice(&0xef53u16.to_le_bytes());
        sb[58..60].copy_from_slice(&1u16.to_le_bytes());
        sb[104..120].copy_from_slice(&geometry.uuid);
        let mut encoded = prepare(&geometry, &sb, &journal, &r).unwrap();
        let read = |logical: u32, out: &mut [u8]| -> io::Result<()> {
            let found = encoded
                .blocks
                .iter()
                .find(|b| b.logical == logical)
                .unwrap();
            out.copy_from_slice(&found.bytes[..out.len()]);
            Ok(())
        };
        let recovered = preparation(&geometry, &r, read).unwrap();
        assert_eq!(recovered.journal_superblock, journal);
        assert_eq!(super::super::u32le(&recovered.superblock, 96) & 4, 4);
        assert_eq!(recovered.next_logical, encoded.next_logical);
        drop(recovered);
        // Native CRCs alone do not authorize an unsupported high destination word
        // or nonzero checksum-format bytes in the commit header.
        for (block, at, checksum_at) in [(0, 20, 1020), (2, 12, 16)] {
            put32(&mut encoded.blocks[block].bytes, at, 1);
            metadata_checksum(
                &geometry,
                &mut encoded.blocks[block].bytes[..1024],
                checksum_at,
            );
            assert!(
                preparation(&geometry, &r, |logical, out| {
                    let found = encoded
                        .blocks
                        .iter()
                        .find(|b| b.logical == logical)
                        .unwrap();
                    out.copy_from_slice(&found.bytes[..out.len()]);
                    Ok(())
                })
                .is_err()
            );
            put32(&mut encoded.blocks[block].bytes, at, 0);
            metadata_checksum(
                &geometry,
                &mut encoded.blocks[block].bytes[..1024],
                checksum_at,
            );
        }
        // Recomputing the native descriptor CRC cannot authorize a wrong capsule version.
        put32(&mut encoded.blocks[0].bytes, 112, 2);
        metadata_checksum(&geometry, &mut encoded.blocks[0].bytes[..1024], 1020);
        assert!(
            preparation(&geometry, &r, |logical, out| {
                let found = encoded
                    .blocks
                    .iter()
                    .find(|b| b.logical == logical)
                    .unwrap();
                out.copy_from_slice(&found.bytes[..out.len()]);
                Ok(())
            })
            .is_err()
        );
        drop(encoded);
        assert_eq!(r.memory.used(), 0);
    }
}
