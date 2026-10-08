//! Strict immutable ext profiles with indexed classic or extent maps and byte names.
//! Unknown features and recovery-required states fail closed; ownership audits are explicit.
use crate::{
    fs_core::{self, FileRead, NativeName, ObjectId, Reservation, Resources},
    fs_file::{ExtentFile, ExtentKind, FileExtent},
    storage::Storage,
};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
#[path = "fs_ext_checksum.rs"]
mod checksum;
// Modern metadata validation is shared by immutable reads and explicit audits.
#[path = "fs_ext_hash.rs"]
mod dir_hash;
#[path = "fs_ext_extent.rs"]
mod extent;
#[path = "fs_ext_directory.rs"]
mod indexed_directory;
#[path = "fs_ext_journal.rs"]
mod journal;
// Native transaction codec is staged independently before owned-session wiring.
#[path = "fs_ext_integrity.rs"]
mod integrity;
#[cfg(test)]
#[path = "fs_ext_jbd.rs"]
mod jbd;
#[path = "fs_ext_metadata.rs"]
mod metadata;
#[path = "fs_ext_modern.rs"]
mod modern;
#[path = "fs_ext_resize.rs"]
mod resize;
#[path = "fs_ext_xattr.rs"]
mod xattr;
use virtdisk::{DiskView, ReadAt};
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
// Only index construction uses this source. Returned files retain the original
// source, so payload reads neither populate this cache nor serialize on its lock.
const DEFAULT_METADATA_CACHE_BLOCKS: usize = 64;
const MAX_METADATA_CACHE_BLOCKS: usize = 4096;
struct CachedBlock {
    number: u64,
    used: u64,
    bytes: Vec<u8>,
}
struct MetadataState {
    blocks: Vec<CachedBlock>,
    clock: u64,
}
struct MetadataSource {
    source: Arc<dyn ReadAt>,
    block_bytes: usize,
    capacity: usize,
    resources: Resources,
    state: Mutex<MetadataState>,
    _reservation: Reservation,
}
impl MetadataSource {
    fn new(
        source: Arc<dyn ReadAt>,
        block_bytes: usize,
        capacity: usize,
        resources: &Resources,
    ) -> io::Result<Self> {
        resources.cancellation.check().map_err(io::Error::other)?;
        // Includes buffers, slot vector and conservative allocator bookkeeping.
        let charge = capacity
            .checked_mul(block_bytes + std::mem::size_of::<CachedBlock>() + 64)
            .ok_or_else(|| invalid("ext metadata cache accounting overflow"))?;
        let reservation = resources
            .memory
            .reserve(charge as u64)
            .map_err(io::Error::other)?;
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        Ok(Self {
            source,
            block_bytes,
            capacity,
            resources: resources.clone(),
            state: Mutex::new(MetadataState { blocks, clock: 0 }),
            _reservation: reservation,
        })
    }
}
impl ReadAt for MetadataSource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        let end = offset
            .checked_add(out.len() as u64)
            .filter(|end| *end <= self.source.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("ext metadata cache poisoned"))?;
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        let mut position = offset;
        while position < end {
            self.resources
                .cancellation
                .check()
                .map_err(io::Error::other)?;
            let number = position / self.block_bytes as u64;
            state.clock = state
                .clock
                .checked_add(1)
                .ok_or_else(|| invalid("ext cache work overflow"))?;
            let used = state.clock;
            let slot = if let Some(slot) = state.blocks.iter().position(|b| b.number == number) {
                slot
            } else {
                // Do not publish failed reads; a failed refill invalidates that
                // slot before the backend can partially overwrite its buffer.
                let mut block = if state.blocks.len() == self.capacity {
                    let slot = state
                        .blocks
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, b)| b.used)
                        .map(|(i, _)| i)
                        .unwrap();
                    state.blocks.swap_remove(slot)
                } else {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(self.block_bytes)
                        .map_err(io::Error::other)?;
                    bytes.resize(self.block_bytes, 0);
                    CachedBlock {
                        number,
                        used,
                        bytes,
                    }
                };
                self.source
                    .read_exact_at(number * self.block_bytes as u64, &mut block.bytes)?;
                block.number = number;
                block.used = used;
                state.blocks.push(block);
                state.blocks.len() - 1
            };
            state.blocks[slot].used = used;
            let within = (position % self.block_bytes as u64) as usize;
            let count = (self.block_bytes - within).min((end - position) as usize);
            let done = (position - offset) as usize;
            out[done..done + count]
                .copy_from_slice(&state.blocks[slot].bytes[within..within + count]);
            position += count as u64;
        }
        Ok(())
    }
}
/// Checked geometry of a supported immutable ext profile.
#[derive(Clone, Debug)]
pub struct ExtGeometry {
    pub(crate) blocks: u32,
    pub(crate) inodes: u32,
    pub(crate) block_size: u32,
    pub(crate) first: u32,
    pub(crate) blocks_per_group: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) inode_size: u16,
    pub(crate) minimum_extra_size: u16,
    pub(crate) groups: u32,
    pub(crate) filetype: bool,
    pub(crate) sparse_super: bool,
    pub(crate) extent_profile: bool,
    pub(crate) has_journal: bool,
    pub(crate) journal_inode: u32,
    pub(crate) uuid: [u8; 16],
    pub(crate) modern: Option<Arc<modern::ModernProof>>,
}
impl ExtGeometry {
    /// Whether geometry belongs to the classic profile accepted by owned editing.
    pub fn is_classic(&self) -> bool {
        if self.modern.is_some() {
            return false;
        }
        self.inode_size == 128 && !self.extent_profile && !self.has_journal
    }
    /// Filesystem block byte size.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    /// Whether the filesystem explicitly permits ext4 extent-mapped inodes.
    pub fn uses_extents(&self) -> bool {
        self.extent_profile
    }
    /// Whether the immutable profile validates native ext4 metadata CRC32C encodings.
    pub fn has_metadata_checksums(&self) -> bool {
        self.modern
            .as_ref()
            .is_some_and(|p| p.checksums.has_metadata())
    }
    /// Whether an explicitly validated inactive internal JBD/JBD2 journal is present.
    pub fn has_journal(&self) -> bool {
        self.has_journal
    }
    /// Declared number of blocks.
    pub fn blocks(&self) -> u32 {
        self.blocks
    }
}
/// An immutable caller-stabilized bounded ext volume.
pub struct ExtVolume {
    decoder: ExtDecoder<Arc<dyn ReadAt>>,
}
pub(crate) trait ExtDecodeRead {
    fn decode_len(&self) -> io::Result<u64>;
    fn decode_read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()>;
}
impl ExtDecodeRead for Arc<dyn ReadAt> {
    fn decode_len(&self) -> io::Result<u64> {
        Ok(self.as_ref().len())
    }
    fn decode_read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.as_ref().read_exact_at(offset, out)
    }
}
impl ExtDecodeRead for &dyn Storage {
    fn decode_len(&self) -> io::Result<u64> {
        Storage::len(*self)
    }
    fn decode_read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        Storage::read_exact_at(*self, offset, out)
    }
}
pub(crate) struct ExtDecoder<R> {
    source_id: u128,
    source: R,
    geometry: ExtGeometry,
}
pub(crate) type ExtStorageDecoder<'a> = ExtDecoder<&'a dyn Storage>;
pub(crate) struct ExtDecodedFileMap {
    pub(crate) identity: ObjectId,
    pub(crate) length: u64,
    pub(crate) extents: Vec<FileExtent>,
    pub(crate) reservation: Reservation,
}

/// Decoded classic inode; no preservation or allocation ownership claim.
#[derive(Clone, Debug)]
pub struct ExtInode {
    number: u32,
    mode: u16,
    length: u64,
    generation: u32,
    pointers: [u32; 15],
    raw: [u8; 128],
    extra: [u8; 128],
    extra_size: u16,
}
impl ExtInode {
    pub(crate) fn decode_raw(number: u32, b: [u8; 128]) -> io::Result<Self> {
        Self::decode_profile(number, b, false)
    }
    fn decode_profile(number: u32, b: [u8; 128], extent_profile: bool) -> io::Result<Self> {
        if u32le(&b, 20) != 0 || u16le(&b, 26) == 0 {
            return Err(invalid("ext deleted/unlinked inode"));
        }
        let allowed_flags = if extent_profile { 0x80000 } else { 0 };
        if u32le(&b, 32) & !allowed_flags != 0
            || u32le(&b, 104) != 0
            || u32le(&b, 108) != 0
            || u16le(&b, 118) != 0
        {
            return Err(unsupported("ext inode flags, xattrs or high size"));
        }
        if u32le(&b, 112) != 0 || b[116] != 0 || b[117] != 0 {
            return Err(unsupported("ext obsolete fragment allocation"));
        }
        let mut pointers = [0; 15];
        for (i, p) in pointers.iter_mut().enumerate() {
            *p = u32le(&b, 40 + i * 4);
        }
        Ok(ExtInode {
            number,
            mode: u16le(&b, 0),
            length: u64::from(u32le(&b, 4)),
            generation: u32le(&b, 100),
            pointers,
            raw: b,
            extra: [0; 128],
            extra_size: 0,
        })
    }

    /// Exact Linux-profile 128-byte inode encoding, including ownership and native times.
    pub fn raw_metadata(&self) -> &[u8; 128] {
        &self.raw
    }
    /// Exact declared Linux inode extension, including native epoch/nanosecond fields.
    /// Empty for classic inodes or a zero extra-isize field. Undeclared tail bytes
    /// must be zero; inline extended attributes are outside this profile.
    pub fn raw_extended_metadata(&self) -> &[u8] {
        &self.extra[..usize::from(self.extra_size)]
    }
    pub(crate) fn validate_extra(extra: &[u8; 128]) -> io::Result<u16> {
        let size = u16le(extra, 0);
        if size > 128 || !size.is_multiple_of(4) {
            return Err(invalid("ext inode extra-isize bounds/alignment"));
        }
        if extra[usize::from(size)..].iter().any(|b| *b != 0) {
            return Err(unsupported(
                "ext inode inline xattrs or undeclared extension",
            ));
        }
        for offset in [4, 8, 12, 20] {
            if usize::from(size) >= offset + 4 && u32le(extra, offset) >> 2 >= 1_000_000_000 {
                return Err(invalid("ext inode native nanoseconds out of range"));
            }
        }
        Ok(size)
    }
    /// Linux UID with the low and high 16-bit components combined.
    pub fn uid(&self) -> u32 {
        u32::from(u16le(&self.raw, 2)) | (u32::from(u16le(&self.raw, 120)) << 16)
    }
    /// Linux GID with the low and high 16-bit components combined.
    pub fn gid(&self) -> u32 {
        u32::from(u16le(&self.raw, 24)) | (u32::from(u16le(&self.raw, 122)) << 16)
    }

    /// Native inode number.
    pub fn number(&self) -> u32 {
        self.number
    }
    /// Native Unix mode bits.
    pub fn mode(&self) -> u16 {
        self.mode
    }
    /// Logical byte length.
    pub fn len(&self) -> u64 {
        self.length
    }
    /// Whether logical length is zero.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Native inode generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}
impl<R: ExtDecodeRead> ExtDecoder<R> {
    /// Validate superblock and every group descriptor. Unknown features fail closed.
    fn open_reader(
        source: R,
        source_id: u128,
        resources: &Resources,
        immutable_profile: bool,
    ) -> io::Result<Self> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let mut sb = [0; 1024];
        source.decode_read_exact_at(1024, &mut sb)?;
        if u16le(&sb, 56) != 0xef53 {
            return Err(invalid("ext superblock magic"));
        }
        if u16le(&sb, 58) != 1 {
            return Err(unsupported("ext filesystem needs recovery or is not clean"));
        }
        let revision = u32le(&sb, 76);
        if revision > 1 || u32le(&sb, 72) != 0 {
            return Err(unsupported("ext revision or non-Linux inode encoding"));
        }
        let (compat, incompat, ro) = if revision == 1 {
            (u32le(&sb, 92), u32le(&sb, 96), u32le(&sb, 100))
        } else {
            (0, 0, 0)
        };
        if incompat & 4 != 0 {
            return Err(unsupported("ext journal requires replay"));
        }
        if ro & 0x400 != 0 {
            if !immutable_profile {
                return Err(unsupported("owned ext2 decoder requires classic profile"));
            }
            return Self::open_modern(source, source_id, resources);
        }
        if compat & !4 != 0 || incompat & !(2 | 0x40) != 0 || ro & !(3 | 0x40) != 0 {
            return Err(unsupported(
                "ext feature profile: journal, xattrs, checksums, 64-bit groups or unknown feature",
            ));
        }
        if !immutable_profile && (compat & 4 != 0 || incompat & 0x40 != 0 || ro & 0x40 != 0) {
            return Err(unsupported("owned ext2 decoder requires classic profile"));
        }
        let journal_inode = u32le(&sb, 224);
        if compat & 4 != 0
            && (journal_inode != 8
                || u32le(&sb, 228) != 0
                || sb[208..224].iter().any(|v| *v != 0)
                || u32le(&sb, 232) != 0)
        {
            return Err(unsupported(
                "ext external/nonstandard journal or orphan recovery state",
            ));
        }
        let log = u32le(&sb, 24);
        if log > 2 || u32le(&sb, 28) != log {
            return Err(unsupported("ext block/fragment geometry"));
        }
        let block_size = 1024u32 << log;
        let blocks = u32le(&sb, 4);
        let first = u32le(&sb, 20);
        let bpg = u32le(&sb, 32);
        let ipg = u32le(&sb, 40);
        let inodes = u32le(&sb, 0);
        let inode_size = if revision == 0 { 128 } else { u16le(&sb, 88) };
        if !immutable_profile && inode_size != 128 {
            return Err(unsupported(
                "owned ext2 decoder requires classic inode size",
            ));
        }
        if ro & 0x40 != 0 && inode_size != 256 {
            return Err(unsupported(
                "ext extra-isize feature requires extended inode profile",
            ));
        }
        let minimum_extra_size = if inode_size == 256 {
            u16le(&sb, 348)
        } else {
            0
        };
        if inode_size == 256 {
            let desired = u16le(&sb, 350);
            if minimum_extra_size > 128
                || !minimum_extra_size.is_multiple_of(4)
                || desired > 128
                || !desired.is_multiple_of(4)
                || desired < minimum_extra_size
            {
                return Err(invalid("ext superblock inode extension bounds"));
            }
        }
        if first != u32::from(block_size == 1024)
            || blocks <= first
            || bpg == 0
            || ipg == 0
            || bpg > block_size * 8
            || ipg > block_size * 8
            || inodes < 2
            || !matches!(inode_size, 128 | 256)
            || u32le(&sb, 36) != bpg
        {
            return Err(invalid("ext geometry or inode size"));
        }
        let groups = (blocks - first).div_ceil(bpg);
        if inodes.div_ceil(ipg) != groups {
            return Err(invalid("ext inode/block group counts disagree"));
        }
        let bytes = u64::from(blocks) * u64::from(block_size);
        if bytes > source.decode_len()? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let volume = Self {
            source_id,
            source,
            geometry: ExtGeometry {
                blocks,
                inodes,
                block_size,
                first,
                blocks_per_group: bpg,
                inodes_per_group: ipg,
                inode_size,
                minimum_extra_size,
                groups,
                filetype: incompat & 2 != 0,
                sparse_super: ro & 1 != 0,
                extent_profile: incompat & 0x40 != 0,
                has_journal: compat & 4 != 0,
                journal_inode,
                uuid: sb[104..120].try_into().unwrap(),
                modern: None,
            },
        };
        if u64::from(groups) * 32 > u64::from(bpg) * u64::from(block_size) {
            return Err(invalid("ext descriptor table exceeds first group"));
        }
        for group in 0..groups {
            resources.cancellation.check().map_err(io::Error::other)?;
            volume.group(group)?;
        }
        volume.validate_journal(resources)?;
        Ok(volume)
    }
    pub(crate) fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or_else(|| invalid("ext read offset overflow"))?;
        if end > u64::from(self.geometry.blocks) * u64::from(self.geometry.block_size) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.source.decode_read_exact_at(offset, out)
    }
    /// Validated geometry.
    pub fn geometry(&self) -> &ExtGeometry {
        &self.geometry
    }
    /// Source-scoped identity for an allocated, supported inode.
    pub fn identity(&self, number: u32, resources: &Resources) -> io::Result<ObjectId> {
        let inode = self.inode(number, resources)?;
        self.inode_identity(&inode)
    }
    fn inode_identity(&self, inode: &ExtInode) -> io::Result<ObjectId> {
        let mut native = Vec::new();
        native.try_reserve_exact(4).map_err(io::Error::other)?;
        native.extend_from_slice(&inode.number.to_le_bytes());
        Ok(ObjectId {
            source: self.source_id,
            generation: u64::from(inode.generation),
            native,
        })
    }
    pub(crate) fn reserved_end(&self, group: u32) -> u64 {
        let g = &self.geometry;
        let power = |base: u32| {
            let mut n = group;
            while n > 1 && n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        let backup = !g.sparse_super || group <= 1 || power(3) || power(5) || power(7);
        if let Some(proof) = &g.modern {
            return u64::from(g.first)
                + u64::from(group) * u64::from(g.blocks_per_group)
                + if backup {
                    1 + (u64::from(g.groups) * u64::from(proof.descriptor_size))
                        .div_ceil(u64::from(g.block_size))
                        + u64::from(proof.reserved_gdt)
                } else {
                    0
                };
        }
        u64::from(g.first)
            + u64::from(group) * u64::from(g.blocks_per_group)
            + if backup {
                1 + (u64::from(g.groups) * 32).div_ceil(u64::from(g.block_size))
            } else {
                0
            }
    }
    pub(crate) fn group(&self, group: u32) -> io::Result<[u32; 3]> {
        if group >= self.geometry.groups {
            return Err(invalid("ext group index"));
        }
        let g = &self.geometry;
        if let Some(proof) = &g.modern {
            let d = &proof.descriptors[group as usize];
            return Ok([u32le(d, 0), u32le(d, 4), u32le(d, 8)]);
        }
        let mut d = [0; 32];
        self.read_exact_at(
            u64::from(g.first + 1) * u64::from(g.block_size) + u64::from(group) * 32,
            &mut d,
        )?;
        let result = [u32le(&d, 0), u32le(&d, 4), u32le(&d, 8)];
        let start = g.first + group * g.blocks_per_group;
        let end = (u64::from(start) + u64::from(g.blocks_per_group)).min(u64::from(g.blocks));
        let table_blocks = (u64::from(g.inodes_per_group) * u64::from(g.inode_size))
            .div_ceil(u64::from(g.block_size));
        if result
            .iter()
            .any(|b| *b < start || u64::from(*b) < self.reserved_end(group) || u64::from(*b) >= end)
            || result[0] == result[1]
            || u64::from(result[2]) + table_blocks > end
            || result[..2].iter().any(|b| {
                u64::from(*b) >= u64::from(result[2])
                    && u64::from(*b) < u64::from(result[2]) + table_blocks
            })
        {
            return Err(invalid("ext group metadata ranges overlap or escape group"));
        }
        Ok(result)
    }
    fn allocated(&self, number: u32, inode: bool) -> io::Result<()> {
        let g = &self.geometry;
        if let Some(proof) = &g.modern {
            return if proof.is_allocated(number, inode) {
                Ok(())
            } else {
                Err(invalid("ext reference to unallocated object"))
            };
        }
        let (index, per, bitmap) = if inode {
            (
                number.checked_sub(1).ok_or_else(|| invalid("zero inode"))?,
                g.inodes_per_group,
                1,
            )
        } else {
            (
                number
                    .checked_sub(g.first)
                    .ok_or_else(|| invalid("reserved block"))?,
                g.blocks_per_group,
                0,
            )
        };
        let descriptor = self.group(index / per)?;
        let bit = index % per;
        let mut byte = [0];
        self.read_exact_at(
            u64::from(descriptor[bitmap]) * u64::from(g.block_size) + u64::from(bit / 8),
            &mut byte,
        )?;
        if byte[0] & (1 << (bit % 8)) == 0 {
            return Err(invalid("ext reference to unallocated object"));
        }
        Ok(())
    }
    /// Inspect an allocated inode, rejecting unsupported per-inode states.
    pub fn inode(&self, number: u32, resources: &Resources) -> io::Result<ExtInode> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let g = &self.geometry;
        if number == 0 || number > g.inodes {
            return Err(invalid("ext inode out of bounds"));
        }
        self.allocated(number, true)?;
        let d = self.group((number - 1) / g.inodes_per_group)?;
        let mut bytes = [0; 256];
        self.read_exact_at(
            u64::from(d[2]) * u64::from(g.block_size)
                + u64::from((number - 1) % g.inodes_per_group) * u64::from(g.inode_size),
            &mut bytes[..usize::from(g.inode_size)],
        )?;
        if let Some(proof) = &g.modern {
            return self.modern_inode(number, bytes, proof, resources);
        }
        let mut inode =
            ExtInode::decode_profile(number, bytes[..128].try_into().unwrap(), g.extent_profile)?;
        if g.inode_size == 256 {
            inode.extra.copy_from_slice(&bytes[128..]);
            inode.extra_size = ExtInode::validate_extra(&inode.extra)?;
            if inode.extra_size < g.minimum_extra_size {
                return Err(invalid("ext inode extension below filesystem minimum"));
            }
        }
        Ok(inode)
    }
    fn symlink_error(error: io::Error) -> fs_core::Error {
        if let Some(cause) = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<fs_core::Error>())
        {
            return fs_core::Error::new(cause.kind, cause.context.clone());
        }
        let kind = match error.kind() {
            io::ErrorKind::InvalidData => fs_core::ErrorKind::InvalidData,
            io::ErrorKind::Unsupported => fs_core::ErrorKind::Unsupported,
            _ => return fs_core::Error::io("ext symlink access", error),
        };
        fs_core::Error::new(kind, error.to_string())
    }
    /// Read an unfollowed native symlink target under shared memory and block ceilings.
    /// Fast symlinks use i_block only when i_blocks is zero; external xattrs remain gated.
    pub fn symlink_target(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<fs_core::Budgeted<Vec<u8>>> {
        let inode = self.inode(number, resources)?;
        if inode.mode & 0xf000 != 0xa000 {
            return Err(unsupported("ext inode is not symlink"));
        }
        let length = usize::try_from(inode.length).map_err(io::Error::other)?;
        if length == 0 {
            return Err(invalid("ext empty symlink target"));
        }
        if inode.length.div_ceil(u64::from(self.geometry.block_size)) > max_blocks as u64 {
            return Err(io::Error::other(fs_core::Error::new(
                fs_core::ErrorKind::BudgetExhausted,
                "ext symlink block cap",
            )));
        }
        fs_core::Budgeted::try_new(&resources.memory, inode.length, || {
            let mut target = Vec::new();
            target.try_reserve_exact(length).map_err(|e| {
                fs_core::Error::new(fs_core::ErrorKind::BudgetExhausted, e.to_string())
            })?;
            target.resize(length, 0);
            let xattr_sectors = if self.geometry.modern.is_some() && u32le(&inode.raw, 104) != 0 {
                self.geometry.block_size / 512
            } else {
                0
            };
            if u32le(&inode.raw, 28) == xattr_sectors {
                if length >= 60 {
                    return Err(fs_core::Error::new(
                        fs_core::ErrorKind::InvalidData,
                        "ext fast symlink exceeds terminated inode storage",
                    ));
                }
                target.copy_from_slice(&inode.raw[40..40 + length]);
                if inode.raw[40 + length] != 0 {
                    return Err(fs_core::Error::new(
                        fs_core::ErrorKind::InvalidData,
                        "ext fast symlink lacks terminator",
                    ));
                }
            } else {
                let file = self
                    .file_map(number, max_blocks, resources, true)
                    .map_err(Self::symlink_error)?;
                self.read_map(&file, 0, &mut target, resources)
                    .map_err(Self::symlink_error)?;
            }
            if target.contains(&0) {
                return Err(fs_core::Error::new(
                    fs_core::ErrorKind::InvalidData,
                    "ext symlink target contains NUL",
                ));
            }
            Ok(target)
        })
        .map_err(io::Error::other)
    }
    fn block(&self, number: u32) -> io::Result<()> {
        let g = &self.geometry;
        if number <= g.first || number >= g.blocks {
            return Err(invalid("ext data block out of bounds"));
        }
        if let Some(proof) = &g.modern {
            if proof.metadata_block(number) {
                return Err(invalid("ext payload aliases global group metadata"));
            }
            return self.allocated(number, false);
        }
        let group = (number - g.first) / g.blocks_per_group;
        if u64::from(number) < self.reserved_end(group) {
            return Err(invalid("ext payload aliases superblock/descriptors"));
        }
        let d = self.group(group)?;
        let table = (u64::from(g.inodes_per_group) * u64::from(g.inode_size))
            .div_ceil(u64::from(g.block_size));
        if d[..2].contains(&number)
            || (number >= d[2] && u64::from(number) < u64::from(d[2]) + table)
        {
            return Err(invalid("ext payload aliases group metadata"));
        }
        self.allocated(number, false)
    }
    fn pointer(&self, block: u32, index: u64, path: &mut Vec<u32>) -> io::Result<u32> {
        self.block(block)?;
        if path.contains(&block) {
            return Err(invalid("ext indirect cycle"));
        }
        path.push(block);
        let mut b = [0; 4];
        self.read_exact_at(
            u64::from(block) * u64::from(self.geometry.block_size) + index * 4,
            &mut b,
        )?;
        Ok(u32le(&b, 0))
    }
    pub(crate) fn file_map(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
        symlink: bool,
    ) -> io::Result<ExtDecodedFileMap> {
        let inode = self.inode(number, resources)?;
        if !matches!(inode.mode & 0xf000, 0x8000 | 0x4000)
            && !(symlink && inode.mode & 0xf000 == 0xa000)
        {
            return Err(unsupported("ext stream kind (including symlink)"));
        }
        if u32le(&inode.raw, 32) & 0x80000 != 0 {
            let decoded = self.extent_map(&inode, max_blocks, resources)?;
            // The decoder's maximum-capacity buffers are temporary validation
            // workspace. Retained files charge only their compact logical map.
            let charge = (decoded.map.len() as u64)
                .checked_mul(std::mem::size_of::<FileExtent>() as u64)
                .and_then(|n| n.checked_add(512))
                .ok_or_else(|| io::Error::other("ext retained map accounting overflow"))?;
            let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
            let mut extents = Vec::new();
            extents
                .try_reserve_exact(decoded.map.len())
                .map_err(io::Error::other)?;
            extents.extend_from_slice(&decoded.map);
            drop(decoded.map);
            drop(decoded.allocations);
            drop(decoded.metadata);
            drop(decoded.reservation);
            return Ok(ExtDecodedFileMap {
                identity: self.inode_identity(&inode)?,
                length: inode.length,
                extents,
                reservation,
            });
        }
        let bs = u64::from(self.geometry.block_size);
        let count = inode.length.div_ceil(bs);
        if count > max_blocks as u64 {
            return Err(io::Error::other(fs_core::Error::new(
                fs_core::ErrorKind::BudgetExhausted,
                "ext file block budget",
            )));
        }
        let charge = count
            .checked_mul((3 * std::mem::size_of::<FileExtent>() + 32) as u64)
            .and_then(|n| n.checked_add(68))
            .ok_or_else(|| io::Error::other("ext map accounting overflow"))?;
        let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(count as usize)
            .map_err(io::Error::other)?;
        let mut data = Vec::new();
        data.try_reserve_exact(count as usize)
            .map_err(io::Error::other)?;
        let mut indirect = Vec::new();
        indirect
            .try_reserve_exact(count as usize * 3)
            .map_err(io::Error::other)?;
        let mut path = Vec::new();
        path.try_reserve_exact(3).map_err(io::Error::other)?;
        let n = bs / 4;
        for logical in 0..count {
            resources.cancellation.check().map_err(io::Error::other)?;
            path.clear();
            let mut block;
            if logical < 12 {
                block = inode.pointers[logical as usize];
            } else {
                let mut index = logical - 12;
                let depth = if index < n {
                    1
                } else {
                    index -= n;
                    if index < n * n {
                        2
                    } else {
                        index -= n * n;
                        3
                    }
                };
                if index >= n.pow(depth) {
                    return Err(invalid("ext file exceeds classic mapping capacity"));
                }
                block = inode.pointers[11 + depth as usize];
                for level in (0..depth).rev() {
                    if block == 0 {
                        break;
                    }
                    let stride = n.pow(level);
                    block = self.pointer(block, index / stride, &mut path)?;
                    index %= stride;
                }
            }
            if block != 0 {
                self.block(block)?;
                if path.contains(&block) {
                    return Err(invalid("ext data aliases indirect metadata"));
                }
                data.push(block);
            }
            indirect.extend_from_slice(&path);
            extents.push(FileExtent {
                offset: logical * bs,
                length: (inode.length - logical * bs).min(bs),
                kind: if block == 0 {
                    ExtentKind::Hole
                } else {
                    ExtentKind::Data(u64::from(block) * bs)
                },
            });
        }
        indirect.sort_unstable();
        indirect.dedup();
        if self.geometry.modern.is_some() {
            let xattr = u32le(&inode.raw, 104);
            if xattr != 0 && (data.contains(&xattr) || indirect.binary_search(&xattr).is_ok()) {
                return Err(invalid("ext inode map aliases its external xattrs"));
            }
        }
        if data.iter().any(|b| indirect.binary_search(b).is_ok()) {
            return Err(invalid("ext data aliases indirect metadata"));
        }
        data.sort_unstable();
        if data.windows(2).any(|w| w[0] == w[1]) {
            return Err(invalid("ext duplicate file data block"));
        }
        Ok(ExtDecodedFileMap {
            identity: self.inode_identity(&inode)?,
            length: inode.length,
            extents,
            reservation,
        })
    }
    /// Read a bounded whole directory, preserving non-UTF-8 names and inode hard links.
    pub fn directory(
        &self,
        number: u32,
        max_blocks: usize,
        max_entries: usize,
        resources: &Resources,
    ) -> io::Result<ExtDirectory> {
        self.directory_inner(number, max_blocks, max_entries, resources, true)
    }
    pub(crate) fn directory_for_audit(
        &self,
        number: u32,
        max_blocks: usize,
        max_entries: usize,
        resources: &Resources,
    ) -> io::Result<ExtDirectory> {
        self.directory_inner(number, max_blocks, max_entries, resources, false)
    }
    fn directory_inner(
        &self,
        number: u32,
        max_blocks: usize,
        max_entries: usize,
        resources: &Resources,
        validate_children: bool,
    ) -> io::Result<ExtDirectory> {
        let inode = self.inode(number, resources)?;
        if inode.mode & 0xf000 != 0x4000 {
            return Err(invalid("ext object is not directory"));
        }
        let file = self.file_map(number, max_blocks, resources, false)?;
        let bs = self.geometry.block_size as usize;
        if !file.length.is_multiple_of(bs as u64) {
            return Err(invalid("ext directory partial block"));
        }
        let index = if let Some(proof) = &self.geometry.modern {
            if u32le(&inode.raw, 32) & 0x1000 != 0 {
                Some(indexed_directory::validate(
                    &proof.checksums,
                    indexed_directory::IndexOptions {
                        inode: number,
                        generation: inode.generation,
                        block_size: bs,
                        logical_blocks: (file.length / bs as u64) as usize,
                        maximum_entries: max_entries,
                        hash_seed: proof.hash_seed,
                        unsigned_hash: proof.unsigned_hash,
                    },
                    resources,
                    |logical, dst| {
                        if self.read_map(&file, logical as u64 * bs as u64, dst, resources)?
                            != dst.len()
                        {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        Ok(())
                    },
                )?)
            } else {
                None
            }
        } else {
            None
        };
        let charge = (max_entries as u64)
            .checked_mul((std::mem::size_of::<ExtEntry>() + 255) as u64)
            .ok_or_else(|| io::Error::other("ext directory accounting overflow"))?;
        let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
        let _scratch = resources
            .memory
            .reserve(bs as u64)
            .map_err(io::Error::other)?;
        let mut block = Vec::new();
        block.try_reserve_exact(bs).map_err(io::Error::other)?;
        block.resize(bs, 0);
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(max_entries)
            .map_err(io::Error::other)?;
        for offset in (0..file.length).step_by(bs) {
            if index
                .as_ref()
                .is_some_and(|index| index.nodes[(offset / bs as u64) as usize].kind == 2)
            {
                continue;
            }
            self.read_map(&file, offset, &mut block, resources)?;
            let end = bs;
            let end = if let Some(proof) = &self.geometry.modern {
                if index.is_some() && offset == 0 {
                    bs
                } else {
                    proof
                        .checksums
                        .directory_leaf(number, inode.generation, &block)?
                }
            } else {
                end
            };
            let mut p = 0;
            while p < end {
                resources.cancellation.check().map_err(io::Error::other)?;
                if end - p < 8 {
                    return Err(invalid("ext directory header truncated"));
                }
                let ino = u32le(&block, p);
                let record = u16le(&block, p + 4) as usize;
                let length = if self.geometry.filetype {
                    block[p + 6] as usize
                } else {
                    u16le(&block, p + 6) as usize
                };
                if record < 8
                    || !record.is_multiple_of(4)
                    || record > end - p
                    || length > 255
                    || length > record - 8
                {
                    return Err(invalid("ext directory record geometry"));
                }
                if ino != 0 {
                    if length == 0
                        || block[p + 8..p + 8 + length]
                            .iter()
                            .any(|c| *c == 0 || *c == b'/')
                    {
                        return Err(invalid("ext invalid native name"));
                    }
                    if validate_children {
                        if self.geometry.modern.as_ref().is_some_and(|proof| {
                            proof.orphan_inode != 0 && ino == proof.orphan_inode
                        }) {
                            return Err(invalid("ext namespace aliases hidden orphan file"));
                        }
                        let child = self.inode(ino, resources)?;
                        if self.geometry.filetype {
                            let expected = match child.mode & 0xf000 {
                                0x8000 => 1,
                                0x4000 => 2,
                                0x2000 => 3,
                                0x6000 => 4,
                                0x1000 => 5,
                                0xc000 => 6,
                                0xa000 => 7,
                                _ => return Err(invalid("ext inode mode")),
                            };
                            if block[p + 7] != 0 && block[p + 7] != expected {
                                return Err(invalid("ext directory type disagrees with inode"));
                            }
                        }
                    }
                    if entries.len() == max_entries {
                        return Err(io::Error::other(fs_core::Error::new(
                            fs_core::ErrorKind::BudgetExhausted,
                            "ext directory entry budget",
                        )));
                    }
                    let mut name = Vec::new();
                    name.try_reserve_exact(length).map_err(io::Error::other)?;
                    name.extend_from_slice(&block[p + 8..p + 8 + length]);
                    if entries
                        .iter()
                        .any(|entry: &ExtEntry| matches!(&entry.name, NativeName::Bytes(bytes) if bytes == &name))
                    {
                        return Err(invalid("ext duplicate directory name"));
                    }
                    entries.push(ExtEntry {
                        inode: ino,
                        file_type: if self.geometry.filetype {
                            Some(block[p + 7])
                        } else {
                            None
                        },
                        name: NativeName::Bytes(name),
                    });
                }
                p += record;
            }
        }
        Ok(ExtDirectory {
            entries,
            _reservation: reservation,
        })
    }

    pub(crate) fn read_map(
        &self,
        map: &ExtDecodedFileMap,
        offset: u64,
        out: &mut [u8],
        resources: &Resources,
    ) -> io::Result<usize> {
        read_indexed_map(map, offset, out, resources, |at, bytes| {
            self.read_exact_at(at, bytes)
        })
    }
}

/// Read retained indexed ext payload with a checked positional backend.
/// Callers retain source/generation authority; this grants no backend capability.
pub(crate) fn read_indexed_map(
    map: &ExtDecodedFileMap,
    offset: u64,
    out: &mut [u8],
    resources: &Resources,
    mut read_exact_at: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<usize> {
    resources.cancellation.check().map_err(io::Error::other)?;
    if offset >= map.length || out.is_empty() {
        return Ok(0);
    }
    let count = (map.length - offset).min(out.len() as u64) as usize;
    let mut done = 0;
    let first = map
        .extents
        .partition_point(|extent| extent.offset + extent.length <= offset);
    for extent in &map.extents[first..] {
        resources.cancellation.check().map_err(io::Error::other)?;
        let at = offset + done as u64;
        if at < extent.offset || at >= extent.offset + extent.length {
            continue;
        }
        let within = at - extent.offset;
        let n = (extent.length - within).min((count - done) as u64) as usize;
        match extent.kind {
            ExtentKind::Hole | ExtentKind::Unwritten => out[done..done + n].fill(0),
            ExtentKind::Data(physical) => {
                read_exact_at(physical + within, &mut out[done..done + n])?
            }
        }
        done += n;
        if done == count {
            return Ok(done);
        }
    }
    Err(invalid("ext map does not cover logical range"))
}

impl ExtDecoder<Arc<dyn ReadAt>> {
    /// Index classic direct/single/double/triple indirect mappings once, with a block work limit.
    ///
    /// Construction uses at most 64 budgeted metadata blocks with bounded LRU
    /// replacement. Its reservation is refunded when indexing ends, including
    /// errors. Payload reads use the uncached source and retained file map; they
    /// do not take the metadata-cache lock. Inputs must remain immutable.
    pub fn open_file(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<ExtFile> {
        self.open_file_with_cache(number, max_blocks, DEFAULT_METADATA_CACHE_BLOCKS, resources)
    }
    /// Index a file with an explicit operation-local metadata cache block cap.
    ///
    /// `metadata_cache_blocks` must be between zero and 4096 inclusive. Zero
    /// disables caching and its reservation, allowing low-memory indexing at
    /// the cost of repeated metadata reads. Nonzero caps reserve their entire
    /// conservative capacity before allocation; bounded LRU eviction never
    /// relaxes allocation or mapping validation. The cache lease is refunded
    /// when construction returns, including errors. Returned payload handles
    /// keep only the original immutable source and indexed-map reservation.
    pub fn open_file_with_cache(
        &self,
        number: u32,
        max_blocks: usize,
        metadata_cache_blocks: usize,
        resources: &Resources,
    ) -> io::Result<ExtFile> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if metadata_cache_blocks > MAX_METADATA_CACHE_BLOCKS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ext metadata cache cap exceeds 4096 blocks",
            ));
        }
        if metadata_cache_blocks == 0 {
            return self.index_file(number, max_blocks, resources, self.source.clone(), false);
        }
        let cached = Self {
            source_id: self.source_id,
            source: Arc::new(MetadataSource::new(
                self.source.clone(),
                self.geometry.block_size as usize,
                metadata_cache_blocks,
                resources,
            )?),
            geometry: self.geometry.clone(),
        };
        cached.index_file(number, max_blocks, resources, self.source.clone(), false)
    }

    fn index_file(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
        payload_source: Arc<dyn ReadAt>,
        symlink: bool,
    ) -> io::Result<ExtFile> {
        let map = self.file_map(number, max_blocks, resources, symlink)?;
        Ok(ExtFile {
            identity: map.identity,
            file: ExtentFile::new(payload_source, map.length, map.extents, max_blocks)?,
            _reservation: map.reservation,
        })
    }
}
impl<'a> ExtDecoder<&'a dyn Storage> {
    pub(crate) fn open_storage(
        source: &'a dyn Storage,
        scope: u128,
        resources: &Resources,
    ) -> io::Result<Self> {
        let decoder = Self::open_reader(source, scope, resources, false)?;
        if decoder.geometry.extent_profile || decoder.geometry.has_journal {
            return Err(unsupported("owned ext2 decoder requires classic profile"));
        }
        Ok(decoder)
    }
}
impl ExtVolume {
    /// Validate superblock and every group descriptor. Unknown features fail closed.
    pub fn open(source: Arc<dyn ReadAt>, resources: &Resources) -> io::Result<Self> {
        let scope = (2u128 << 64)
            | u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| {
                        io::Error::other(fs_core::Error::new(
                            fs_core::ErrorKind::BudgetExhausted,
                            "ext source identity space exhausted",
                        ))
                    })?,
            );
        let mut decoder = ExtDecoder::open_reader(source, scope, resources, true)?;
        let bytes = u64::from(decoder.geometry.blocks) * u64::from(decoder.geometry.block_size);
        decoder.source = Arc::new(DiskView::new(decoder.source, 0, bytes)?);
        Ok(Self { decoder })
    }
    pub(crate) fn decoder(&self) -> &ExtDecoder<Arc<dyn ReadAt>> {
        &self.decoder
    }
    /// Validated geometry.
    pub fn geometry(&self) -> &ExtGeometry {
        self.decoder.geometry()
    }
    /// Source-scoped native inode identity.
    pub fn identity(&self, number: u32, resources: &Resources) -> io::Result<ObjectId> {
        self.decoder.identity(number, resources)
    }
    /// Inspect an allocated supported-profile inode.
    pub fn inode(&self, number: u32, resources: &Resources) -> io::Result<ExtInode> {
        self.decoder.inode(number, resources)
    }
    /// Exact native symlink target, without following it.
    pub fn symlink_target(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<fs_core::Budgeted<Vec<u8>>> {
        self.decoder.symlink_target(number, max_blocks, resources)
    }
    /// Index classic file mapping using a bounded operation-local metadata cache.
    pub fn open_file(
        &self,
        number: u32,
        max_blocks: usize,
        resources: &Resources,
    ) -> io::Result<ExtFile> {
        self.decoder.open_file(number, max_blocks, resources)
    }
    /// Index a file with an explicit operation-local metadata cache bound.
    pub fn open_file_with_cache(
        &self,
        number: u32,
        max_blocks: usize,
        metadata_cache_blocks: usize,
        resources: &Resources,
    ) -> io::Result<ExtFile> {
        self.decoder
            .open_file_with_cache(number, max_blocks, metadata_cache_blocks, resources)
    }
    /// Read a bounded directory preserving exact native byte names.
    pub fn directory(
        &self,
        number: u32,
        max_blocks: usize,
        max_entries: usize,
        resources: &Resources,
    ) -> io::Result<ExtDirectory> {
        self.decoder
            .directory(number, max_blocks, max_entries, resources)
    }
}

/// Native directory reference; repeated inode numbers denote hard links.
#[derive(Debug)]
pub struct ExtEntry {
    pub(crate) file_type: Option<u8>,
    /// Referenced native inode.
    pub inode: u32,
    /// Exact native byte name.
    pub name: NativeName,
}
/// Bounded directory inventory retaining its memory charge.
pub struct ExtDirectory {
    entries: Vec<ExtEntry>,
    _reservation: Reservation,
}
impl ExtDirectory {
    /// Borrow native entries including dot entries.
    pub fn entries(&self) -> &[ExtEntry] {
        &self.entries
    }
}
/// Reusable indexed positional ext2 file handle.
pub struct ExtFile {
    identity: ObjectId,
    file: ExtentFile,
    _reservation: Reservation,
}
impl ExtFile {
    /// Logical byte length.
    pub fn len(&self) -> u64 {
        self.file.len()
    }
    /// Whether this file is empty.
    pub fn is_empty(&self) -> bool {
        self.file.is_empty()
    }
    /// Read with cooperative cancellation; backend failures may partially modify output.
    pub fn read_at(&self, offset: u64, out: &mut [u8], resources: &Resources) -> io::Result<usize> {
        resources.cancellation.check().map_err(io::Error::other)?;
        self.file.read_at(offset, out)
    }
    /// Validated coalesced data and hole map.
    pub fn extents(&self) -> &[FileExtent] {
        self.file.extents()
    }
}

impl FileRead for ExtFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(
        &self,
        offset: u64,
        buffer: &mut [u8],
        resources: &Resources,
    ) -> fs_core::Result<usize> {
        resources.cancellation.check()?;
        if offset >= self.file.len() {
            return Ok(0);
        }
        self.file
            .read_at(offset, buffer)
            .map_err(|error| fs_core::Error::io("ext2 indexed read", error))
    }
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(fs_core::LogicalExtent) -> fs_core::Result<()>,
    ) -> fs_core::Result<()> {
        for extent in self.file.extents() {
            resources.cancellation.check()?;
            visitor(fs_core::LogicalExtent {
                offset: extent.offset,
                length: extent.length,
                kind: match extent.kind {
                    ExtentKind::Data(_) => fs_core::ExtentKind::Data,
                    ExtentKind::Hole => fs_core::ExtentKind::Hole,
                    ExtentKind::Unwritten => fs_core::ExtentKind::Unwritten,
                },
            })?;
        }
        Ok(())
    }
}
