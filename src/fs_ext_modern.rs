//! Bounded source-independent ext4 geometry and global metadata exclusions.
//! Metadata geometry proof is retained by immutable decoding; full inode ownership is audited separately.
use super::{ExtDecodeRead, integrity::Integrity, invalid, u16le, u32le, unsupported};
use crate::fs_core::{Error, ErrorKind, Reservation, Resources};
use std::io;

const MAX_GROUPS: usize = 1024;
impl<R: ExtDecodeRead> super::ExtDecoder<R> {
    pub(crate) fn validate_modern_orphan(&self, resources: &Resources) -> io::Result<()> {
        let proof = self.geometry.modern.as_ref().unwrap();
        if proof.orphan_inode == 0 {
            return Ok(());
        }
        let inode = self.inode(proof.orphan_inode, resources)?;
        let bs = u64::from(proof.block_size);
        if inode.mode != 0o100600
            || u16le(&inode.raw, 26) != 1
            || inode.uid() != 0
            || inode.gid() != 0
            || !matches!(u32le(&inode.raw, 32), 0 | 0x80000)
            || u32le(&inode.raw, 104) != 0
            || inode.length == 0
            || !inode.length.is_multiple_of(bs)
            || inode.extra[usize::from(inode.extra_size)..]
                .iter()
                .any(|v| *v != 0)
        {
            return Err(unsupported("ext clean orphan file inode profile"));
        }
        let blocks = inode.length / bs;
        let cap = blocks
            .checked_mul(2)
            .and_then(|n| n.checked_add(16))
            .filter(|n| *n <= 65536)
            .ok_or_else(|| {
                io::Error::other(Error::new(
                    ErrorKind::BudgetExhausted,
                    "ext orphan file block ceiling",
                ))
            })? as usize;
        if u32le(&inode.raw, 32) == 0 {
            let decoded = self.file_map(inode.number, cap, resources, false)?;
            let mut buffer = [0; 4096];
            for extent in &decoded.extents {
                resources.cancellation.check().map_err(io::Error::other)?;
                let super::ExtentKind::Data(offset) = extent.kind else {
                    return Err(invalid("ext orphan file hole mapping"));
                };
                if extent.length != bs || !offset.is_multiple_of(bs) {
                    return Err(invalid("ext orphan file partial block mapping"));
                }
                self.read_exact_at(offset, &mut buffer[..bs as usize])?;
                proof.checksums.orphan(
                    inode.number,
                    inode.generation,
                    offset / bs,
                    &buffer[..bs as usize],
                )?;
            }
            return Ok(());
        }
        let decoded = self.extent_allocations(&inode, cap, resources)?;
        let mut logical = 0;
        let mut buffer = [0; 4096];
        for allocation in decoded.allocations {
            if allocation.unwritten || allocation.logical != logical {
                return Err(invalid("ext orphan file uninitialized/hole mapping"));
            }
            logical += u64::from(allocation.blocks);
            if logical > blocks {
                return Err(invalid("ext orphan file allocation after EOF"));
            }
            for physical in allocation.physical..allocation.physical + allocation.blocks {
                resources.cancellation.check().map_err(io::Error::other)?;
                self.read_exact_at(u64::from(physical) * bs, &mut buffer[..bs as usize])?;
                proof.checksums.orphan(
                    inode.number,
                    inode.generation,
                    u64::from(physical),
                    &buffer[..bs as usize],
                )?;
            }
        }
        if logical != blocks {
            return Err(invalid("ext orphan file incomplete mapping"));
        }
        Ok(())
    }
    pub(crate) fn xattr_encoding(
        &self,
        inode: &super::ExtInode,
        resources: &Resources,
    ) -> io::Result<crate::fs_core::Budgeted<Vec<u8>>> {
        let Some(proof) = &self.geometry.modern else {
            return crate::fs_core::Budgeted::try_new(&resources.memory, 0, || Ok(Vec::new()))
                .map_err(io::Error::other);
        };
        let tail = &inode.extra[usize::from(inode.extra_size)..];
        let inline = if proof.inode_size == 256 && tail.iter().any(|v| *v != 0) {
            tail
        } else {
            &[]
        };
        let external = u32le(&inode.raw, 104);
        let external_bytes = if external == 0 {
            0
        } else {
            proof.block_size as usize
        };
        let length = if inline.is_empty() && external == 0 {
            0
        } else {
            16 + inline.len() + external_bytes
        };
        crate::fs_core::Budgeted::try_new(&resources.memory, (length + 64) as u64, || {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|_| {
                crate::fs_core::Error::new(
                    ErrorKind::BudgetExhausted,
                    "ext xattr metadata encoding allocation",
                )
            })?;
            if length != 0 {
                // Native container framing: inode number, external block number,
                // inline byte count, external byte count, then exact container bytes.
                for word in [
                    inode.number,
                    external,
                    inline.len() as u32,
                    external_bytes as u32,
                ] {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                bytes.extend_from_slice(inline);
                let at = bytes.len();
                bytes.resize(length, 0);
                if external != 0 {
                    self.read_exact_at(
                        u64::from(external) * u64::from(proof.block_size),
                        &mut bytes[at..],
                    )
                    .map_err(|error| crate::fs_core::Error::io("ext opaque xattr read", error))?;
                    proof
                        .checksums
                        .xattr(u64::from(external), &bytes[at..])
                        .map_err(|error| {
                            crate::fs_core::Error::io("ext opaque xattr checksum", error)
                        })?;
                    super::xattr::validate(&bytes[at..], 0, true, resources).map_err(|error| {
                        crate::fs_core::Error::io("ext opaque xattr layout", error)
                    })?;
                }
            }
            Ok(bytes)
        })
        .map_err(io::Error::other)
    }
    pub(crate) fn resize_block(
        &self,
        inode: &[u8; 256],
        resources: &Resources,
    ) -> io::Result<(u32, u32)> {
        let proof = self
            .geometry
            .modern
            .as_ref()
            .ok_or_else(|| unsupported("modern resize profile absent"))?;
        let ownership = super::resize::validate(&self.source, proof, inode, resources)?;
        Ok((ownership.double_indirect, ownership.shared_reserved_blocks))
    }
    pub(super) fn open_modern(
        source: R,
        source_id: u128,
        resources: &Resources,
    ) -> io::Result<Self> {
        Self::open_structural(source, source_id, resources, false)
    }
    // Private owned qualification only; immutable/public admission stays strict.
    #[cfg(test)]
    pub(super) fn open_owned_profile_qualification(
        source: R,
        source_id: u128,
        resources: &Resources,
    ) -> io::Result<Self> {
        let mut sb = [0; 1024];
        source.decode_read_exact_at(1024, &mut sb)?;
        let structural_legacy = u32le(&sb, 100) & 0x400 == 0
            && (u32le(&sb, 92) & !4 != 0 || u32le(&sb, 96) & !6 != 0 || u32le(&sb, 100) & !3 != 0);
        if structural_legacy {
            Self::open_legacy_structural_qualification(source, source_id, resources)
        } else {
            Self::open_reader(source, source_id, resources, true)
        }
    }
    #[cfg(test)]
    pub(super) fn open_legacy_structural_qualification(
        source: R,
        source_id: u128,
        resources: &Resources,
    ) -> io::Result<Self> {
        Self::open_structural(source, source_id, resources, true)
    }
    fn open_structural(
        source: R,
        source_id: u128,
        resources: &Resources,
        legacy_qualification: bool,
    ) -> io::Result<Self> {
        let mut sb = [0; 1024];
        source.decode_read_exact_at(1024, &mut sb)?;
        let proof = std::sync::Arc::new(if legacy_qualification {
            ModernProof::inspect_profile(&source, &sb, resources, true)?
        } else {
            ModernProof::inspect(&source, &sb, resources)?
        });
        let minimum_extra_size = u16le(&sb, 348);
        let desired = u16le(&sb, 350);
        if minimum_extra_size > 128
            || !minimum_extra_size.is_multiple_of(4)
            || desired > 128
            || !desired.is_multiple_of(4)
            || desired < minimum_extra_size
        {
            return Err(invalid("ext modern inode extension geometry"));
        }
        let journal_inode = u32le(&sb, 224);
        if proof.compat & 4 != 0
            && (journal_inode != 8 || u32le(&sb, 228) != 0 || sb[208..224].iter().any(|v| *v != 0))
        {
            return Err(unsupported("ext modern external/nonstandard journal"));
        }
        let decoder = Self {
            source_id,
            source,
            geometry: super::ExtGeometry {
                blocks: proof.blocks,
                inodes: proof.inodes,
                block_size: proof.block_size,
                first: proof.first,
                blocks_per_group: proof.blocks_per_group,
                inodes_per_group: proof.inodes_per_group,
                inode_size: proof.inode_size,
                minimum_extra_size,
                groups: proof.descriptors.len() as u32,
                filetype: proof.incompat & 2 != 0,
                sparse_super: proof.ro & 1 != 0,
                extent_profile: proof.incompat & 0x40 != 0,
                has_journal: proof.compat & 4 != 0,
                journal_inode,
                uuid: sb[104..120].try_into().unwrap(),
                modern: Some(proof),
            },
        };
        decoder.validate_journal(resources)?;
        decoder.validate_modern_orphan(resources)?;
        Ok(decoder)
    }
    pub(super) fn modern_inode(
        &self,
        number: u32,
        bytes: [u8; 256],
        proof: &ModernProof,
        resources: &Resources,
    ) -> io::Result<super::ExtInode> {
        let size = usize::from(proof.inode_size);
        proof.checksums.inode(number, &bytes[..size])?;
        let mut raw: [u8; 128] = bytes[..128].try_into().unwrap();
        let flags = u32le(&raw, 32);
        if flags & 0x1000 != 0 {
            if u16le(&raw, 0) & 0xf000 != 0x4000 || proof.compat & 0x20 == 0 {
                return Err(unsupported("ext indexed inode mode/feature"));
            }
            raw[32..36].copy_from_slice(&(flags & !0x1000).to_le_bytes());
        }
        let external = u32le(&raw, 104);
        if external != 0 {
            if proof.compat & 8 == 0 {
                return Err(unsupported("ext xattr block without feature"));
            }
            self.block(external)?;
            let mut block = [0; 4096];
            let bs = proof.block_size as usize;
            self.read_exact_at(
                u64::from(external) * u64::from(proof.block_size),
                &mut block[..bs],
            )?;
            proof.checksums.xattr(u64::from(external), &block[..bs])?;
            super::xattr::validate(&block[..bs], 0, true, resources)?;
            raw[104..108].fill(0);
        }
        let mut inode = super::ExtInode::decode_profile(number, raw, proof.incompat & 0x40 != 0)?;
        inode.raw = bytes[..128].try_into().unwrap();
        if size == 256 {
            let extra_size = u16le(&bytes, 128);
            if extra_size > 128
                || !extra_size.is_multiple_of(4)
                || extra_size < self.geometry.minimum_extra_size
            {
                return Err(invalid("ext modern inode extension bounds"));
            }
            let header = 128 + usize::from(extra_size);
            if bytes[header..].iter().any(|v| *v != 0) {
                if proof.compat & 8 == 0 {
                    return Err(unsupported("ext inline xattrs without feature"));
                }
                super::xattr::validate(&bytes, header, false, resources)?;
            }
            let mut validated: [u8; 128] = bytes[128..].try_into().unwrap();
            validated[usize::from(extra_size)..].fill(0);
            super::ExtInode::validate_extra(&validated)?;
            inode.extra.copy_from_slice(&bytes[128..]);
            inode.extra_size = extra_size;
        }
        Ok(inode)
    }
}
#[derive(Debug)]
pub(crate) struct ModernProof {
    pub checksums: Integrity,
    pub block_size: u32,
    pub blocks: u32,
    pub inodes: u32,
    pub first: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub descriptor_size: u16,
    pub compat: u32,
    pub incompat: u32,
    pub ro: u32,
    pub reserved_gdt: u16,
    pub orphan_inode: u32,
    pub hash_seed: [u32; 4],
    pub unsigned_hash: bool,
    pub descriptors: Vec<[u8; 64]>,
    pub ranges: Vec<(u32, u32)>,
    pub bitmaps: Vec<u8>,
    _reservation: Reservation,
}
impl ModernProof {
    pub(crate) fn backup_superblock(&self, bytes: &[u8; 1024]) -> io::Result<()> {
        if !Integrity::superblock(bytes)?.same_policy(&self.checksums) {
            return Err(invalid("ext backup checksum seed disagrees"));
        }
        Ok(())
    }
    pub fn inspect<R: ExtDecodeRead>(
        source: &R,
        sb: &[u8; 1024],
        resources: &Resources,
    ) -> io::Result<Self> {
        Self::inspect_profile(source, sb, resources, false)
    }
    fn inspect_profile<R: ExtDecodeRead>(
        source: &R,
        sb: &[u8; 1024],
        resources: &Resources,
        legacy_qualification: bool,
    ) -> io::Result<Self> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if u16le(sb, 56) != 0xef53 || u32le(sb, 76) != 1 || u32le(sb, 72) != 0 {
            return Err(unsupported("ext modern revision/Linux profile"));
        }
        let compat = u32le(sb, 92);
        let incompat = u32le(sb, 96);
        let ro = u32le(sb, 100);
        let allowed_ro = 0x46b | if legacy_qualification { 0x10 } else { 0 };
        if compat & !0x103c != 0 || incompat & !0x22c2 != 0 || ro & !allowed_ro != 0 {
            return Err(unsupported("ext modern feature profile"));
        }
        // Legacy structural profiles remain gated until every ownership validator
        // and native mutation writer handles their explicit checksum policy.
        if ro & 0x400 == 0 && !legacy_qualification {
            return Err(unsupported("ext legacy structural profile not qualified"));
        }
        if u32le(sb, 352) & 3 == 3 {
            return Err(invalid("ext conflicting native directory hash signedness"));
        }
        if compat & 0x20 != 0 && u32le(sb, 352) & 3 == 0 {
            return Err(unsupported(
                "ext native directory hash signedness unspecified",
            ));
        }
        if u16le(sb, 58) != 1 || u32le(sb, 232) != 0 {
            return Err(unsupported("ext modern dirty/orphan recovery state"));
        }
        let checksums = Integrity::superblock(sb)?;
        let log = u32le(sb, 24);
        if log > 2
            || u32le(sb, 28) != log
            || u32le(sb, 336) != 0
            || u32le(sb, 340) != 0
            || u32le(sb, 344) != 0
        {
            return Err(unsupported("ext modern block/address profile"));
        }
        let block_size = 1024u32 << log;
        let blocks = u32le(sb, 4);
        let inodes = u32le(sb, 0);
        let first = u32le(sb, 20);
        let blocks_per_group = u32le(sb, 32);
        let inodes_per_group = u32le(sb, 40);
        let inode_size = u16le(sb, 88);
        let descriptor_size = if incompat & 0x80 != 0 {
            u16le(sb, 254)
        } else {
            32
        };
        if first != u32::from(block_size == 1024)
            || blocks <= first
            || inodes < 2
            || blocks_per_group == 0
            || blocks_per_group > block_size * 8
            || !blocks_per_group.is_multiple_of(8)
            || inodes_per_group == 0
            || inodes_per_group > block_size * 8
            || !inodes_per_group.is_multiple_of(8)
            || u32le(sb, 36) != blocks_per_group
            || !matches!(inode_size, 128 | 256)
            || !matches!(descriptor_size, 32 | 64)
            || (incompat & 0x80 != 0 && descriptor_size != 64)
        {
            return Err(invalid("ext modern geometry"));
        }
        if ro & 0x40 != 0 && inode_size != 256 {
            return Err(unsupported(
                "ext modern extra-isize requires 256-byte inodes",
            ));
        }
        let group_count = (blocks - first).div_ceil(blocks_per_group) as usize;
        if inodes.div_ceil(inodes_per_group) as usize != group_count {
            return Err(invalid("ext modern inode/block groups disagree"));
        }
        if group_count > MAX_GROUPS {
            return Err(io::Error::other(Error::new(
                ErrorKind::BudgetExhausted,
                "ext modern group setup ceiling",
            )));
        }
        let charge = group_count * (64 + 5 * 16 + 2 * block_size as usize) + 512;
        let reservation = resources
            .memory
            .reserve(charge as u64)
            .map_err(io::Error::other)?;
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(group_count)
            .map_err(io::Error::other)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(group_count * 5)
            .map_err(io::Error::other)?;
        let reserved_gdt = u16le(sb, 206);
        if compat & 0x10 == 0 && reserved_gdt != 0 {
            return Err(invalid("ext reserved GDT without resize inode"));
        }
        if u64::from(blocks) * u64::from(block_size) > source.decode_len()? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        for group in 0..group_count {
            resources.cancellation.check().map_err(io::Error::other)?;
            let mut descriptor = [0; 64];
            source.decode_read_exact_at(
                u64::from(first + 1) * u64::from(block_size)
                    + group as u64 * u64::from(descriptor_size),
                &mut descriptor[..usize::from(descriptor_size)],
            )?;
            checksums.descriptor(group as u32, &descriptor[..usize::from(descriptor_size)])?;
            if u16le(&descriptor, 18) & !7 != 0
                || descriptor[32..56].iter().any(|byte| *byte != 0)
                || u32le(&descriptor, 20) != 0
                || descriptor[60..64].iter().any(|byte| *byte != 0)
            {
                return Err(unsupported(
                    "ext descriptor flags/high addresses/exclusion bitmap",
                ));
            }
            let start = u64::from(first) + group as u64 * u64::from(blocks_per_group);
            let group_end = (start + u64::from(blocks_per_group)).min(u64::from(blocks));
            let power = |base: usize| {
                let mut n = group;
                while n > 1 && n.is_multiple_of(base) {
                    n /= base;
                }
                n == 1
            };
            if ro & 1 == 0 || group <= 1 || power(3) || power(5) || power(7) {
                let end = start
                    + 1
                    + (group_count as u64 * u64::from(descriptor_size))
                        .div_ceil(u64::from(block_size))
                    + u64::from(reserved_gdt);
                if end > group_end {
                    return Err(invalid("ext backup/reserved GDT escapes group"));
                }
                ranges.push((start as u32, end as u32));
            }
            for (slot, length) in [
                (0, 1),
                (4, 1),
                (
                    8,
                    (u64::from(inodes_per_group) * u64::from(inode_size))
                        .div_ceil(u64::from(block_size)),
                ),
            ] {
                let physical = u64::from(u32le(&descriptor, slot));
                let end = physical
                    .checked_add(length)
                    .filter(|end| *end <= u64::from(blocks))
                    .ok_or_else(|| invalid("ext global metadata range"))?;
                if physical < u64::from(first)
                    || (incompat & 0x200 == 0 && (physical < start || end > group_end))
                {
                    return Err(invalid("ext metadata physical placement"));
                }
                ranges.push((physical as u32, end as u32));
            }
            descriptors.push(descriptor);
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(invalid("ext global metadata ranges overlap"));
        }
        let orphan_inode = if compat & 0x1000 != 0 {
            u32le(sb, 640)
        } else {
            0
        };
        if orphan_inode != 0 && (orphan_inode < u32le(sb, 84) || orphan_inode > inodes) {
            return Err(invalid("ext orphan-file inode bounds"));
        }
        if compat & 0x1000 != 0 && orphan_inode == 0 {
            return Err(invalid("ext orphan-file inode absent"));
        }
        let mut bitmaps = Vec::new();
        bitmaps
            .try_reserve_exact(group_count * 2 * block_size as usize)
            .map_err(io::Error::other)?;
        if descriptors
            .capacity()
            .checked_mul(64)
            .and_then(|bytes| bytes.checked_add(ranges.capacity().checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add(bitmaps.capacity()))
            .and_then(|bytes| bytes.checked_add(512))
            .is_none_or(|bytes| bytes > charge)
        {
            return Err(io::Error::other(Error::new(
                ErrorKind::BudgetExhausted,
                "ext modern actual vector capacity",
            )));
        }
        let mut proof = Self {
            checksums,
            block_size,
            blocks,
            inodes,
            first,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            descriptor_size,
            compat,
            incompat,
            ro,
            reserved_gdt,
            orphan_inode,
            hash_seed: [
                u32le(sb, 236),
                u32le(sb, 240),
                u32le(sb, 244),
                u32le(sb, 248),
            ],
            unsigned_hash: u32le(sb, 352) & 2 != 0,
            descriptors,
            ranges,
            bitmaps,
            _reservation: reservation,
        };
        for group in 0..group_count {
            for inode in [false, true] {
                let mut bitmap = [0; 4096];
                proof.bitmap(source, group, inode, &mut bitmap, resources)?;
                proof
                    .bitmaps
                    .extend_from_slice(&bitmap[..block_size as usize]);
            }
        }
        for &(start, end) in &proof.ranges {
            for block in start..end {
                if block.is_multiple_of(256) {
                    resources.cancellation.check().map_err(io::Error::other)?;
                }
                if !proof.is_allocated(block, false) {
                    return Err(invalid("ext global metadata bitmap bit is free"));
                }
            }
        }
        Ok(proof)
    }
    pub fn is_allocated(&self, number: u32, inode: bool) -> bool {
        let (index, per) = if inode {
            if number == 0 || number > self.inodes {
                return false;
            }
            (number - 1, self.inodes_per_group)
        } else {
            if number < self.first || number >= self.blocks {
                return false;
            }
            (number - self.first, self.blocks_per_group)
        };
        let group = (index / per) as usize;
        let bit = (index % per) as usize;
        let offset = (group * 2 + usize::from(inode)) * self.block_size as usize + bit / 8;
        self.bitmaps
            .get(offset)
            .is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
    }
    pub fn metadata_block(&self, number: u32) -> bool {
        let at = self.ranges.partition_point(|range| range.0 <= number);
        at != 0 && number < self.ranges[at - 1].1
    }
    pub fn bitmap<R: ExtDecodeRead>(
        &self,
        source: &R,
        group: usize,
        inode: bool,
        out: &mut [u8; 4096],
        resources: &Resources,
    ) -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        let descriptor = self
            .descriptors
            .get(group)
            .ok_or_else(|| invalid("ext bitmap group bounds"))?;
        let flags = u16le(descriptor, 18);
        if flags & 3 != 0 && !self.checksums.has_group_checksum() {
            return Err(unsupported(
                "ext uninitialized bitmap without descriptor checksum",
            ));
        }
        let uninitialized = flags & if inode { 1 } else { 2 } != 0;
        let bs = self.block_size as usize;
        let per = if inode {
            self.inodes_per_group
        } else {
            self.blocks_per_group
        };
        let first = if inode {
            group as u64 * u64::from(per)
        } else {
            u64::from(self.first) + group as u64 * u64::from(per)
        };
        let total = if inode { self.inodes } else { self.blocks };
        let count = (u64::from(total) - first).min(u64::from(per)) as usize;
        out.fill(0);
        if uninitialized {
            for bit in 0..bs * 8 {
                if bit.is_multiple_of(256) {
                    resources.cancellation.check().map_err(io::Error::other)?;
                }
                if bit >= count || (!inode && self.metadata_block((first + bit as u64) as u32)) {
                    out[bit / 8] |= 1 << (bit % 8);
                }
            }
        } else {
            let physical = u32le(descriptor, if inode { 4 } else { 0 });
            source.decode_read_exact_at(
                u64::from(physical) * u64::from(self.block_size),
                &mut out[..bs],
            )?;
            self.checksums.bitmap(
                &out[..bs],
                per,
                &descriptor[..usize::from(self.descriptor_size)],
                inode,
            )?;
        }
        resources.cancellation.check().map_err(io::Error::other)?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use std::sync::Arc;
    use virtdisk::ReadAt;
    struct Image(Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
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
    }
    fn w(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn d(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn forward(mut crc: u32, bytes: &[u8]) -> u32 {
        crc = crc.reverse_bits();
        for &byte in bytes {
            crc ^= u32::from(byte.reverse_bits()) << 24;
            for _ in 0..8 {
                let high = crc & 0x80000000 != 0;
                crc <<= 1;
                if high {
                    crc ^= 0x1edc6f41;
                }
            }
        }
        crc.reverse_bits()
    }
    fn fixture() -> (Vec<u8>, [u8; 1024]) {
        let mut image = vec![0; 128 * 1024];
        let mut sb = [0; 1024];
        w(&mut sb, 56, 0xef53);
        w(&mut sb, 58, 1);
        d(&mut sb, 76, 1);
        d(&mut sb, 0, 32);
        d(&mut sb, 4, 128);
        d(&mut sb, 20, 1);
        d(&mut sb, 32, 64);
        d(&mut sb, 36, 64);
        d(&mut sb, 40, 16);
        w(&mut sb, 88, 256);
        d(&mut sb, 84, 11);
        d(&mut sb, 96, 0x2282);
        d(&mut sb, 100, 0x401);
        w(&mut sb, 254, 64);
        sb[373] = 1;
        d(&mut sb, 624, 0x12345678);
        for group in 0..2 {
            let at = 2048 + group * 64;
            // Group one metadata is packed beside group zero metadata (flex_bg).
            d(&mut image, at, 3 + group as u32);
            d(&mut image, at + 4, 5 + group as u32);
            d(&mut image, at + 8, 7 + group as u32 * 4);
            w(&mut image, at + 18, 7);
            let crc = forward(
                forward(0x12345678, &(group as u32).to_le_bytes()),
                &image[at..at + 64],
            );
            w(&mut image, at + 30, crc as u16);
        }
        let crc = forward(!0, &sb[..1020]);
        d(&mut sb, 1020, crc);
        image[1024..2048].copy_from_slice(&sb);
        (image, sb)
    }
    fn resources(bytes: u64) -> Resources {
        Resources {
            memory: Budget::new(bytes),
            cancellation: Cancellation::default(),
        }
    }
    pub(in crate::fs_ext) mod independent {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fs_ext_modern.rs"
        ));
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fs_ext_legacy_integrity.rs"
        ));
    }
    use independent::fixture as ownership_fixture;
    fn audit_limits() -> crate::fs_ext_audit::ExtAuditLimits {
        crate::fs_ext_audit::ExtAuditLimits {
            blocks: 128,
            inodes: 32,
            work: 100000,
            directory_blocks: 16,
            directory_entries: 32,
            findings: 32,
        }
    }
    #[test]
    fn private_legacy_structural_ownership_payload_and_public_gate() {
        for extents in [false, true] {
            for gdt16 in [false, true] {
                let (image, payload) = independent::without_metadata_checksums(extents, gdt16);
                let r = resources(4 << 20);
                assert!(super::super::ExtVolume::open(Arc::new(Image(image.clone())), &r).is_err());
                assert_eq!(r.memory.used(), 0);
                let source: Arc<dyn ReadAt> = Arc::new(Image(image.clone()));
                let decoder = super::super::ExtDecoder::open_legacy_structural_qualification(
                    source,
                    18u128 << 64,
                    &r,
                )
                .unwrap();
                assert!(!decoder.geometry().has_metadata_checksums());
                assert!(!decoder.geometry().is_classic());
                let report =
                    crate::fs_ext_audit::audit_decoder(&decoder, audit_limits(), &r).unwrap();
                assert!(report.is_clean(), "{:?}", report.findings());
                drop(report);
                let directory = decoder.directory(2, 16, 32, &r).unwrap();
                assert_eq!(
                    directory.entries().last().unwrap().name,
                    crate::fs_core::NativeName::Bytes(b"x\xff".to_vec())
                );
                drop(directory);
                let map = decoder.file_map(12, 16, &r, false).unwrap();
                let mut out = vec![0; 2048];
                assert_eq!(
                    decoder.read_map(&map, 0, &mut out, &r).unwrap(),
                    payload.len()
                );
                assert_eq!(&out[..payload.len()], payload);
                assert_eq!(
                    decoder
                        .read_map(&map, payload.len() as u64, &mut out, &r)
                        .unwrap(),
                    0
                );
                drop(map);
                drop(decoder);
                assert_eq!(r.memory.used(), 0);
                // Bitmap bytes have no checksum in either legacy policy. Complete
                // ownership/counter validation must still reject altered allocation.
                let mut bad = image;
                bad[3 * 1024 + 1] &= !(1 << 1);
                let source: Arc<dyn ReadAt> = Arc::new(Image(bad));
                match super::super::ExtDecoder::open_legacy_structural_qualification(
                    source,
                    18u128 << 64,
                    &r,
                ) {
                    Ok(decoder) => {
                        let report =
                            crate::fs_ext_audit::audit_decoder(&decoder, audit_limits(), &r);
                        assert!(report.is_err() || !report.unwrap().is_clean());
                        drop(decoder);
                    }
                    Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
                }
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    fn orphan_fixture(alias: bool, active: bool) -> Vec<u8> {
        let (mut image, _) = ownership_fixture();
        d(&mut image, 1024 + 92, 0x1008);
        d(&mut image, 1024 + 640, 13);
        d(&mut image, 1024 + 12, 50);
        d(&mut image, 1024 + 16, 4);
        image[3 * 1024 + 1] |= 1 << 4;
        image[4 * 1024 + 1] |= 1 << 4;
        let at = 5 * 1024 + 12 * 256;
        let inode = &mut image[at..at + 256];
        w(inode, 0, 0o100600);
        d(inode, 4, 1024);
        w(inode, 26, 1);
        d(inode, 28, 2);
        d(inode, 32, 0x80000);
        w(inode, 40, 0xf30a);
        w(inode, 42, 1);
        w(inode, 44, 4);
        w(inode, 56, 1);
        d(inode, 60, 13);
        w(inode, 128, 32);
        independent::inode_checksum(&mut image, 13);
        let orphan = &mut image[13 * 1024..14 * 1024];
        if active {
            d(orphan, 0, 12);
        }
        d(orphan, 1016, 0x0b10ca04);
        let seed = forward(
            forward(0x12345678, &13u32.to_le_bytes()),
            &0u32.to_le_bytes(),
        );
        let checksum = forward(forward(seed, &13u64.to_le_bytes()), &orphan[..1016]);
        d(orphan, 1020, checksum);
        if alias {
            let root = &mut image[9 * 1024..10 * 1024];
            w(root, 28, 12);
            d(root, 36, 13);
            w(root, 40, 976);
            root[42] = 2;
            root[43] = 1;
            root[44..46].copy_from_slice(b"or");
            let seed = forward(
                forward(0x12345678, &2u32.to_le_bytes()),
                &0u32.to_le_bytes(),
            );
            let checksum = forward(seed, &root[..1012]);
            d(root, 1020, checksum);
        }
        let bc = forward(0x12345678, &image[3 * 1024..3 * 1024 + 8]);
        let ic = forward(0x12345678, &image[4 * 1024..4 * 1024 + 2]);
        let gd = &mut image[2048..2112];
        w(gd, 12, 50);
        w(gd, 14, 4);
        w(gd, 24, bc as u16);
        w(gd, 56, (bc >> 16) as u16);
        w(gd, 26, ic as u16);
        w(gd, 58, (ic >> 16) as u16);
        w(gd, 30, 0);
        let checksum = forward(forward(0x12345678, &0u32.to_le_bytes()), gd);
        w(gd, 30, checksum as u16);
        let checksum = forward(!0, &image[1024..2044]);
        d(&mut image, 2044, checksum);
        image
    }
    #[test]
    fn clean_orphan_hidden_ownership_rechecksummed_alias_and_active_slots() {
        for (alias, active) in [(false, false), (true, false), (false, true)] {
            let source: Arc<dyn ReadAt> = Arc::new(Image(orphan_fixture(alias, active)));
            let r = resources(4 << 20);
            let opened = super::super::ExtVolume::open(source, &r);
            if active {
                assert_eq!(opened.err().unwrap().kind(), io::ErrorKind::Unsupported);
                assert_eq!(r.memory.used(), 0);
                continue;
            }
            let volume = opened.unwrap();
            let report = crate::fs_ext_audit::audit(&volume, audit_limits(), &r).unwrap();
            assert_eq!(report.is_clean(), !alias);
            if alias {
                assert!(report.findings().iter().any(|finding| matches!(
                    finding,
                    crate::fs_ext_audit::ExtAuditFinding::InvalidInodeReference { inode: 13, .. }
                )));
                assert!(volume.directory(2, 16, 32, &r).is_err());
            } else {
                assert_eq!(report.owned_blocks(), 5);
                assert_eq!(report.allocated_inodes(), 2);
            }
            drop(report);
            drop(volume);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn independent_classic_orphan_map_checksum_hole_and_trailing_ownership() {
        for defect in 0..5 {
            let mut image = orphan_fixture(false, false);
            let at = 5 * 1024 + 12 * 256;
            d(&mut image, at + 32, 0);
            image[at + 40..at + 100].fill(0);
            d(&mut image, at + 40, 13);
            match defect {
                1 => image[13 * 1024 + 1020] ^= 1,
                2 => d(&mut image, at + 40, 0),
                3 => d(&mut image, at + 44, 13),
                4 => d(&mut image, at + 88, 13),
                _ => {}
            }
            independent::inode_checksum(&mut image, 13);
            let r = resources(4 << 20);
            let opened = super::super::ExtVolume::open(Arc::new(Image(image)), &r);
            if matches!(defect, 1 | 2) {
                assert!(opened.is_err());
            } else {
                let volume = opened.unwrap();
                let report = crate::fs_ext_audit::audit(&volume, audit_limits(), &r);
                if defect == 0 {
                    assert!(report.unwrap().is_clean());
                } else {
                    assert!(report.is_err() || !report.unwrap().is_clean());
                }
                drop(volume);
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn independent_zero_reserved_gdt_resize_root_ownership_and_defects() {
        for defect in 0..4 {
            let mut image = orphan_fixture(false, false);
            d(&mut image, 1024 + 92, 0x1018);
            d(&mut image, 1024 + 12, 49);
            image[3 * 1024 + 1] |= 1 << 5;
            let at = 5 * 1024 + 6 * 256;
            image[at..at + 256].fill(0);
            w(&mut image, at, 0o100600);
            d(&mut image, at + 4, (12 + 256 + 256 * 256) * 1024);
            w(&mut image, at + 26, 1);
            d(&mut image, at + 28, 2);
            d(&mut image, at + 92, 14);
            w(&mut image, at + 128, 32);
            match defect {
                1 => d(&mut image, 14 * 1024, 13),
                2 => d(&mut image, at + 28, 0),
                3 => d(&mut image, at + 92, 3),
                _ => {}
            }
            independent::inode_checksum(&mut image, 7);
            let bc = forward(0x12345678, &image[3 * 1024..3 * 1024 + 8]);
            let gd = &mut image[2048..2112];
            w(gd, 12, 49);
            w(gd, 24, bc as u16);
            w(gd, 56, (bc >> 16) as u16);
            w(gd, 30, 0);
            let checksum = forward(forward(0x12345678, &0u32.to_le_bytes()), gd);
            w(gd, 30, checksum as u16);
            let checksum = forward(!0, &image[1024..2044]);
            d(&mut image, 2044, checksum);
            let r = resources(4 << 20);
            let volume = super::super::ExtVolume::open(Arc::new(Image(image)), &r).unwrap();
            let report = crate::fs_ext_audit::audit(&volume, audit_limits(), &r);
            if defect == 0 {
                let report = report.unwrap();
                assert!(report.is_clean(), "{:?}", report.findings());
                assert_eq!(report.owned_blocks(), 6);
                drop(report);
            } else {
                assert!(report.is_err());
            }
            drop(volume);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn independent_complete_ownership_shared_xattrs_native_names_and_payload() {
        let (image, payload) = ownership_fixture();
        let source: Arc<dyn ReadAt> = Arc::new(Image(image));
        let r = resources(4 << 20);
        let decoder = super::super::ExtDecoder::open_modern(source, 101, &r).unwrap();
        let baseline = r.memory.used();
        let report = crate::fs_ext_audit::audit_decoder(&decoder, audit_limits(), &r).unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.allocated_inodes(), 2);
        assert_eq!(report.owned_blocks(), 4);
        drop(report);
        assert_eq!(r.memory.used(), baseline);
        let directory = decoder.directory(2, 16, 32, &r).unwrap();
        assert!(
            matches!(&directory.entries()[2].name,crate::fs_core::NativeName::Bytes(name) if name == b"x\xff")
        );
        drop(directory);
        let map = decoder.file_map(12, 16, &r, false).unwrap();
        let mut range = [0; 31];
        assert_eq!(decoder.read_map(&map, 1018, &mut range, &r).unwrap(), 31);
        assert_eq!(&range, payload[1018..1049].as_ref());
        drop(map);
        let mut limits = audit_limits();
        limits.work = 1;
        assert!(crate::fs_ext_audit::audit_decoder(&decoder, limits, &r).is_err());
        assert_eq!(r.memory.used(), baseline);
        r.cancellation.cancel();
        assert!(decoder.inode(12, &r).is_err());
        drop(decoder);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn rechecksummed_shared_xattr_refcount_and_inode_map_alias_fail() {
        for (mutation, image) in independent::mutation_seeds()
            .into_iter()
            .take(3)
            .enumerate()
        {
            let source: Arc<dyn ReadAt> = Arc::new(Image(image));
            let r = resources(4 << 20);
            let decoder = super::super::ExtDecoder::open_modern(source, 101, &r).unwrap();
            assert!(crate::fs_ext_audit::audit_decoder(&decoder, audit_limits(), &r).is_err());
            if mutation != 0 {
                assert!(decoder.file_map(12, 16, &r, false).is_err());
            }
            drop(decoder);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn public_source_scope_and_modern_owned_editor_zero_write_gate() {
        use crate::{
            fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditor},
            fs_undo::UndoLimits,
            storage::Storage,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Owned {
            bytes: Vec<u8>,
            writes: Arc<AtomicUsize>,
        }
        impl Storage for Owned {
            fn len(&self) -> io::Result<u64> {
                Ok(self.bytes.len() as u64)
            }
            fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
                let first = usize::try_from(offset).map_err(io::Error::other)?;
                let end = first
                    .checked_add(dst.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                dst.copy_from_slice(
                    self.bytes
                        .get(first..end)
                        .ok_or(io::ErrorKind::UnexpectedEof)?,
                );
                Ok(())
            }
            fn write_at(&mut self, _: u64, bytes: &[u8]) -> io::Result<usize> {
                self.writes.fetch_add(1, Ordering::Relaxed);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.writes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let (image, _) = ownership_fixture();
        let r = resources(4 << 20);
        let source: Arc<dyn ReadAt> = Arc::new(Image(image.clone()));
        let a = super::super::ExtVolume::open(source.clone(), &r).unwrap();
        let b = super::super::ExtVolume::open(source, &r).unwrap();
        assert_ne!(a.identity(12, &r).unwrap(), b.identity(12, &r).unwrap());
        assert!(!a.geometry().is_classic());
        drop(a);
        drop(b);
        assert_eq!(r.memory.used(), 0);
        let writes = Arc::new(AtomicUsize::new(0));
        let result = ExtEditor::open(
            Owned {
                bytes: image,
                writes: writes.clone(),
            },
            Owned {
                bytes: vec![0; 32768],
                writes: writes.clone(),
            },
            ExtEditRegion {
                offset: 0,
                length: 65536,
            },
            ExtEditBinding {
                volume: [4; 32],
                generation: 0,
            },
            ExtEditLimits {
                audit: audit_limits(),
                file_blocks: 64,
                directory_entries: 32,
                affected_bytes: 4096,
                work: 65536,
                undo: UndoLimits {
                    patches: 32,
                    body_bytes: 16384,
                },
            },
            &r,
        );
        assert_eq!(result.err().unwrap().kind, ErrorKind::Unsupported);
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn checksums_without_extents_public_facade_family_and_classic_rejection() {
        use crate::{
            fs_core::Family,
            fs_image::{AllocationEvidence, AllocationPolicy, ReadImage, ReadOptions},
        };
        let (image, _) = independent::without_extents();
        let source: Arc<dyn ReadAt> = Arc::new(Image(image));
        let r = resources(4 << 20);
        let volume = super::super::ExtVolume::open(source.clone(), &r).unwrap();
        assert!(volume.geometry().has_metadata_checksums());
        assert!(!volume.geometry().uses_extents());
        assert!(!volume.geometry().is_classic());
        drop(volume);
        let opened = ReadImage::open(
            source.clone(),
            ReadOptions::Ext {
                audit: audit_limits(),
                objects: 16,
                entries: 32,
                map_blocks: 16,
                directory_slots: 32,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        assert_eq!(opened.profile().family, Family::Ext4);
        assert_eq!(
            opened.allocation_evidence(),
            AllocationEvidence::CleanProfileAudit
        );
        drop(opened);
        let denied = ReadImage::open(
            source,
            ReadOptions::Ext2 {
                audit: audit_limits(),
                objects: 16,
                entries: 32,
                map_blocks: 16,
                directory_slots: 32,
            },
            AllocationPolicy::RequireClean,
            &r,
        );
        assert_eq!(denied.err().unwrap().kind, ErrorKind::Unsupported);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn flex_global_exclusions_uninitialized_bitmaps_limits_and_refunds() {
        let (image, sb) = fixture();
        let source: Arc<dyn ReadAt> = Arc::new(Image(image));
        let r = resources(8192);
        let proof = ModernProof::inspect(&source, &sb, &r).unwrap();
        assert_eq!(
            (proof.block_size, proof.blocks, proof.inodes, proof.first),
            (1024, 128, 32, 1)
        );
        assert_eq!(
            (
                proof.blocks_per_group,
                proof.inodes_per_group,
                proof.inode_size,
                proof.descriptor_size
            ),
            (64, 16, 256, 64)
        );
        assert_eq!(
            (
                proof.compat,
                proof.incompat,
                proof.ro,
                proof.reserved_gdt,
                proof.orphan_inode
            ),
            (0, 0x2282, 0x401, 0, 0)
        );
        assert!(proof.metadata_block(13));
        assert!(!proof.metadata_block(16));
        let mut bitmap = [0; 4096];
        proof.bitmap(&source, 0, false, &mut bitmap, &r).unwrap();
        assert_eq!(bitmap[0], 255);
        assert_eq!(bitmap[1] & 63, 63); // primary prefix plus all flex metadata.
        proof.bitmap(&source, 1, false, &mut bitmap, &r).unwrap();
        assert_eq!(bitmap[0] & 3, 3);
        assert_eq!(bitmap[1], 0);
        proof.bitmap(&source, 1, true, &mut bitmap, &r).unwrap();
        assert_eq!(&bitmap[..3], &[0, 0, 255]);
        assert!(proof.bitmap(&source, 3, true, &mut bitmap, &r).is_err());
        r.cancellation.cancel();
        assert!(proof.bitmap(&source, 0, true, &mut bitmap, &r).is_err());
        drop(proof);
        assert_eq!(r.memory.used(), 0);
        let r = resources(1);
        assert!(ModernProof::inspect(&source, &sb, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn rechecksummed_metadata_alias_unknown_flags_and_high_addresses_fail() {
        for mutation in 0..4 {
            let (mut image, sb) = fixture();
            let at = 2048 + 64;
            match mutation {
                0 => d(&mut image, at + 8, 7),
                1 => w(&mut image, at + 18, 15),
                2 => d(&mut image, at + 32, 1),
                _ => d(&mut image, at + 60, 1),
            }
            w(&mut image, at + 30, 0);
            let crc = forward(
                forward(0x12345678, &1u32.to_le_bytes()),
                &image[at..at + 64],
            );
            w(&mut image, at + 30, crc as u16);
            let source: Arc<dyn ReadAt> = Arc::new(Image(image));
            let r = resources(8192);
            assert!(ModernProof::inspect(&source, &sb, &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[cfg(all(test, unix))]
mod native_checks {
    use super::*;
    use crate::fs_core::{Budget, Cancellation, MetadataField, TreeSource};
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStringExt;
    use std::{fs, path::PathBuf, process::Command, sync::Arc};
    use virtdisk::ReadAt;
    struct Image(Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
            let start = usize::try_from(offset).map_err(io::Error::other)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            bytes.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
            Ok(())
        }
    }
    // Independent fixture inspection: bounded, initialized 32-bit native extents.
    // This does not author any reader inputs or substitute for production ownership checks.
    fn native_mapping(bytes: &[u8], proof: &ModernProof, number: u32, inode: &[u8]) -> Vec<usize> {
        let bs = proof.block_size as usize;
        let mut mapping = vec![None; u32le(inode, 4) as usize / bs];
        let mut queue = vec![(&inode[40..100], u16le(inode, 46))];
        let mut work = 0;
        while let Some((node, depth)) = queue.pop() {
            work += 1;
            assert!(work <= 256 && depth <= 5);
            assert_eq!(u16le(node, 0), 0xf30a);
            assert_eq!(u16le(node, 6), depth);
            let entries = usize::from(u16le(node, 2));
            assert!(12 + entries * 12 <= node.len());
            for entry in 0..entries {
                let at = 12 + entry * 12;
                if depth != 0 {
                    assert_eq!(u16le(node, at + 8), 0);
                    let physical = u32le(node, at + 4) as usize;
                    let child = &bytes[physical * bs..(physical + 1) * bs];
                    proof
                        .checksums
                        .extent(number, u32le(inode, 100), child)
                        .unwrap();
                    queue.push((child, depth - 1));
                } else {
                    assert_eq!(u16le(node, at + 6), 0);
                    let first = u32le(node, at) as usize;
                    let count = usize::from(u16le(node, at + 4));
                    assert!(count > 0 && count < 32768);
                    for delta in 0..count {
                        assert!(
                            mapping[first + delta]
                                .replace(u32le(node, at + 8) as usize + delta)
                                .is_none()
                        );
                    }
                }
            }
        }
        mapping
            .into_iter()
            .map(|block| block.expect("native directory has no holes"))
            .collect()
    }
    #[test]
    #[ignore = "explicit modern default reader/audit/native metadata gate; requires fresh PARTMGR_EXT_METADATA_EVIDENCE and all e2fsprogs tools"]
    fn native_default_checksums_flex_and_uninitialized_geometry() {
        let out = PathBuf::from(
            std::env::var_os("PARTMGR_EXT_METADATA_EVIDENCE")
                .expect("enabled oracle requires evidence destination"),
        );
        assert!(out.is_absolute());
        fs::create_dir(&out).expect("fresh evidence destination required");
        let sources = [
            "src/fs_ext.rs",
            "src/fs_ext_metadata.rs",
            "src/fs_ext_modern.rs",
            "src/fs_ext_checksum.rs",
            "src/fs_ext_resize.rs",
            "src/fs_ext_directory.rs",
            "src/fs_ext_hash.rs",
            "src/fs_ext_xattr.rs",
            "src/fs_ext_audit.rs",
            "src/fs_ext_extent.rs",
            "src/fs_ext_journal.rs",
            "src/fs_ext_tree.rs",
            "src/fs_image.rs",
            "tests/fixtures/fs_ext_modern.rs",
            "src/fs_core.rs",
            "src/fs_file.rs",
            "Cargo.lock",
        ];
        let mut receipt = String::from(
            "scope=bounded immutable default ext4 metadata/reader/whole-audit/tree integration\n",
        );
        for source in sources {
            let bytes = fs::read(source).unwrap();
            let dest = out.join("sources").join(source);
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(&dest, &bytes).unwrap();
            receipt.push_str(&format!(
                "source={source} sha256={:x}\n",
                Sha256::digest(bytes)
            ));
        }
        let exe = std::env::current_exe().unwrap();
        let binary = fs::read(&exe).unwrap();
        fs::write(out.join("gate-binary"), &binary).unwrap();
        fs::set_permissions(
            out.join("gate-binary"),
            fs::metadata(exe).unwrap().permissions(),
        )
        .unwrap();
        receipt.push_str(&format!("binary_sha256={:x}\n", Sha256::digest(binary)));
        let mut tools = std::collections::BTreeMap::new();
        for tool in ["mke2fs", "debugfs", "e2fsck"] {
            let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|path| path.join(tool))
                .find(|path| path.is_file())
                .expect("enabled oracle requires every tool");
            receipt.push_str(&format!(
                "tool={tool} path={} sha256={:x}\n",
                path.display(),
                Sha256::digest(fs::read(&path).unwrap())
            ));
            tools.insert(tool, path);
        }
        let mut command = 0;
        let run = |tool: &str, args: Vec<String>, receipt: &mut String, command: &mut usize| {
            let output = Command::new(&tools[tool]).args(&args).output().unwrap();
            let name = format!("command-{:04}-{tool}", *command);
            *command += 1;
            fs::write(out.join(format!("{name}.stdout")), &output.stdout).unwrap();
            fs::write(out.join(format!("{name}.stderr")), &output.stderr).unwrap();
            receipt.push_str(&format!("command={} {args:?} status={} stdout={name}.stdout sha256={:x} stderr={name}.stderr sha256={:x}\n", tools[tool].display(), output.status, Sha256::digest(&output.stdout), Sha256::digest(&output.stderr)));
            fs::write(out.join("receipt.txt"), &*receipt).unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        for tool in ["mke2fs", "debugfs", "e2fsck"] {
            run(tool, vec!["-V".into()], &mut receipt, &mut command);
        }
        let input = out.join("native-input");
        fs::create_dir(&input).unwrap();
        let entry_name = |number| format!("entry-{number:04}-{}", "n".repeat(220));
        for number in 0..600 {
            fs::write(input.join(entry_name(number)), [number as u8; 17]).unwrap();
        }
        let expected_payload: Vec<u8> = (0..131089).map(|n| (n * 73 + n / 251) as u8).collect();
        fs::write(input.join("large"), &expected_payload).unwrap();
        fs::write(
            input.join(std::ffi::OsString::from_vec(b"x\xffname".to_vec())),
            b"native byte name",
        )
        .unwrap();
        fs::hard_link(input.join(entry_name(599)), input.join("alias")).unwrap();
        let attr = out.join("external-xattr-value.bin");
        fs::write(&attr, (0..512).map(|n| (n * 37) as u8).collect::<Vec<_>>()).unwrap();
        for (block_size, explicit_seed) in [
            (1024, true),
            (1024, false),
            (2048, true),
            (2048, false),
            (4096, true),
            (4096, false),
        ] {
            let image = out.join(format!("default-b{block_size}-seed{explicit_seed}.img"));
            fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
            run(
                "mke2fs",
                vec![
                    "-q".into(),
                    "-F".into(),
                    "-t".into(),
                    "ext4".into(),
                    "-b".into(),
                    block_size.to_string(),
                    "-O".into(),
                    if explicit_seed {
                        "metadata_csum_seed"
                    } else {
                        "^metadata_csum_seed"
                    }
                    .into(),
                    "-d".into(),
                    input.display().to_string(),
                    image.display().to_string(),
                ],
                &mut receipt,
                &mut command,
            );
            for request in [
                "ea_set / user.inline native-value".to_owned(),
                format!("ea_set -f {} / user.external", attr.display()),
            ] {
                run(
                    "debugfs",
                    vec![
                        "-w".into(),
                        "-R".into(),
                        request,
                        image.display().to_string(),
                    ],
                    &mut receipt,
                    &mut command,
                );
            }
            // e2fsprogs authors the native directory index and its checksums.
            run(
                "e2fsck",
                vec!["-fyD".into(), image.display().to_string()],
                &mut receipt,
                &mut command,
            );
            run(
                "e2fsck",
                vec!["-fn".into(), image.display().to_string()],
                &mut receipt,
                &mut command,
            );
            let bytes = fs::read(&image).unwrap();
            let sb: [u8; 1024] = bytes[1024..2048].try_into().unwrap();
            let source: Arc<dyn ReadAt> = Arc::new(Image(bytes.clone()));
            let resources = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let proof = ModernProof::inspect(&source, &sb, &resources).unwrap();
            assert_eq!(proof.block_size, block_size);
            assert_eq!(proof.inode_size, 256);
            assert_eq!(proof.descriptor_size, 64);
            assert_eq!(proof.incompat & 0x2000 != 0, explicit_seed);
            let mut checked = 0;
            for number in [2, 7, 8, 11, proof.orphan_inode]
                .into_iter()
                .filter(|number| *number != 0)
            {
                let group = (number - 1) / proof.inodes_per_group;
                let slot = (number - 1) % proof.inodes_per_group;
                let table = u32le(&proof.descriptors[group as usize], 8);
                let start = table as usize * block_size as usize + slot as usize * 256;
                let inode = &bytes[start..start + 256];
                proof.checksums.inode(number, inode).unwrap();
                checked += 1;
                if number == 7 {
                    let ownership = super::super::resize::validate(
                        &source,
                        &proof,
                        inode.try_into().unwrap(),
                        &resources,
                    )
                    .unwrap();
                    assert!(proof.is_allocated(ownership.double_indirect, false));
                    assert!(!proof.metadata_block(ownership.double_indirect));
                    assert!(ownership.shared_reserved_blocks >= u32::from(proof.reserved_gdt));
                }
                if number == 2 || number == proof.orphan_inode {
                    let physical = u32le(inode, 60);
                    let generation = u32le(inode, 100);
                    let data = &bytes[physical as usize * block_size as usize
                        ..(physical as usize + 1) * block_size as usize];
                    if number == 2 {
                        assert_ne!(u32le(inode, 32) & 0x1000, 0, "native root must be indexed");
                        let logical_blocks = u32le(inode, 4) as usize / block_size as usize;
                        let mapping = native_mapping(&bytes, &proof, number, inode);
                        let index = super::super::indexed_directory::validate(
                            &proof.checksums,
                            super::super::indexed_directory::IndexOptions {
                                inode: number,
                                generation,
                                block_size: block_size as usize,
                                logical_blocks,
                                maximum_entries: 1024,
                                hash_seed: [
                                    u32le(&sb, 236),
                                    u32le(&sb, 240),
                                    u32le(&sb, 244),
                                    u32le(&sb, 248),
                                ],
                                unsigned_hash: u32le(&sb, 352) & 2 != 0,
                            },
                            &resources,
                            |logical, dst| {
                                let physical = mapping[logical];
                                dst.copy_from_slice(
                                    &bytes[physical * block_size as usize
                                        ..(physical + 1) * block_size as usize],
                                );
                                Ok(())
                            },
                        )
                        .unwrap();
                        assert!(index.nodes.iter().filter(|node| node.kind == 3).count() > 1);
                        if block_size == 1024 {
                            assert!(
                                index.nodes.iter().any(|node| node.kind == 2),
                                "native fixture must exercise internal directory index blocks"
                            );
                        }
                        drop(index);
                        let header = 128 + usize::from(u16le(inode, 128));
                        let inline =
                            super::super::xattr::validate(inode, header, false, &resources)
                                .unwrap();
                        assert!(inline.entries > 0);
                        let external = u32le(inode, 104);
                        assert_ne!(external, 0);
                        let block = &bytes[external as usize * block_size as usize
                            ..(external as usize + 1) * block_size as usize];
                        proof.checksums.xattr(u64::from(external), block).unwrap();
                        let external =
                            super::super::xattr::validate(block, 0, true, &resources).unwrap();
                        assert!(external.entries > 0);
                    } else {
                        proof
                            .checksums
                            .orphan(number, generation, u64::from(physical), data)
                            .unwrap();
                    }
                }
            }
            let volume = super::super::ExtVolume::open(source.clone(), &resources).unwrap();
            assert!(!volume.geometry().is_classic());
            let public_audit = crate::fs_ext_audit::audit(
                &volume,
                crate::fs_ext_audit::ExtAuditLimits {
                    blocks: 32768,
                    inodes: 8192,
                    work: 1_000_000,
                    directory_blocks: 1024,
                    directory_entries: 2048,
                    findings: 128,
                },
                &resources,
            )
            .unwrap();
            assert!(public_audit.is_clean(), "{:?}", public_audit.findings());
            drop(public_audit);
            drop(volume);
            {
                let volume = super::super::ExtVolume::open(source.clone(), &resources).unwrap();
                let decoder = volume.decoder();
                assert!(!decoder.geometry.is_classic());
                let directory = decoder.directory(2, 256, 1024, &resources).unwrap();
                assert_eq!(directory.entries().len(), 606);
                let find = |name: &[u8]| {
                    directory.entries().iter().find(|entry|matches!(&entry.name,crate::fs_core::NativeName::Bytes(bytes) if bytes == name)).unwrap()
                };
                assert_eq!(find(entry_name(599).as_bytes()).inode, find(b"alias").inode);
                assert_ne!(find(b"x\xffname").inode, find(b"large").inode);
                let entry = find(entry_name(599).as_bytes());
                let map = decoder
                    .file_map(entry.inode, 64, &resources, false)
                    .unwrap();
                let mut payload = [0; 17];
                decoder.read_map(&map, 0, &mut payload, &resources).unwrap();
                assert_eq!(payload, [599u16 as u8; 17]);
                drop(map);
                let map = decoder
                    .file_map(find(b"large").inode, 512, &resources, false)
                    .unwrap();
                assert_eq!(map.length, expected_payload.len() as u64);
                let mut buffer = [0; 513];
                let mut digest = Sha256::new();
                let mut offset = 0;
                while offset < expected_payload.len() {
                    let count = decoder
                        .read_map(&map, offset as u64, &mut buffer, &resources)
                        .unwrap();
                    assert_eq!(&buffer[..count], &expected_payload[offset..offset + count]);
                    digest.update(&buffer[..count]);
                    offset += count;
                }
                assert_eq!(
                    digest.finalize().as_slice(),
                    Sha256::digest(&expected_payload).as_slice()
                );
                assert_eq!(
                    decoder
                        .read_map(&map, map.length, &mut buffer, &resources)
                        .unwrap(),
                    0
                );
                drop(map);
                drop(directory);
                let report = crate::fs_ext_audit::audit_decoder(
                    decoder,
                    crate::fs_ext_audit::ExtAuditLimits {
                        blocks: 32768,
                        inodes: 8192,
                        work: 1_000_000,
                        directory_blocks: 1024,
                        directory_entries: 2048,
                        findings: 128,
                    },
                    &resources,
                )
                .unwrap();
                assert!(report.is_clean(), "{:?}", report.findings());
                drop(report);
                let tree = crate::fs_ext_tree::ExtTreeSource::inventory(
                    volume, 1024, 1024, 512, 1024, &resources,
                )
                .unwrap();
                let root = tree.root();
                let metadata = tree.metadata(&root, &resources).unwrap();
                assert!(matches!(
                    metadata.security,
                    MetadataField::Uninspectable { .. }
                ));
                let (_,encoding) = metadata.attributes.iter().find(|(name,_)|matches!(name,crate::fs_core::NativeName::Bytes(bytes) if bytes == b"ext.xattrs")).unwrap();
                assert!(
                    matches!(encoding,MetadataField::Opaque { bytes,.. } if bytes.len() > block_size as usize)
                );
                drop(metadata);
                let page = tree.directory_page(&root, None, 1024, &resources).unwrap();
                assert_eq!(page.entries.len(), 604);
                let find = |name: &[u8]| {
                    page.entries.iter().find(|entry|matches!(&entry.name,crate::fs_core::NativeName::Bytes(bytes) if bytes == name)).unwrap()
                };
                assert_eq!(
                    find(b"alias").object,
                    find(entry_name(599).as_bytes()).object
                );
                let file = tree
                    .open_stream(
                        &find(b"large").object,
                        &crate::fs_core::StreamKind::Data,
                        &resources,
                    )
                    .unwrap();
                let mut range = [0; 37];
                assert_eq!(
                    file.read_at(65530, &mut range, &resources).unwrap(),
                    range.len()
                );
                assert_eq!(&range, expected_payload[65530..65567].as_ref());
                drop(file);
                drop(page);
                drop(tree);
            }
            let dump = out.join(format!(
                "native-large-b{block_size}-seed{explicit_seed}.bin"
            ));
            run(
                "debugfs",
                vec![
                    "-R".into(),
                    format!("dump /large {}", dump.display()),
                    image.display().to_string(),
                ],
                &mut receipt,
                &mut command,
            );
            assert_eq!(fs::read(&dump).unwrap(), expected_payload);
            let groups = proof.descriptors.len();
            let normalized_bytes = proof.bitmaps.len();
            drop(proof);
            assert_eq!(resources.memory.used(), 0);
            run(
                "e2fsck",
                vec!["-fn".into(), image.display().to_string()],
                &mut receipt,
                &mut command,
            );
            assert_eq!(fs::read(&image).unwrap(), bytes);
            receipt.push_str(&format!("validated={block_size} explicit_checksum_seed={explicit_seed} image_sha256={:x} payload_sha256={:x} groups={groups} inode_checksums={checked} normalized_bitmap_bytes={normalized_bytes} public_reader_acceptance=true complete_audit=true tree_metadata=true indexed_native_entries=606 hardlink=true non_utf8=true inline_external_xattrs=true unchanged=true resource_refund=true\n", Sha256::digest(bytes),Sha256::digest(&expected_payload)));
        }
        for source in sources {
            assert_eq!(
                fs::read(source).unwrap(),
                fs::read(out.join("sources").join(source)).unwrap(),
                "source changed during gate"
            );
        }
        receipt.push_str("source_end_matches_start=true\nresult=pass\n");
        fs::write(out.join("receipt.txt"), receipt).unwrap();
        for entry in fs::read_dir(&out).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                fs::File::open(path).unwrap().sync_all().unwrap();
            }
        }
        fs::File::open(out).unwrap().sync_all().unwrap();
    }
}
