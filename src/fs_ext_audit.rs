//! Whole-volume classic ext2 allocation and namespace reference accounting.
//! Strict opening and ordinary file reads remain separate from this explicit audit.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{io, mem::size_of};
use crate::{
    fs_core::{Error, ErrorKind, NativeName, Reservation, Resources, Result},
    fs_ext::{ExtDecodeRead, ExtDecoder, ExtStorageDecoder, ExtVolume},
    storage::Storage,
};
/// Explicit geometry, namespace and work bounds for an immutable audit.
#[derive(Clone, Copy, Debug)]
pub struct ExtAuditLimits {
    /// Maximum declared filesystem blocks, including metadata.
    pub blocks: usize,
    /// Maximum declared inode slots, including reserved slots.
    pub inodes: usize,
    /// Maximum decoded bitmap bits, inode slots, pointer slots and descriptor records.
    pub work: usize,
    /// Maximum total logical blocks scanned across all directory payloads.
    pub directory_blocks: usize,
    /// Maximum retained directory references, including dot references.
    pub directory_entries: usize,
    /// Maximum retained diagnostic records; exhaustion returns an error, never a clean report.
    pub findings: usize,
}
/// A defect established by an accounting pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtAuditFinding {
    /// An allocated block has no metadata or inode owner.
    LostBlock {
        /// Volume-relative block number.
        block: u32,
    },
    /// An inode/metadata reference points at a free block.
    ReferencedFreeBlock {
        /// Block number.
        block: u32,
        /// Inode owner; zero means filesystem metadata.
        inode: u32,
    },
    /// Multiple pointers claim one block, including data/indirect aliases.
    CrossLink {
        /// Block number.
        block: u32,
        /// First inode owner; zero means filesystem metadata.
        first_inode: u32,
        /// Second inode owner.
        second_inode: u32,
    },
    /// An indirect path refers back to its own ancestor.
    IndirectCycle {
        /// Inode number.
        inode: u32,
        /// Revisited indirect block.
        block: u32,
    },
    /// An allocation pointer is outside the declared filesystem.
    InvalidBlock {
        /// Inode number.
        inode: u32,
        /// Invalid block number.
        block: u32,
    },
    /// A nonzero classic map pointer occurs beyond the file's logical EOF.
    BeyondEof {
        /// Inode number.
        inode: u32,
        /// Allocated data or indirect block.
        block: u32,
    },
    /// The inode's 512-byte sector count disagrees with its complete block map.
    BlockCount {
        /// Inode number.
        inode: u32,
        /// Native 512-byte sector count.
        recorded: u32,
        /// Count established by the map, including indirect blocks.
        actual: u64,
    },
    /// An allocated ordinary inode is deleted, unlinked, or has no valid mode.
    InvalidInode {
        /// Inode number.
        inode: u32,
    },
    /// An ordinary allocated inode is unreachable from root inode two.
    UnreachableInode {
        /// Inode number.
        inode: u32,
    },
    /// A directory refers to an out-of-range, reserved or unallocated inode.
    InvalidInodeReference {
        /// Containing directory inode.
        directory: u32,
        /// Referenced inode number.
        inode: u32,
    },
    /// Directory record type disagrees with the referenced inode.
    DirectoryType {
        /// Containing directory.
        directory: u32,
        /// Referenced inode.
        inode: u32,
    },
    /// Native link count differs from all directory references, including dot entries.
    LinkCount {
        /// Inode number.
        inode: u32,
        /// Native link count.
        recorded: u16,
        /// Counted directory references.
        actual: u64,
    },
    /// A directory could not be decoded; link/reachability completeness is false.
    InvalidDirectory {
        /// Directory inode number.
        inode: u32,
    },
    /// Dot or dot-dot topology is missing or inconsistent with root traversal.
    DirectoryTopology {
        /// Directory inode number.
        inode: u32,
    },
    /// A directory has multiple non-dot parents or a directory cycle.
    DirectoryAlias {
        /// Referenced directory inode number.
        inode: u32,
    },
    /// A group bitmap free count differs from its descriptor.
    GroupFreeCount {
        /// Group number.
        group: u32,
        /// True for inode bitmap; false for block bitmap.
        inodes: bool,
        /// Descriptor count.
        recorded: u16,
        /// Counted free objects.
        actual: u32,
    },
    /// A primary superblock free count differs from complete bitmap accounting.
    SuperFreeCount {
        /// True for inode bitmap; false for block bitmap.
        inodes: bool,
        /// Primary superblock count.
        recorded: u32,
        /// Counted free objects.
        actual: u64,
    },
    /// Group directory count differs from allocated directory inode accounting.
    GroupDirectoryCount {
        /// Group number.
        group: u32,
        /// Descriptor count.
        recorded: u16,
        /// Counted directory inodes.
        actual: u32,
    },
    /// An out-of-range bitmap tail bit is not marked allocated.
    BitmapTail {
        /// Group number.
        group: u32,
        /// True for inode bitmap.
        inodes: bool,
    },
    /// A backup superblock's static geometry/features/UUID disagree with the primary.
    BackupSuperblock {
        /// Backup group number.
        group: u32,
    },
    /// A backup descriptor's metadata pointers disagree with the primary.
    BackupDescriptor {
        /// Backup group number.
        backup_group: u32,
        /// Descriptor's group number.
        group: u32,
    },
}
/// A data-only range available only when the complete audit has no findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtFreeRange {
    /// Volume-relative byte offset.
    pub offset: u64,
    /// Byte length.
    pub length: u64,
}
/// Bounded audit evidence; no write, exclusivity or durability authority is granted.
pub struct ExtAuditReport {
    findings: Vec<ExtAuditFinding>,
    free: Vec<ExtFreeRange>,
    namespace_complete: bool,
    complete: bool,
    allocated_inodes: usize,
    owned_blocks: usize,
    _reservation: Reservation,
}
impl ExtAuditReport {
    /// Established allocation/reference defects.
    pub fn findings(&self) -> &[ExtAuditFinding] {
        &self.findings
    }
    /// Whether every allocated directory was decoded for reference accounting.
    pub fn namespace_complete(&self) -> bool {
        self.namespace_complete
    }
    /// Whether every accounting pass ran to completion.
    pub fn complete(&self) -> bool {
        self.complete
    }
    /// Whether all passes completed and no defect was found.
    pub fn is_clean(&self) -> bool {
        self.complete && self.namespace_complete && self.findings.is_empty()
    }
    /// Audited unallocated data ranges; withheld whenever the audit has any defect.
    pub fn free_ranges(&self) -> &[ExtFreeRange] {
        if self.is_clean() { &self.free } else { &[] }
    }
    /// Number of ordinary allocated inodes, including unreachable ones.
    pub fn allocated_inodes(&self) -> usize {
        self.allocated_inodes
    }
    /// Number of uniquely claimed inode payload/indirect blocks, excluding filesystem metadata.
    /// Zero when final allocation accounting did not complete.
    pub fn owned_blocks(&self) -> usize {
        self.owned_blocks
    }
}
/// A failed audit together with any evidence established before the failure.
/// Partial reports retain their memory reservation and never authorize free space.
pub struct ExtAuditFailure {
    /// The reason the accounting passes stopped.
    pub error: Error,
    /// Evidence retained after scan initialization; absent when setup failed.
    pub partial: Option<ExtAuditReport>,
}
impl From<Error> for ExtAuditFailure {
    fn from(error: Error) -> Self {
        Self {
            error,
            partial: None,
        }
    }
}
#[derive(Clone, Default)]
struct Inode {
    mode: u16,
    links: u16,
    size: u32,
    sectors: u32,
    pointers: [u32; 15],
    allocated: bool,
    flags: u32,
    external_xattr: u32,
}
#[derive(Clone, Copy)]
struct Edge {
    child: u32,
    dot: u8,
}
fn word(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn dword(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn convert(error: io::Error) -> Error {
    Error::classified_io("ext2 audit input", error)
}
fn zeros<T: Default + Clone>(count: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(count)
        .map_err(|_| budget("audit allocation failed"))?;
    v.resize(count, T::default());
    Ok(v)
}
struct Mapping {
    inode: u32,
    file_blocks: u64,
    path: [u32; 3],
    sectors: u64,
}
struct Scan<'a, R> {
    volume: &'a ExtDecoder<R>,
    resources: &'a Resources,
    limits: ExtAuditLimits,
    work: usize,
    owners: Vec<u64>,
    allocated: Vec<u8>,
    findings: Vec<ExtAuditFinding>,
    xattr_references: Vec<u16>,
    xattr_expected: Vec<u16>,
}
impl<R: ExtDecodeRead> Scan<'_, R> {
    fn classic_xattr_reader_work(&mut self, external: u32, scans: usize) -> Result<()> {
        if self.volume.geometry().modern.is_none() && external != 0 {
            let count = (self.volume.geometry().block_size as usize)
                .checked_mul(258)
                .and_then(|v| v.checked_mul(scans))
                .ok_or_else(|| budget("classic xattr reader work overflow"))?;
            for _ in 0..count {
                self.step()?;
            }
        }
        Ok(())
    }
    fn claim_xattr(&mut self, block: u32, inode: u32) -> Result<()> {
        self.step()?;
        if block < self.volume.geometry().first || block >= self.volume.geometry().blocks {
            return Err(Error::new(ErrorKind::InvalidData, "ext xattr block bounds"));
        }
        if self.owners[block as usize] != u64::MAX - 1 && self.claim(block, inode)? {
            self.owners[block as usize] = u64::MAX - 1;
        }
        let expected = if self.volume.geometry().modern.is_some() {
            let mut header = [0; 32];
            self.read(
                u64::from(block) * u64::from(self.volume.geometry().block_size),
                &mut header,
            )?;
            u16::try_from(dword(&header, 4))
                .map_err(|_| Error::new(ErrorKind::Unsupported, "ext xattr reference count"))?
        } else {
            let mut bytes = [0; 4096];
            let bs = self.volume.geometry().block_size as usize;
            self.read(u64::from(block) * bs as u64, &mut bytes[..bs])?;
            // Classic admission now charges a conservative complete layout scan.
            for _ in 0..bs.saturating_mul(258) {
                self.step()?;
            }
            let references = self
                .volume
                .external_xattr_reference_count(&bytes[..bs], self.resources)
                .map_err(convert)?;
            u16::try_from(references)
                .map_err(|_| Error::new(ErrorKind::Unsupported, "ext xattr reference count"))?
        };
        let count = &mut self.xattr_references[block as usize];
        if *count != 0 && self.xattr_expected[block as usize] != expected {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext xattr reference header changed during audit",
            ));
        }
        *count = count
            .checked_add(1)
            .ok_or_else(|| budget("ext xattr reference overflow"))?;
        self.xattr_expected[block as usize] = expected;
        Ok(())
    }
    fn step(&mut self) -> Result<()> {
        self.resources.cancellation.check()?;
        self.work = self
            .work
            .checked_add(1)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("ext2 audit work limit"))?;
        Ok(())
    }
    fn finding(&mut self, finding: ExtAuditFinding) -> Result<()> {
        if self.findings.len() == self.limits.findings {
            return Err(budget("ext2 audit findings limit"));
        }
        self.findings.push(finding);
        Ok(())
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        self.resources.cancellation.check()?;
        self.volume.read_exact_at(offset, out).map_err(convert)
    }
    fn claim(&mut self, block: u32, inode: u32) -> Result<bool> {
        let g = self.volume.geometry();
        if block < g.first || block >= g.blocks {
            self.finding(ExtAuditFinding::InvalidBlock { inode, block })?;
            return Ok(false);
        }
        if self.allocated[block as usize] == 0 {
            self.finding(ExtAuditFinding::ReferencedFreeBlock { block, inode })?;
        }
        let previous = self.owners[block as usize];
        if previous != 0 {
            self.finding(ExtAuditFinding::CrossLink {
                block,
                first_inode: if previous >= u64::MAX - 1 {
                    0
                } else {
                    previous as u32
                },
                second_inode: inode,
            })?;
            return Ok(false);
        }
        self.owners[block as usize] = if inode == 0 {
            u64::MAX
        } else {
            u64::from(inode)
        };
        Ok(true)
    }
    fn pointer(
        &mut self,
        block: u32,
        depth: u32,
        logical: u64,
        mapping: &mut Mapping,
    ) -> Result<bool> {
        let inode = mapping.inode;
        let file_blocks = mapping.file_blocks;
        self.step()?;
        if block == 0 {
            return Ok(true);
        }
        if logical >= file_blocks {
            self.finding(ExtAuditFinding::BeyondEof { inode, block })?;
        }
        if depth > 0 && mapping.path[..(3 - depth) as usize].contains(&block) {
            self.finding(ExtAuditFinding::IndirectCycle { inode, block })?;
            return Ok(false);
        }
        if !self.claim(block, inode)? {
            return Ok(false);
        }
        mapping.sectors += u64::from(self.volume.geometry().block_size) / 512;
        if depth == 0 {
            return Ok(true);
        }
        let n = self.volume.geometry().block_size / 4;
        let stride = u64::from(n).pow(depth - 1);
        let mut complete = true;
        // One bounded stack buffer per indirect depth; recursion is at most three.
        let mut bytes = [0; 4096];
        self.read(
            u64::from(block) * u64::from(self.volume.geometry().block_size),
            &mut bytes[..self.volume.geometry().block_size as usize],
        )?;
        mapping.path[(3 - depth) as usize] = block;
        for slot in 0..n {
            let child = dword(&bytes, slot as usize * 4);
            complete &= self.pointer(
                child,
                depth - 1,
                logical + u64::from(slot) * stride,
                mapping,
            )?;
        }
        Ok(complete)
    }
}
/// Audit every bitmap, allocated inode, complete classic map and directory reference.
///
/// Accepted classic inode kinds include regular files/directories and explicit terminated fast/one-direct symlinks, plus empty reserved slots.
/// Unsupported inode features or special allocated objects fail explicitly.
/// Findings do not truncate the remaining accounting passes; exhausted budgets do.
pub fn audit(
    volume: &ExtVolume,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> Result<ExtAuditReport> {
    audit_decoder(volume.decoder(), limits, resources)
}
pub(crate) fn audit_ext_storage(
    source: &dyn Storage,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> Result<ExtAuditReport> {
    audit_ext_storage_detailed(source, limits, resources).map_err(|failure| failure.error)
}
/// Audit while retaining established findings if a later pass fails.
#[expect(
    clippy::result_large_err,
    reason = "failure retains leased evidence without another allocation"
)]
pub fn audit_detailed(
    volume: &ExtVolume,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> core::result::Result<ExtAuditReport, ExtAuditFailure> {
    audit_decoder_detailed(volume.decoder(), limits, resources)
}
#[expect(
    clippy::result_large_err,
    reason = "failure retains leased evidence without another allocation"
)]
pub(crate) fn audit_ext_storage_detailed(
    source: &dyn Storage,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> core::result::Result<ExtAuditReport, ExtAuditFailure> {
    let decoder = ExtStorageDecoder::open_storage(source, 0, resources).map_err(convert)?;
    audit_decoder_detailed(&decoder, limits, resources)
}
pub(crate) fn audit_decoder<R: ExtDecodeRead>(
    volume: &ExtDecoder<R>,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> Result<ExtAuditReport> {
    audit_decoder_detailed(volume, limits, resources).map_err(|failure| failure.error)
}
#[expect(
    clippy::result_large_err,
    reason = "failure retains leased evidence without another allocation"
)]
fn audit_decoder_detailed<R: ExtDecodeRead>(
    volume: &ExtDecoder<R>,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> core::result::Result<ExtAuditReport, ExtAuditFailure> {
    resources.cancellation.check()?;
    let g = volume.geometry();
    if g.blocks as u64 > limits.blocks as u64 || g.inodes as u64 > limits.inodes as u64 {
        return Err(budget("ext2 audit geometry cap").into());
    }
    let inode_count =
        usize::try_from(u64::from(g.inodes) + 1).map_err(|_| budget("inode address space"))?;
    let block_count = g.blocks as usize;
    let bytes = (block_count as u64)
        .checked_mul(48)
        .and_then(|n| n.checked_add((inode_count as u64).checked_mul(128)?))
        .and_then(|n| n.checked_add((limits.directory_entries as u64).checked_mul(32)?))
        .and_then(|n| {
            n.checked_add(
                (limits.findings as u64).checked_mul(size_of::<ExtAuditFinding>() as u64)?,
            )
        })
        .and_then(|n| n.checked_add(32 * 1024))
        .ok_or_else(|| budget("ext2 audit accounting overflow"))?;
    let reservation = resources.memory.reserve(bytes)?;
    let mut findings = Vec::new();
    findings
        .try_reserve_exact(limits.findings)
        .map_err(|_| budget("finding allocation"))?;
    let mut scan = Scan {
        volume,
        resources,
        limits,
        work: 0,
        owners: zeros(block_count)?,
        allocated: zeros(block_count)?,
        findings,
        xattr_references: zeros(if g.external_xattrs { block_count } else { 0 })?,
        xattr_expected: zeros(if g.external_xattrs { block_count } else { 0 })?,
    };
    let mut allocated_inodes = 0;
    let outcome = (|| -> Result<_> {
        let mut superblock = [0; 1024];
        scan.read(1024, &mut superblock)?;
        let first_inode = if dword(&superblock, 76) == 0 {
            11
        } else {
            dword(&superblock, 84)
        };
        if first_inode != 11 || g.inodes < 11 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 audit requires standard reserved inode range 1..11",
            ));
        }
        let mut inodes: Vec<Inode> = zeros(inode_count)?;
        let mut references: Vec<u64> = zeros(inode_count)?;
        let mut reachable: Vec<bool> = zeros(inode_count)?;
        let mut group_dirs: Vec<u16> = zeros(g.groups as usize)?;
        let mut free_blocks = 0u64;
        let mut free_inodes = 0u64;
        for group in 0..g.groups {
            scan.step()?;
            let descriptor = volume.group(group).map_err(convert)?;
            let mut raw = [0; 32];
            scan.read(
                u64::from(g.first + 1) * u64::from(g.block_size) + u64::from(group) * 32,
                &mut raw,
            )?;
            if let Some(proof) = &g.modern {
                raw.copy_from_slice(&proof.descriptors[group as usize][..32]);
            }
            group_dirs[group as usize] = word(&raw, 16);
            let start = u64::from(g.first) + u64::from(group) * u64::from(g.blocks_per_group);
            let count = (u64::from(g.blocks) - start).min(u64::from(g.blocks_per_group)) as usize;
            let inode_start = u64::from(group) * u64::from(g.inodes_per_group);
            let inode_slots =
                (u64::from(g.inodes) - inode_start).min(u64::from(g.inodes_per_group)) as usize;
            let mut block_bitmap = [0; 4096];
            let mut inode_bitmap = [0; 4096];
            let bs = g.block_size as usize;
            scan.read(
                u64::from(descriptor[0]) * u64::from(g.block_size),
                &mut block_bitmap[..bs],
            )?;
            scan.read(
                u64::from(descriptor[1]) * u64::from(g.block_size),
                &mut inode_bitmap[..bs],
            )?;
            if let Some(proof) = &g.modern {
                let start = group as usize * 2 * bs;
                block_bitmap[..bs].copy_from_slice(&proof.bitmaps[start..start + bs]);
                inode_bitmap[..bs].copy_from_slice(&proof.bitmaps[start + bs..start + 2 * bs]);
            }
            let mut blocks_free = 0u32;
            let mut inodes_free = 0u32;
            let mut bad_block_tail = false;
            let mut bad_inode_tail = false;
            for bit in 0..bs * 8 {
                scan.step()?;
                let allocated = block_bitmap[bit / 8] & (1 << (bit % 8)) != 0;
                if bit < count {
                    scan.allocated[start as usize + bit] = u8::from(allocated);
                    blocks_free += u32::from(!allocated);
                } else if !allocated {
                    bad_block_tail = true;
                }
            }
            for bit in 0..bs * 8 {
                scan.step()?;
                let allocated = inode_bitmap[bit / 8] & (1 << (bit % 8)) != 0;
                if bit < inode_slots {
                    inodes[inode_start as usize + bit + 1].allocated = allocated;
                    inodes_free += u32::from(!allocated);
                } else if !allocated {
                    bad_inode_tail = true;
                }
            }
            free_blocks += u64::from(blocks_free);
            free_inodes += u64::from(inodes_free);
            if blocks_free != u32::from(word(&raw, 12)) {
                scan.finding(ExtAuditFinding::GroupFreeCount {
                    group,
                    inodes: false,
                    recorded: word(&raw, 12),
                    actual: blocks_free,
                })?;
            }
            if inodes_free != u32::from(word(&raw, 14)) {
                scan.finding(ExtAuditFinding::GroupFreeCount {
                    group,
                    inodes: true,
                    recorded: word(&raw, 14),
                    actual: inodes_free,
                })?;
            }
            if bad_block_tail {
                scan.finding(ExtAuditFinding::BitmapTail {
                    group,
                    inodes: false,
                })?;
            }
            if bad_inode_tail {
                scan.finding(ExtAuditFinding::BitmapTail {
                    group,
                    inodes: true,
                })?;
            }
            for block in start..volume.reserved_end(group) {
                scan.step()?;
                scan.claim(block as u32, 0)?;
            }
            for block in &descriptor[..2] {
                scan.claim(*block, 0)?;
            }
            let table_blocks = (u64::from(g.inodes_per_group) * u64::from(g.inode_size))
                .div_ceil(u64::from(g.block_size));
            for block in u64::from(descriptor[2])..u64::from(descriptor[2]) + table_blocks {
                scan.step()?;
                scan.claim(block as u32, 0)?;
            }
            if group != 0 && volume.reserved_end(group) > start {
                let mut backup = [0; 1024];
                scan.read(start * u64::from(g.block_size), &mut backup)?;
                if let Some(proof) = &g.modern {
                    proof.backup_superblock(&backup).map_err(convert)?;
                }
                let equal = [(0, 12), (20, 44), (56, 58), (72, 90), (92, 120)]
                    .iter()
                    .all(|(a, b)| superblock[*a..*b] == backup[*a..*b])
                    && (g.inode_size != 256 || superblock[348..352] == backup[348..352]);
                if !equal {
                    scan.finding(ExtAuditFinding::BackupSuperblock { group })?;
                }
                for original in 0..g.groups {
                    scan.step()?;
                    let pointers = volume.group(original).map_err(convert)?;
                    let stride = 32u64;
                    let stride = g
                        .modern
                        .as_ref()
                        .map_or(stride, |proof| u64::from(proof.descriptor_size));
                    let mut d = [0; 64];
                    let length = 12;
                    let length = g
                        .modern
                        .as_ref()
                        .map_or(length, |proof| usize::from(proof.descriptor_size));
                    scan.read(
                        (start + 1) * u64::from(g.block_size) + u64::from(original) * stride,
                        &mut d[..length],
                    )?;
                    if let Some(proof) = &g.modern {
                        proof
                            .checksums
                            .descriptor(original, &d[..length])
                            .map_err(convert)?;
                        let primary = &proof.descriptors[original as usize];
                        if d[20..24] != primary[20..24]
                            || d[32..56] != primary[32..56]
                            || d[60..64] != primary[60..64]
                        {
                            scan.finding(ExtAuditFinding::BackupDescriptor {
                                backup_group: group,
                                group: original,
                            })?;
                        }
                    }
                    if pointers != [dword(&d, 0), dword(&d, 4), dword(&d, 8)] {
                        scan.finding(ExtAuditFinding::BackupDescriptor {
                            backup_group: group,
                            group: original,
                        })?;
                    }
                }
            }
        }
        if free_blocks != u64::from(dword(&superblock, 12)) {
            scan.finding(ExtAuditFinding::SuperFreeCount {
                inodes: false,
                recorded: dword(&superblock, 12),
                actual: free_blocks,
            })?;
        }
        if free_inodes != u64::from(dword(&superblock, 16)) {
            scan.finding(ExtAuditFinding::SuperFreeCount {
                inodes: true,
                recorded: dword(&superblock, 16),
                actual: free_inodes,
            })?;
        }
        let mut dirs: Vec<u32> = zeros(g.groups as usize)?;
        for number in 1..=g.inodes {
            scan.step()?;
            if !inodes[number as usize].allocated {
                if number < first_inode {
                    scan.finding(ExtAuditFinding::InvalidInode { inode: number })?;
                }
                continue;
            }
            let descriptor = volume
                .group((number - 1) / g.inodes_per_group)
                .map_err(convert)?;
            let mut raw = [0; 128];
            let inode_offset = u64::from(descriptor[2]) * u64::from(g.block_size)
                + u64::from((number - 1) % g.inodes_per_group) * u64::from(g.inode_size);
            scan.read(inode_offset, &mut raw)?;
            let mut extra = [0; 128];
            if g.inode_size == 256 {
                scan.read(inode_offset + 128, &mut extra)?;
            }
            let mut native_observation = None;
            if let Some(proof) = &g.modern {
                let mut whole = [0; 256];
                whole[..128].copy_from_slice(&raw);
                whole[128..].copy_from_slice(&extra);
                if word(&raw, 0) != 0 {
                    proof
                        .checksums
                        .inode(number, &whole[..usize::from(g.inode_size)])
                        .map_err(convert)?;
                }
                if number == 7 && proof.compat & 0x10 != 0 {
                    // Charge every checked root/leaf pointer slot before the hidden map reads.
                    for _ in 0..(u32::from(proof.reserved_gdt) + 1) * (g.block_size / 4) {
                        scan.step()?;
                    }
                    let (block, shared) =
                        volume.resize_block(&whole, resources).map_err(convert)?;
                    for _ in 0..shared {
                        scan.step()?;
                    }
                    scan.claim(block, number)?;
                    continue;
                }
                if word(&raw, 0) != 0 {
                    native_observation = Some(volume.inode(number, resources).map_err(convert)?);
                }
            }
            let classic_extension = g.modern.is_none();
            if g.inode_size == 256 && classic_extension {
                let size = crate::fs_ext::ExtInode::validate_extra(&extra).map_err(convert)?;
                if word(&raw, 0) != 0 && size < g.minimum_extra_size {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "ext inode extension below filesystem minimum",
                    ));
                }
            }
            let journal = g.has_journal && number == g.journal_inode;
            if g.modern
                .as_ref()
                .is_some_and(|proof| proof.orphan_inode == number)
            {
                volume.validate_modern_orphan(resources).map_err(convert)?;
            }
            if number < first_inode && number != 2 && !journal {
                if word(&raw, 0) != 0
                    || dword(&raw, 4) != 0
                    || word(&raw, 26) != 0
                    || dword(&raw, 28) != 0
                    || dword(&raw, 32) != 0
                    || raw[40..100].iter().any(|b| *b != 0)
                    || raw[104..120].iter().any(|b| *b != 0)
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "reserved ext2 inode owns unsupported allocation (including bad-block inode)",
                    ));
                }
                continue;
            }
            let xattr_sectors = 0u64;
            let xattr_sectors = if g.external_xattrs && dword(&raw, 104) != 0 {
                scan.claim_xattr(dword(&raw, 104), number)?;
                u64::from(g.block_size) / 512
            } else {
                xattr_sectors
            };
            let hidden = journal;
            let hidden = hidden
                || g.modern
                    .as_ref()
                    .is_some_and(|proof| proof.orphan_inode == number);
            if !hidden {
                allocated_inodes += 1;
            }
            let inode = &mut inodes[number as usize];
            inode.mode = word(&raw, 0);
            inode.links = word(&raw, 26);
            inode.size = dword(&raw, 4);
            inode.sectors = dword(&raw, 28);
            inode.flags = dword(&raw, 32);
            inode.external_xattr = dword(&raw, 104);
            for (i, p) in inode.pointers.iter_mut().enumerate() {
                *p = dword(&raw, 40 + i * 4);
            }
            if g.modern.is_some() {
                let flags = dword(&raw, 32) & !0x1000;
                raw[32..36].copy_from_slice(&flags.to_le_bytes());
            }
            if g.external_xattrs {
                raw[104..108].fill(0);
            }
            let allowed_flags = if g.extent_profile { 0x80000 } else { 0 };
            if dword(&raw, 32) & !allowed_flags != 0
                || dword(&raw, 104) != 0
                || dword(&raw, 108) != 0
                || dword(&raw, 112) != 0
                || raw[116..120].iter().any(|b| *b != 0)
            {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "ext2 audit inode flags/xattrs/high-size/fragments unsupported",
                ));
            }
            if matches!(inode.mode & 0xf000, 0x1000 | 0x2000 | 0x6000 | 0xc000) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "ext2 audit special inode profile unsupported",
                ));
            }
            if !matches!(inode.mode & 0xf000, 0x4000 | 0x8000 | 0xa000)
                || inode.links == 0
                || dword(&raw, 20) != 0
            {
                scan.finding(ExtAuditFinding::InvalidInode { inode: number })?;
            }
            if inode.mode & 0xf000 == 0x4000 {
                dirs[((number - 1) / g.inodes_per_group) as usize] += 1;
            }
            if inode.mode & 0xf000 == 0xa000 {
                // The target is a leaf namespace object; never interpret fast
                // target bytes as allocation pointers or follow its contents.
                if (g.modern.is_none() && (g.extent_profile || inode.flags & 0x80000 != 0))
                    || !matches!(g.block_size, 1024 | 2048 | 4096)
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "audit symlink requires classic 1/2/4KiB profile",
                    ));
                }
                let length = inode.size as usize;
                if length == 0 || length >= g.block_size as usize {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "audit symlink target length",
                    ));
                }
                if u64::from(inode.sectors) == xattr_sectors {
                    if inode.flags & 0x80000 != 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "audit fast symlink cannot carry extent flag",
                        ));
                    }
                    if length >= 60 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "audit fast symlink target exceeds terminated storage",
                        ));
                    }
                    for byte in &raw[40..40 + length] {
                        scan.step()?;
                        if *byte == 0 {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "audit symlink target contains NUL",
                            ));
                        }
                    }
                    scan.step()?;
                    if raw[40 + length] != 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "audit fast symlink terminator",
                        ));
                    }
                } else {
                    // Keep noncanonical block-backed short source profiles
                    // unqualified; the general reader remains independent.
                    if length < 60 {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "audit short block-backed symlink profile unqualified",
                        ));
                    }
                    let body = if g.modern.is_some() && inode.flags & 0x80000 != 0 {
                        let cap = limits.blocks.min(6); // at most depth5 nodes plus one body block.
                        let charged = cap
                            .checked_mul(g.block_size as usize + 8)
                            .and_then(|n| n.checked_add(64))
                            .ok_or_else(|| budget("audit symlink extent work overflow"))?;
                        for _ in 0..charged {
                            scan.step()?;
                        }
                        let native = native_observation.as_ref().ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "audit modern symlink inode evidence missing",
                            )
                        })?;
                        let decoded = volume
                            .extent_allocations(native, cap, resources)
                            .map_err(convert)?;
                        if decoded.allocations.len() != 1
                            || decoded.allocations[0].logical != 0
                            || decoded.allocations[0].blocks != 1
                            || decoded.allocations[0].unwritten
                        {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "audit slow symlink requires one initialized logical body block",
                            ));
                        }
                        let sectors = (decoded.metadata.len() as u64 + 1)
                            .checked_mul(u64::from(g.block_size / 512))
                            .and_then(|n| n.checked_add(xattr_sectors))
                            .ok_or_else(|| budget("audit symlink sectors overflow"))?;
                        if u64::from(inode.sectors) != sectors {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "audit slow symlink extent sector count",
                            ));
                        }
                        for &block in &decoded.metadata {
                            scan.step()?;
                            scan.claim(block, number)?;
                        }
                        decoded.allocations[0].physical
                    } else {
                        let mut extra_pointer = false;
                        for block in &inode.pointers[1..] {
                            scan.step()?;
                            extra_pointer |= *block != 0;
                        }
                        if u64::from(inode.sectors) != u64::from(g.block_size / 512) + xattr_sectors
                            || inode.pointers[0] == 0
                            || extra_pointer
                        {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "audit slow symlink requires exactly one direct block",
                            ));
                        }
                        inode.pointers[0]
                    };
                    scan.step()?;
                    if scan.claim(body, number)? {
                        let mut target = [0; 4096];
                        let bs = g.block_size as usize;
                        scan.read(u64::from(body) * u64::from(g.block_size), &mut target[..bs])?;
                        for byte in &target[..length] {
                            scan.step()?;
                            if *byte == 0 {
                                return Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "audit symlink target contains NUL",
                                ));
                            }
                        }
                        scan.step()?;
                        if target[length] != 0 {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "audit slow symlink terminator",
                            ));
                        }
                    }
                }
                // Directory traversal below counts every exact alias and type7;
                // reachability treats this inode as a non-directory leaf.
                continue;
            }
            if dword(&raw, 32) & 0x80000 != 0 {
                scan.classic_xattr_reader_work(inode.external_xattr, 1)?;
                let native = volume.inode(number, resources).map_err(convert)?;
                let decoded = volume
                    .extent_allocations(&native, limits.blocks, resources)
                    .map_err(convert)?;
                let orphan = g
                    .modern
                    .as_ref()
                    .filter(|proof| proof.orphan_inode == number);
                if orphan.is_some()
                    && (inode.mode != 0o100600
                        || inode.links != 1
                        || xattr_sectors != 0
                        || inode.size == 0
                        || !inode.size.is_multiple_of(g.block_size))
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "ext orphan file inode profile",
                    ));
                }
                let mut orphan_logical = 0u64;
                let mut actual = xattr_sectors;
                for block in decoded.metadata {
                    scan.step()?;
                    scan.claim(block, number)?;
                    actual += u64::from(g.block_size) / 512;
                }
                for allocation in decoded.allocations {
                    if orphan.is_some() {
                        if allocation.unwritten || allocation.logical != orphan_logical {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "ext orphan file hole/unwritten mapping",
                            ));
                        }
                        orphan_logical += u64::from(allocation.blocks);
                    }
                    for block in allocation.physical..allocation.physical + allocation.blocks {
                        scan.step()?;
                        if let Some(proof) = orphan {
                            let mut bytes = [0; 4096];
                            scan.read(
                                u64::from(block) * u64::from(g.block_size),
                                &mut bytes[..g.block_size as usize],
                            )?;
                            proof
                                .checksums
                                .orphan(
                                    number,
                                    native.generation(),
                                    u64::from(block),
                                    &bytes[..g.block_size as usize],
                                )
                                .map_err(convert)?;
                        }
                        scan.claim(block, number)?;
                        actual += u64::from(g.block_size) / 512;
                    }
                    if !allocation.unwritten
                        && allocation.logical + u64::from(allocation.blocks)
                            > u64::from(inode.size).div_ceil(u64::from(g.block_size))
                    {
                        scan.finding(ExtAuditFinding::BeyondEof {
                            inode: number,
                            block: allocation.physical,
                        })?;
                    }
                }
                if orphan.is_some() && orphan_logical != u64::from(inode.size / g.block_size) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "ext orphan file complete initialized length",
                    ));
                }
                if actual != u64::from(inode.sectors) {
                    scan.finding(ExtAuditFinding::BlockCount {
                        inode: number,
                        recorded: inode.sectors,
                        actual,
                    })?;
                }
                continue;
            }
            let pointers = inode.pointers;
            let file_blocks = u64::from(inode.size).div_ceil(u64::from(g.block_size));
            let recorded = inode.sectors;
            let mut mapping = Mapping {
                inode: number,
                file_blocks,
                path: [0; 3],
                sectors: xattr_sectors,
            };
            let mut complete = true;
            for (slot, block) in pointers[..12].iter().enumerate() {
                complete &= scan.pointer(*block, 0, slot as u64, &mut mapping)?;
            }
            let n = u64::from(g.block_size) / 4;
            let mut logical = 12;
            for depth in 1..=3 {
                complete &=
                    scan.pointer(pointers[11 + depth as usize], depth, logical, &mut mapping)?;
                logical += n.pow(depth);
            }
            if complete && mapping.sectors != u64::from(recorded) {
                scan.finding(ExtAuditFinding::BlockCount {
                    inode: number,
                    recorded,
                    actual: mapping.sectors,
                })?;
            }
        }
        for group in 0..g.groups {
            if dirs[group as usize] != u32::from(group_dirs[group as usize]) {
                scan.finding(ExtAuditFinding::GroupDirectoryCount {
                    group,
                    recorded: group_dirs[group as usize],
                    actual: dirs[group as usize],
                })?;
            }
        }
        let mut ranges: Vec<(usize, usize)> = zeros(inode_count)?;
        let mut decoded: Vec<bool> = zeros(inode_count)?;
        let mut directory_entries = 0usize;
        let mut edges = Vec::new();
        edges
            .try_reserve_exact(limits.directory_entries)
            .map_err(|_| budget("directory edge allocation"))?;
        let mut directory_work = 0usize;
        let mut namespace_complete = true;
        for number in 1..=g.inodes {
            if !inodes[number as usize].allocated || inodes[number as usize].mode & 0xf000 != 0x4000
            {
                continue;
            }
            let blocks = u64::from(inodes[number as usize].size).div_ceil(u64::from(g.block_size));
            directory_work = directory_work
                .checked_add(
                    usize::try_from(blocks).map_err(|_| budget("directory block address space"))?,
                )
                .filter(|n| *n <= limits.directory_blocks)
                .ok_or_else(|| budget("ext2 audit directory block work limit"))?;
            let remaining = limits.directory_entries - directory_entries;
            // directory_inner validates the directory inode, then file_map
            // validates it again. Charge both newly admitted classic EA scans.
            scan.classic_xattr_reader_work(inodes[number as usize].external_xattr, 2)?;
            let directory = match volume.directory_for_audit(
                number,
                limits.directory_blocks,
                remaining,
                resources,
            ) {
                Ok(d) => d,
                Err(error) => {
                    let e = convert(error);
                    if matches!(e.kind, ErrorKind::InvalidData) {
                        namespace_complete = false;
                        scan.finding(ExtAuditFinding::InvalidDirectory { inode: number })?;
                        continue;
                    }
                    return Err(e);
                }
            };
            directory_entries = directory_entries
                .checked_add(directory.entries().len())
                .filter(|n| *n <= limits.directory_entries)
                .ok_or_else(|| budget("directory reference limit"))?;
            decoded[number as usize] = true;
            let first_edge = edges.len();
            for entry in directory.entries() {
                scan.step()?;
                if entry.inode > g.inodes
                    || !inodes[entry.inode as usize].allocated
                    || (entry.inode < first_inode && entry.inode != 2)
                    || g.modern.as_ref().is_some_and(|proof| {
                        proof.orphan_inode != 0 && entry.inode == proof.orphan_inode
                    })
                {
                    scan.finding(ExtAuditFinding::InvalidInodeReference {
                        directory: number,
                        inode: entry.inode,
                    })?;
                    continue;
                }
                let expected = match inodes[entry.inode as usize].mode & 0xf000 {
                    0x8000 => 1,
                    0x4000 => 2,
                    0xa000 => 7,
                    _ => 0,
                };
                if entry.file_type.is_some_and(|t| t != 0 && t != expected) {
                    scan.finding(ExtAuditFinding::DirectoryType {
                        directory: number,
                        inode: entry.inode,
                    })?;
                }
                references[entry.inode as usize] = references[entry.inode as usize]
                    .checked_add(1)
                    .ok_or_else(|| budget("inode reference count overflow"))?;
                let dot = match &entry.name {
                    NativeName::Bytes(n) if n == b"." => 1,
                    NativeName::Bytes(n) if n == b".." => 2,
                    _ => 0,
                };
                edges.push(Edge {
                    child: entry.inode,
                    dot,
                });
            }
            ranges[number as usize] = (first_edge, edges.len());
        }
        // Inspect dot topology in every decoded directory, including unreachable ones.
        for number in 2..=g.inodes {
            if !decoded[number as usize] {
                continue;
            }
            let (begin, end) = ranges[number as usize];
            let mut dot = 0usize;
            let mut dotdot = 0usize;
            let mut valid = true;
            for edge in &edges[begin..end] {
                scan.step()?;
                match edge.dot {
                    1 => {
                        dot += 1;
                        valid &= edge.child == number;
                    }
                    2 => {
                        dotdot += 1;
                        valid &= inodes[edge.child as usize].mode & 0xf000 == 0x4000;
                    }
                    _ => {}
                }
            }
            if !valid || dot != 1 || dotdot != 1 {
                scan.finding(ExtAuditFinding::DirectoryTopology { inode: number })?;
            }
        }
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(inode_count)
            .map_err(|_| budget("namespace queue allocation"))?;
        let mut parents: Vec<u32> = zeros(inode_count)?;
        if inodes[2].allocated && inodes[2].mode & 0xf000 == 0x4000 {
            reachable[2] = true;
            parents[2] = 2;
            queue.push(2);
        } else {
            namespace_complete = false;
            scan.finding(ExtAuditFinding::InvalidDirectory { inode: 2 })?;
        }
        let mut position = 0;
        while position < queue.len() {
            resources.cancellation.check()?;
            let parent = queue[position];
            position += 1;
            let (begin, end) = ranges[parent as usize];
            for edge in &edges[begin..end] {
                scan.step()?;
                if edge.dot == 1 {
                    continue;
                }
                if edge.dot == 2 {
                    if edge.child != parents[parent as usize] {
                        scan.finding(ExtAuditFinding::DirectoryTopology { inode: parent })?;
                    }
                    continue;
                }
                if inodes[edge.child as usize].mode & 0xf000 == 0x4000 {
                    if parents[edge.child as usize] != 0 {
                        scan.finding(ExtAuditFinding::DirectoryAlias { inode: edge.child })?;
                        continue;
                    }
                    parents[edge.child as usize] = parent;
                    queue.push(edge.child);
                }
                reachable[edge.child as usize] = true;
            }
        }
        for number in 2..=g.inodes {
            if !inodes[number as usize].allocated || (number < first_inode && number != 2) {
                continue;
            }
            scan.step()?;
            if g.modern
                .as_ref()
                .is_some_and(|proof| proof.orphan_inode == number)
            {
                continue;
            }
            if namespace_complete && !reachable[number as usize] {
                scan.finding(ExtAuditFinding::UnreachableInode { inode: number })?;
            }
            let saturated_directory = g.modern.as_ref().is_some_and(|proof| proof.ro & 0x20 != 0)
                && inodes[number as usize].mode & 0xf000 == 0x4000
                && inodes[number as usize].flags & 0x1000 != 0
                && inodes[number as usize].links == 1;
            if namespace_complete
                && !saturated_directory
                && references[number as usize] != u64::from(inodes[number as usize].links)
            {
                scan.finding(ExtAuditFinding::LinkCount {
                    inode: number,
                    recorded: inodes[number as usize].links,
                    actual: references[number as usize],
                })?;
            }
        }
        for (count, expected) in scan.xattr_references.iter().zip(&scan.xattr_expected) {
            if count != expected {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ext xattr actual/native reference count mismatch",
                ));
            }
        }
        let mut free: Vec<ExtFreeRange> = Vec::new();
        free.try_reserve_exact(block_count)
            .map_err(|_| budget("free-range allocation"))?;
        let mut owned_blocks = 0;
        for block in g.first..g.blocks {
            scan.step()?;
            if scan.allocated[block as usize] != 0 && scan.owners[block as usize] == 0 {
                scan.finding(ExtAuditFinding::LostBlock { block })?;
            }
            if scan.owners[block as usize] != 0 && scan.owners[block as usize] != u64::MAX {
                owned_blocks += 1;
            }
            if scan.allocated[block as usize] == 0 && scan.owners[block as usize] == 0 {
                let offset = u64::from(block) * u64::from(g.block_size);
                if let Some(last) = free.last_mut()
                    && last.offset + last.length == offset
                {
                    last.length += u64::from(g.block_size);
                } else {
                    free.push(ExtFreeRange {
                        offset,
                        length: u64::from(g.block_size),
                    });
                }
            }
        }
        Ok((free, namespace_complete, owned_blocks))
    })();
    let (free, namespace_complete, owned_blocks, error) = match outcome {
        Ok((free, namespace_complete, owned_blocks)) => {
            (free, namespace_complete, owned_blocks, None)
        }
        Err(error) => (Vec::new(), false, 0, Some(error)),
    };
    let report = ExtAuditReport {
        findings: scan.findings,
        free,
        namespace_complete,
        complete: error.is_none(),
        allocated_inodes,
        owned_blocks,
        _reservation: reservation,
    };
    match error {
        Some(error) => Err(ExtAuditFailure {
            error,
            partial: Some(report),
        }),
        None => Ok(report),
    }
}
