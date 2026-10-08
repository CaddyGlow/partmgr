//! Explicit read-profile dispatch over immutable bounded filesystem sources.
//! Signature candidates are separate from validated profiles and clean allocation evidence.
use crate::{
    fs_apfs::{ApfsContainer, ApfsReadLimits, ApfsVolume},
    fs_apfs_audit::ApfsAuditLimits,
    fs_apfs_tree::ApfsTreeSource,
    fs_core::{
        Availability, Budgeted, Cancellation, CapabilityProfile, DirectoryPage, Error, ErrorKind,
        Family, FileRead, LogicalExtent, Metadata, ObjectId, Operation, Reservation, Resources,
        Result, SourceStability, StreamInfo, StreamKind, TreeSource,
    },
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_tree::{ExfatTreeLimits, ExfatTreeSource},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditLimits, audit as audit_ext},
    fs_ext_tree::ExtTreeSource,
    fs_fat::{FatFamily, FatVolume},
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_fat_tree::FatTreeSource,
    fs_flash::FlashGeometry,
    fs_hfs::{HfsReadLimits, HfsVolume},
    fs_hfs_audit::HfsAuditLimits,
    fs_hfs_tree::HfsTreeSource,
    fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
    fs_hfsplus_audit::HfsPlusAuditLimits,
    fs_hfsplus_tree::HfsPlusTreeSource,
    fs_jffs2::{Jffs2CompressionLimits, Jffs2Endian, Jffs2ReadLimits, Jffs2Volume},
    fs_jffs2_audit::Jffs2AuditLimits,
    fs_jffs2_tree::Jffs2TreeSource,
    fs_jfs::{JfsReadLimits, JfsVolume},
    fs_jfs_audit::JfsAuditLimits,
    fs_jfs_tree::JfsTreeSource,
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
    fs_ntfs_audit::{NtfsAuditLimits, audit_ntfs},
    fs_ntfs_tree::{NtfsTreePolicy, NtfsTreeSource},
    fs_xfs::{XfsReadLimits, XfsVolume},
    fs_xfs_audit::{XfsAuditLimits, audit as audit_xfs},
    fs_xfs_tree::{XfsTreeLimits, XfsTreeSource},
};
use std::sync::Arc;
use virtdisk::ReadAt;

/// Signature candidate; no operation support or metadata validity follows from a match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFormat {
    /// APFS container superblock candidate; no checkpoint or volume proof follows.
    Apfs,
    /// JFS primary superblock candidate; feature and log validation remain required.
    Jfs,
    /// Classic HFS master-directory-block signature candidate.
    Hfs,
    /// Bare HFS+ or HFSX volume header candidate; catalog comparison remains validated.
    HfsPlus,
    /// JFFS2 first-node magic candidate; byte order and flash geometry remain explicit.
    Jffs2,
    /// Conventional FAT BPB candidate; family is established by checked geometry.
    Fat,
    /// exFAT OEM signature candidate.
    Exfat,
    /// Linux ext superblock signature candidate; features determine the actual profile.
    Ext,
    /// NTFS OEM signature candidate.
    Ntfs,
    /// XFS primary-superblock signature candidate; features require checked opening.
    Xfs,
}
/// Read-only allocation policy, independent of source snapshot/exclusivity assurance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationPolicy {
    /// Complete allocation/reference audit must pass before tree inventory.
    RequireClean,
    /// Explicit inspection without global ownership evidence; never mutation authority.
    MetadataOnly,
}
/// Allocation evidence obtained by this opening, never a write capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationEvidence {
    /// Complete profile audit passed under the caller's immutable-source contract.
    CleanProfileAudit,
    /// The implemented profile audit was deliberately not requested.
    NotRequested,
    /// No complete allocation audit is implemented for the selected profile.
    Unavailable,
}
/// Exact engine selection and caller-supplied bounds; unsupported features fail inside the engine.
#[derive(Clone, Copy, Debug)]
pub enum ReadOptions {
    /// Explicit volume selection inside a bounded APFS container.
    Apfs {
        /// Container, checkpoint and object-tree limits.
        read: ApfsReadLimits,
        /// Complete implemented-profile allocation/reference audit limits.
        audit: ApfsAuditLimits,
        /// Native volume object identifier; no automatic first-volume fallback.
        volume_oid: u64,
    },
    /// Linux JFS with explicit bounds and complete inventory audit.
    Jfs {
        /// Geometry, inode, extent and directory decoding limits.
        read: JfsReadLimits,
        /// Allocation and namespace limits; inventory always audits.
        audit: JfsAuditLimits,
    },
    /// Classic HFS with exact native byte names and bounded ASCII comparison.
    Hfs {
        /// Volume, B-tree and extent decoding limits.
        read: HfsReadLimits,
        /// Complete ownership and namespace limits; inventory always audits.
        audit: HfsAuditLimits,
    },
    /// Bare nonjournaled HFS+ ASCII-fold or HFSX binary native catalog profile.
    HfsPlus {
        /// Volume, B-tree and extent decoding limits.
        read: HfsPlusReadLimits,
        /// Complete ownership and namespace limits; inventory always audits.
        audit: HfsPlusAuditLimits,
    },
    /// Checked logical NOR node history with uncompressed/zero payload nodes.
    Jffs2 {
        /// Caller-declared erase and program geometry; never inferred from magic.
        geometry: FlashGeometry,
        /// Caller-selected on-disk node byte order.
        endian: Jffs2Endian,
        /// Complete node-scan and reconstruction limits.
        read: Jffs2ReadLimits,
        /// Complete reachable namespace audit limits, always required by inventory.
        audit: Jffs2AuditLimits,
    },
    /// Explicit immutable NONE/ZERO/RTIME/ZLIB logical NOR profile.
    Jffs2Compressed {
        /// Caller-declared erase/program geometry.
        geometry: FlashGeometry,
        /// Caller-selected node byte order.
        endian: Jffs2Endian,
        /// Complete node-scan limits.
        read: Jffs2ReadLimits,
        /// Encoded/decoded node, total validation and byte-work limits.
        compression: Jffs2CompressionLimits,
        /// Complete reachable namespace audit limits, always required.
        audit: Jffs2AuditLimits,
    },
    /// XFS v5 leaf AG trees, inline extent forks and shortform directories.
    Xfs {
        /// Allocation-group, inode, extent and clean-log opening limits.
        read: XfsReadLimits,
        /// Complete allocation/reference accounting limits.
        audit: XfsAuditLimits,
        /// Retained native namespace limits.
        tree: XfsTreeLimits,
    },
    /// Conventional FAT12/16/32 namespace profile, with exact OEM bytes/VFAT units.
    Fat {
        /// Allocation and per-directory bounds.
        audit: FatAuditLimits,
        /// Maximum retained namespace objects including root.
        objects: usize,
    },
    /// Clean classic ext2 profile; advanced ext features remain rejected.
    Ext2 {
        /// Allocation/reference work envelope.
        audit: ExtAuditLimits,
        /// Maximum retained objects.
        objects: usize,
        /// Maximum retained name occurrences.
        entries: usize,
        /// Maximum blocks in each file/directory map.
        map_blocks: usize,
        /// Maximum directory slots decoded in each directory.
        directory_slots: usize,
    },
    /// Explicit supported immutable ext2/ext3/ext4 profile selection.
    Ext {
        /// Allocation/reference work envelope.
        audit: ExtAuditLimits,
        /// Maximum retained objects.
        objects: usize,
        /// Maximum retained name occurrences.
        entries: usize,
        /// Maximum blocks in each file/directory map.
        map_blocks: usize,
        /// Maximum directory slots decoded in each directory.
        directory_slots: usize,
    },
    /// Clean single-FAT exFAT revision 1.00 profile.
    Exfat {
        /// Volume decoding limits.
        read: ExfatReadLimits,
        /// Complete allocation/reference audit limits.
        audit: ExfatAuditLimits,
        /// Retained namespace bounds.
        tree: ExfatTreeLimits,
    },
    /// NTFS3.1 native index profile; system-stream exclusions require explicit opt-in.
    Ntfs {
        /// Complete allocation/reference audit limits.
        audit: NtfsAuditLimits,
        /// Record/attribute limits.
        read: NtfsReadLimits,
        /// Native index traversal limits.
        index: NtfsDirectoryLimits,
        /// Maximum native name occurrences including root and exclusions.
        occurrences: usize,
        /// Maximum namespace directory depth.
        depth: usize,
        /// Exact capture scope; Complete rejects unavailable system-stream support.
        namespace: NtfsTreePolicy,
    },
}
/// Probe only bounded fixed signatures; ambiguous candidates require explicit engine selection.
/// No repair, payload access, tree inventory or automatic fallback is performed.
pub fn probe(source: &dyn ReadAt, r: &Resources) -> Result<Budgeted<Vec<ReadFormat>>> {
    r.cancellation.check()?;
    let length = source.len();
    Budgeted::try_new(&r.memory, 1024, || {
        let mut boot = [0; 512];
        let n = length.min(512) as usize;
        source
            .read_exact_at(0, &mut boot[..n])
            .map_err(|e| Error::io("filesystem signature probe", e))?;
        r.cancellation.check()?;
        let mut out = Vec::new();
        out.try_reserve_exact(8).map_err(|_| {
            Error::new(
                ErrorKind::BudgetExhausted,
                "filesystem candidate allocation",
            )
        })?;
        if n >= 2 && matches!(&boot[..2], [0x85, 0x19] | [0x19, 0x85]) {
            out.push(ReadFormat::Jffs2);
        }
        if n >= 36 && &boot[32..36] == b"NXSB" {
            out.push(ReadFormat::Apfs);
        }
        if n >= 4 && &boot[..4] == b"XFSB" {
            out.push(ReadFormat::Xfs);
        }
        if n >= 11 && &boot[3..11] == b"EXFAT   " {
            out.push(ReadFormat::Exfat);
        }
        if n >= 11 && &boot[3..11] == b"NTFS    " {
            out.push(ReadFormat::Ntfs);
        }
        if n == 512
            && boot[510..512] == [0x55, 0xaa]
            && matches!(
                u16::from_le_bytes([boot[11], boot[12]]),
                512 | 1024 | 2048 | 4096
            )
            && boot[13].is_power_of_two()
            && boot[16] != 0
            && u16::from_le_bytes([boot[14], boot[15]]) != 0
        {
            out.push(ReadFormat::Fat);
        }
        if length >= 32772 {
            let mut magic = [0; 4];
            source
                .read_exact_at(32768, &mut magic)
                .map_err(|e| Error::io("JFS signature probe", e))?;
            if &magic == b"JFS1" {
                out.push(ReadFormat::Jfs);
            }
        }
        if length >= 1082 {
            let mut magic = [0; 2];
            source
                .read_exact_at(1080, &mut magic)
                .map_err(|e| Error::io("ext signature probe", e))?;
            if magic == [0x53, 0xef] {
                out.push(ReadFormat::Ext);
            }
        }
        if length >= 1026 {
            let mut signature = [0; 2];
            source
                .read_exact_at(1024, &mut signature)
                .map_err(|e| Error::io("HFS+ signature probe", e))?;
            if matches!(&signature, b"H+" | b"HX") {
                out.push(ReadFormat::HfsPlus);
            }
            if &signature == b"BD" {
                out.push(ReadFormat::Hfs);
            }
        }
        r.cancellation.check()?;
        if source.len() != length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "source length changed during signature probe",
            ));
        }
        Ok(out)
    })
}
fn malformed(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn fat_error(e: std::io::Error) -> Error {
    Error::classified_io("FAT profile opening/audit", e)
}
fn ext_error(e: std::io::Error) -> Error {
    Error::classified_io("ext2 profile opening/audit", e)
}
struct SourceGuard {
    source: Arc<dyn ReadAt>,
    length: u64,
    cancellation: Cancellation,
    _lease: Reservation,
}
impl SourceGuard {
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.cancellation.check()?;
        if self.source.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "filesystem source length changed",
            ));
        }
        Ok(())
    }
}
impl ReadAt for SourceGuard {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.cancellation.check().map_err(std::io::Error::other)?;
        if self.source.len() != self.length {
            return Err(std::io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "filesystem source length changed",
            )));
        }
        self.source.read_exact_at(offset, out)?;
        if self.source.len() != self.length {
            return Err(std::io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "filesystem source length changed during read",
            )));
        }
        self.cancellation.check().map_err(std::io::Error::other)
    }
}
struct GuardedFile {
    file: Arc<dyn FileRead>,
    source: Arc<SourceGuard>,
    _lease: Reservation,
}
impl FileRead for GuardedFile {
    fn identity(&self) -> &ObjectId {
        self.file.identity()
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.source.check(r)?;
        let n = self.file.read_at(offset, out, r)?;
        self.source.check(r)?;
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.source.check(r)?;
        self.file.visit_extents(r, visitor)?;
        self.source.check(r)
    }
}
/// Common immutable tree handle with explicit selected profile and opening evidence.
/// Caller-stabilized sources must remain unchanged for every deferred operation.
/// This handle exposes no writable backend or mutation/recovery method.
pub struct ReadImage {
    tree: Arc<dyn TreeSource>,
    source: Arc<SourceGuard>,
    profile: CapabilityProfile,
    _profile_lease: Reservation,
    allocation: AllocationEvidence,
}
impl ReadImage {
    /// Open exactly one selected profile; failures never retry another engine.
    /// Clean audit, when requested, precedes inventory. Unsupported audit is an error.
    pub fn open(
        source: Arc<dyn ReadAt>,
        options: ReadOptions,
        allocation: AllocationPolicy,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let profile_lease = r.memory.reserve(4096)?;
        let guard = Arc::new(SourceGuard {
            length: source.len(),
            source,
            cancellation: r.cancellation.clone(),
            _lease: r.memory.reserve(256)?,
        });
        guard.check(r)?;
        let source: Arc<dyn ReadAt> = guard.clone();
        let (tree, family, description, evidence, audit_available): (
            Arc<dyn TreeSource>,
            Family,
            &str,
            AllocationEvidence,
            bool,
        ) = match options {
            ReadOptions::Apfs {
                read,
                audit,
                volume_oid,
            } => {
                let container = ApfsContainer::open(source, read, r)?;
                let volume = ApfsVolume::open(container, volume_oid, r)?;
                let tree = ApfsTreeSource::inventory(volume, audit, r)?;
                (
                    Arc::new(tree),
                    Family::Apfs,
                    "APFS explicit container volume; checked checkpoint and object trees; inventory always audits the implemented profile",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::Jfs { read, audit } => {
                let volume = JfsVolume::open(source, read, r)?;
                let tree = JfsTreeSource::inventory(volume, audit, r)?;
                (
                    Arc::new(tree),
                    Family::Jfs,
                    "Linux JFS; native UTF16 names, sparse/unwritten extents and indexed directories; inventory always audits",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::Hfs { read, audit } => {
                let volume = HfsVolume::open(source, read, r)?;
                let tree = HfsTreeSource::inventory(volume, audit, r)?;
                (
                    Arc::new(tree),
                    Family::Hfs,
                    "Classic HFS; bounded native ASCII comparison, exact byte names, separate data/resource forks; inventory always audits",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::HfsPlus { read, audit } => {
                let volume = HfsPlusVolume::open(source, read, r)?;
                let family = volume.geometry().family();
                let tree = HfsPlusTreeSource::inventory(volume, audit, r)?;
                (
                    Arc::new(tree),
                    family,
                    "Bare nonjournaled HFS+/HFSX; validated catalog comparison, data/resource forks and native UTF16 names; inventory always audits",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::Jffs2 {
                geometry,
                endian,
                read,
                audit,
            } => {
                let volume = Jffs2Volume::open(source, geometry, endian, read, r)?;
                let tree = Jffs2TreeSource::inventory(volume, audit, r)?;
                if !tree.audit_report().is_complete() || !tree.audit_report().is_clean() {
                    return Err(malformed("JFFS2 scan/namespace audit did not pass"));
                }
                (
                    Arc::new(tree),
                    Family::Jffs2,
                    "JFFS2 declared logical NOR and byte order; checked node history, uncompressed/zero data, exact byte names and unfollowed symlinks; inventory always audits",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::Jffs2Compressed {
                geometry,
                endian,
                read,
                compression,
                audit,
            } => {
                let volume =
                    Jffs2Volume::open_compressed(source, geometry, endian, read, compression, r)?;
                let tree = Jffs2TreeSource::inventory(volume, audit, r)?;
                if !tree.audit_report().is_complete() || !tree.audit_report().is_clean() {
                    return Err(malformed("JFFS2 scan/namespace audit did not pass"));
                }
                (
                    Arc::new(tree),
                    Family::Jffs2,
                    "JFFS2 declared logical NOR and byte order; checked node history, NONE/ZERO/RTIME/ZLIB bounded lazy data, exact byte names and unfollowed symlinks; inventory always audits",
                    AllocationEvidence::CleanProfileAudit,
                    true,
                )
            }
            ReadOptions::Xfs { read, audit, tree } => {
                let volume = XfsVolume::open(source, read, r)?;
                let evidence = if allocation == AllocationPolicy::RequireClean {
                    let report = audit_xfs(&volume, audit, r)?;
                    if !report.is_complete() || !report.is_clean() {
                        return Err(malformed("XFS allocation/reference audit did not pass"));
                    }
                    AllocationEvidence::CleanProfileAudit
                } else {
                    AllocationEvidence::NotRequested
                };
                (
                    Arc::new(XfsTreeSource::inventory(volume, tree, r)?),
                    Family::Xfs,
                    "XFS v5 leaf AG allocation/inode trees; inline extent forks and shortform native byte names; narrow clean-log profile",
                    evidence,
                    true,
                )
            }
            ReadOptions::Fat { audit, objects } => {
                let volume = FatVolume::open(source.clone()).map_err(fat_error)?;
                let family = match volume.geometry().family() {
                    FatFamily::Fat12 => Family::Fat12,
                    FatFamily::Fat16 => Family::Fat16,
                    FatFamily::Fat32 => Family::Fat32,
                };
                let evidence = if allocation == AllocationPolicy::RequireClean {
                    let report = audit_fat(source, audit, r).map_err(fat_error)?;
                    if !report.namespace_complete() || !report.findings().is_empty() {
                        return Err(malformed("FAT allocation/state audit did not pass"));
                    }
                    AllocationEvidence::CleanProfileAudit
                } else {
                    AllocationEvidence::NotRequested
                };
                (
                    Arc::new(FatTreeSource::inventory(
                        volume,
                        objects,
                        audit.clusters,
                        audit.directory_slots,
                        r,
                    )?),
                    family,
                    "conventional BPB; exact short aliases and strict VFAT; opaque timestamps; caller-stabilized reads",
                    evidence,
                    true,
                )
            }
            ReadOptions::Ext2 {
                audit,
                objects,
                entries,
                map_blocks,
                directory_slots,
            }
            | ReadOptions::Ext {
                audit,
                objects,
                entries,
                map_blocks,
                directory_slots,
            } => {
                let volume = ExtVolume::open(source, r).map_err(ext_error)?;
                if matches!(options, ReadOptions::Ext2 { .. }) && !volume.geometry().is_classic() {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "Ext2 options require a classic nonjournaled profile",
                    ));
                }
                let family = if volume.geometry().uses_extents()
                    || volume.geometry().has_metadata_checksums()
                {
                    Family::Ext4
                } else if volume.geometry().has_journal() {
                    Family::Ext3
                } else {
                    Family::Ext2
                };

                let evidence = if allocation == AllocationPolicy::RequireClean {
                    let report = audit_ext(&volume, audit, r)?;
                    if !report.is_clean() {
                        return Err(malformed("ext2 allocation/reference audit did not pass"));
                    }
                    AllocationEvidence::CleanProfileAudit
                } else {
                    AllocationEvidence::NotRequested
                };
                (
                    Arc::new(ExtTreeSource::inventory(
                        volume,
                        objects,
                        entries,
                        map_blocks,
                        directory_slots,
                        r,
                    )?),
                    family,
                    "checked immutable Linux ext profile; classic or extent maps and inactive internal journal; unsupported features gated",
                    evidence,
                    true,
                )
            }
            ReadOptions::Exfat { read, audit, tree } => {
                let evidence = if allocation == AllocationPolicy::RequireClean {
                    let report = audit_exfat(source.clone(), read, audit, r)?;
                    if !report.is_clean() {
                        return Err(malformed("exFAT allocation/state audit did not pass"));
                    }
                    AllocationEvidence::CleanProfileAudit
                } else {
                    AllocationEvidence::NotRequested
                };
                let volume = ExfatVolume::open(source, read, r)?;
                (
                    Arc::new(ExfatTreeSource::inventory(volume, tree, r)?),
                    Family::ExFat,
                    "clean single-FAT exFAT revision1.00; native UTF16/full volume upcase; VDL zeros",
                    evidence,
                    true,
                )
            }
            ReadOptions::Ntfs {
                audit,
                read,
                index,
                occurrences,
                depth,
                namespace,
            } => {
                let evidence = if allocation == AllocationPolicy::RequireClean {
                    let report = audit_ntfs(source.clone(), read, audit, r)?;
                    if !report.is_complete() || !report.is_clean() {
                        return Err(malformed("NTFS allocation/reference audit did not pass"));
                    }
                    AllocationEvidence::CleanProfileAudit
                } else {
                    AllocationEvidence::NotRequested
                };
                let volume = NtfsVolume::open(source, read, r)?;
                let description = match namespace {
                    NtfsTreePolicy::Complete => {
                        "NTFS3.1 native indexes; complete namespace policy; unsupported system streams rejected"
                    }
                    NtfsTreePolicy::UserNamespace => {
                        "NTFS3.1 native indexes; explicit user namespace with exact reserved-root exclusions; allocation evidence reported separately"
                    }
                };
                (
                    Arc::new(NtfsTreeSource::inventory_with_policy(
                        volume,
                        occurrences,
                        depth,
                        index,
                        namespace,
                        r,
                    )?),
                    Family::Ntfs,
                    description,
                    evidence,
                    true,
                )
            }
        };
        guard.check(r)?;
        let profile=CapabilityProfile {
            family,profile:description.into(),
            operations:vec![
                (Operation::Recognize,Availability::Supported),
                (Operation::ValidateMetadata,Availability::Supported),
                (Operation::DecodePayload,Availability::Supported),
                (Operation::Read,Availability::Supported),
                (Operation::AuditAllocation,if audit_available { Availability::Requires { condition:"separate complete bounded profile audit on caller-stabilized source; opening evidence reported separately".into() } } else { Availability::Unsupported { reason:"complete allocation/reference audit is not implemented for this profile".into() } }),
            ],
            durability:"Immutable read handle only; no exclusive mutation, flush, publication, recovery or snapshot guarantee".into(),
            validation_evidence:Vec::new(),
        };
        Ok(Self {
            tree,
            source: guard,
            profile,
            _profile_lease: profile_lease,
            allocation: evidence,
        })
    }
    /// Selected checked profile; absent operations remain unsupported.
    pub fn profile(&self) -> &CapabilityProfile {
        &self.profile
    }
    /// Allocation evidence actually established during opening, scoped to this immutable source.
    pub fn allocation_evidence(&self) -> AllocationEvidence {
        self.allocation
    }
}
impl ReadImage {
    fn checked<T>(&self, r: &Resources, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.source.check(r)?;
        let value = action()?;
        self.source.check(r)?;
        Ok(value)
    }
}
impl TreeSource for ReadImage {
    fn root(&self) -> ObjectId {
        self.tree.root()
    }
    fn stability(&self) -> SourceStability {
        self.tree.stability()
    }
    fn metadata(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.checked(r, || self.tree.metadata(object, r))
    }
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.checked(r, || {
            self.tree
                .directory_page(directory, continuation, maximum_entries, r)
        })
    }
    fn streams(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.checked(r, || self.tree.streams(object, r))
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.checked(r, || {
            let lease = r.memory.reserve(128)?;
            let file = self.tree.open_stream(object, stream, r)?;
            Ok(Arc::new(GuardedFile {
                file,
                source: self.source.clone(),
                _lease: lease,
            }) as Arc<dyn FileRead>)
        })
    }
    fn revalidate(&self, object: &ObjectId, r: &Resources) -> Result<()> {
        self.checked(r, || self.tree.revalidate(object, r))
    }
}
