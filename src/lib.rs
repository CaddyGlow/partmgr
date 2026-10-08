//! Lossless GPT and MBR inspection, checked editing, and explicit durable commits.
//!
//! Inspect borrowed readers with [`error::inspect`], then edit owned
//! [`layout::DiskLayout`] values. [`codec`] produces reviewable [`storage::WritePlan`]
//! values; writes require an explicit exclusive [`storage::Storage`] capability.
//! GPT recovery is an explicit source-selection operation in [`recovery`].
//! Filesystem and firmware operations have separate adapters and outcomes.
#![deny(missing_docs)]

/// Deterministic table serialization and ordered commit planning.
pub mod codec;
/// Owned editing and managed filesystem boundary changes.
pub mod editor;
/// Domain errors for inspection, editing, and commits.
pub mod error;
/// Bounded extended-MBR traversal, editing, and EBR write plans.
pub mod extended;
mod fs_apfs_disk;
mod fs_build_io;
mod gpt;
/// Typed partition identifiers, names, and attributes.
pub mod guid;
/// Owned partition layouts and lossless inspection.
pub mod layout;
/// Basic disk partition inspection with checked bounds and consistency.
pub mod partition;
/// Recoverable payload operations using independent recovery storage.
pub mod payload;
/// Explicit storage capabilities and durable metadata write plans.
pub mod storage;
/// UEFI layout and boot preparation integration boundaries.
pub mod uefi;
pub use partition::PartitionTable;
/// Explicit partition scheme conversion.
pub mod conversion;
/// Explicit file-tree copy preflight, transformation reports, and staged emission.
pub mod fs_copy;
/// Lossless filesystem contracts, resource accounting, and operation capabilities.
pub mod fs_core;
/// Bounded exFAT revision 1.00 boot-region and geometry inspection.
pub mod fs_exfat;
/// Bounded complete exFAT allocation ownership audit.
pub mod fs_exfat_audit;
/// Deterministic direct new-image exFAT authoring.
pub mod fs_exfat_builder;
/// Explicit common-tree content-only exFAT capture.
pub mod fs_exfat_copy;
/// Bounded exFAT capture inventory and deferred native tree access.
pub mod fs_exfat_tree;
/// Immutable exFAT namespace and positional file access.
pub mod fs_exfat_volume;
/// Strict bounded ext-family read profiles and deferred file access.
pub mod fs_ext;
/// Bounded whole-volume classic ext2 allocation and reference audit.
pub mod fs_ext_audit;
pub mod fs_ext_builder;
pub mod fs_ext_copy;
/// Exclusively owned classic ext2 sessions with complete allocation audits.
pub mod fs_ext_edit;
/// Bounded ext2 capture inventories preserving native names and file identities.
pub mod fs_ext_tree;
/// Strict baseline FAT geometry and bounded allocation-chain file reads.
pub mod fs_fat;
/// Bounded FAT whole-volume allocation and state audits.
pub mod fs_fat_audit;
/// Deterministic bounded new-output FAT authoring for explicit build profiles.
pub mod fs_fat_builder;
/// Exclusive audited FAT sessions with external-journal range replacement.
pub mod fs_fat_edit;
/// Bounded FAT namespace capture and deferred common file-tree access.
pub mod fs_fat_tree;
/// Indexed positional access to validated uncompressed file extents.
pub mod fs_file;
/// Explicit logical NOR flash storage emulation and failure contracts.
pub mod fs_flash;
pub mod fs_jffs2;
pub mod fs_jffs2_audit;
pub mod fs_jffs2_builder;
pub mod fs_jffs2_tree;
/// Explicit outcomes and recovery obligations for independently committed media layers.
pub mod fs_pipeline;
/// Bounded storage sessions and immutable filesystem read regions.
pub mod fs_storage;
/// Bounded external undo transactions and restartable recovery.
pub mod fs_undo;
pub mod fs_xfs;
pub mod fs_xfs_audit;
pub mod fs_xfs_tree;
/// Explicit GPT metadata recovery and geometry changes.
pub mod recovery;

/// Strict clean NTFS 3.1 base-record and positional unnamed-data reader.
pub mod fs_ntfs;
/// Volume-bound native NTFS metadata and lossless security capture.
pub mod fs_ntfs_metadata;
/// Lossless bounded inspection of native self-relative security descriptors.
pub mod fs_ntfs_security;
/// Bounded read-only USN V2/V3 evidence decoding; no replay or recovery claim.
pub mod fs_ntfs_usn;

/// Bounded native NTFS user-namespace tree inventory.
pub mod fs_ntfs_tree;

/// Explicit immutable filesystem read-profile dispatch and allocation evidence.
pub mod fs_image;

/// Complete bounded NTFS base-record allocation and native-reference audit.
pub mod fs_ntfs_audit;

/// Exclusive recoverable exFAT file editing.
pub mod fs_exfat_edit;
/// Strict immutable classic HFS profile reader.
pub mod fs_hfs;
/// Complete supported-profile classic HFS ownership audit.
pub mod fs_hfs_audit;
/// Native classic HFS common tree source.
pub mod fs_hfs_tree;
/// Strict bounded immutable bare HFS+/HFSX read profiles.
pub mod fs_hfsplus;
/// Complete allocation and catalog-reference audit for supported HFS+/HFSX profiles.
pub mod fs_hfsplus_audit;
/// Fresh unpublished HFS+/HFSX construction from deferred common trees.
pub mod fs_hfsplus_builder;
/// Complete native HFS+/HFSX tree inventory and deferred data/resource forks.
pub mod fs_hfsplus_tree;

/// Owned logical NOR JFFS2 append and exact external-intent recovery.
pub mod fs_jffs2_edit;

/// Strict immutable Linux JFS initial profile reader.
pub mod fs_jfs;

/// Complete accepted-profile JFS allocation/reference audit.
pub mod fs_jfs_audit;
/// Common native JFS tree after complete clean allocation proof.
pub mod fs_jfs_tree;

/// Immutable APFS checkpoint discovery and explicitly gated volume access.
pub mod fs_apfs;
/// Complete accepted-profile APFS container allocation/reference audit.
pub mod fs_apfs_audit;
/// Deterministic fresh native APFS construction with deferred common-tree payloads.
pub mod fs_apfs_builder;
/// Owned APFS container preparation and native COW sessions.
pub mod fs_apfs_edit;
/// Common native APFS tree after complete accepted-profile allocation proof.
pub mod fs_apfs_tree;

/// Bounded source-bound USN stream extraction.
pub mod fs_ntfs_usn_extract;
