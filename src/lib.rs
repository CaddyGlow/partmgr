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
/// Lossless filesystem contracts, resource accounting, and operation capabilities.
pub mod fs_core;
/// Indexed positional access to validated uncompressed file extents.
pub mod fs_file;
/// Bounded storage sessions and immutable filesystem read regions.
pub mod fs_storage;
/// Explicit GPT metadata recovery and geometry changes.
pub mod recovery;
