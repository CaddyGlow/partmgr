//! Strict read-only GPT and MBR partition table parsing.
//!
//! Tables are validated over a [`virtdisk::ReadAt`] reader and exposed as bounded
//! [`virtdisk::DiskView`] partition views. Nothing is repaired or written.
#![deny(missing_docs)]

/// Basic disk partition inspection with checked bounds and consistency.
pub mod partition;
pub use partition::PartitionTable;
