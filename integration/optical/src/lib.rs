//! Development optical integration over bounded filesystem sources.
//!
//! libmkiso owns optical codecs. Published API versions must be verified before
//! release; local development overrides are not crates.io availability evidence.
#![deny(missing_docs)]
/// Retained bounded positional optical reads and common file handles.
pub mod read;
/// Deferred common tree sources and explicit optical preservation decisions.
#[cfg(feature = "native-writer")]
pub mod write;

/// Bounded native optical topology implementing the common TreeSource contract.
pub mod tree;
