//! Typed catalog metadata authoring; opaque catalog bytes are never transplanted.
use super::bad;
use crate::fs_core::{Metadata, MetadataField, NativeName, Result};

/// Dates are native unsigned seconds since 1904-01-01 00:00:00 GMT.
#[derive(Clone, Copy, Debug)]
pub struct CatalogMetadata {
    /// Native owner ID.
    pub uid: u32,
    /// Native group ID.
    pub gid: u32,
    /// Permission bits, without file-type bits.
    pub permissions: u16,
    /// Creation date.
    pub created: u32,
    /// Content modification date.
    pub modified: u32,
    /// Attribute modification date.
    pub attributes_modified: u32,
    /// Access date.
    pub accessed: u32,
    /// Backup date.
    pub backup: u32,
}

/// Explicit native HFS catalog conversion. The caller selects this format policy;
/// a generic ownership byte vector alone is never sufficient provenance.
pub(super) fn from_native_hfs(metadata: &Metadata, directory: bool) -> Result<CatalogMetadata> {
    let mut records = metadata
        .attributes
        .iter()
        .filter(|(name, _)| name == &NativeName::Bytes(b"hfs.catalog-record".to_vec()));
    let Some((_, MetadataField::Opaque { bytes, .. })) = records.next() else {
        return Err(bad("HFS+ native metadata requires retained catalog record"));
    };
    if records.next().is_some()
        || bytes.len() != if directory { 88 } else { 248 }
        || u16::from_be_bytes(bytes[..2].try_into().unwrap()) != if directory { 1 } else { 2 }
    {
        return Err(bad("HFS+ native metadata catalog record shape"));
    }
    let native = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    for (field, at) in [
        (&metadata.created, 12),
        (&metadata.modified, 16),
        (&metadata.accessed, 24),
    ] {
        let MetadataField::Known(time) = field else {
            return Err(bad("HFS+ native metadata date unavailable"));
        };
        if time.ticks_per_second != 1
            || time.epoch != "1904-01-01 00:00:00 GMT; native unsigned seconds"
            || time.ticks != i128::from(native(at))
        {
            return Err(bad("HFS+ native metadata date disagrees with catalog"));
        }
    }
    let mode = u16::from_be_bytes(bytes[42..44].try_into().unwrap());
    if metadata.owner != MetadataField::Known(bytes[32..40].to_vec())
        || metadata.mode != MetadataField::Known(u32::from(mode))
        || mode & 0xf000 != if directory { 0x4000 } else { 0x8000 }
    {
        return Err(bad("HFS+ native metadata ownership/type disagreement"));
    }
    Ok(CatalogMetadata {
        uid: native(32),
        gid: native(36),
        permissions: mode & 0o7777,
        created: native(12),
        modified: native(16),
        attributes_modified: native(20),
        accessed: native(24),
        backup: native(28),
    })
}

pub(super) fn apply(
    body: &mut [u8],
    directory: bool,
    metadata: Option<&CatalogMetadata>,
) -> Result<()> {
    if body.len() != if directory { 88 } else { 248 } {
        return Err(bad("HFS+ typed catalog metadata body size"));
    }
    let defaults = CatalogMetadata {
        uid: 0,
        gid: 0,
        permissions: if directory { 0o755 } else { 0o644 },
        created: 0,
        modified: 0,
        attributes_modified: 0,
        accessed: 0,
        backup: 0,
    };
    let metadata = metadata.unwrap_or(&defaults);
    if metadata.permissions & !0o7777 != 0 {
        return Err(bad("HFS+ typed catalog permission bits"));
    }
    for (at, date) in [
        (12, metadata.created),
        (16, metadata.modified),
        (20, metadata.attributes_modified),
        (24, metadata.accessed),
        (28, metadata.backup),
    ] {
        body[at..at + 4].copy_from_slice(&date.to_be_bytes());
    }
    body[32..36].copy_from_slice(&metadata.uid.to_be_bytes());
    body[36..40].copy_from_slice(&metadata.gid.to_be_bytes());
    let mode = (if directory { 0x4000 } else { 0x8000 }) | metadata.permissions;
    body[42..44].copy_from_slice(&mode.to_be_bytes());
    Ok(())
}
