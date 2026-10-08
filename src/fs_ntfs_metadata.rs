//! Volume-bound native metadata with retained exact ACL bytes.
use crate::{
    fs_core::*,
    fs_ntfs::{NtfsRecord, NtfsVolume},
    fs_ntfs_security::{NtfsResolvedSecurity, NtfsSecureLimits, lookup_ntfs_security},
};

/// Native metadata and security retained under their original budget leases.
/// Security interpretation does not imply ACL restoration or access evaluation.
pub struct NtfsNativeMetadata {
    base: Budgeted<Metadata>,
    security: NtfsResolvedSecurity,
    _lease: Reservation,
}
impl NtfsNativeMetadata {
    /// Existing timestamp/flag metadata; unsupported classes remain explicit.
    pub fn base(&self) -> &Metadata {
        self.base.get()
    }
    /// Exact volume-resolved descriptor, SIDs, ACLs and lookup provenance.
    pub fn security(&self) -> &NtfsResolvedSecurity {
        &self.security
    }
    /// Consume the capture and attach exact native descriptor/owner SID bytes.
    /// This encoding is native NTFS security, not POSIX ownership or restore authority.
    pub fn into_metadata(self, r: &Resources) -> Result<Budgeted<Metadata>> {
        r.cancellation.check()?;
        let descriptor = self.security.descriptor();
        let owner = descriptor.owner().map(|sid| sid.raw());
        let additional = (descriptor.raw().len() as u64)
            .checked_add(owner.map_or(0, |sid| sid.len() as u64))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::BudgetExhausted,
                    "NTFS security metadata charge overflow",
                )
            })?;
        self.base.try_map(additional, |mut metadata| {
            fn copy(bytes: &[u8]) -> Result<Vec<u8>> {
                let mut result = Vec::new();
                result.try_reserve_exact(bytes.len()).map_err(|_| {
                    Error::new(
                        ErrorKind::BudgetExhausted,
                        "NTFS security metadata allocation",
                    )
                })?;
                result.extend_from_slice(bytes);
                Ok(result)
            }
            r.cancellation.check()?;
            metadata.security = MetadataField::Known(copy(descriptor.raw())?);
            metadata.owner = match owner {
                Some(sid) => MetadataField::Known(copy(sid)?),
                None => MetadataField::Absent,
            };
            r.cancellation.check()?;
            Ok(metadata)
        })
    }
    /// Source-scoped FILE identity bound to this metadata and descriptor.
    pub fn record(&self) -> &ObjectId {
        self.security.record()
    }
}
/// Resolve native security before exposing this combined capture object.
/// Preserves the base metadata and security leases without cloning ACL payloads.
pub fn inspect_ntfs_native_metadata(
    volume: &NtfsVolume,
    record: &NtfsRecord,
    limits: NtfsSecureLimits,
    r: &Resources,
) -> Result<NtfsNativeMetadata> {
    r.cancellation.check()?;
    let security = lookup_ntfs_security(volume, record, limits, r)?;
    if security.record() != record.identity() {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS security metadata identity mismatch",
        ));
    }
    let base = record.metadata(r)?;
    r.cancellation.check()?;
    let lease = r
        .memory
        .reserve(std::mem::size_of::<NtfsNativeMetadata>() as u64)?;
    Ok(NtfsNativeMetadata {
        base,
        security,
        _lease: lease,
    })
}
