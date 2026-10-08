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

/// Complete resolved attribute evidence and native security for one immutable FILE identity.
/// Encoded attributes retain physical provenance and are not relocatable restore templates.
pub struct NtfsResolvedNativeMetadata {
    attributes: Budgeted<Vec<crate::fs_ntfs::NtfsNativeAttribute>>,
    security: NtfsResolvedSecurity,
    _lease: Reservation,
}
/// Resolved native attribute evidence without authorizing security interpretation.
/// Raw security attributes may be retained as evidence; owner/security fields
/// remain uninspectable until an explicit volume-bound security lookup is selected.
pub struct NtfsResolvedAttributeMetadata {
    attributes: Budgeted<Vec<crate::fs_ntfs::NtfsNativeAttribute>>,
    object: ObjectId,
    _lease: Reservation,
}
impl NtfsResolvedAttributeMetadata {
    /// Exact source-scoped base FILE identity.
    pub fn record(&self) -> &ObjectId {
        &self.object
    }
    /// Every resolved encoded attribute with physical occurrence provenance.
    pub fn native_attributes(&self) -> &[crate::fs_ntfs::NtfsNativeAttribute] {
        self.attributes.get()
    }
    /// Verified SI observation, distinct from FILE_NAME observations.
    pub fn standard_information(
        &self,
    ) -> Option<crate::fs_ntfs::NtfsNativeStandardInformation<'_>> {
        self.attributes
            .iter()
            .find_map(|attribute| attribute.standard_information())
    }
    /// Exact FILE_NAME values and their independent timestamp sets.
    pub fn file_names(&self) -> impl Iterator<Item = crate::fs_ntfs::NtfsNativeFileName<'_>> {
        self.attributes
            .iter()
            .filter_map(|attribute| attribute.file_name())
    }
    /// Consume native attribute evidence into common metadata. Security and owner
    /// remain explicitly uninspectable; no fallback to lossy base-record metadata.
    pub fn into_metadata(self, r: &Resources) -> Result<Budgeted<Metadata>> {
        map_resolved_attributes(self.attributes, None, r)
    }
}
/// Capture exact native attributes and SI/FN observations without resolving ACLs.
/// Requires the caller's source-stability contract and grants no restore authority.
pub fn inspect_ntfs_resolved_attributes(
    volume: &NtfsVolume,
    object: &ObjectId,
    limits: crate::fs_ntfs::NtfsStreamLimits,
    r: &Resources,
) -> Result<NtfsResolvedAttributeMetadata> {
    r.cancellation.check()?;
    let attributes = volume.native_attributes(object, limits, r)?;
    check_resolved_attributes(volume, object, attributes.get(), r)?;
    let charge = (std::mem::size_of::<NtfsResolvedAttributeMetadata>() as u64)
        .checked_add(object.native.len() as u64)
        .ok_or_else(|| metadata_cap("NTFS attribute metadata identity charge"))?;
    let lease = r.memory.reserve(charge)?;
    let identity = ObjectId {
        source: object.source,
        generation: object.generation,
        native: metadata_copy(&object.native)?,
    };
    r.cancellation.check()?;
    Ok(NtfsResolvedAttributeMetadata {
        attributes,
        object: identity,
        _lease: lease,
    })
}
impl NtfsResolvedNativeMetadata {
    /// Exact source-scoped base FILE identity bound to every retained attribute.
    pub fn record(&self) -> &ObjectId {
        self.security.record()
    }
    /// Every resolved attribute, including reserved bytes and extension-record provenance.
    pub fn native_attributes(&self) -> &[crate::fs_ntfs::NtfsNativeAttribute] {
        self.attributes.get()
    }
    /// Verified STANDARD_INFORMATION; FILE_NAME observations never replace these timestamps.
    pub fn standard_information(
        &self,
    ) -> Option<crate::fs_ntfs::NtfsNativeStandardInformation<'_>> {
        self.attributes
            .iter()
            .find_map(|a| a.standard_information())
    }
    /// Exact native FILE_NAME values, including each independent timestamp set and namespace.
    pub fn file_names(&self) -> impl Iterator<Item = crate::fs_ntfs::NtfsNativeFileName<'_>> {
        self.attributes.iter().filter_map(|a| a.file_name())
    }
    /// Exact descriptor, owner/group SID views and lookup provenance.
    pub fn security(&self) -> &NtfsResolvedSecurity {
        &self.security
    }
    /// Preserve verified SI timestamps/security and all encoded native attribute evidence.
    /// Attribute evidence keys identify source, generation, physical FILE, offset, type,
    /// instance and ordinal. Values are fixed-up encoded attributes, not restore authority.
    pub fn into_metadata(self, r: &Resources) -> Result<Budgeted<Metadata>> {
        map_resolved_attributes(self.attributes, Some(&self.security), r)
    }
}
fn map_resolved_attributes(
    attributes: Budgeted<Vec<crate::fs_ntfs::NtfsNativeAttribute>>,
    security: Option<&NtfsResolvedSecurity>,
    r: &Resources,
) -> Result<Budgeted<Metadata>> {
    r.cancellation.check()?;
    let descriptor = security.map(|resolved| resolved.descriptor());
    let owner = descriptor
        .and_then(|value| value.owner())
        .map(|sid| sid.raw());
    let additional = (attributes.len() as u64)
        .checked_mul(512)
        .and_then(|n| n.checked_add(4096))
        .and_then(|n| n.checked_add(descriptor.map_or(0, |value| value.raw().len() as u64)))
        .and_then(|n| n.checked_add(owner.map_or(0, |s| s.len() as u64)))
        .ok_or_else(|| metadata_cap("NTFS resolved metadata charge overflow"))?;
    attributes.try_map(additional, |native| {
        r.cancellation.check()?;
        let standard = native.iter().find_map(|a| a.standard_information());
        let stamp = |index: usize| {
            standard.map_or_else(
                || MetadataField::Uninspectable {
                    reason: "STANDARD_INFORMATION absent".into(),
                },
                |si| {
                    MetadataField::Known(NativeTimestamp {
                        // Preserve the legacy generic FILETIME contract: unsigned wire bits.
                        // Typed native SI/FN views retain their signed interpretation.
                        ticks: i128::from(u64::from_le_bytes(si.timestamps[index].to_le_bytes())),
                        ticks_per_second: 10_000_000,
                        epoch: "NTFS FILETIME: 1601-01-01 UTC".into(),
                    })
                },
            )
        };
        let created = stamp(0);
        let modified = stamp(1);
        let accessed = stamp(3);
        let native_flags = match standard {
            None => MetadataField::Uninspectable {
                reason: "STANDARD_INFORMATION flags absent".into(),
            },
            Some(si) => MetadataField::Known(metadata_copy(&si.flags.to_le_bytes())?),
        };
        let changed = standard.map(|si| si.timestamps[2].to_le_bytes());
        let mut attributes = Vec::new();
        attributes
            .try_reserve_exact(
                native
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| metadata_cap("NTFS metadata count overflow"))?,
            )
            .map_err(|_| metadata_cap("NTFS resolved metadata attribute allocation"))?;
        for (ordinal, a) in native.into_iter().enumerate() {
            r.cancellation.check()?;
            let number =
                u64::from_le_bytes(a.record.native.as_slice().try_into().map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "NTFS metadata physical record identity",
                    )
                })?);
            use std::fmt::Write;
            let mut label = String::new();
            // Maximum native numeric widths and separators fit below 256 bytes.
            // This allocation is covered by the per-attribute 512-byte envelope.
            label
                .try_reserve_exact(256)
                .map_err(|_| metadata_cap("NTFS evidence label allocation"))?;
            write!(
                label,
                "ntfs.attribute-evidence.v1.{:032x}.{}.{}.{}.{:08x}.{}.{}",
                a.record.source, a.record.generation, number, a.offset, a.kind, a.instance, ordinal
            )
            .map_err(|_| Error::new(ErrorKind::InvalidData, "NTFS evidence label formatting"))?;
            attributes.push((
                NativeName::Bytes(label.into_bytes()),
                MetadataField::Known(a.raw),
            ));
        }
        if let Some(changed) = changed {
            attributes.push((
                NativeName::Bytes(metadata_copy(
                    b"ntfs.STANDARD_INFORMATION.mft_changed.FILETIME",
                )?),
                MetadataField::Known(metadata_copy(&changed)?),
            ));
        }
        let security = match descriptor {
            Some(value) => MetadataField::Known(metadata_copy(value.raw())?),
            None => MetadataField::Uninspectable {
                reason: "native security inspection not selected".into(),
            },
        };
        let owner = if descriptor.is_none() {
            MetadataField::Uninspectable {
                reason: "native security inspection not selected".into(),
            }
        } else {
            match owner {
                Some(sid) => MetadataField::Known(metadata_copy(sid)?),
                None => MetadataField::Absent,
            }
        };
        r.cancellation.check()?;
        Ok(Metadata {
            created,
            modified,
            accessed,
            owner,
            mode: MetadataField::Absent,
            security,
            attributes,
            native_flags,
            symlink_target: MetadataField::Uninspectable {
                reason: "NTFS reparse interpretation not implemented".into(),
            },
            reparse_data: MetadataField::Uninspectable {
                reason: "NTFS reparse value remains native attribute evidence".into(),
            },
        })
    })
}
fn metadata_cap(reason: &'static str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, reason)
}
fn metadata_copy(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| metadata_cap("NTFS resolved metadata byte allocation"))?;
    result.extend_from_slice(bytes);
    Ok(result)
}
/// Capture complete native attributes and security through bounded fresh extension resolution.
/// Requires the caller's immutable-source contract; does not acquire a VSS snapshot.
pub fn inspect_ntfs_resolved_metadata(
    volume: &NtfsVolume,
    object: &ObjectId,
    limits: crate::fs_ntfs_security::NtfsSecureObjectLimits,
    r: &Resources,
) -> Result<NtfsResolvedNativeMetadata> {
    r.cancellation.check()?;
    let security = crate::fs_ntfs_security::lookup_ntfs_security_object(volume, object, limits, r)?;
    let attributes = volume.native_attributes(object, limits.streams, r)?;
    check_resolved_attributes(volume, object, attributes.get(), r)?;
    let lease = r
        .memory
        .reserve(std::mem::size_of::<NtfsResolvedNativeMetadata>() as u64)?;
    Ok(NtfsResolvedNativeMetadata {
        attributes,
        security,
        _lease: lease,
    })
}

fn check_resolved_attributes(
    volume: &NtfsVolume,
    object: &ObjectId,
    attributes: &[crate::fs_ntfs::NtfsNativeAttribute],
    r: &Resources,
) -> Result<()> {
    let mut standards = 0;
    for a in attributes.iter() {
        r.cancellation.check()?;
        if a.owner != *object {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS metadata attribute owner mismatch",
            ));
        }
        if a.kind == 0x10 {
            standards += 1;
            if standards > 1
                || !a.name.is_empty()
                || a.flags != 0
                || a.standard_information().is_none()
            {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "NTFS resolved metadata STANDARD_INFORMATION profile",
                ));
            }
        }
        if a.kind == 0x30
            && (!a.name.is_empty() || a.flags != 0 || a.file_name().is_none_or(|f| f.namespace > 3))
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "NTFS resolved metadata FILE_NAME profile",
            ));
        }
    }
    let number =
        u64::from_le_bytes(
            object.native.as_slice().try_into().map_err(|_| {
                Error::new(ErrorKind::InvalidData, "NTFS resolved metadata identity")
            })?,
        );
    if volume.stream_identity(number, r)? != *object {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "NTFS resolved metadata FILE sequence changed",
        ));
    }
    Ok(())
}
