//! Additive maintenance contracts. These types enable no filesystem writer.
//!
//! Evidence and plans describe one exact profile and bounded source generation.
//! Callers must obtain fresh binding facts from an exclusively held session before
//! mutation; comparing caller-supplied identities does not establish exclusivity.
use crate::fs_core::{Error, ErrorKind, NativeName, NativeTimestamp, ObjectId, Result};
use crate::fs_storage::SectorGeometry;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use crate::platform::prelude::*;

/// Maintenance operations, independent of build, recovery and file resizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceOperation {
    /// Read-only logical consistency inspection.
    Check,
    /// Explicitly planned consistency repair.
    Repair,
    /// Native filesystem initialization with an explicit erase policy.
    Format,
    /// Grow native filesystem geometry inside an existing boundary.
    Grow,
    /// Shrink native filesystem geometry before shrinking its boundary.
    Shrink,
}

/// One maintenance capability under an exact profile and backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceCapability<'a> {
    /// Independently admitted maintenance operation.
    pub operation: MaintenanceOperation,
    /// Implementation and qualification status, including restrictions.
    pub status: FeatureStatus<'a>,
}

/// Additive capability inventory; existing build/resize/recover entries are not consulted.
#[derive(Debug)]
pub struct MaintenanceCapabilities<'a> {
    /// Exact native filesystem profile.
    pub profile: &'a str,
    /// Exact backend identity for which capabilities were determined.
    pub backend: [u8; 32],
    /// Explicit operation inventory; omitted operations remain unqualified.
    pub operations: &'a [MaintenanceCapability<'a>],
}
impl<'a> MaintenanceCapabilities<'a> {
    /// Query without inferring maintenance support from other capabilities.
    /// Duplicate declarations and mismatched evidence never establish support.
    pub fn status(&self, operation: MaintenanceOperation) -> FeatureStatus<'a> {
        let mut entries = self
            .operations
            .iter()
            .filter(|entry| entry.operation == operation);
        let Some(entry) = entries.next() else {
            return FeatureStatus::Unqualified("maintenance operation is not inventoried");
        };
        if entries.next().is_some() {
            return FeatureStatus::Unqualified("duplicate maintenance operation entries");
        }
        if let FeatureStatus::Qualified(evidence) = entry.status
            && (evidence.profile != self.profile
                || evidence.binding.backend != self.backend
                || evidence.receipt.is_empty()
                || evidence.implementation_revision.is_empty()
                || evidence.binding.validate().is_err())
        {
            return FeatureStatus::Unqualified("invalid maintenance qualification evidence");
        }
        entry.status
    }
}

/// Exact binding facts to capture during planning and refresh before mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanBinding {
    /// Source identity and generation, including native volume identity.
    pub source: ObjectId,
    /// Backend identity; equal lengths do not establish identity.
    pub backend: [u8; 32],
    /// Region start within the backend in bytes.
    pub region_start: u64,
    /// Available bounded region length in bytes.
    pub region_bytes: u64,
    /// Native filesystem length in bytes.
    pub filesystem_bytes: u64,
    /// Native allocation unit in bytes.
    pub allocation_unit: u32,
    /// Backend sector facts, without guessing unknown facts.
    pub sectors: SectorGeometry,
    /// Digest of the precise native profile and feature configuration.
    pub features: [u8; 32],
    /// Digest of the metadata evidence used to construct the plan.
    pub metadata: [u8; 32],
}
impl PlanBinding {
    /// Reject inconsistent or overflowing geometry without performing I/O.
    pub fn validate(&self) -> Result<()> {
        let unit = u64::from(self.allocation_unit);
        if unit == 0
            || self.filesystem_bytes == 0
            || self.filesystem_bytes > self.region_bytes
            || self.region_start.checked_add(self.region_bytes).is_none()
            || [self.sectors.logical, self.sectors.physical]
                .into_iter()
                .flatten()
                .any(|sector| sector == 0)
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid maintenance geometry",
            ));
        }
        if let Some(sector) = self.sectors.logical {
            let sector = u64::from(sector);
            if !self.filesystem_bytes.is_multiple_of(sector)
                || !self.region_start.is_multiple_of(sector)
                || !self.region_bytes.is_multiple_of(sector)
                || !unit.is_multiple_of(sector)
            {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "maintenance geometry is not sector aligned",
                ));
            }
        }
        Ok(())
    }

    /// Compare all facts with a fresh observation, rejecting stale plans.
    /// This is necessary but does not replace exclusive ownership or engine preflight.
    pub fn revalidate(&self, observed: &Self) -> Result<()> {
        self.validate()?;
        observed.validate()?;
        if self != observed {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "maintenance source, geometry, features or metadata changed",
            ));
        }
        Ok(())
    }
}

/// Independent feature dimensions. Preservation does not imply mutation support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureOperation {
    /// Recognize the feature.
    Inspect,
    /// Interpret native semantics.
    Decode,
    /// Preserve its original native representation.
    Preserve,
    /// Create new instances.
    Create,
    /// Mutate existing instances.
    Edit,
    /// Repair inconsistencies.
    Repair,
    /// Initialize the feature during formatting.
    Format,
    /// Preserve the feature during geometry growth.
    Grow,
    /// Recover interrupted mutations.
    Recovery,
}

/// Qualification state for one feature and operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureStatus<'a> {
    /// Native semantics are unavailable for this exact profile.
    Unsupported(&'a str),
    /// Implementation or qualification is incomplete.
    Unqualified(&'a str),
    /// Implemented and independently qualified under the attached evidence.
    Qualified(&'a QualificationEvidence<'a>),
}

/// Source-bound qualification receipt; it is evidence, not execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationEvidence<'a> {
    /// Exact implementation revision tested.
    pub implementation_revision: &'a str,
    /// Exact native profile tested.
    pub profile: &'a str,
    /// Binding of the fixture/source tested.
    pub binding: &'a PlanBinding,
    /// Independently reviewable receipt location.
    pub receipt: &'a str,
    /// SHA-256 of the immutable receipt bytes; consumers verify the referenced artifact.
    pub receipt_sha256: [u8; 32],
    /// Qualification prerequisites and limits; empty means none recorded.
    pub prerequisites: &'a [&'a str],
}

/// One explicit feature-operation entry; omitted entries remain unqualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureEntry<'a> {
    /// Native feature identifier, including vendor/historical variants.
    pub feature: &'a str,
    /// Independent semantic operation.
    pub operation: FeatureOperation,
    /// Actual qualification status.
    pub status: FeatureStatus<'a>,
}

/// Borrowed manifest: allocation and inventory limits remain with its owner.
#[derive(Debug)]
pub struct FeatureManifest<'a> {
    /// Schema revision; only version 1 is understood by this API.
    pub version: u32,
    /// Exact format profile, not merely the filesystem family.
    pub profile: &'a str,
    /// Explicit feature inventory.
    pub entries: &'a [FeatureEntry<'a>],
}
impl<'a> FeatureManifest<'a> {
    /// Query conservatively. Missing, duplicate, foreign-profile or empty receipts
    /// never establish qualified support. This performs no backend access.
    pub fn status(&self, feature: &str, operation: FeatureOperation) -> FeatureStatus<'a> {
        if self.version != 1 {
            return FeatureStatus::Unqualified("unknown manifest version");
        }
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| entry.feature == feature && entry.operation == operation);
        let Some(entry) = matches.next() else {
            return FeatureStatus::Unqualified("feature operation is not inventoried");
        };
        if matches.next().is_some() {
            return FeatureStatus::Unqualified("duplicate feature operation entries");
        }
        if let FeatureStatus::Qualified(evidence) = entry.status
            && (evidence.profile != self.profile
                || evidence.receipt.is_empty()
                || evidence.implementation_revision.is_empty()
                || evidence.binding.validate().is_err())
        {
            return FeatureStatus::Unqualified("invalid qualification evidence");
        }
        entry.status
    }
}

/// Explicit portable patch; omitted input never means clear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FieldPatch<T> {
    /// Preserve the current native value.
    #[default]
    Unchanged,
    /// Set a value after native representation and semantic validation.
    Set(T),
    /// Remove the native field, if the selected profile permits absence.
    Remove,
}

/// Portable metadata requests retaining native encodings. Engines validate the
/// entire patch for their exact profile before writes; these fields grant no
/// capability and do not translate incompatible ACL or timestamp models.
#[derive(Debug, Default)]
pub struct MetadataPatch<'a> {
    /// Native creation timestamp.
    pub created: FieldPatch<&'a NativeTimestamp>,
    /// Native content modification timestamp.
    pub modified: FieldPatch<&'a NativeTimestamp>,
    /// Native access timestamp.
    pub accessed: FieldPatch<&'a NativeTimestamp>,
    /// Native metadata-change timestamp, where explicit restoration is supported.
    pub changed: FieldPatch<&'a NativeTimestamp>,
    /// Native backup timestamp, where represented.
    pub backup: FieldPatch<&'a NativeTimestamp>,
    /// Native owner identity, retaining its exact encoding.
    pub owner: FieldPatch<&'a [u8]>,
    /// Native group identity, retaining its exact encoding.
    pub group: FieldPatch<&'a [u8]>,
    /// Mode bits under the selected native profile.
    pub mode: FieldPatch<u32>,
    /// Native ACL/security descriptor, preserving absent/null/empty distinctions.
    pub security: FieldPatch<&'a [u8]>,
    /// Native flags; engines preserve unknown unrelated bits.
    pub native_flags: FieldPatch<&'a [u8]>,
    /// Explicit named native attribute requests; missing names remain unchanged.
    pub attributes: &'a [(NativeName, FieldPatch<&'a [u8]>)],
}
impl MetadataPatch<'_> {
    /// Check shared representation invariants without assuming native semantics.
    /// Native ranges, ACL models, privileges and derived invariants still require
    /// profile-specific whole-patch preflight before mutation.
    pub fn validate(&self) -> Result<()> {
        for patch in [
            &self.created,
            &self.modified,
            &self.accessed,
            &self.changed,
            &self.backup,
        ] {
            if let FieldPatch::Set(timestamp) = patch
                && (timestamp.ticks_per_second == 0 || timestamp.epoch.is_empty())
            {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "timestamp requires explicit epoch and nonzero native resolution",
                ));
            }
        }
        for (index, (name, _)) in self.attributes.iter().enumerate() {
            if self.attributes[..index]
                .iter()
                .any(|(previous, _)| previous == name)
            {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "duplicate native attribute patch",
                ));
            }
        }
        Ok(())
    }
}

/// Severity of a logical consistency finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSeverity {
    /// Informational observation, without a consistency defect.
    Information,
    /// A suspected issue that prevents an unconditional clean result.
    Warning,
    /// An established native invariant violation.
    Error,
}
/// Structured finding with native object and byte location when known.
#[derive(Debug)]
pub struct CheckFinding<'a> {
    /// Stable engine-defined invariant identifier.
    pub code: &'a str,
    /// Human-readable diagnostic.
    pub message: &'a str,
    /// Native object identity, when identifiable.
    pub object: Option<&'a ObjectId>,
    /// Byte offset relative to the bounded region, when known.
    pub offset: Option<u64>,
    /// Defect severity.
    pub severity: FindingSeverity,
}
/// Why the declared scope could not be fully checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckCompletion {
    /// All declared checks completed.
    Complete,
    /// A memory or scan-work bound stopped checking.
    LimitReached,
    /// A native scan stopped before completing its declared scope.
    Incomplete,
    /// Cooperative cancellation stopped checking.
    Cancelled,
    /// A required native feature could not be checked.
    Unsupported,
    /// Backend reading failed; findings already obtained remain available.
    IoFailure,
}
/// Derived logical outcome; a partial report can never be clean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckOutcome {
    /// All checks in the explicitly declared scope passed.
    Clean,
    /// Findings prevent a clean result.
    Inconsistent,
    /// Native recovery is required before ordinary mutation.
    RecoveryRequired,
    /// Required native checks are unsupported.
    Unsupported,
    /// Limits or cancellation prevented completion.
    Incomplete,
    /// Reading failed.
    IoFailure,
}
/// Read-only check evidence. Slices borrow bounded engine-owned report storage.
#[derive(Debug)]
pub struct CheckReport<'a> {
    /// Context for the inspected source. An engine must document which facts it
    /// authenticated; a report alone does not authenticate caller-supplied identities.
    pub binding: &'a PlanBinding,
    /// Explicit logical scope, e.g. allocation ownership or namespace.
    pub scope: &'a [&'a str],
    /// Findings retained even if later scanning fails.
    pub findings: &'a [CheckFinding<'a>],
    /// Features skipped, with a reason per feature.
    pub skipped: &'a [(&'a str, &'a str)],
    /// Actual scan completion.
    pub completion: CheckCompletion,
    /// Native recovery obligation observed by the checker.
    pub recovery_required: bool,
}
impl CheckReport<'_> {
    /// Derive outcome from evidence; callers cannot supply a clean flag.
    /// Completion failure takes precedence; recovery remains separately visible.
    pub fn outcome(&self) -> CheckOutcome {
        match self.completion {
            CheckCompletion::IoFailure => return CheckOutcome::IoFailure,
            CheckCompletion::Unsupported => return CheckOutcome::Unsupported,
            CheckCompletion::LimitReached
            | CheckCompletion::Cancelled
            | CheckCompletion::Incomplete => {
                return CheckOutcome::Incomplete;
            }
            CheckCompletion::Complete => {}
        }
        if self.recovery_required {
            CheckOutcome::RecoveryRequired
        } else if self
            .findings
            .iter()
            .any(|finding| finding.severity != FindingSeverity::Information)
        {
            CheckOutcome::Inconsistent
        } else if !self.skipped.is_empty()
            || self.scope.is_empty()
            || self.binding.validate().is_err()
        {
            CheckOutcome::Incomplete
        } else {
            CheckOutcome::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_queries_reject_missing_duplicate_and_foreign_backend_evidence() {
        let binding = binding();
        let evidence = QualificationEvidence {
            implementation_revision: "fixture-only",
            profile: "test-profile",
            binding: &binding,
            receipt: "fixture-receipt",
            receipt_sha256: [4; 32],
            prerequisites: &[],
        };
        let entry = MaintenanceCapability {
            operation: MaintenanceOperation::Grow,
            status: FeatureStatus::Qualified(&evidence),
        };
        let entries = [entry, entry];
        let mut capabilities = MaintenanceCapabilities {
            profile: "test-profile",
            backend: binding.backend,
            operations: &entries[..1],
        };
        assert!(matches!(
            capabilities.status(MaintenanceOperation::Grow),
            FeatureStatus::Qualified(_)
        ));
        assert!(matches!(
            capabilities.status(MaintenanceOperation::Shrink),
            FeatureStatus::Unqualified(_)
        ));
        capabilities.operations = &entries;
        assert!(matches!(
            capabilities.status(MaintenanceOperation::Grow),
            FeatureStatus::Unqualified(_)
        ));
        capabilities.operations = &entries[..1];
        capabilities.backend = [9; 32];
        assert!(matches!(
            capabilities.status(MaintenanceOperation::Grow),
            FeatureStatus::Unqualified(_)
        ));
    }
    fn binding() -> PlanBinding {
        PlanBinding {
            source: ObjectId {
                source: 1,
                generation: 2,
                native: vec![3],
            },
            backend: [1; 32],
            region_start: 512,
            region_bytes: 8192,
            filesystem_bytes: 4096,
            allocation_unit: 4096,
            sectors: SectorGeometry {
                logical: Some(512),
                physical: Some(4096),
            },
            features: [2; 32],
            metadata: [3; 32],
        }
    }
    #[test]
    fn partial_checks_never_report_clean() {
        let binding = binding();
        let mut report = CheckReport {
            binding: &binding,
            scope: &["ownership"],
            findings: &[],
            skipped: &[],
            completion: CheckCompletion::Complete,
            recovery_required: false,
        };
        assert_eq!(report.outcome(), CheckOutcome::Clean);
        for completion in [
            CheckCompletion::LimitReached,
            CheckCompletion::Cancelled,
            CheckCompletion::Unsupported,
            CheckCompletion::IoFailure,
        ] {
            report.completion = completion;
            assert_ne!(report.outcome(), CheckOutcome::Clean);
        }
        report.completion = CheckCompletion::Complete;
        report.skipped = &[("ACL", "unqualified")];
        assert_eq!(report.outcome(), CheckOutcome::Incomplete);
    }
    #[test]
    fn binding_rejects_changes_to_each_bound_fact() {
        let original = binding();
        let mut changed = original.clone();
        changed.source.generation += 1;
        assert_eq!(
            original.revalidate(&changed).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        changed = original.clone();
        changed.metadata[0] ^= 1;
        assert_eq!(
            original.revalidate(&changed).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        changed = original;
        changed.region_start = u64::MAX;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn duplicate_and_missing_manifest_entries_remain_unqualified() {
        let entry = FeatureEntry {
            feature: "ADS",
            operation: FeatureOperation::Edit,
            status: FeatureStatus::Unsupported("reader only"),
        };
        let entries = [entry, entry];
        let manifest = FeatureManifest {
            version: 1,
            profile: "NTFS",
            entries: &entries,
        };
        assert!(matches!(
            manifest.status("ADS", FeatureOperation::Edit),
            FeatureStatus::Unqualified(_)
        ));
        assert!(matches!(
            manifest.status("EFS", FeatureOperation::Edit),
            FeatureStatus::Unqualified(_)
        ));
    }
    #[test]
    fn sector_aligned_partial_allocation_unit_is_valid() {
        let mut geometry = binding();
        geometry.filesystem_bytes = 4608;
        assert!(geometry.validate().is_ok());
    }
    #[test]
    fn timestamp_patch_rejects_implicit_resolution() {
        let timestamp = NativeTimestamp {
            ticks: 0,
            ticks_per_second: 0,
            epoch: "native".into(),
        };
        let patch = MetadataPatch {
            modified: FieldPatch::Set(&timestamp),
            ..MetadataPatch::default()
        };
        assert_eq!(
            patch.validate().unwrap_err().kind,
            ErrorKind::InvalidOperation
        );
    }
    #[test]
    fn known_findings_survive_skipped_features() {
        let binding = binding();
        let findings = [CheckFinding {
            code: "ownership",
            message: "cross-linked allocation",
            object: None,
            offset: Some(512),
            severity: FindingSeverity::Error,
        }];
        let report = CheckReport {
            binding: &binding,
            scope: &["ownership"],
            findings: &findings,
            skipped: &[("ACL", "unqualified")],
            completion: CheckCompletion::Complete,
            recovery_required: false,
        };
        assert_eq!(report.outcome(), CheckOutcome::Inconsistent);
    }
    #[test]
    fn omitted_patch_preserves_and_remove_is_explicit() {
        assert_eq!(FieldPatch::<u32>::default(), FieldPatch::Unchanged);
        assert_ne!(FieldPatch::Set(0), FieldPatch::Remove);
    }
}
