//! Conservative read-only maintenance checks backed by existing native audits.
//!
//! These adapters retain the original leased audit evidence and its typed
//! findings. Completing an allocation/namespace audit does not establish full
//! filesystem consistency, journal recovery safety, or writable support.
//!
//! Interrupted audits preserve previously established findings and their memory
//! reservations alongside the original failure. Incomplete evidence cannot
//! establish clean allocation or expose audited free ranges.

use crate::fs_core::{Error, ErrorKind, Resources};
use crate::fs_ext::ExtVolume;
use crate::fs_ext_audit::{self, ExtAuditLimits, ExtAuditReport};
use crate::fs_maintenance::{
    CheckCompletion, CheckFinding, CheckReport, FindingSeverity, PlanBinding,
};
use crate::fs_ntfs::{NtfsReadLimits, NtfsStreamLimits, NtfsVolume};
use crate::fs_ntfs_audit::{self, NtfsAuditLimits, NtfsAuditReport};
use crate::io::ReadAt;
use crate::platform::sync::Arc;

const EXT_SCOPE: &[&str] = &[
    "classic block allocation",
    "inode and directory references",
    "backup geometry",
];
const EXT_SKIPPED: &[(&str, &str)] = &[
    ("journal", "no replay or transaction recovery validation"),
    (
        "metadata and ACL semantics",
        "allocation audit does not validate security semantics",
    ),
    (
        "payload integrity",
        "allocation ownership does not verify file contents",
    ),
    (
        "modern ext profiles",
        "classic audit does not qualify ext3/ext4 maintenance",
    ),
];
const NTFS_SCOPE: &[&str] = &[
    "base-record allocation",
    "directory index references",
    "boot and MFT mirrors",
];
const NTFS_RESOLVED_SCOPE: &[&str] = &[
    "resolved base and extension allocation",
    "resolved directory index references",
    "boot and MFT mirrors",
];
const NTFS_RESOLVED_SKIPPED: &[(&str, &str)] = &[
    ("$LogFile", "no transaction recovery validation or replay"),
    ("USN", "no change-journal consistency validation"),
    (
        "security",
        "no complete $Secure and ACL consistency validation",
    ),
    (
        "compression and EFS",
        "no compressed or encrypted content verification",
    ),
    (
        "native qualification",
        "resolved ownership is not Windows mutation qualification",
    ),
    (
        "system and vendor features",
        "no complete system metadata or filter-owned feature validation",
    ),
];
const NTFS_SKIPPED: &[(&str, &str)] = &[
    ("$LogFile", "no transaction recovery validation or replay"),
    ("USN", "no change-journal consistency validation"),
    (
        "security",
        "no complete $Secure and ACL consistency validation",
    ),
    (
        "compression and EFS",
        "no compressed or encrypted content verification",
    ),
    (
        "resolved attribute ownership",
        "base-record audit is not complete resolved ownership qualification",
    ),
    (
        "system and vendor features",
        "no complete system metadata or filter-owned feature validation",
    ),
];

/// Maintenance summary together with the original native audit evidence.
///
/// Retaining the native report preserves typed object locations and its memory
/// reservation. A failure retains the original diagnostic and I/O cause chain.
pub struct AuditedCheck<'a, R> {
    binding: &'a PlanBinding,
    scope: &'static [&'static str],
    skipped: &'static [(&'static str, &'static str)],
    findings: [CheckFinding<'static>; 1],
    finding_count: usize,
    completion: CheckCompletion,
    recovery_required: bool,
    audit: Option<R>,
    error: Option<Error>,
}

impl<R> AuditedCheck<'_, R> {
    /// Common report describing check scope and its limitations.
    pub fn report(&self) -> CheckReport<'_> {
        CheckReport {
            binding: self.binding,
            scope: self.scope,
            findings: &self.findings[..self.finding_count],
            skipped: self.skipped,
            completion: self.completion,
            recovery_required: self.recovery_required,
        }
    }

    /// Native audit evidence, complete or partial, with exact typed finding locations.
    pub fn audit(&self) -> Option<&R> {
        self.audit.as_ref()
    }

    /// Original failure when the native audit did not complete.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
}

fn summary(code: &'static str, message: &'static str) -> CheckFinding<'static> {
    CheckFinding {
        code,
        message,
        object: None,
        offset: None,
        severity: FindingSeverity::Error,
    }
}

fn failed<'a, R>(
    binding: &'a PlanBinding,
    scope: &'static [&'static str],
    skipped: &'static [(&'static str, &'static str)],
    error: Error,
    audit: Option<R>,
    recovery_required: bool,
) -> AuditedCheck<'a, R> {
    let completion = match error.kind {
        ErrorKind::Io => CheckCompletion::IoFailure,
        ErrorKind::Unsupported => CheckCompletion::Unsupported,
        ErrorKind::BudgetExhausted => CheckCompletion::LimitReached,
        ErrorKind::Cancelled => CheckCompletion::Cancelled,
        _ => CheckCompletion::Incomplete,
    };
    AuditedCheck {
        binding,
        scope,
        skipped,
        findings: [summary(
            "native-audit-failed",
            "native audit stopped; inspect error() and any retained audit().findings() for established evidence",
        )],
        finding_count: 1,
        completion,
        recovery_required,
        audit,
        error: Some(error),
    }
}

/// Check a classic ext volume without modifying or replaying into the source.
///
/// `binding` is caller-established context: this adapter does not authenticate
/// source identity, generation, feature digests or metadata digests. It grants
/// no repair authority. Exact findings remain available in [`AuditedCheck::audit`].
/// Even a successful native audit leaves full maintenance coverage incomplete.
pub fn check_ext<'a>(
    volume: &ExtVolume,
    binding: &'a PlanBinding,
    limits: ExtAuditLimits,
    resources: &Resources,
) -> AuditedCheck<'a, ExtAuditReport> {
    let preflight = (|| -> crate::fs_core::Result<()> {
        binding.validate()?;
        if binding.filesystem_bytes
            != u64::from(volume.geometry().blocks()) * u64::from(volume.geometry().block_size())
            || binding.allocation_unit != volume.geometry().block_size()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext maintenance binding geometry differs from inspected volume",
            ));
        }
        Ok(())
    })();
    if let Err(error) = preflight {
        return failed(binding, EXT_SCOPE, EXT_SKIPPED, error, None, false);
    }
    match fs_ext_audit::audit_detailed(volume, limits, resources) {
        Ok(audit) => {
            let has_findings = !audit.findings().is_empty();
            let completion = if audit.namespace_complete() {
                CheckCompletion::Complete
            } else {
                CheckCompletion::Incomplete
            };
            AuditedCheck {
                binding,
                scope: EXT_SCOPE,
                skipped: EXT_SKIPPED,
                findings: [summary(
                    "ext-native-findings",
                    "classic ext audit found inconsistencies; inspect audit().findings() for native object locations",
                )],
                finding_count: usize::from(has_findings),
                completion,
                recovery_required: false,
                audit: Some(audit),
                error: None,
            }
        }
        Err(failure) => failed(
            binding,
            EXT_SCOPE,
            EXT_SKIPPED,
            failure.error,
            failure.partial,
            false,
        ),
    }
}

/// Check NTFS base-record allocation and indexes without writing or replaying.
///
/// `binding` identity and digests are caller-established context; native geometry
/// is checked, but source generation and digests are not authenticated. The
/// source must stay immutable across geometry opening and auditing.
/// A successful audit does not establish complete resolved ownership,
/// journal recovery, ACL, compressed-content, or encrypted-content consistency.
/// Exact findings and volume flags remain in [`AuditedCheck::audit`].
pub fn check_ntfs<'a>(
    source: Arc<dyn ReadAt>,
    binding: &'a PlanBinding,
    read_limits: NtfsReadLimits,
    limits: NtfsAuditLimits,
    resources: &Resources,
) -> AuditedCheck<'a, NtfsAuditReport> {
    check_ntfs_inner(source, binding, read_limits, None, limits, resources)
}

/// Check resolved plain/sparse NTFS allocation, extensions and directory indexes.
/// Native geometry is compared with caller-provided binding context. Journal,
/// security and encrypted/compressed-content semantics remain explicitly skipped.
pub fn check_ntfs_resolved<'a>(
    source: Arc<dyn ReadAt>,
    binding: &'a PlanBinding,
    read_limits: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: NtfsAuditLimits,
    resources: &Resources,
) -> AuditedCheck<'a, NtfsAuditReport> {
    check_ntfs_inner(
        source,
        binding,
        read_limits,
        Some(streams),
        limits,
        resources,
    )
}

fn check_ntfs_inner<'a>(
    source: Arc<dyn ReadAt>,
    binding: &'a PlanBinding,
    read_limits: NtfsReadLimits,
    streams: Option<NtfsStreamLimits>,
    limits: NtfsAuditLimits,
    resources: &Resources,
) -> AuditedCheck<'a, NtfsAuditReport> {
    let (scope, skipped) = if streams.is_some() {
        (NTFS_RESOLVED_SCOPE, NTFS_RESOLVED_SKIPPED)
    } else {
        (NTFS_SCOPE, NTFS_SKIPPED)
    };
    let preflight = (|| -> crate::fs_core::Result<()> {
        binding.validate()?;
        let volume = if let Some(streams) = streams {
            NtfsVolume::open_for_resolved_audit(
                Arc::clone(&source),
                read_limits,
                streams,
                resources,
            )?
        } else {
            NtfsVolume::open_for_audit(Arc::clone(&source), read_limits, resources)?
        };
        if binding.filesystem_bytes != volume.geometry().volume_bytes()
            || u64::from(binding.allocation_unit) != volume.geometry().cluster_bytes()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS maintenance binding geometry differs from inspected volume",
            ));
        }
        Ok(())
    })();
    if let Err(error) = preflight {
        return failed(binding, scope, skipped, error, None, false);
    }
    let result = if let Some(streams) = streams {
        fs_ntfs_audit::audit_ntfs_resolved_detailed(source, read_limits, streams, limits, resources)
    } else {
        fs_ntfs_audit::audit_ntfs_detailed(source, read_limits, limits, resources)
    };
    match result {
        Ok(audit) => {
            let has_findings = !audit.findings().is_empty();
            let completion = if audit.volume_flags() & !1 != 0 {
                CheckCompletion::Unsupported
            } else if audit.is_complete() {
                CheckCompletion::Complete
            } else {
                CheckCompletion::Incomplete
            };
            AuditedCheck {
                binding,
                scope,
                skipped,
                findings: [summary(
                    "ntfs-native-findings",
                    "NTFS audit found defects or unsupported volume state; inspect audit().findings() for exact native records",
                )],
                finding_count: usize::from(has_findings),
                completion,
                recovery_required: audit.volume_flags() & 1 != 0,
                audit: Some(audit),
                error: None,
            }
        }
        Err(failure) => {
            let (error, audit) = failure.into_parts();
            let recovery_required = audit
                .as_ref()
                .is_some_and(|audit| audit.volume_flags() & 1 != 0);
            failed(binding, scope, skipped, error, audit, recovery_required)
        }
    }
}

#[cfg(all(test, feature = "std"))]
#[path = "../tests/fixtures/ext2_clean.rs"]
pub(crate) mod clean_fixture;

#[cfg(all(test, feature = "std"))]
#[path = "../tests/fixtures/ntfs_clean.rs"]
mod ntfs_fixture;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation, ObjectId};
    use crate::fs_maintenance::CheckOutcome;
    use crate::fs_storage::SectorGeometry;
    use crate::platform::io;

    struct Image(Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
            let start = usize::try_from(offset).map_err(io::Error::other)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            bytes.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
            Ok(())
        }
    }

    fn binding() -> PlanBinding {
        PlanBinding {
            source: ObjectId {
                source: 1,
                generation: 1,
                native: vec![1],
            },
            backend: [0; 32],
            region_start: 0,
            region_bytes: 65536,
            filesystem_bytes: 65536,
            allocation_unit: 1024,
            sectors: SectorGeometry {
                logical: Some(512),
                physical: None,
            },
            features: [0; 32],
            metadata: [0; 32],
        }
    }

    fn limits() -> ExtAuditLimits {
        ExtAuditLimits {
            blocks: 32768,
            inodes: 8192,
            work: 1_000_000,
            directory_blocks: 256,
            directory_entries: 1024,
            findings: 1024,
        }
    }

    #[test]
    fn clean_allocation_audit_does_not_claim_complete_maintenance() {
        let resources = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let volume =
            ExtVolume::open(Arc::new(Image(clean_fixture::fixture())), &resources).unwrap();
        let binding = binding();
        let checked = check_ext(&volume, &binding, limits(), &resources);
        assert!(checked.audit().unwrap().is_clean());
        assert_eq!(checked.report().outcome(), CheckOutcome::Incomplete);
    }

    #[test]
    fn budget_failure_retains_failure_and_never_returns_clean() {
        let resources = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let volume =
            ExtVolume::open(Arc::new(Image(clean_fixture::fixture())), &resources).unwrap();
        let binding = binding();
        let mut limits = limits();
        limits.work = 0;
        let checked = check_ext(&volume, &binding, limits, &resources);
        assert_eq!(checked.report().completion, CheckCompletion::LimitReached);
        assert!(!checked.audit().unwrap().complete());
        assert_eq!(checked.error().unwrap().kind, ErrorKind::BudgetExhausted);
    }

    #[test]
    fn known_allocation_defect_retains_native_location_despite_skipped_checks() {
        let resources = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = clean_fixture::fixture();
        bytes[3073] |= 1;
        let volume = ExtVolume::open(Arc::new(Image(bytes)), &resources).unwrap();
        let binding = binding();
        let checked = check_ext(&volume, &binding, limits(), &resources);
        assert!(
            checked
                .audit()
                .unwrap()
                .findings()
                .contains(&crate::fs_ext_audit::ExtAuditFinding::LostBlock { block: 9 })
        );
        assert_eq!(checked.report().outcome(), CheckOutcome::Inconsistent);
    }

    #[test]
    fn wrong_ext_geometry_rejects_binding_before_audit() {
        let resources = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let volume =
            ExtVolume::open(Arc::new(Image(clean_fixture::fixture())), &resources).unwrap();
        let mut binding = binding();
        binding.allocation_unit = 512;
        let checked = check_ext(&volume, &binding, limits(), &resources);
        assert_eq!(checked.error().unwrap().kind, ErrorKind::StalePlan);
    }

    fn ntfs_binding() -> PlanBinding {
        let mut binding = binding();
        binding.region_bytes = 1024 * 512 + 512;
        binding.filesystem_bytes = 1024 * 512;
        binding.allocation_unit = 512;
        binding
    }

    fn ntfs_limits() -> NtfsAuditLimits {
        NtfsAuditLimits {
            clusters: 2048,
            records: 128,
            attributes: 1024,
            ranges: 256,
            entries: 128,
            index_blocks: 32,
            depth: 8,
            work: 50000,
            findings: 64,
            free_ranges: 64,
        }
    }

    fn ntfs_check<'a>(
        bytes: Vec<u8>,
        binding: &'a PlanBinding,
        resources: &Resources,
    ) -> AuditedCheck<'a, NtfsAuditReport> {
        check_ntfs(
            Arc::new(Image(bytes)),
            binding,
            NtfsReadLimits {
                attributes: 32,
                runs: 64,
                names: 8,
            },
            ntfs_limits(),
            resources,
        )
    }

    #[test]
    fn ntfs_clean_native_allocation_does_not_claim_complete_maintenance() {
        let resources = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let binding = ntfs_binding();
        let checked = ntfs_check(ntfs_fixture::ntfs_audit_seed(), &binding, &resources);
        assert!(checked.audit().unwrap().is_clean());
        assert_eq!(checked.report().outcome(), CheckOutcome::Incomplete);
    }

    #[test]
    fn ntfs_wrong_geometry_rejects_binding_before_audit() {
        let resources = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let mut binding = ntfs_binding();
        binding.filesystem_bytes -= 512;
        let checked = ntfs_check(ntfs_fixture::ntfs_audit_seed(), &binding, &resources);
        assert_eq!(checked.error().unwrap().kind, ErrorKind::StalePlan);
    }

    #[test]
    fn ntfs_dirty_volume_retains_recovery_obligation() {
        let resources = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let binding = ntfs_binding();
        let mut bytes = ntfs_fixture::ntfs_audit_seed();
        let flags = 2048
            + 3 * 1024
            + 56
            + ntfs_fixture::resident(0x30, &ntfs_fixture::name_value("$Volume", 5), 2).len()
            + 24
            + 10;
        bytes[flags] = 1;
        let checked = ntfs_check(bytes, &binding, &resources);
        assert!(checked.report().recovery_required);
        assert!(
            checked
                .audit()
                .unwrap()
                .findings()
                .contains(&crate::fs_ntfs_audit::NtfsAuditFinding::Dirty)
        );
        assert_eq!(checked.report().outcome(), CheckOutcome::RecoveryRequired);
    }
    #[test]
    fn ext_failure_retains_established_finding_and_original_error() {
        let resources = Resources {
            memory: Budget::new(16 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = clean_fixture::fixture();
        bytes[2060..2062].copy_from_slice(&54u16.to_le_bytes());
        let file = 5 * 1024 + 10 * 128;
        bytes[file..file + 2].copy_from_slice(&0xa1ffu16.to_le_bytes());
        // Canonical symlinks are now admitted. A valid short block-backed
        // target remains outside the qualified audit profile.
        bytes[file + 4..file + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8 * 1024..9 * 1024].fill(0);
        bytes[8 * 1024] = b'x';
        bytes[7 * 1024 + 24 + 7] = 7;
        bytes[7 * 1024 + 40 + 7] = 7;
        let volume = ExtVolume::open(Arc::new(Image(bytes)), &resources).unwrap();
        let binding = binding();
        let checked = check_ext(&volume, &binding, limits(), &resources);
        assert_eq!(checked.report().completion, CheckCompletion::Unsupported);
        assert_eq!(checked.error().unwrap().kind, ErrorKind::Unsupported);
        let audit = checked.audit().unwrap();
        assert!(!audit.complete());
        assert!(!audit.is_clean());
        assert!(audit.free_ranges().is_empty());
        assert!(
            audit
                .findings()
                .contains(&crate::fs_ext_audit::ExtAuditFinding::GroupFreeCount {
                    group: 0,
                    inodes: false,
                    recorded: 54,
                    actual: 55,
                })
        );
        assert!(resources.memory.used() > 0);
        drop(checked);
        assert_eq!(resources.memory.used(), 0);
    }

    #[test]
    fn ntfs_failure_retains_dirty_finding_and_recovery_obligation() {
        let resources = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let binding = ntfs_binding();
        let mut bytes = ntfs_fixture::ntfs_audit_seed();
        let flags = 2048
            + 3 * 1024
            + 56
            + ntfs_fixture::resident(0x30, &ntfs_fixture::name_value("$Volume", 5), 2).len()
            + 24
            + 10;
        bytes[flags] = 1;
        let mut limits = ntfs_limits();
        limits.work = 0;
        let checked = check_ntfs(
            Arc::new(Image(bytes)),
            &binding,
            NtfsReadLimits {
                attributes: 32,
                runs: 64,
                names: 8,
            },
            limits,
            &resources,
        );
        assert_eq!(checked.report().completion, CheckCompletion::LimitReached);
        assert_eq!(checked.error().unwrap().kind, ErrorKind::BudgetExhausted);
        assert!(checked.report().recovery_required);
        let audit = checked.audit().unwrap();
        assert!(
            audit
                .findings()
                .contains(&crate::fs_ntfs_audit::NtfsAuditFinding::Dirty)
        );
        assert!(!audit.is_complete());
        assert!(!audit.is_clean());
        assert!(audit.free_ranges().is_empty());
        assert!(resources.memory.used() > 0);
        drop(checked);
        assert_eq!(resources.memory.used(), 0);
    }
}
