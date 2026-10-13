//! Stable read-only evidence sources and bounded scan completion contracts.
use crate::io::{self, ReadAt};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Half-open range in the enclosing contract's explicitly identified coordinates.
/// Source regions and translations always use logical bytes, never container offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte.
    pub offset: u64,
    /// Number of bytes.
    pub length: u64,
}
impl ByteRange {
    /// Validate a range against its enclosing address space.
    pub fn checked(offset: u64, length: u64, capacity: u64) -> io::Result<Self> {
        if offset.checked_add(length).is_none_or(|end| end > capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evidence range outside source",
            ));
        }
        Ok(Self { offset, length })
    }
}
/// Process-local opaque identity of one bounded source view, never a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(u64);
impl SourceId {
    /// Integer token for streaming manifests within this process/session.
    pub fn get(self) -> u64 {
        self.0
    }
}
static NEXT_SOURCE_ID: AtomicU64 = AtomicU64::new(1);
fn next_source_id() -> io::Result<SourceId> {
    NEXT_SOURCE_ID
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map(SourceId)
        .map_err(|_| io::Error::other("source view identity exhausted"))
}
/// Acquisition information; labels are explicitly not verified digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    /// Caller acquisition identifier.
    pub acquisition: String,
    /// Backend/source label.
    pub source: String,
    /// Provider holding the stable acquisition.
    pub stability_provider: String,
}
/// Lifetime capability for a snapshot, immutable artifact or offline device.
/// Implementors must hold stability until their last reference is dropped.
/// A successful check is not generic detection of same-length modifications.
pub trait StabilityProvider: Send + Sync {
    /// Verify that the held acquisition remains available and stable.
    fn check(&self) -> io::Result<()>;
}
/// Shared revocable acquisition lease; the owner promises stable bytes while valid.
#[derive(Default)]
pub struct AcquisitionLease {
    invalid: AtomicBool,
}
impl AcquisitionLease {
    /// Invalidate this lease and every deferred reader using it.
    pub fn invalidate(&self) {
        self.invalid.store(true, Ordering::Release);
    }
}
impl StabilityProvider for AcquisitionLease {
    fn check(&self) -> io::Result<()> {
        if self.invalid.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "acquisition stability lost",
            ))
        } else {
            Ok(())
        }
    }
}
/// Bounded evidence view preserving acquisition identity and unavailable ranges.
#[derive(Clone)]
pub struct ForensicSource {
    id: SourceId,
    reader: Arc<dyn ReadAt>,
    identity: Arc<SourceIdentity>,
    stability: Arc<dyn StabilityProvider>,
    region: ByteRange,
    unavailable: Arc<[ByteRange]>,
    failure: Arc<spin::Mutex<Option<Arc<io::Error>>>>,
    manifest: Option<Arc<AcquisitionManifest>>,
}
impl ForensicSource {
    /// Bind explicitly stable bytes, a selected logical region and known acquisition gaps.
    pub fn new(
        reader: Arc<dyn ReadAt>,
        identity: SourceIdentity,
        stability: Arc<dyn StabilityProvider>,
        region: ByteRange,
        mut unavailable: Vec<ByteRange>,
    ) -> io::Result<Self> {
        if identity.acquisition.is_empty()
            || identity.source.is_empty()
            || identity.stability_provider.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "acquisition, source and stability provider identities must be nonempty",
            ));
        }
        ByteRange::checked(region.offset, region.length, reader.len())?;
        for range in &unavailable {
            ByteRange::checked(range.offset, range.length, reader.len())?;
        }
        // Canonicalize the exact unavailable union in place. Reads can then use
        // binary search instead of rescanning an adversarially fragmented map.
        unavailable.retain(|range| range.length != 0);
        unavailable.sort_unstable_by_key(|range| range.offset);
        let mut count = 0usize;
        for index in 0..unavailable.len() {
            let range = unavailable[index];
            if count != 0
                && range.offset <= unavailable[count - 1].offset + unavailable[count - 1].length
            {
                let previous = &mut unavailable[count - 1];
                previous.length = (previous.offset + previous.length)
                    .max(range.offset + range.length)
                    - previous.offset;
            } else {
                unavailable[count] = range;
                count += 1;
            }
        }
        unavailable.truncate(count);
        stability.check()?;
        let reader: Arc<dyn ReadAt> = Arc::new(virtdisk::DiskView::new(
            reader,
            region.offset,
            region.length,
        )?);
        Ok(Self {
            id: next_source_id()?,
            reader,
            identity: Arc::new(identity),
            stability,
            region,
            unavailable: unavailable.into(),
            failure: Arc::new(spin::Mutex::new(None)),
            manifest: None,
        })
    }
    /// Select a nested region while retaining original logical-disk provenance.
    pub fn select_region(&self, region: ByteRange) -> io::Result<Self> {
        let translated = self.translate_range(region)?;
        self.check_stability()?;
        Ok(Self {
            id: next_source_id()?,
            reader: Arc::new(virtdisk::DiskView::new(
                Arc::new(self.clone()),
                region.offset,
                region.length,
            )?),
            identity: self.identity.clone(),
            stability: self.stability.clone(),
            region: translated,
            unavailable: self.unavailable.clone(),
            failure: self.failure.clone(),
            manifest: self.manifest.clone(),
        })
    }
    /// Attach acquisition metadata without promoting caller labels to digests.
    pub fn with_acquisition_manifest(mut self, manifest: AcquisitionManifest) -> io::Result<Self> {
        for time in [manifest.started, manifest.completed].into_iter().flatten() {
            if time.nanoseconds >= 1_000_000_000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "acquisition nanoseconds out of range",
                ));
            }
        }
        self.manifest = Some(Arc::new(manifest));
        Ok(self)
    }
    /// Acquisition metadata, if supplied; absence means unknown acquisition facts.
    pub fn acquisition_manifest(&self) -> Option<&AcquisitionManifest> {
        self.manifest.as_deref()
    }
    /// Selected view in original logical disk coordinates.
    pub fn logical_disk_region(&self) -> ByteRange {
        self.region
    }
    /// Canonical nonoverlapping unavailable union in original logical disk coordinates.
    pub fn unavailable_ranges(&self) -> &[ByteRange] {
        &self.unavailable
    }
    /// Process-local token for this bounded view; clones retain it, subviews get a new token.
    pub fn id(&self) -> SourceId {
        self.id
    }
    /// Acquisition and backend identity, independent of content digests.
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
    /// Translate selected-volume offsets into logical disk offsets.
    pub fn translate_range(&self, range: ByteRange) -> io::Result<ByteRange> {
        ByteRange::checked(range.offset, range.length, self.region.length)?;
        Ok(ByteRange {
            offset: self.region.offset + range.offset,
            length: range.length,
        })
    }
    /// Check the lifetime capability; detected failure permanently invalidates this view.
    pub fn check_stability(&self) -> io::Result<()> {
        let mut failure = self.failure.lock();
        if let Some(cause) = failure.as_ref() {
            return Err(io::Error::new(
                cause.kind(),
                RetainedStabilityError(cause.clone()),
            ));
        }
        if let Err(error) = self.stability.check() {
            let cause = Arc::new(error);
            let result = io::Error::new(cause.kind(), RetainedStabilityError(cause.clone()));
            *failure = Some(cause);
            return Err(result);
        }
        Ok(())
    }
}
impl ReadAt for ForensicSource {
    fn len(&self) -> u64 {
        self.region.length
    }
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        self.check_stability()?;
        let range = self.translate_range(ByteRange {
            offset,
            length: buffer.len() as u64,
        })?;
        let end = range.offset + range.length;
        let preceding = self.unavailable.partition_point(|gap| gap.offset < end);
        if range.length != 0
            && preceding != 0
            && self.unavailable[preceding - 1].offset + self.unavailable[preceding - 1].length
                > range.offset
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unavailable acquired evidence range",
            ));
        }
        self.reader.read_exact_at(offset, buffer)?;
        self.check_stability()
    }
}
/// Why traversal stopped; validity of individual findings is independent.
#[derive(Debug)]
pub enum StopReason {
    /// All requested boundaries visited.
    Completed,
    /// Cancellation requested.
    Cancelled,
    /// Visitor deliberately stopped.
    CallerStop,
    /// Independent resource ceiling reached.
    ResourceLimit(&'static str),
    /// A resource ceiling with its original decoder or allocation cause.
    ResourceCause {
        /// Independent exhausted ceiling.
        ceiling: &'static str,
        /// Original causal failure.
        cause: io::Error,
    },
    /// Backing read failed, retaining its cause.
    Io(io::Error),
    /// Bootstrap could not be validated.
    InvalidBootstrap(io::Error),
    /// Requested mapping/profile is unsupported.
    UnsupportedProfile,
    /// Unsupported profile retaining its causal decoder or host error.
    UnsupportedCause(io::Error),
    /// Acquisition lost stability.
    SourceStability(io::Error),
    /// Visitor/output failed; event was not delivered.
    DeliveryFailed(io::Error),
}
/// Interpretation of a streamed coverage range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageKind {
    /// Bytes inspected (not necessarily validated).
    Inspected,
    /// Deliberately omitted independent boundary.
    Skipped,
    /// Read failure or acquisition hole.
    Unreadable,
    /// Unsupported mapping.
    Unsupported,
}
/// Streamed coverage; scanners retain counters instead of an unbounded range list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageEvent {
    /// Coordinates in the enclosing scan outcome's `coordinate_space`.
    pub range: ByteRange,
    /// Coverage interpretation.
    pub kind: CoverageKind,
}
/// Address space of a scan domain and its streamed coverage events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinateSpace {
    /// Selected filesystem volume-relative bytes.
    VolumeBytes,
    /// Original virtual/logical disk bytes, never physical container bytes.
    LogicalDiskBytes,
    /// Bytes within the selected logical stream or directory chain.
    LogicalStreamBytes,
    /// Copy-major table entry ordinals; never byte offsets.
    EntryOrdinals,
    /// Cluster ordinals; never byte offsets.
    ClusterOrdinals,
    /// Ordered output/event record ordinals; never byte offsets.
    RecordOrdinals,
}
/// Allocation-free terminal state, available even before the first observation.
#[derive(Debug)]
pub struct ScanOutcome {
    /// Bounded evidence view, or None for a detached/aggregate decoding domain.
    pub source_id: Option<SourceId>,
    /// Coordinate space shared by domain, remainder and coverage events.
    pub coordinate_space: CoordinateSpace,
    /// Requested scan domain.
    pub domain: ByteRange,
    /// Explicit scan profile.
    pub profile: &'static str,
    /// Number of delivered findings.
    pub observations: u64,
    /// Number of delivered coverage events.
    pub coverage_events: u64,
    /// Last successfully delivered position; none means no event delivered.
    pub last_delivered: Option<u64>,
    /// Unvisited suffix for ordered traversal; counts alone never establish coverage.
    pub unvisited: ByteRange,
    /// Terminal reason, with causal error where available.
    pub stop_reason: StopReason,
}
impl ScanOutcome {
    /// Reserve terminal state before beginning a scan.
    pub fn new(domain: ByteRange, profile: &'static str) -> Self {
        Self {
            source_id: None,
            coordinate_space: CoordinateSpace::VolumeBytes,
            domain,
            profile,
            observations: 0,
            coverage_events: 0,
            last_delivered: None,
            unvisited: domain,
            stop_reason: if domain.offset.checked_add(domain.length).is_some() {
                StopReason::Completed
            } else {
                StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "scan domain overflow",
                ))
            },
        }
    }
    /// Bind this scan's domain to one bounded evidence source view.
    pub fn with_source_id(mut self, source_id: SourceId) -> Self {
        self.source_id = Some(source_id);
        self
    }
    /// Set the explicit coordinate space before any coverage is delivered.
    pub fn with_coordinate_space(mut self, coordinate_space: CoordinateSpace) -> Self {
        self.coordinate_space = coordinate_space;
        self
    }
    /// Whether the traversal completed, independent of evidence validity.
    pub fn is_complete(&self) -> bool {
        matches!(self.stop_reason, StopReason::Completed) && self.unvisited.length == 0
    }
    /// Record successful ordered delivery through an explicit boundary.
    pub fn advance(&mut self, end: u64) {
        let limit = self.domain.offset.saturating_add(self.domain.length);
        let end = end.min(limit).max(self.unvisited.offset);
        self.last_delivered = Some(end);
        self.unvisited = ByteRange {
            offset: end,
            length: limit - end,
        };
    }
}
/// Independent scan ceilings; zero means no work allowed.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    /// Maximum inspected boundaries.
    pub records: u64,
    /// Maximum logical bytes requested from bounded `ReadAt`, including bootstrap.
    /// Container decoding and sector alignment may perform additional host I/O.
    pub read_bytes: u64,
    /// Maximum emitted evidence bytes.
    pub output_bytes: u64,
    /// Maximum simultaneous scratch/evidence allocation.
    pub memory_bytes: u64,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            records: 1_000_000,
            read_bytes: 1 << 30,
            output_bytes: 1 << 30,
            memory_bytes: 16 << 20,
        }
    }
}
/// Caller cancellation interface used at independent boundaries.
pub trait ScanControl {
    /// Whether cancellation was requested.
    fn cancelled(&self) -> bool;
}
impl ScanControl for AtomicBool {
    fn cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}
/// Control that never requests cancellation.
pub struct NeverCancel;
impl ScanControl for NeverCancel {
    fn cancelled(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct RetainedStabilityError(Arc<io::Error>);
impl core::fmt::Display for RetainedStabilityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl core::error::Error for RetainedStabilityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// UTC acquisition time with explicit nanosecond representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcquisitionTime {
    /// Whole seconds since Unix epoch (negative values precede it).
    pub unix_seconds: i64,
    /// Nanoseconds within the second, less than one billion.
    pub nanoseconds: u32,
}
/// Byte domain to which a supplied digest applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashDomain {
    /// Original physical container artifact bytes.
    OriginalContainerBytes,
    /// Decoded logical disk bytes.
    LogicalDiskBytes,
    /// Selected original logical disk evidence bytes.
    SelectedEvidenceRange(ByteRange),
    /// Delivered extraction prefix, independent of historical authenticity.
    ExtractedOutputPrefix,
}
/// Explicit SHA-256 digest with its byte domain; no historical authenticity claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDigest {
    /// Exact digest domain.
    pub domain: HashDomain,
    /// SHA-256 bytes.
    pub sha256: [u8; 32],
}
/// Role of an explicit immutable evidence input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceInputRole {
    /// Original container artifact.
    Container,
    /// Authorized immutable parent, in manifest order.
    Parent,
    /// Authorized immutable replay/recovery overlay.
    ImmutableRecoveryOverlay,
}
/// Container chains and overlays remain separate acquisition evidence inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceInput {
    /// Input role.
    pub role: EvidenceInputRole,
    /// Caller acquisition identity, never itself a digest.
    pub identity_label: String,
    /// Optional computed content digest with explicit domain.
    pub digest: Option<EvidenceDigest>,
}
/// Acquisition facts, independent of stability and filesystem consistency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcquisitionManifest {
    /// Start time, if known.
    pub started: Option<AcquisitionTime>,
    /// Artifact closure/end time, if known.
    pub completed: Option<AcquisitionTime>,
    /// Capturing stable bytes does not establish a point-in-time filesystem.
    pub consistency_uncertainty: String,
    /// Explicit ordered container/parent/overlay evidence inputs.
    pub inputs: Vec<EvidenceInput>,
    /// Computed digests; caller labels remain separate.
    pub digests: Vec<EvidenceDigest>,
}
impl AcquisitionManifest {
    /// Conservative retained metadata charge for bounded host serialization.
    pub fn metadata_bytes(&self) -> u64 {
        self.inputs
            .iter()
            .fold(self.consistency_uncertainty.len() as u64, |sum, input| {
                sum.saturating_add(input.identity_label.len() as u64)
                    .saturating_add(core::mem::size_of::<EvidenceInput>() as u64)
            })
            .saturating_add(
                (self.digests.len() as u64)
                    .saturating_mul(core::mem::size_of::<EvidenceDigest>() as u64),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Bytes;
    impl ReadAt for Bytes {
        fn len(&self) -> u64 {
            1024
        }
        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
            ByteRange::checked(offset, buffer.len() as u64, self.len())?;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (offset + index as u64) as u8;
            }
            Ok(())
        }
    }
    fn source(lease: Arc<AcquisitionLease>, gaps: Vec<ByteRange>) -> ForensicSource {
        ForensicSource::new(
            Arc::new(Bytes),
            SourceIdentity {
                acquisition: "acquired".into(),
                source: "memory".into(),
                stability_provider: "test lease".into(),
            },
            lease,
            ByteRange {
                offset: 512,
                length: 512,
            },
            gaps,
        )
        .unwrap()
    }
    #[test]
    fn bounded_deferred_reads_preserve_translation_and_revocation() {
        let lease = Arc::new(AcquisitionLease::default());
        let reader = source(lease.clone(), Vec::new());
        let mut bytes = [0; 4];
        reader.read_exact_at(3, &mut bytes).unwrap();
        assert_eq!(bytes, [3, 4, 5, 6]);
        assert_eq!(
            reader
                .translate_range(ByteRange {
                    offset: 3,
                    length: 4
                })
                .unwrap()
                .offset,
            515
        );
        assert!(reader.read_exact_at(510, &mut bytes).is_err());
        lease.invalidate();
        assert!(reader.read_exact_at(0, &mut bytes).is_err());
        assert!(reader.clone().read_exact_at(0, &mut bytes).is_err());
    }
    #[test]
    fn acquisition_holes_are_errors_without_fabricated_zero_bytes() {
        let reader = source(
            Arc::new(AcquisitionLease::default()),
            alloc::vec![ByteRange {
                offset: 514,
                length: 2
            }],
        );
        let mut bytes = [99; 4];
        assert!(reader.read_exact_at(0, &mut bytes).is_err());
        assert_eq!(bytes, [99; 4]);
        reader.read_exact_at(4, &mut bytes).unwrap();
    }
    #[test]
    fn empty_success_and_never_started_failure_are_distinct() {
        let empty = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: 0,
            },
            "empty",
        );
        assert!(empty.is_complete());
        let mut failed = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: 32,
            },
            "records",
        );
        failed.stop_reason = StopReason::Cancelled;
        assert!(!failed.is_complete());
        assert_eq!(failed.last_delivered, None);
        failed.advance(16);
        assert_eq!(
            failed.unvisited,
            ByteRange {
                offset: 16,
                length: 16
            }
        );
    }
    #[test]
    fn unstable_sources_are_rejected_before_any_read() {
        let lease = Arc::new(AcquisitionLease::default());
        lease.invalidate();
        let result = ForensicSource::new(
            Arc::new(Bytes),
            SourceIdentity {
                acquisition: "test".into(),
                source: "test".into(),
                stability_provider: "revoked".into(),
            },
            lease,
            ByteRange {
                offset: 0,
                length: 1024,
            },
            Vec::new(),
        );
        assert!(result.is_err());
    }
    #[test]
    fn nested_regions_keep_original_disk_coordinates() {
        let parent = source(Arc::new(AcquisitionLease::default()), Vec::new());
        let nested = parent
            .select_region(ByteRange {
                offset: 16,
                length: 32,
            })
            .unwrap();
        assert_eq!(
            nested
                .translate_range(ByteRange {
                    offset: 2,
                    length: 4
                })
                .unwrap(),
            ByteRange {
                offset: 530,
                length: 4
            }
        );
        let mut bytes = [0; 4];
        nested.read_exact_at(2, &mut bytes).unwrap();
        assert_eq!(bytes, [18, 19, 20, 21]);
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    struct Bytes;
    impl ReadAt for Bytes {
        fn len(&self) -> u64 {
            64
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
            ByteRange::checked(offset, bytes.len() as u64, 64)?;
            bytes.fill(7);
            Ok(())
        }
    }
    fn identity() -> SourceIdentity {
        SourceIdentity {
            acquisition: "case".into(),
            source: "immutable bytes".into(),
            stability_provider: "lease".into(),
        }
    }
    #[test]
    fn unsorted_overlapping_holes_preserve_exact_unavailable_union() {
        let source = ForensicSource::new(
            Arc::new(Bytes),
            identity(),
            Arc::new(AcquisitionLease::default()),
            ByteRange {
                offset: 0,
                length: 64,
            },
            alloc::vec![
                ByteRange {
                    offset: 20,
                    length: 4
                },
                ByteRange {
                    offset: 10,
                    length: 8
                },
                ByteRange {
                    offset: 17,
                    length: 3
                },
                ByteRange {
                    offset: 9,
                    length: 0
                }
            ],
        )
        .unwrap();
        assert_eq!(
            source.unavailable_ranges(),
            &[ByteRange {
                offset: 10,
                length: 14
            }]
        );
        let mut bytes = [99; 2];
        assert!(source.read_exact_at(9, &mut bytes).is_err());
        assert_eq!(bytes, [99; 2]);
        source.read_exact_at(8, &mut bytes).unwrap();
        assert_eq!(bytes, [7; 2]);
        source.read_exact_at(24, &mut bytes).unwrap();
        source.read_exact_at(12, &mut []).unwrap();
    }
    #[test]
    fn missing_identity_and_overflowed_domains_never_claim_completion() {
        let mut missing = identity();
        missing.stability_provider.clear();
        assert!(
            ForensicSource::new(
                Arc::new(Bytes),
                missing,
                Arc::new(AcquisitionLease::default()),
                ByteRange {
                    offset: 0,
                    length: 64
                },
                Vec::new()
            )
            .is_err()
        );
        let outcome = ScanOutcome::new(
            ByteRange {
                offset: u64::MAX,
                length: 1,
            },
            "invalid-domain",
        );
        assert!(!outcome.is_complete());
        assert!(matches!(
            outcome.stop_reason,
            StopReason::InvalidBootstrap(_)
        ));
        assert_eq!(outcome.last_delivered, None);
    }
}

#[cfg(test)]
mod acquisition_tests {
    use super::*;
    struct Empty;
    impl ReadAt for Empty {
        fn len(&self) -> u64 {
            0
        }
        fn read_exact_at(&self, _: u64, _: &mut [u8]) -> io::Result<()> {
            Ok(())
        }
    }
    fn source(lease: Arc<AcquisitionLease>) -> ForensicSource {
        ForensicSource::new(
            Arc::new(Empty),
            SourceIdentity {
                acquisition: "test".into(),
                source: "empty".into(),
                stability_provider: "lease".into(),
            },
            lease,
            ByteRange {
                offset: 0,
                length: 0,
            },
            Vec::new(),
        )
        .unwrap()
    }
    #[test]
    fn repeated_stability_checks_retain_original_causal_error() {
        let lease = Arc::new(AcquisitionLease::default());
        let source = source(lease.clone());
        lease.invalidate();
        let first = source.check_stability().unwrap_err();
        let subsequent = source.check_stability().unwrap_err();
        assert_eq!(alloc::format!("{first}"), "acquisition stability lost");
        assert_eq!(alloc::format!("{subsequent}"), "acquisition stability lost");
        assert!(core::error::Error::source(&subsequent).is_some());
    }
    #[test]
    fn acquisition_times_validate_and_nested_sources_retain_metadata() {
        let source = source(Arc::new(AcquisitionLease::default()));
        let invalid = AcquisitionManifest {
            started: Some(AcquisitionTime {
                unix_seconds: 0,
                nanoseconds: 1_000_000_000,
            }),
            ..AcquisitionManifest::default()
        };
        assert!(source.clone().with_acquisition_manifest(invalid).is_err());
        let manifest = AcquisitionManifest {
            consistency_uncertainty: "captured changing media".into(),
            ..AcquisitionManifest::default()
        };
        let source = source.with_acquisition_manifest(manifest.clone()).unwrap();
        assert_eq!(
            source
                .select_region(ByteRange {
                    offset: 0,
                    length: 0
                })
                .unwrap()
                .acquisition_manifest(),
            Some(&manifest)
        );
    }
}
