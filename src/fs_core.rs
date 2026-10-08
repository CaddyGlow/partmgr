//! Format-independent filesystem contracts. These types advertise no filesystem engine.
//!
//! Native names and metadata retain their original representation. Engines, rather
//! than host path APIs, own comparison and normalization. Deferred sources must
//! remain stable throughout inventory and all repeated positional reads.

use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Lossless on-disk name; conversion to display text is explicitly lossy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NativeName {
    /// Exact byte sequence, including non-UTF-8 names.
    Bytes(Vec<u8>),
    /// Exact UTF-16 code units, including unpaired surrogates.
    Utf16(Vec<u16>),
}
impl NativeName {
    /// Convert to display text, replacing invalid sequences without changing native storage.
    pub fn display_lossy(&self) -> String {
        match self {
            Self::Bytes(v) => String::from_utf8_lossy(v).into_owned(),
            Self::Utf16(v) => String::from_utf16_lossy(v),
        }
    }
}
/// Object identities are meaningful only within their source and generation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ObjectId {
    /// Origin identifier; identities from different sources cannot be equated.
    pub source: u128,
    /// Source generation preventing stale identities after object reuse.
    pub generation: u64,
    /// Engine-defined opaque native object key.
    pub native: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Native namespace object category.
pub enum ObjectKind {
    /// Regular file object.
    File,
    /// Directory containing native-name entries.
    Directory,
    /// Symbolic link inspected without following its target.
    Symlink,
    /// Format-specific device or special object requiring preservation policy.
    Special,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Object-owned content stream category.
pub enum StreamKind {
    /// Ordinary stream data.
    Data,
    /// Named stream owned by its object.
    Named(NativeName),
    /// Separate resource fork.
    ResourceFork,
    /// Format-specific system stream.
    System(NativeName),
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Stream inventory without payload allocation.
pub struct StreamInfo {
    /// Semantic category, interpreted under the selected profile.
    pub kind: StreamKind,
    /// Logical length in bytes.
    pub length: u64,
}
/// Unwritten allocated storage is distinct from a hole and from stored zero bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtentKind {
    /// Ordinary stream data.
    Data,
    /// Unallocated logical zeros.
    Hole,
    /// Allocated extent whose content is logically zero until written.
    Unwritten,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// One logical stream range, without assuming physical contiguity.
pub struct LogicalExtent {
    /// Logical byte offset within the stream.
    pub offset: u64,
    /// Logical length in bytes.
    pub length: u64,
    /// Semantic category, interpreted under the selected profile.
    pub kind: ExtentKind,
}
/// Absent and uninspectable fields must never be conflated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataField<T> {
    /// The native field is absent.
    Absent,
    /// The reader cannot establish whether or how this field is represented.
    Uninspectable {
        /// Why inspection is unavailable.
        reason: String,
    },
    /// The reader understands the typed value.
    Known(T),
    /// Original bytes retained without claiming safe transplantation.
    Opaque {
        /// Native uninterpreted field encoding; no relocation assurance.
        bytes: Vec<u8>,
        /// Description of which meaning remains unknown.
        interpretation: String,
    },
}
/// Native ticks preserve precision and epoch; conversion/rounding belongs to an explicit policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTimestamp {
    /// Signed native tick count relative to the declared epoch.
    pub ticks: i128,
    /// Nonzero native clock resolution; engines reject a zero denominator.
    pub ticks_per_second: u64,
    /// Native epoch and calendar interpretation, without implicit Unix conversion.
    pub epoch: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Native object metadata and explicit inspection status.
pub struct Metadata {
    /// Creation timestamp with native precision.
    pub created: MetadataField<NativeTimestamp>,
    /// Content modification timestamp with native precision.
    pub modified: MetadataField<NativeTimestamp>,
    /// Access timestamp with native precision.
    pub accessed: MetadataField<NativeTimestamp>,
    /// Native ownership encoding; engines specify its typed interpretation.
    pub owner: MetadataField<Vec<u8>>,
    /// Native permission/mode bits under the profile.
    pub mode: MetadataField<u32>,
    /// ACL or security descriptor encoding.
    pub security: MetadataField<Vec<u8>>,
    /// Native extended attribute names and their interpreted or opaque values.
    pub attributes: Vec<(NativeName, MetadataField<Vec<u8>>)>,
    /// Format-specific object flags.
    pub native_flags: MetadataField<Vec<u8>>,
    /// Unfollowed symbolic-link target in its native representation.
    pub symlink_target: MetadataField<NativeName>,
    /// Separate native reparse payload.
    pub reparse_data: MetadataField<Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Directory name referring to a source-scoped object.
pub struct DirectoryEntry {
    /// Exact native directory entry name.
    pub name: NativeName,
    /// Source-scoped identity shared by hard-linked entries.
    pub object: ObjectId,
    /// Semantic category, interpreted under the selected profile.
    pub kind: ObjectKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Format family inventory; variants do not advertise implemented engines.
pub enum Family {
    /// Fat12 filesystem family; support is determined by individual profiles.
    Fat12,
    /// Fat16 filesystem family; support is determined by individual profiles.
    Fat16,
    /// Fat32 filesystem family; support is determined by individual profiles.
    Fat32,
    /// ExFat filesystem family; support is determined by individual profiles.
    ExFat,
    /// Ntfs filesystem family; support is determined by individual profiles.
    Ntfs,
    /// Ext2 filesystem family; support is determined by individual profiles.
    Ext2,
    /// Ext3 filesystem family; support is determined by individual profiles.
    Ext3,
    /// Ext4 filesystem family; support is determined by individual profiles.
    Ext4,
    /// Xfs filesystem family; support is determined by individual profiles.
    Xfs,
    /// Hfs filesystem family; support is determined by individual profiles.
    Hfs,
    /// HfsPlus filesystem family; support is determined by individual profiles.
    HfsPlus,
    /// HfsX filesystem family; support is determined by individual profiles.
    HfsX,
    /// Apfs filesystem family; support is determined by individual profiles.
    Apfs,
    /// Jfs filesystem family; support is determined by individual profiles.
    Jfs,
    /// Jffs2 filesystem family; support is determined by individual profiles.
    Jffs2,
    /// Udf filesystem family; support is determined by individual profiles.
    Udf,
    /// Iso9660 filesystem family; support is determined by individual profiles.
    Iso9660,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Independently gated filesystem operation or feature.
pub enum Operation {
    /// Identify the format signature and candidate profile.
    Recognize,
    /// Strictly validate metadata needed for access.
    ValidateMetadata,
    /// Establish complete ownership accounting under the profile.
    AuditAllocation,
    /// Decode file contents under supported feature states.
    DecodePayload,
    /// Provide positional file and stream access.
    Read,
    /// Author a new unpublished filesystem.
    Build,
    /// Allocate and create objects.
    Create,
    /// Replace supported file ranges.
    Replace,
    /// Change file length with allocation accounting.
    Truncate,
    /// Remove objects or entries.
    Delete,
    /// Change directory entry names.
    Rename,
    /// Create additional entries for an existing identity.
    Link,
    /// Modify supported native metadata.
    EditMetadata,
    /// Represent sparse holes and unwritten extents.
    Sparse,
    /// Decode or encode the declared compression profile.
    Compression,
    /// Access the declared encryption profile.
    Encryption,
    /// Inspect or manage declared snapshot/clone semantics.
    Snapshots,
    /// Use explicitly authorized auxiliary storage.
    AuxiliaryDevices,
    /// Replay or restore the declared recovery protocol.
    Recover,
    /// Relocate allocations and change filesystem boundaries.
    Resize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Explicit operation support and prerequisites.
pub enum Availability {
    /// Available under this precise profile and its stated conditions.
    Supported,
    /// Unavailable with an explicit reason.
    Unsupported {
        /// Why this operation is unavailable.
        reason: String,
    },
    /// Available only after satisfying the stated prerequisite.
    Requires {
        /// Prerequisite that must hold before the operation.
        condition: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Per-profile capability and evidence report.
pub struct CapabilityProfile {
    /// On-disk format family; this alone does not imply support.
    pub family: Family,
    /// Precise version, feature set and operation scope.
    pub profile: String,
    /// Per-operation availability; absent operations remain unsupported.
    pub operations: Vec<(Operation, Availability)>,
    /// Declared flush, recovery and publication guarantees.
    pub durability: String,
    /// Independent evidence establishing the advertised profile.
    pub validation_evidence: Vec<String>,
}
impl CapabilityProfile {
    /// Missing entries are explicitly unsupported, never implicitly enabled.
    pub fn availability(&self, operation: Operation) -> Availability {
        self.operations
            .iter()
            .find(|(op, _)| *op == operation)
            .map(|(_, a)| a.clone())
            .unwrap_or_else(|| Availability::Unsupported {
                reason: "operation is not advertised by this profile".into(),
            })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Structured failure category.
pub enum ErrorKind {
    /// Malformed or inconsistent native structures.
    InvalidData,
    /// Unavailable with an explicit reason.
    Unsupported,
    /// A shared memory or declared work limit would be exceeded.
    BudgetExhausted,
    /// An operation violates current object or session semantics.
    InvalidOperation,
    /// Identity, generation or source state changed after planning.
    StalePlan,
    /// Cancellation observed before an irreversible step.
    Cancelled,
    /// Mutation started and requires explicit recovery.
    InterruptedWrite,
    /// Writes or barriers may have completed without durable confirmation.
    UncertainDurability,
    /// An underlying I/O operation failed; the source is retained.
    Io,
}
#[derive(Debug)]
/// Filesystem failure retaining underlying I/O diagnostics.
pub struct Error {
    /// Semantic category, interpreted under the selected profile.
    pub kind: ErrorKind,
    /// Operation and object context explaining the failure.
    pub context: String,
    /// Original underlying I/O failure, when this error was caused by I/O.
    pub source: Option<io::Error>,
}
impl Error {
    /// Describe a semantic failure without an underlying I/O cause.
    pub fn new(kind: ErrorKind, context: impl Into<String>) -> Self {
        Self {
            kind,
            context: context.into(),
            source: None,
        }
    }
    /// Retain an I/O cause and preserve an embedded framework failure category.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        let kind = source
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Self>())
            .map_or(ErrorKind::Io, |cause| cause.kind);
        Self {
            kind,
            context: context.into(),
            source: Some(source),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
/// Filesystem operation result.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Default, Debug)]
/// Shareable cooperative cancellation signal.
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    /// Signal cancellation to every clone.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Return cancellation before starting the next bounded unit of work.
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(Error::new(ErrorKind::Cancelled, "operation cancelled"))
        } else {
            Ok(())
        }
    }
}
/// A shared concurrent accounting pool. A reservation refunds memory on drop.
#[derive(Clone, Debug)]
pub struct Budget {
    limit: u64,
    used: Arc<AtomicU64>,
}
impl Budget {
    /// Create a shared pool with a maximum retained byte charge.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: Arc::new(AtomicU64::new(0)),
        }
    }
    /// Read the currently reserved byte count.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
    /// Atomically reserve bytes or fail without changing shared accounting.
    pub fn reserve(&self, bytes: u64) -> Result<Reservation> {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|n| *n <= self.limit)
            })
            .map_err(|_| {
                Error::new(
                    ErrorKind::BudgetExhausted,
                    "shared resource budget exceeded",
                )
            })?;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
}
#[derive(Debug)]
/// Owned refundable accounting charge.
pub struct Reservation {
    budget: Budget,
    bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
/// An owned result whose memory charge remains reserved for its entire lifetime.
///
/// The value is exposed by shared reference only: extracting or growing it would
/// detach retained allocations from their accounting. Cloning a referenced value
/// requires a separate reservation from the caller.
#[derive(Debug)]
pub struct Budgeted<T> {
    value: T,
    reservation: Reservation,
}
impl<T> Budgeted<T> {
    /// Reserve an upper bound before constructing the value.
    ///
    /// `bytes` must include retained container capacities and all nested heap
    /// allocations, with checked arithmetic. The constructor must use fallible
    /// allocation and return `BudgetExhausted` on allocation failure. Temporary
    /// scratch needs its own reservation. On failure the charge is refunded.
    pub fn try_new(
        budget: &Budget,
        bytes: u64,
        construct: impl FnOnce() -> Result<T>,
    ) -> Result<Self> {
        let reservation = budget.reserve(bytes)?;
        Ok(Self {
            value: construct()?,
            reservation,
        })
    }

    /// Inspect the retained value without releasing its charge.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Return the upper bound charged to the shared budget.
    pub fn reserved_bytes(&self) -> u64 {
        self.reservation.bytes
    }
}
impl<T> std::ops::Deref for Budgeted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.get()
    }
}
/// Inventory and every metadata/cache/scratch consumer must retain reservations.
#[derive(Clone, Debug)]
pub struct Resources {
    /// Shared accounting across inventory, caches and payload scratch.
    pub memory: Budget,
    /// Shared cancellation signal across deferred operations.
    pub cancellation: Cancellation,
}

/// Reusable immutable positional stream. No shared seek cursor or whole-file buffering.
/// Reads at/after EOF return zero; short reads may occur before EOF. Engines must
/// check cancellation and locally validate mappings, retaining shared accounting.
/// A valid handle keeps its identity and logical length fixed. Source mutation
/// must fail explicitly under the declared stability assurance. Sharing a handle
/// permits concurrent reads; it does not establish source isolation.
pub trait FileRead: Send + Sync {
    /// Return the source-scoped identity and generation for this handle.
    fn identity(&self) -> &ObjectId;
    /// Return the logical stream length in bytes.
    fn len(&self) -> u64;
    /// Report whether the logical stream length is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read a bounded range into caller storage; return the actual count.
    fn read_at(&self, offset: u64, buffer: &mut [u8], resources: &Resources) -> Result<usize>;
    /// Visit validated logical extents without buffering file contents.
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()>;
}
/// Size-bounded convenience access. Retains the allocation reservation with its bytes.
#[derive(Debug)]
pub struct BoundedContent {
    /// Owned payload bytes, charged to the retained memory reservation.
    pub bytes: Vec<u8>,
    _reservation: Reservation,
}
/// Read a size-bounded whole stream, handling short reads and rejecting observed
/// identity or length changes. This check cannot establish snapshot isolation: a
/// source must still uphold its declared stability assurance throughout reading.
pub fn read_all(
    file: &dyn FileRead,
    maximum: u64,
    resources: &Resources,
) -> Result<BoundedContent> {
    resources.cancellation.check()?;
    let identity = file.identity().clone();
    let length = file.len();
    if length > maximum {
        return Err(Error::new(
            ErrorKind::BudgetExhausted,
            "whole-file limit exceeded",
        ));
    }
    let size = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "file exceeds address space"))?;
    let reservation = resources.memory.reserve(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "payload allocation failed"))?;
    bytes.resize(size, 0);
    let mut done = 0;
    while done < size {
        resources.cancellation.check()?;
        let count = file.read_at(done as u64, &mut bytes[done..], resources)?;
        if count == 0 || count > size - done {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "stream changed or returned invalid read length",
            ));
        }
        done += count;
    }
    if file.len() != length || file.identity() != &identity {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "stream identity or length changed during read",
        ));
    }
    Ok(BoundedContent {
        bytes,
        _reservation: reservation,
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Actual deferred-read stability assurance.
pub enum SourceStability {
    /// Source bytes are retained in a genuine immutable snapshot.
    ImmutableSnapshot,
    /// Caller guarantees unchanged backing storage during all deferred access.
    CallerGuaranteedStable,
    /// Changes can be detected, but concurrent mutation is not excluded.
    ChangeDetectionOnly,
}
/// Inventory is paged by the engine using an opaque continuation token. Hard links
/// retain identical object identities. No host path lookup or implicit symlink following.
pub struct DirectoryPage {
    /// Bounded page of native-name entries retaining hard-link identities.
    pub entries: Vec<DirectoryEntry>,
    /// Opaque continuation token, or none at the end of iteration.
    pub next: Option<Vec<u8>>,
    /// Memory charge retained while the page remains alive.
    pub reservation: Reservation,
}
/// Bounded native tree inventory and deferred content source.
/// Implementations must check source-scoped identities and generation on every
/// operation. Reusing an identifier after deletion must change its generation.
/// All returned inventory, metadata, and stream lists count against shared memory
/// accounting; directory pages carry reservations for their entire retained data.
/// Reserve before allocation, use checked size arithmetic and fallible allocation,
/// and charge capacities, nested names, opaque metadata, and continuation tokens.
/// Scratch and caches share the same pool but retain their own reservations.
/// Deferred payload errors retain their I/O cause and never become empty files.
/// Open streams must remain valid under the declared stability assurance, or fail
/// explicitly if the source changes. Repeated reads must produce the same bytes.
pub trait TreeSource: Send + Sync {
    /// Return the source-scoped root identity.
    fn root(&self) -> ObjectId;
    /// Report actual source isolation assurance.
    fn stability(&self) -> SourceStability;
    /// Inspect native metadata without conflating absent and unknown fields.
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>>;
    /// Read at most the requested number of entries using an opaque continuation.
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        resources: &Resources,
    ) -> Result<DirectoryPage>;
    /// Enumerate object-owned ordinary, named and fork streams.
    fn streams(
        &self,
        object: &ObjectId,
        resources: &Resources,
    ) -> Result<Budgeted<Vec<StreamInfo>>>;
    /// Open reusable deferred positional access to one owned stream.
    fn open_stream(
        &self,
        object: &ObjectId,
        stream: &StreamKind,
        resources: &Resources,
    ) -> Result<Arc<dyn FileRead>>;
    /// Detect identity/generation/size changes before publication. Detection alone
    /// is not snapshot isolation and failures must abort the staged operation.
    fn revalidate(&self, object: &ObjectId, resources: &Resources) -> Result<()>;
}

/// Reviewable decision for each metadata class; opaque bytes are never presumed relocatable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Preservation {
    /// Retain the supported native semantics exactly.
    Preserve,
    /// Apply an explicit transformation and report its information loss.
    Transform {
        /// Explicit transformation policy.
        policy: String,
        /// Declared information loss.
        report: String,
    },
    /// Refuse unsupported preservation before emission.
    Reject {
        /// Unsupported preservation requirement.
        reason: String,
    },
}
/// New-output sinks own an unpublished destination. Planning must reject unsupported
/// semantics before payload writes. Publication is a separate orchestration operation.
/// Existing-volume editing requires a format-specific recoverable transaction API.
/// Plans must bind source identities, generations, sizes and preservation decisions,
/// detect name collisions, and declare staging/recovery resource requirements.
/// Emission revalidates deferred inputs and propagates cancellation and failures.
/// Cancellation may leave staging artifacts, but must never publish them.
/// Verification reports actual assurance: content-only copying is not faithful capture.
pub trait TreeSink {
    /// Reviewable preflight result bound to source identity.
    type Plan;
    /// Verification evidence and preservation outcomes.
    type Report;
    /// Inventory and preflight the source before any payload mutation.
    fn plan(&mut self, source: &dyn TreeSource, resources: &Resources) -> Result<Self::Plan>;
    /// Stream the preflighted payload and metadata into unpublished staging.
    fn emit(
        &mut self,
        plan: &Self::Plan,
        source: &dyn TreeSource,
        resources: &Resources,
    ) -> Result<()>;
    /// Flush, reopen, audit and compare supported content/metadata in the staged output.
    fn verify(
        &mut self,
        plan: &Self::Plan,
        source: &dyn TreeSource,
        resources: &Resources,
    ) -> Result<Self::Report>;
}
