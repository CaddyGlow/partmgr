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
/// enum NativeName contract value.
pub enum NativeName {
    /// Bytes contract value.
    Bytes(Vec<u8>),
    /// Utf16 contract value.
    Utf16(Vec<u16>),
}
impl NativeName {
    /// fn display lossy contract value.
    pub fn display_lossy(&self) -> String {
        match self {
            Self::Bytes(v) => String::from_utf8_lossy(v).into_owned(),
            Self::Utf16(v) => String::from_utf16_lossy(v),
        }
    }
}
/// Object identities are meaningful only within their source and generation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
/// struct ObjectId contract value.
pub struct ObjectId {
    /// source contract value.
    pub source: u128,
    /// generation contract value.
    pub generation: u64,
    /// native contract value.
    pub native: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// enum ObjectKind contract value.
pub enum ObjectKind {
    /// File contract value.
    File,
    /// Directory contract value.
    Directory,
    /// Symlink contract value.
    Symlink,
    /// Special contract value.
    Special,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// enum StreamKind contract value.
pub enum StreamKind {
    /// Data contract value.
    Data,
    /// Named contract value.
    Named(NativeName),
    /// ResourceFork contract value.
    ResourceFork,
    /// System contract value.
    System(NativeName),
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct StreamInfo contract value.
pub struct StreamInfo {
    /// kind contract value.
    pub kind: StreamKind,
    /// length contract value.
    pub length: u64,
}
/// Unwritten allocated storage is distinct from a hole and from stored zero bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
/// enum ExtentKind contract value.
pub enum ExtentKind {
    /// Data contract value.
    Data,
    /// Hole contract value.
    Hole,
    /// Unwritten contract value.
    Unwritten,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct LogicalExtent contract value.
pub struct LogicalExtent {
    /// offset contract value.
    pub offset: u64,
    /// length contract value.
    pub length: u64,
    /// kind contract value.
    pub kind: ExtentKind,
}
/// Absent and uninspectable fields must never be conflated.
#[derive(Clone, Debug, Eq, PartialEq)]
/// enum MetadataField contract value.
pub enum MetadataField<T> {
    /// Absent contract value.
    Absent,
    /// Uninspectable contract value.
    Uninspectable {
        /// Why inspection is unavailable.
        reason: String,
    },
    /// Known contract value.
    Known(T),
    /// Opaque contract value.
    Opaque {
        /// Native uninterpreted field encoding; no relocation assurance.
        bytes: Vec<u8>,
        /// Description of which meaning remains unknown.
        interpretation: String,
    },
}
/// Native ticks preserve precision and epoch; conversion/rounding belongs to an explicit policy.
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct NativeTimestamp contract value.
pub struct NativeTimestamp {
    /// ticks contract value.
    pub ticks: i128,
    /// ticks per second contract value.
    pub ticks_per_second: u64,
    /// epoch contract value.
    pub epoch: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct Metadata contract value.
pub struct Metadata {
    /// created contract value.
    pub created: MetadataField<NativeTimestamp>,
    /// modified contract value.
    pub modified: MetadataField<NativeTimestamp>,
    /// accessed contract value.
    pub accessed: MetadataField<NativeTimestamp>,
    /// owner contract value.
    pub owner: MetadataField<Vec<u8>>,
    /// mode contract value.
    pub mode: MetadataField<u32>,
    /// security contract value.
    pub security: MetadataField<Vec<u8>>,
    /// attributes contract value.
    pub attributes: Vec<(NativeName, MetadataField<Vec<u8>>)>,
    /// native flags contract value.
    pub native_flags: MetadataField<Vec<u8>>,
    /// symlink target contract value.
    pub symlink_target: MetadataField<NativeName>,
    /// reparse data contract value.
    pub reparse_data: MetadataField<Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct DirectoryEntry contract value.
pub struct DirectoryEntry {
    /// name contract value.
    pub name: NativeName,
    /// object contract value.
    pub object: ObjectId,
    /// kind contract value.
    pub kind: ObjectKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// enum Family contract value.
pub enum Family {
    /// Fat12 contract value.
    Fat12,
    /// Fat16 contract value.
    Fat16,
    /// Fat32 contract value.
    Fat32,
    /// ExFat contract value.
    ExFat,
    /// Ntfs contract value.
    Ntfs,
    /// Ext2 contract value.
    Ext2,
    /// Ext3 contract value.
    Ext3,
    /// Ext4 contract value.
    Ext4,
    /// Xfs contract value.
    Xfs,
    /// Hfs contract value.
    Hfs,
    /// HfsPlus contract value.
    HfsPlus,
    /// HfsX contract value.
    HfsX,
    /// Apfs contract value.
    Apfs,
    /// Jfs contract value.
    Jfs,
    /// Jffs2 contract value.
    Jffs2,
    /// Udf contract value.
    Udf,
    /// Iso9660 contract value.
    Iso9660,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// enum Operation contract value.
pub enum Operation {
    /// Recognize contract value.
    Recognize,
    /// ValidateMetadata contract value.
    ValidateMetadata,
    /// AuditAllocation contract value.
    AuditAllocation,
    /// DecodePayload contract value.
    DecodePayload,
    /// Read contract value.
    Read,
    /// Build contract value.
    Build,
    /// Create contract value.
    Create,
    /// Replace contract value.
    Replace,
    /// Truncate contract value.
    Truncate,
    /// Delete contract value.
    Delete,
    /// Rename contract value.
    Rename,
    /// Link contract value.
    Link,
    /// EditMetadata contract value.
    EditMetadata,
    /// Sparse contract value.
    Sparse,
    /// Compression contract value.
    Compression,
    /// Encryption contract value.
    Encryption,
    /// Snapshots contract value.
    Snapshots,
    /// AuxiliaryDevices contract value.
    AuxiliaryDevices,
    /// Recover contract value.
    Recover,
    /// Resize contract value.
    Resize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// enum Availability contract value.
pub enum Availability {
    /// Supported contract value.
    Supported,
    /// Unsupported contract value.
    Unsupported {
        /// Why this operation is unavailable.
        reason: String,
    },
    /// Requires contract value.
    Requires {
        /// Prerequisite that must hold before the operation.
        condition: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// struct CapabilityProfile contract value.
pub struct CapabilityProfile {
    /// family contract value.
    pub family: Family,
    /// profile contract value.
    pub profile: String,
    /// operations contract value.
    pub operations: Vec<(Operation, Availability)>,
    /// durability contract value.
    pub durability: String,
    /// validation evidence contract value.
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
/// enum ErrorKind contract value.
pub enum ErrorKind {
    /// InvalidData contract value.
    InvalidData,
    /// Unsupported contract value.
    Unsupported,
    /// BudgetExhausted contract value.
    BudgetExhausted,
    /// InvalidOperation contract value.
    InvalidOperation,
    /// StalePlan contract value.
    StalePlan,
    /// Cancelled contract value.
    Cancelled,
    /// InterruptedWrite contract value.
    InterruptedWrite,
    /// UncertainDurability contract value.
    UncertainDurability,
    /// Io contract value.
    Io,
}
#[derive(Debug)]
/// struct Error contract value.
pub struct Error {
    /// kind contract value.
    pub kind: ErrorKind,
    /// context contract value.
    pub context: String,
    /// source contract value.
    pub source: Option<io::Error>,
}
impl Error {
    /// fn new contract value.
    pub fn new(kind: ErrorKind, context: impl Into<String>) -> Self {
        Self {
            kind,
            context: context.into(),
            source: None,
        }
    }
    /// fn io contract value.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            context: context.into(),
            source: Some(source),
        }
    }
}
impl fmt::Display for Error {
    /// fn fmt contract value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}
impl std::error::Error for Error {
    /// fn source contract value.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
/// type Result contract value.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Default, Debug)]
/// struct Cancellation contract value.
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    /// fn cancel contract value.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// fn check contract value.
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
/// struct Budget contract value.
pub struct Budget {
    limit: u64,
    used: Arc<AtomicU64>,
}
impl Budget {
    /// fn new contract value.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: Arc::new(AtomicU64::new(0)),
        }
    }
    /// fn used contract value.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
    /// fn reserve contract value.
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
/// struct Reservation contract value.
pub struct Reservation {
    budget: Budget,
    bytes: u64,
}
impl Drop for Reservation {
    /// fn drop contract value.
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
/// Inventory and every metadata/cache/scratch consumer must retain reservations.
#[derive(Clone, Debug)]
/// struct Resources contract value.
pub struct Resources {
    /// memory contract value.
    pub memory: Budget,
    /// cancellation contract value.
    pub cancellation: Cancellation,
}

/// Reusable immutable positional stream. No shared seek cursor or whole-file buffering.
/// Reads at/after EOF return zero; short reads may occur before EOF. Engines must
/// check cancellation and locally validate mappings, retaining shared accounting.
/// Sharing a handle permits concurrent reads; it does not establish source isolation.
pub trait FileRead: Send + Sync {
    /// fn identity contract value.
    fn identity(&self) -> &ObjectId;
    /// fn len contract value.
    fn len(&self) -> u64;
    /// fn is empty contract value.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// fn read at contract value.
    fn read_at(&self, offset: u64, buffer: &mut [u8], resources: &Resources) -> Result<usize>;
    /// fn visit extents contract value.
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()>;
}
/// Size-bounded convenience access. Retains the allocation reservation with its bytes.
#[derive(Debug)]
/// struct BoundedContent contract value.
pub struct BoundedContent {
    /// bytes contract value.
    pub bytes: Vec<u8>,
    _reservation: Reservation,
}
/// fn read all contract value.
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
/// enum SourceStability contract value.
pub enum SourceStability {
    /// ImmutableSnapshot contract value.
    ImmutableSnapshot,
    /// CallerGuaranteedStable contract value.
    CallerGuaranteedStable,
    /// ChangeDetectionOnly contract value.
    ChangeDetectionOnly,
}
/// Inventory is paged by the engine using an opaque continuation token. Hard links
/// retain identical object identities. No host path lookup or implicit symlink following.
pub struct DirectoryPage {
    /// entries contract value.
    pub entries: Vec<DirectoryEntry>,
    /// next contract value.
    pub next: Option<Vec<u8>>,
    /// reservation contract value.
    pub reservation: Reservation,
}
/// trait TreeSource contract value.
/// Implementations must check source-scoped identities and generation on every
/// operation. Reusing an identifier after deletion must change its generation.
/// All returned inventory, metadata, and stream lists count against shared memory
/// accounting; directory pages carry reservations for their entire retained data.
/// Deferred payload errors retain their I/O cause and never become empty files.
/// Open streams must remain valid under the declared stability assurance, or fail
/// explicitly if the source changes. Repeated reads must produce the same bytes.
pub trait TreeSource: Send + Sync {
    /// fn root contract value.
    fn root(&self) -> ObjectId;
    /// fn stability contract value.
    fn stability(&self) -> SourceStability;
    /// fn metadata contract value.
    fn metadata(&self, object: &ObjectId, resources: &Resources) -> Result<Metadata>;
    /// fn directory page contract value.
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        resources: &Resources,
    ) -> Result<DirectoryPage>;
    /// fn streams contract value.
    fn streams(&self, object: &ObjectId, resources: &Resources) -> Result<Vec<StreamInfo>>;
    /// fn open stream contract value.
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
/// enum Preservation contract value.
pub enum Preservation {
    /// Preserve contract value.
    Preserve,
    /// Transform contract value.
    Transform {
        /// Explicit transformation policy.
        policy: String,
        /// Declared information loss.
        report: String,
    },
    /// Reject contract value.
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
    /// fn plan contract value.
    fn plan(&mut self, source: &dyn TreeSource, resources: &Resources) -> Result<Self::Plan>;
    /// fn emit contract value.
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
