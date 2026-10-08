//! Portable positional I/O boundary.
//!
//! With `std`, these types are the existing standard I/O and `virtdisk` types.
//! Without `std`, callers provide an exact positional reader and an allocator.

#[cfg(feature = "std")]
pub use std::io::*;
#[cfg(feature = "std")]
pub use virtdisk::*;

#[cfg(not(feature = "std"))]
mod portable {
    use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
    use core::fmt;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Portable classification of storage failures.
    ///
    /// These variants describe failures independently of operating-system codes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[non_exhaustive]
    pub enum ErrorKind {
        /// Requested resource does not exist.
        NotFound,
        /// The caller lacks permission.
        PermissionDenied,
        /// The requested destination already exists.
        AlreadyExists,
        /// An operation argument violates its contract.
        InvalidInput,
        /// Stored bytes fail validation.
        InvalidData,
        /// The requested range exceeds the source.
        UnexpectedEof,
        /// A write operation made no progress.
        WriteZero,
        /// The operation was interrupted.
        Interrupted,
        /// The source or operation uses unsupported semantics.
        Unsupported,
        /// Storage has no remaining capacity.
        StorageFull,
        /// A nonempty directory cannot be removed.
        DirectoryNotEmpty,
        /// A failure without a more specific classification.
        Other,
    }

    /// A classified I/O error retaining an optional caller-provided cause.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        inner: Option<Box<dyn core::error::Error + Send + Sync>>,
    }

    impl Error {
        /// Construct an error with a message or a typed underlying cause.
        pub fn new(
            kind: ErrorKind,
            error: impl Into<Box<dyn core::error::Error + Send + Sync>>,
        ) -> Self {
            Self {
                kind,
                inner: Some(error.into()),
            }
        }

        /// Construct an error classified as [`ErrorKind::Other`].
        pub fn other(error: impl Into<Box<dyn core::error::Error + Send + Sync>>) -> Self {
            Self::new(ErrorKind::Other, error)
        }

        /// Return the portable failure classification.
        pub fn kind(&self) -> ErrorKind {
            self.kind
        }

        /// Borrow the retained typed cause, if present.
        pub fn get_ref(&self) -> Option<&(dyn core::error::Error + Send + Sync + 'static)> {
            self.inner.as_deref()
        }

        /// Recover ownership of the retained cause, if present.
        pub fn into_inner(self) -> Option<Box<dyn core::error::Error + Send + Sync>> {
            self.inner
        }
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Self {
            Self { kind, inner: None }
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.inner {
                Some(inner) => fmt::Display::fmt(inner, f),
                None => write!(f, "{:?}", self.kind),
            }
        }
    }

    impl core::error::Error for Error {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            self.inner.as_ref().and_then(|inner| inner.source())
        }
    }

    /// Result of a portable storage operation.
    pub type Result<T> = core::result::Result<T, Error>;

    /// Optional reader provenance without assuming an operating-system path type.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ReadContext {
        /// Opaque caller-defined container name.
        pub container: Option<String>,
        /// Selected partition slot.
        pub partition: Option<u32>,
        /// Native file record identifier.
        pub record: Option<u64>,
        /// Native attribute code.
        pub attribute: Option<u32>,
        /// Original UTF-16 stream name.
        pub stream: Option<Vec<u16>>,
        /// Original UTF-16 path components.
        pub path: Option<Vec<Vec<u16>>>,
        /// Offset relative to this reader.
        pub offset: Option<u64>,
    }
    impl ReadContext {
        /// Wrap a failure retaining its classification and original source.
        pub fn error(self, operation: &'static str, source: Error) -> Error {
            Error::new(
                source.kind(),
                ReadError {
                    context: self,
                    operation,
                    source,
                },
            )
        }
    }
    /// Failure annotated with reader provenance.
    #[derive(Debug)]
    pub struct ReadError {
        /// Reader identity at the failed operation.
        pub context: ReadContext,
        /// Operation that added provenance.
        pub operation: &'static str,
        source: Error,
    }
    impl fmt::Display for ReadError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.operation)?;
            if let Some(container) = &self.context.container {
                write!(f, " container={container}")?;
            }
            if let Some(partition) = self.context.partition {
                write!(f, " partition={partition}")?;
            }
            if let Some(record) = self.context.record {
                write!(f, " record={record:#x}")?;
            }
            if let Some(attribute) = self.context.attribute {
                write!(f, " attribute={attribute:#x}")?;
            }
            if let Some(path) = &self.context.path {
                for component in path {
                    write!(f, "/{}", String::from_utf16_lossy(component))?;
                }
            }
            if let Some(stream) = &self.context.stream {
                write!(f, " stream={:?}", String::from_utf16_lossy(stream))?;
            }
            if let Some(offset) = self.context.offset {
                write!(f, " offset={offset}")?;
            }
            write!(f, ": {}", self.source)
        }
    }
    impl core::error::Error for ReadError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            Some(&self.source)
        }
    }
    /// Parser ceilings compatible with the hosted reader boundary.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ParserLimits {
        /// Cumulative materialized metadata bytes.
        pub metadata_bytes: u64,
        /// Retained cache ceiling.
        pub cache_bytes: u64,
        /// Traversal depth ceiling.
        pub recursion_depth: u64,
        /// Positional read and traversal work ceiling.
        pub work_items: u64,
        /// Cumulative decoder output ceiling.
        pub decompressed_bytes: u64,
        /// Individual decoder buffer ceiling.
        pub decompression_buffer_bytes: u64,
        /// Individual metadata attribute ceiling.
        pub attribute_bytes: u64,
        /// NTFS attribute list record ceiling.
        pub attribute_list_records: u64,
    }
    impl Default for ParserLimits {
        fn default() -> Self {
            Self {
                metadata_bytes: 2 << 30,
                cache_bytes: 512 << 20,
                recursion_depth: 512,
                work_items: 16 << 20,
                decompressed_bytes: 64 << 30,
                decompression_buffer_bytes: 2 << 20,
                attribute_bytes: 64 << 20,
                attribute_list_records: 65536,
            }
        }
    }
    impl ParserLimits {
        /// Reject zero limits or limits above the fixed parser ceilings.
        pub fn validate(&self) -> Result<()> {
            let hard = Self::default();
            for (value, ceiling) in [
                (self.metadata_bytes, hard.metadata_bytes),
                (self.cache_bytes, hard.cache_bytes),
                (self.recursion_depth, hard.recursion_depth),
                (self.work_items, hard.work_items),
                (self.decompressed_bytes, hard.decompressed_bytes),
                (
                    self.decompression_buffer_bytes,
                    hard.decompression_buffer_bytes,
                ),
                (self.attribute_bytes, hard.attribute_bytes),
                (self.attribute_list_records, hard.attribute_list_records),
            ] {
                if value == 0 || value > ceiling {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "parser limit exceeds hard ceiling or is zero",
                    ));
                }
            }
            Ok(())
        }
    }
    #[derive(Debug)]
    struct Accounting {
        limits: ParserLimits,
        metadata: AtomicU64,
        cache: AtomicU64,
        work: AtomicU64,
        decoded: AtomicU64,
    }
    /// Current shared parser accounting, read atomically without resetting limits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReadBudgetUsage {
        /// Cumulative materialized metadata bytes.
        pub metadata_bytes: u64,
        /// Live retained cache bytes.
        pub cache_bytes: u64,
        /// Cumulative physical-read and format-iteration work.
        pub work_items: u64,
        /// Cumulative decoded output bytes.
        pub decompressed_bytes: u64,
    }
    /// Shared accounting retained by deferred readers. Counters never wrap.
    #[derive(Debug, Clone)]
    pub struct ReadBudget(Arc<Accounting>);
    fn charge(counter: &AtomicU64, amount: u64, limit: u64, name: &str) -> Result<()> {
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(amount).filter(|&next| next <= limit)
            })
            .map(|_| ())
            .map_err(|_| {
                Error::new(
                    ErrorKind::Unsupported,
                    format!("{name} exceeds configured parser limit {limit}"),
                )
            })
    }
    impl ReadBudget {
        /// Start a bounded parser operation with validated caller limits.
        pub fn new(limits: ParserLimits) -> Result<Self> {
            limits.validate()?;
            Ok(Self(Arc::new(Accounting {
                limits,
                metadata: AtomicU64::new(0),
                cache: AtomicU64::new(0),
                work: AtomicU64::new(0),
                decoded: AtomicU64::new(0),
            })))
        }
        /// Snapshot counters; concurrent readers may advance individual fields.
        pub fn usage(&self) -> ReadBudgetUsage {
            ReadBudgetUsage {
                metadata_bytes: self.0.metadata.load(Ordering::Acquire),
                cache_bytes: self.0.cache.load(Ordering::Acquire),
                work_items: self.0.work.load(Ordering::Acquire),
                decompressed_bytes: self.0.decoded.load(Ordering::Acquire),
            }
        }
        /// Effective immutable limits.
        pub fn limits(&self) -> ParserLimits {
            self.0.limits
        }
        /// Charge cumulative metadata before materializing it.
        pub fn metadata(&self, bytes: u64) -> Result<()> {
            charge(
                &self.0.metadata,
                bytes,
                self.0.limits.metadata_bytes,
                "metadata",
            )
        }
        /// Charge positional reads or format iteration work before doing it.
        pub fn work(&self, items: u64) -> Result<()> {
            charge(&self.0.work, items, self.0.limits.work_items, "work")
        }
        /// Charge output before allocating or decoding a compression unit.
        pub fn decode(&self, bytes: u64) -> Result<()> {
            if bytes > self.0.limits.decompression_buffer_bytes {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "compression unit exceeds configured decompression-buffer limit",
                ));
            }
            charge(
                &self.0.decoded,
                bytes,
                self.0.limits.decompressed_bytes,
                "decoded output",
            )
        }
        /// Reserve live cache bytes; dropping the returned reservation releases them.
        pub fn cache(&self, bytes: u64) -> Result<CacheReservation> {
            charge(&self.0.cache, bytes, self.0.limits.cache_bytes, "cache")?;
            Ok(CacheReservation {
                budget: self.clone(),
                bytes,
            })
        }
        /// Wrap positional reads with shared work accounting and original provenance.
        pub fn reader(&self, source: Arc<dyn ReadAt>) -> Arc<dyn ReadAt> {
            Arc::new(BudgetReader {
                source,
                budget: self.clone(),
            })
        }
    }
    /// Lifetime of retained cache storage. Reservations cannot be copied.
    #[derive(Debug)]
    pub struct CacheReservation {
        budget: ReadBudget,
        bytes: u64,
    }
    impl Drop for CacheReservation {
        fn drop(&mut self) {
            self.budget.0.cache.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
    struct BudgetReader {
        source: Arc<dyn ReadAt>,
        budget: ReadBudget,
    }
    impl ReadAt for BudgetReader {
        fn len(&self) -> u64 {
            self.source.len()
        }
        fn visit_extents(&self, visitor: &mut dyn FnMut(DiskExtent) -> Result<()>) -> Result<()> {
            self.source.visit_extents(visitor)
        }
        fn sparse_holes(&self) -> Result<Vec<(u64, u64)>> {
            self.source.sparse_holes()
        }
        fn context(&self) -> ReadContext {
            self.source.context()
        }
        fn budget(&self) -> Option<ReadBudget> {
            Some(self.budget.clone())
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
            self.budget
                .work(1)
                .map_err(|e| self.context().error("read budget", e))?;
            self.source.read_exact_at(offset, bytes)
        }
    }
    /// Logical allocation semantics without a container-format assumption.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExtentKind {
        /// Allocated container payload.
        Allocated,
        /// Reads produce zeros without accessing a parent.
        Zero,
        /// Payload resolved from an immutable backing source.
        Inherited,
        /// Allocation is unknown.
        Unknown,
    }
    /// One nonempty ordered logical allocation extent.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DiskExtent {
        /// Starting logical byte offset.
        pub offset: u64,
        /// Length wholly contained in its source.
        pub length: u64,
        /// Logical allocation semantics.
        pub kind: ExtentKind,
    }

    /// Exact positional reads from a fixed-length logical source.
    ///
    /// Implementations must reject overflowing or out-of-bounds ranges,
    /// including an empty read beyond the end. A failed read may partially
    /// modify its destination. Shared readers must not use an unprotected seek
    /// cursor, and their contents must remain stable during a validated operation.
    pub trait ReadAt: Send + Sync {
        /// Original source provenance when available.
        fn context(&self) -> ReadContext {
            ReadContext::default()
        }
        /// Shared reader metadata accounting when available.
        fn budget(&self) -> Option<ReadBudget> {
            None
        }
        /// Known logical sparse holes as half-open ranges.
        fn sparse_holes(&self) -> Result<Vec<(u64, u64)>> {
            Ok(Vec::new())
        }
        /// Visit ordered logical allocation extents without reading payloads.
        fn visit_extents(&self, visitor: &mut dyn FnMut(DiskExtent) -> Result<()>) -> Result<()> {
            if !self.is_empty() {
                visitor(DiskExtent {
                    offset: 0,
                    length: self.len(),
                    kind: ExtentKind::Unknown,
                })?;
            }
            Ok(())
        }
        /// Fixed logical length, in bytes.
        fn len(&self) -> u64;
        /// Whether the logical source is empty.
        fn is_empty(&self) -> bool {
            self.len() == 0
        }
        /// Fill the destination from the requested logical offset.
        fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> Result<()>;
    }

    /// A bounded logical subrange retaining its parent reader.
    ///
    /// Construction establishes range containment, not partition validity.
    pub struct DiskView {
        source: Arc<dyn ReadAt>,
        start: u64,
        length: u64,
        context: ReadContext,
    }

    fn check_range(offset: u64, count: u64, length: u64) -> Result<()> {
        if offset.checked_add(count).is_none_or(|end| end > length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "disk read range overflows or exceeds logical length",
            ));
        }
        Ok(())
    }

    impl DiskView {
        /// Create a view wholly contained in its parent source.
        pub fn new(source: Arc<dyn ReadAt>, start: u64, length: u64) -> Result<Self> {
            check_range(start, length, source.len())?;
            let context = source.context();
            Ok(Self {
                source,
                start,
                length,
                context,
            })
        }
        /// Attach a validated selected partition slot.
        pub fn with_partition(mut self, index: u32) -> Self {
            self.context.partition = Some(index);
            self
        }
    }

    impl ReadAt for DiskView {
        fn context(&self) -> ReadContext {
            self.context.clone()
        }
        fn budget(&self) -> Option<ReadBudget> {
            self.source.budget()
        }
        fn visit_extents(&self, visitor: &mut dyn FnMut(DiskExtent) -> Result<()>) -> Result<()> {
            if self.is_empty() {
                return Ok(());
            }
            let end = self.start + self.length;
            self.source.visit_extents(&mut |extent| {
                check_range(extent.offset, extent.length, self.source.len())?;
                let start = extent.offset.max(self.start);
                let stop = (extent.offset + extent.length).min(end);
                if start < stop {
                    visitor(DiskExtent {
                        offset: start - self.start,
                        length: stop - start,
                        kind: extent.kind,
                    })?;
                }
                Ok(())
            })
        }
        fn len(&self) -> u64 {
            self.length
        }

        fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> Result<()> {
            let result = (|| {
                check_range(offset, destination.len() as u64, self.length)?;
                let absolute = self.start.checked_add(offset).ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "disk view offset overflow")
                })?;
                self.source.read_exact_at(absolute, destination)
            })();
            result.map_err(|error| {
                let mut context = self.context();
                context.offset = Some(offset);
                context.error("read partition view", error)
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Bytes([u8; 8]);
        impl ReadAt for Bytes {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> Result<()> {
                check_range(offset, destination.len() as u64, self.len())?;
                let start = offset as usize;
                destination.copy_from_slice(&self.0[start..start + destination.len()]);
                Ok(())
            }
        }

        #[derive(Debug)]
        struct Cause;
        impl fmt::Display for Cause {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("cause")
            }
        }
        impl core::error::Error for Cause {}

        #[test]
        fn typed_causes_and_classifications_are_preserved() {
            let error = Error::new(ErrorKind::PermissionDenied, Cause);
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
            assert!(error.get_ref().unwrap().is::<Cause>());
            assert!(error.into_inner().unwrap().is::<Cause>());
            let error = Error::from(ErrorKind::UnexpectedEof);
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
            assert!(error.get_ref().is_none());
        }

        #[test]
        fn shared_budget_failed_charges_do_not_consume_metadata_capacity() {
            let budget = ReadBudget::new(ParserLimits {
                metadata_bytes: 4,
                ..ParserLimits::default()
            })
            .unwrap();
            budget.metadata(2).unwrap();
            assert_eq!(
                budget.metadata(3).unwrap_err().kind(),
                ErrorKind::Unsupported
            );
            budget.metadata(2).unwrap();
            assert_eq!(
                budget.metadata(1).unwrap_err().kind(),
                ErrorKind::Unsupported
            );
        }

        #[test]
        fn reader_work_and_cache_reservations_share_accounting() {
            let budget = ReadBudget::new(ParserLimits::default()).unwrap();
            let reader = budget.reader(Arc::new(Bytes([0, 1, 2, 3, 4, 5, 6, 7])));
            reader.read_exact_at(0, &mut [0]).unwrap();
            assert_eq!(budget.usage().work_items, 1);
            let reservation = budget.cache(64).unwrap();
            assert_eq!(reader.budget().unwrap().usage().cache_bytes, 64);
            drop(reservation);
            assert_eq!(budget.usage().cache_bytes, 0);
            budget.decode(32).unwrap();
            assert_eq!(budget.usage().decompressed_bytes, 32);
            assert!(budget.decode(u64::MAX).is_err());
            assert_eq!(budget.usage().decompressed_bytes, 32);
        }

        #[test]
        fn budget_readers_preserve_known_extents_and_views_clip_them() {
            struct AllocatedBytes(Bytes);
            impl ReadAt for AllocatedBytes {
                fn len(&self) -> u64 {
                    self.0.len()
                }
                fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> Result<()> {
                    self.0.read_exact_at(offset, destination)
                }
                fn visit_extents(
                    &self,
                    visitor: &mut dyn FnMut(DiskExtent) -> Result<()>,
                ) -> Result<()> {
                    visitor(DiskExtent {
                        offset: 0,
                        length: 3,
                        kind: ExtentKind::Zero,
                    })?;
                    visitor(DiskExtent {
                        offset: 3,
                        length: 5,
                        kind: ExtentKind::Allocated,
                    })
                }
            }
            let source: Arc<dyn ReadAt> = Arc::new(AllocatedBytes(Bytes([0; 8])));
            let budget = ReadBudget::new(ParserLimits::default()).unwrap();
            let reader = budget.reader(source.clone());
            let mut expected = Vec::new();
            source
                .visit_extents(&mut |extent| {
                    expected.push(extent);
                    Ok(())
                })
                .unwrap();
            let mut actual = Vec::new();
            reader
                .visit_extents(&mut |extent| {
                    actual.push(extent);
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual, expected);
            actual.clear();
            let view = DiskView::new(reader, 2, 3).unwrap();
            view.visit_extents(&mut |extent| {
                actual.push(extent);
                Ok(())
            })
            .unwrap();
            assert_eq!(
                actual,
                alloc::vec![
                    DiskExtent {
                        offset: 0,
                        length: 1,
                        kind: ExtentKind::Zero
                    },
                    DiskExtent {
                        offset: 1,
                        length: 2,
                        kind: ExtentKind::Allocated
                    },
                ]
            );
            assert_eq!(budget.usage().work_items, 0);
        }

        #[test]
        fn nested_views_translate_offsets_and_check_empty_and_overflowing_ranges() {
            let source: Arc<dyn ReadAt> = Arc::new(Bytes([0, 1, 2, 3, 4, 5, 6, 7]));
            let outer: Arc<dyn ReadAt> = Arc::new(DiskView::new(source.clone(), 2, 5).unwrap());
            let inner = DiskView::new(outer, 1, 3).unwrap();
            let mut bytes = [0; 2];
            inner.read_exact_at(1, &mut bytes).unwrap();
            assert_eq!(bytes, [4, 5]);
            inner.read_exact_at(3, &mut []).unwrap();
            for (offset, count) in [(3, 1), (4, 0), (u64::MAX, 1)] {
                assert_eq!(
                    inner
                        .read_exact_at(offset, &mut bytes[..count])
                        .unwrap_err()
                        .kind(),
                    ErrorKind::UnexpectedEof
                );
            }
            assert_eq!(
                DiskView::new(source, u64::MAX, 1).err().unwrap().kind(),
                ErrorKind::UnexpectedEof
            );
        }
    }
}

#[cfg(not(feature = "std"))]
pub use portable::{
    CacheReservation, DiskExtent, DiskView, Error, ErrorKind, ExtentKind, ParserLimits, ReadAt,
    ReadBudget, ReadBudgetUsage, ReadContext, ReadError, Result,
};
