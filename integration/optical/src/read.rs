//! Deferred ISO/UDF access through versioned interfaces. Publication remains a release gate.
use libmkiso::{IsoNamespace, IsoReadOptions, IsoReader, SourceCursor, UdfReader};
use partmgr::{
    fs_core::{
        Error, ErrorKind, FileRead, LogicalExtent, NativeName, ObjectId, ObjectKind, Reservation,
        Resources, Result,
    },
    fs_file::{ExtentFile, ExtentKind, FileExtent},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;

/// An immutable positional source retaining caller cancellation and shared read accounting.
/// Region/provenance wrappers supplied by the caller remain on every actual read path.
#[derive(Clone)]
pub struct SourceAdapter {
    source: Arc<dyn ReadAt>,
    length: u64,
    resources: Resources,
    reads: Arc<AtomicU64>,
    maximum_reads: u64,
}
impl SourceAdapter {
    /// Length and bytes must remain stable until every deferred handle is dropped.
    pub fn new(source: Arc<dyn ReadAt>, resources: Resources, maximum_reads: u64) -> Self {
        let length = source.len();
        Self {
            source,
            length,
            resources,
            reads: Arc::new(AtomicU64::new(0)),
            maximum_reads,
        }
    }
    /// Cumulative requested bytes shared by discovery and all deferred handles.
    pub fn requested_bytes(&self) -> u64 {
        self.reads.load(Ordering::Acquire)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.resources.cancellation.check()?;
        if self.source.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "optical source length changed",
            ));
        }
        Ok(())
    }
    fn checked_read(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        self.revalidate().map_err(io_error)?;
        let length = buffer.len() as u64;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.reads
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(length)
                    .filter(|n| *n <= self.maximum_reads)
            })
            .map_err(|_| io::Error::other("optical shared source read budget exhausted"))?;
        let _scratch = self.resources.memory.reserve(length).map_err(io_error)?;
        self.source.read_exact_at(offset, buffer)
    }
}
impl libmkiso::source::ReadAt for SourceAdapter {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.length {
            self.revalidate().map_err(io_error)?;
            return Ok(0);
        }
        let count = (self.length - offset).min(buffer.len() as u64) as usize;
        self.checked_read(offset, &mut buffer[..count])?;
        Ok(count)
    }
}
impl ReadAt for SourceAdapter {
    fn context(&self) -> virtdisk::ReadContext {
        self.source.context()
    }
    fn budget(&self) -> Option<virtdisk::ReadBudget> {
        self.source.budget()
    }
    fn sparse_holes(&self) -> io::Result<Vec<(u64, u64)>> {
        self.source.sparse_holes()
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        self.checked_read(offset, buffer)
    }
}
fn io_error(error: Error) -> io::Error {
    let kind = if error.kind == ErrorKind::Cancelled {
        io::ErrorKind::Interrupted
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, error)
}
fn iso_error(error: libmkiso::IsoError) -> Error {
    match error {
        libmkiso::IsoError::Io(e) => Error::io("optical ISO read", e),
        libmkiso::IsoError::ResourceLimit(context) => {
            Error::new(ErrorKind::BudgetExhausted, context)
        }
        libmkiso::IsoError::Unsupported(context) => Error::new(ErrorKind::Unsupported, context),
        libmkiso::IsoError::Malformed(context) => Error::new(ErrorKind::InvalidData, context),
    }
}
fn udf_error(error: libmkiso::UdfError) -> Error {
    match error {
        libmkiso::UdfError::Io(e) => Error::io("optical UDF read", e),
        libmkiso::UdfError::ResourceLimit(context) => {
            Error::new(ErrorKind::BudgetExhausted, context)
        }
        libmkiso::UdfError::Unsupported(context) => Error::new(ErrorKind::Unsupported, context),
        libmkiso::UdfError::Malformed(context) | libmkiso::UdfError::Integrity(context) => {
            Error::new(ErrorKind::InvalidData, context)
        }
    }
}
/// Explicit discovery and retained inventory envelope.
#[derive(Clone, Copy, Debug)]
pub struct OpticalReadLimits {
    /// Maximum selected namespace objects.
    pub max_entries: u64,
    /// Upstream directory and native metadata budget.
    pub max_metadata_bytes: u64,
    /// Cumulative file sections across the selected namespace, not just per file.
    pub max_extents: usize,
    /// Maximum namespace nesting depth.
    pub max_depth: usize,
}
impl OpticalReadLimits {
    fn reserve(self, resources: &Resources) -> Result<Arc<Reservation>> {
        let size = self
            .max_metadata_bytes
            .checked_mul(4)
            .and_then(|n| {
                self.max_entries
                    .checked_mul(1024)
                    .and_then(|e| n.checked_add(e))
            })
            .and_then(|n| {
                (self.max_extents as u64)
                    .checked_mul(128)
                    .and_then(|e| n.checked_add(e))
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::BudgetExhausted,
                    "optical inventory envelope overflow",
                )
            })?;
        Ok(Arc::new(resources.memory.reserve(size)?))
    }
}
/// Source-scoped native inspection. Display paths never become object identities.
pub struct OpticalReadEntry {
    /// Caller-scoped stable identity; UDF hard links retain their shared ICB key.
    pub identity: ObjectId,
    /// Display-only decoded path, never used to reconstruct native metadata.
    pub display_path: String,
    /// Exact stored ISO identifier (namespace-specific encoding), or UDF OSTA bytes.
    pub native_name: Vec<u8>,
    /// Semantic native leaf in the selected namespace, independent of display paths.
    pub leaf: NativeName,
    /// Native ordinary parent occurrence; streams have no directory parent.
    pub parent: Option<libmkiso::topology::Parent>,
    /// Object category; symbolic links are not followed.
    pub kind: ObjectKind,
    /// Link text is inspected without following it.
    pub link_target: Option<String>,
    /// UDF owner/stream association, distinct from the main directory namespace.
    pub stream: Option<libmkiso::UdfStreamInfo>,
    /// Upstream native metadata, preserving Absent/Uninspected/NotWritable distinctions.
    pub metadata: libmkiso::preservation::Metadata,
    file: Option<Arc<OpticalFile>>,
}
impl OpticalReadEntry {
    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.link_target == other.link_target
            && self.metadata.timestamps == other.metadata.timestamps
            && self.metadata.ownership == other.metadata.ownership
            && self.metadata.permissions == other.metadata.permissions
            && self.metadata.extensions == other.metadata.extensions
            && self.metadata.opaque == other.metadata.opaque
            && match (&self.file, &other.file) {
                (None, None) => true,
                (Some(a), Some(b)) => a.len() == b.len() && a.file.extents() == b.file.extents(),
                _ => false,
            }
    }
    pub(crate) fn file_length(&self) -> Option<u64> {
        self.file.as_ref().map(|file| file.len())
    }
}
/// Parsed selected namespace retaining bounded inventory and immutable deferred sources.
pub struct OpticalReadIndex {
    entries: Vec<OpticalReadEntry>,
    /// Root metadata inspected separately from namespace entries.
    pub root_metadata: libmkiso::preservation::Metadata,
    /// Source-scoped root; UDF retains its prevailing ICB identity.
    pub root_identity: ObjectId,
    pub(crate) context: SourceAdapter,
    pub(crate) max_depth: usize,
    _reservation: Arc<Reservation>,
}
impl OpticalReadIndex {
    /// Selected namespace inventory, including separately associated UDF streams.
    pub fn entries(&self) -> &[OpticalReadEntry] {
        &self.entries
    }
    /// Reusable file access; directories and links are never silently read as files.
    pub fn open_file(&self, index: usize) -> Result<Arc<dyn FileRead>> {
        self.entries
            .get(index)
            .and_then(|e| e.file.clone())
            .map(|file| file as Arc<dyn FileRead>)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    "optical entry is not a regular file or owned stream",
                )
            })
    }
    /// Discover one explicit ISO namespace through an independent checked cursor.
    pub fn iso(
        source: SourceAdapter,
        scope: u128,
        generation: u64,
        namespace: IsoNamespace,
        limits: OpticalReadLimits,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        let reservation = limits.reserve(resources)?;
        let reader = IsoReader::open_with_options(
            SourceCursor::new(source.clone()),
            IsoReadOptions {
                namespace,
                limits: libmkiso::IsoLimits {
                    max_entries: limits.max_entries,
                    max_metadata_bytes: limits.max_metadata_bytes,
                    max_nesting_depth: limits.max_depth,
                },
            },
        )
        .map_err(iso_error)?;
        let (_, index, root_metadata, metadata, topology) = reader.into_topology_parts();
        if topology.parents.len() != index.entries.len()
            || topology.names.len() != index.entries.len()
            || metadata.len() != index.entries.len()
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ISO topology cardinality",
            ));
        }
        let root_identity = ObjectId {
            source: scope,
            generation,
            native: Vec::new(),
        };
        let mut entries = allocated(index.entries.len())?;
        let mut total = 0_usize;
        for (i, (entry, metadata)) in index.entries.into_iter().zip(metadata).enumerate() {
            resources.cancellation.check()?;
            let identity = ObjectId {
                source: scope,
                generation,
                native: (i as u64).to_le_bytes().to_vec(),
            };
            let kind = if entry.directory {
                ObjectKind::Directory
            } else if entry.link_target.is_some() {
                ObjectKind::Symlink
            } else {
                ObjectKind::File
            };
            let kind = if let Some(unix) = &entry.unix {
                match unix.mode & 0xf000 {
                    0 => kind,
                    0x8000 if kind == ObjectKind::File => ObjectKind::File,
                    0x4000 if kind == ObjectKind::Directory => ObjectKind::Directory,
                    0xa000 if !entry.directory => ObjectKind::Symlink,
                    0x8000 | 0x4000 | 0xa000 => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Rock Ridge object type contradicts ISO record",
                        ));
                    }
                    _ => ObjectKind::Special,
                }
            } else {
                kind
            };
            let file = if kind == ObjectKind::File {
                let mut logical = 0_u64;
                let mut extents = allocated(index.extents[i].len())?;
                for section in &index.extents[i] {
                    if section.size == 0 {
                        continue;
                    }
                    total = total.checked_add(1).ok_or_else(extent_budget)?;
                    if total > limits.max_extents {
                        return Err(extent_budget());
                    }
                    extents.push(FileExtent {
                        offset: logical,
                        length: section.size,
                        kind: ExtentKind::Data(section.offset),
                    });
                    logical = logical
                        .checked_add(section.size)
                        .ok_or_else(extent_budget)?;
                }
                Some(Arc::new(OpticalFile {
                    identity: identity.clone(),
                    context: source.clone(),
                    file: ExtentFile::new(
                        Arc::new(source.clone()),
                        entry.size,
                        extents,
                        limits.max_extents,
                    )
                    .map_err(|e| Error::io("ISO extent map", e))?,
                    _reservation: reservation.clone(),
                }))
            } else {
                None
            };
            entries.push(OpticalReadEntry {
                identity,
                display_path: entry.name,
                native_name: entry.raw_name,
                leaf: match &topology.names[i] {
                    libmkiso::iso9660::NativeName::Primary(b)
                    | libmkiso::iso9660::NativeName::RockRidge(b) => NativeName::Bytes(b.clone()),
                    libmkiso::iso9660::NativeName::Joliet(u) => NativeName::Utf16(u.clone()),
                },
                parent: Some(topology.parents[i]),
                kind,
                link_target: entry.link_target,
                stream: None,
                metadata,
                file,
            });
        }
        Ok(Self {
            entries,
            root_metadata,
            root_identity,
            context: source,
            max_depth: limits.max_depth,
            _reservation: reservation,
        })
    }
    /// Discover UDF and retain direct maps for files and owned streams.
    pub fn udf(
        source: SourceAdapter,
        scope: u128,
        generation: u64,
        limits: OpticalReadLimits,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check()?;
        let reservation = limits.reserve(resources)?;
        let reader = UdfReader::open_source(
            source.clone(),
            libmkiso::UdfLimits {
                max_entries: limits.max_entries,
                max_metadata_bytes: limits.max_metadata_bytes,
                max_input_bytes: source.length,
                max_nesting_depth: limits.max_depth,
                max_entry_bytes: u64::MAX,
                max_total_bytes: u64::MAX,
            },
        )
        .map_err(udf_error)?;
        let mut entries = allocated(reader.entries().len())?;
        let mut total = 0_usize;
        for (i, entry) in reader.entries().iter().enumerate() {
            resources.cancellation.check()?;
            let mut native = allocated(6)?;
            native.extend_from_slice(&entry.icb.partition.to_le_bytes());
            native.extend_from_slice(&entry.icb.block.to_le_bytes());
            let identity = ObjectId {
                source: scope,
                generation,
                native,
            };
            let kind = match entry.kind {
                libmkiso::UdfEntryKind::Directory => ObjectKind::Directory,
                libmkiso::UdfEntryKind::SymbolicLink => ObjectKind::Symlink,
                libmkiso::UdfEntryKind::File
                | libmkiso::UdfEntryKind::NamedStream
                | libmkiso::UdfEntryKind::SystemStream => ObjectKind::File,
            };
            let file = if kind == ObjectKind::File {
                let mut extents = Vec::new();
                reader
                    .visit_classified_extents(i, |logical, kind, length| {
                        if length == 0 {
                            return Ok(());
                        }
                        total = total
                            .checked_add(1)
                            .ok_or(libmkiso::UdfError::ResourceLimit("extent count"))?;
                        if total > limits.max_extents {
                            return Err(libmkiso::UdfError::ResourceLimit("extent count"));
                        }
                        extents
                            .try_reserve(1)
                            .map_err(|_| libmkiso::UdfError::ResourceLimit("extent allocation"))?;
                        extents.push(FileExtent {
                            offset: logical,
                            length,
                            kind: match kind {
                                libmkiso::UdfExtentKind::Recorded { source_offset } => {
                                    ExtentKind::Data(source_offset)
                                }
                                libmkiso::UdfExtentKind::Unallocated => ExtentKind::Hole,
                                libmkiso::UdfExtentKind::AllocatedUnrecorded => {
                                    ExtentKind::Unwritten
                                }
                            },
                        });
                        Ok(())
                    })
                    .map_err(udf_error)?;
                Some(Arc::new(OpticalFile {
                    identity: identity.clone(),
                    context: source.clone(),
                    file: ExtentFile::new(
                        Arc::new(source.clone()),
                        entry.size,
                        extents,
                        limits.max_extents,
                    )
                    .map_err(|e| Error::io("UDF extent map", e))?,
                    _reservation: reservation.clone(),
                }))
            } else {
                None
            };
            entries.push(OpticalReadEntry {
                identity,
                display_path: entry.name.clone(),
                native_name: entry.raw_name.clone(),
                leaf: udf_leaf(&entry.raw_name)?,
                parent: reader.parent(i),
                kind,
                link_target: entry.link_target.clone(),
                stream: entry.stream.clone(),
                metadata: reader
                    .metadata(i)
                    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing UDF metadata"))?
                    .clone(),
                file,
            });
        }
        Ok(Self {
            entries,
            root_metadata: reader.root_metadata().clone(),
            root_identity: ObjectId {
                source: scope,
                generation,
                native: {
                    let icb = reader.root_icb();
                    let mut b = allocated(6)?;
                    b.extend_from_slice(&icb.partition.to_le_bytes());
                    b.extend_from_slice(&icb.block.to_le_bytes());
                    b
                },
            },
            context: source,
            max_depth: limits.max_depth,
            _reservation: reservation,
        })
    }
}
struct OpticalFile {
    context: SourceAdapter,
    identity: ObjectId,
    file: ExtentFile,
    _reservation: Arc<Reservation>,
}
impl FileRead for OpticalFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, offset: u64, out: &mut [u8], resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        self.context.revalidate()?;
        if offset >= self.file.len() {
            return Ok(0);
        }
        self.file
            .read_at(offset, out)
            .map_err(|e| Error::io("optical deferred payload", e))
    }
    fn visit_extents(
        &self,
        resources: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        resources.cancellation.check()?;
        self.context.revalidate()?;
        for e in self.file.extents() {
            resources.cancellation.check()?;
            visitor(LogicalExtent {
                offset: e.offset,
                length: e.length,
                kind: match e.kind {
                    ExtentKind::Data(_) => partmgr::fs_core::ExtentKind::Data,
                    ExtentKind::Hole => partmgr::fs_core::ExtentKind::Hole,
                    ExtentKind::Unwritten => partmgr::fs_core::ExtentKind::Unwritten,
                },
            })?;
        }
        Ok(())
    }
}
fn extent_budget() -> Error {
    Error::new(
        ErrorKind::BudgetExhausted,
        "optical extent budget exhausted",
    )
}
fn allocated<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| {
        Error::new(
            ErrorKind::BudgetExhausted,
            "optical inventory allocation failed",
        )
    })?;
    Ok(v)
}

pub(crate) fn udf_leaf(raw: &[u8]) -> Result<NativeName> {
    let Some((&compression, body)) = raw.split_first() else {
        return Err(Error::new(ErrorKind::InvalidData, "empty OSTA identifier"));
    };
    let mut units = allocated(body.len())?;
    match compression {
        8 => units.extend(body.iter().map(|b| u16::from(*b))),
        16 if body.len().is_multiple_of(2) => units.extend(
            body.as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_be_bytes([b[0], b[1]])),
        ),
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "OSTA identifier compression",
            ));
        }
    }
    Ok(NativeName::Utf16(units))
}
