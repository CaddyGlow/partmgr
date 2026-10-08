//! Exclusively owned classic ext2 storage sessions with same-owner complete audits.
use crate::{
    fs_core::{Error, ErrorKind, NativeName, ObjectId, Reservation, Resources, Result},
    fs_ext::{ExtDecodedFileMap, ExtGeometry, ExtInode, ExtStorageDecoder},
    fs_ext_audit::{ExtAuditLimits, ExtAuditReport, audit_ext_storage},
    fs_undo::{self, UndoLimits, UndoState},
    storage::Storage,
};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};
#[path = "fs_ext_edit_allocation.rs"]
pub(crate) mod allocation;
#[path = "fs_ext_edit_namespace.rs"]
mod namespace;
pub use namespace::{
    ExtCreateMetadata, ExtEditDirectory, ExtNamespaceOperation, ExtNamespaceReport,
};
#[path = "fs_ext_edit_transaction.rs"]
mod transaction;
pub use allocation::{ExtRangeAllocationReport, ExtResizeReport};
pub use transaction::{ExtEditBatch, ExtReplacement};
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
/// Selected filesystem region inside the exclusively owned target.
#[derive(Clone, Copy, Debug)]
pub struct ExtEditRegion {
    /// Container-relative first byte.
    pub offset: u64,
    /// Maximum declared filesystem bytes.
    pub length: u64,
}
/// Caller-verified journal binding; owning separate handles does not prove disjoint media.
#[derive(Clone, Copy, Debug)]
pub struct ExtEditBinding {
    /// Independently verified volume, region and external journal identity.
    pub volume: [u8; 32],
    /// Caller-assigned persistent session generation.
    pub generation: u64,
}
/// Explicit shared-resource and transaction ceilings.
#[derive(Clone, Copy, Debug)]
pub struct ExtEditLimits {
    /// Complete allocation/reference audit ceilings.
    pub audit: ExtAuditLimits,
    /// Maximum retained logical blocks for one file mapping.
    pub file_blocks: usize,
    /// Maximum decoded directory entries per lookup.
    pub directory_entries: usize,
    /// Maximum physically affected transaction bytes.
    pub affected_bytes: u64,
    /// Maximum transaction planning work.
    pub work: usize,
    /// External undo ceilings.
    pub undo: UndoLimits,
}
/// Exclusive session authorization state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtEditState {
    /// Complete clean audit established on the currently owned storage.
    Ready,
    /// Uncertain mutation requires journal recovery and fresh inspection.
    NeedsRecovery,
}
struct Region<S> {
    storage: S,
    selected: ExtEditRegion,
    container_length: u64,
}
impl<S: Storage> Region<S> {
    fn position(&self, at: u64, length: usize) -> io::Result<u64> {
        self.len()?;
        if at
            .checked_add(length as u64)
            .is_none_or(|end| end > self.selected.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.selected
            .offset
            .checked_add(at)
            .ok_or(io::ErrorKind::InvalidInput.into())
    }
}
impl<S: Storage> Storage for Region<S> {
    fn len(&self) -> io::Result<u64> {
        if self.storage.len()? != self.container_length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "ext2 editor container length changed",
            )));
        }
        Ok(self.selected.length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.storage
            .read_exact_at(self.position(at, out.len())?, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.storage
            .write_at(self.position(at, bytes.len())?, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.storage.flush()
    }
}
fn native(error: io::Error) -> Error {
    let kind = match error.kind() {
        io::ErrorKind::InvalidData => ErrorKind::InvalidData,
        io::ErrorKind::Unsupported => ErrorKind::Unsupported,
        io::ErrorKind::InvalidInput => ErrorKind::InvalidOperation,
        _ => ErrorKind::Io,
    };
    let mut mapped = Error::io("exclusive ext2 decoder/storage", error);
    if mapped.kind == ErrorKind::Io {
        mapped.kind = kind;
    }
    mapped
}
/// Reusable mapping that grants no independent backend capability.
pub struct ExtEditFile {
    identity: ObjectId,
    inode: ExtInode,
    map: ExtDecodedFileMap,
    _metadata: Reservation,
}
impl ExtEditFile {
    /// Source and editor-generation scoped object identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// Native inode metadata inspected when the handle was opened.
    pub fn inode(&self) -> &ExtInode {
        &self.inode
    }
    /// Logical byte size.
    pub fn len(&self) -> u64 {
        self.map.length
    }
    /// Whether the logical file is empty.
    pub fn is_empty(&self) -> bool {
        self.map.length == 0
    }
}
/// Owns both the exclusively writable target and caller-verified disjoint external journal.
pub struct ExtEditor<S: Storage, J: Storage> {
    target: Region<S>,
    journal: J,
    binding: ExtEditBinding,
    limits: ExtEditLimits,
    scope: u128,
    generation: u64,
    state: ExtEditState,
    geometry: ExtGeometry,
    audit: Option<ExtAuditReport>,
    pending: Option<fs_undo::UndoBinding>,
    pending_write: bool,
}
impl<S: Storage, J: Storage> ExtEditor<S, J> {
    /// Inspect currently owned clean storage; pending prepared journals require recovery first.
    pub fn open(
        storage: S,
        journal: J,
        region: ExtEditRegion,
        binding: ExtEditBinding,
        limits: ExtEditLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let container_length = storage.len().map_err(native)?;
        if region.length < 2048
            || region
                .offset
                .checked_add(region.length)
                .is_none_or(|end| end > container_length)
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ext2 editor region outside target",
            ));
        }
        let target = Region {
            storage,
            selected: region,
            container_length,
        };
        let status = fs_undo::inspect(&journal, r)?;
        if status
            .binding
            .is_some_and(|b| b.volume != binding.volume || b.generation != binding.generation)
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "ext2 journal binding mismatch",
            ));
        }
        if status.state == UndoState::Prepared {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 pending external undo requires recovery",
            ));
        }
        let n = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "ext2 editor scope exhausted"))?;
        let scope = (12u128 << 64) | u128::from(n);
        let geometry = ExtStorageDecoder::open_storage(&target, scope, r)
            .map_err(native)?
            .geometry()
            .clone();
        let audit = audit_ext_storage(&target, limits.audit, r)?;
        if !audit.is_clean() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "exclusive ext2 editing requires a complete clean ownership audit",
            ));
        }
        Ok(Self {
            target,
            journal,
            binding,
            limits,
            scope,
            generation: 0,
            state: ExtEditState::Ready,
            geometry,
            audit: Some(audit),
            pending: None,
            pending_write: false,
        })
    }
    fn ready(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.state != ExtEditState::Ready {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 editor requires recovery and inspection",
            ));
        }
        self.target.len().map_err(native)?;
        Ok(())
    }
    /// Current authorization state.
    pub fn state(&self) -> ExtEditState {
        self.state
    }
    /// Current handle generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Declared and validated filesystem geometry.
    pub fn geometry(&self) -> &ExtGeometry {
        &self.geometry
    }
    /// Complete audit established under this exclusively owned session.
    pub fn audit(&self) -> Option<&ExtAuditReport> {
        self.audit.as_ref()
    }
    /// Persistent independently verified external journal binding.
    pub fn binding(&self) -> ExtEditBinding {
        self.binding
    }
    /// Open an exact native byte path, without following symlinks.
    pub fn open_file(&self, path: &[NativeName], r: &Resources) -> Result<ExtEditFile> {
        self.ready(r)?;
        if path.is_empty() || path.len() > self.limits.work {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "ext2 file path must be bounded and nonempty",
            ));
        }
        let metadata = r.memory.reserve(512)?;
        let decoder =
            ExtStorageDecoder::open_storage(&self.target, self.scope, r).map_err(native)?;
        let mut number = 2;
        let mut work = 0usize;
        for name in path {
            r.cancellation.check()?;
            if !matches!(name,NativeName::Bytes(bytes) if !bytes.is_empty()&&bytes.len()<=255&&bytes!=b"."&&bytes!=b"..")
            {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "ext2 exact byte path component required",
                ));
            }
            let directory = decoder
                .directory(
                    number,
                    self.limits.file_blocks,
                    self.limits.directory_entries,
                    r,
                )
                .map_err(native)?;
            work = work
                .checked_add(directory.entries().len() + 1)
                .filter(|work| *work <= self.limits.work)
                .ok_or_else(|| {
                    Error::new(ErrorKind::BudgetExhausted, "ext2 path lookup work ceiling")
                })?;
            number = directory
                .entries()
                .iter()
                .find(|e| &e.name == name)
                .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "ext2 file path not found"))?
                .inode;
        }
        let inode = decoder.inode(number, r).map_err(native)?;
        if inode.mode() & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ext2 edit handle requires regular file",
            ));
        }
        let map = decoder
            .file_map(number, self.limits.file_blocks, r, false)
            .map_err(native)?;
        let mut identity = decoder.identity(number, r).map_err(native)?;
        identity.generation = self.generation;
        Ok(ExtEditFile {
            identity,
            inode,
            map,
            _metadata: metadata,
        })
    }
    /// Positional access through this owner; borrowed storage never implements immutable ReadAt.
    pub fn read_at(
        &self,
        file: &ExtEditFile,
        offset: u64,
        out: &mut [u8],
        r: &Resources,
    ) -> Result<usize> {
        self.ready(r)?;
        if file.identity.source != self.scope || file.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated ext2 file handle",
            ));
        }
        ExtStorageDecoder::open_storage(&self.target, self.scope, r)
            .map_err(native)?
            .read_map(&file.map, offset, out, r)
            .map_err(native)
    }
    /// Return owned capabilities and their authorization state.
    pub fn into_stores(self) -> (S, J, ExtEditState) {
        (self.target.storage, self.journal, self.state)
    }
}
