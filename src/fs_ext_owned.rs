//! Owned ordered classic-ext3 sessions. No immutable source authority is created.
use super::{Checksums, bootstrap, session};
use crate::{
    fs_core::{Cancellation, FileRead, NativeName, ObjectId, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
    platform::io,
    storage::Storage,
};

/// Explicit bounds for an exclusively owned classic-ext3 journal session.
#[derive(Clone, Copy, Debug)]
pub struct ExtJournalLimits {
    /// Complete ownership audit limits. Exhaustion never establishes readiness.
    pub audit: ExtAuditLimits,
    /// Maximum logical blocks retained for one file or directory map.
    /// Operation planning may impose a smaller `ExtEditLimits::file_blocks` bound.
    pub file_blocks: usize,
    /// Maximum metadata blocks changed by one operation, excluding preparation.
    pub affected_blocks: usize,
    /// Maximum physical transaction footprint, including data and journal writes.
    pub affected_bytes: u64,
}
impl From<ExtJournalLimits> for session::Limits {
    fn from(value: ExtJournalLimits) -> Self {
        Self {
            audit: value.audit,
            file_blocks: value.file_blocks,
            affected_blocks: value.affected_blocks,
            affected_bytes: value.affected_bytes,
        }
    }
}

/// Authorization state of an owned ordered journal session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtJournalState {
    /// A complete clean audit and final source guards permit operations.
    Ready,
    /// Explicit owned recovery and a fresh audit are required before further use.
    NeedsRecovery,
}
impl From<session::State> for ExtJournalState {
    fn from(value: session::State) -> Self {
        match value {
            session::State::Ready => Self::Ready,
            session::State::NeedsRecovery => Self::NeedsRecovery,
        }
    }
}

/// Versioned admitted profile; reader support does not widen this write profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtJournalProfile {
    /// Manifest version. Version five adds within-EOF COW writes; version six adds sparse extension; version seven adds canonical unfollowed symlink lifecycle operations.
    pub version: u32,
    /// Native block size: 1024, 2048 or 4096 bytes.
    pub block_bytes: u32,
    /// Number of filesystem blocks, excluding any backing-storage tail.
    pub volume_blocks: u32,
    /// Native inode record size; all admitted versions require 128 bytes.
    pub inode_bytes: u16,
    /// Internal journal block count, including its superblock.
    pub journal_blocks: u32,
    /// Admitted filesystem compatibility features.
    pub compatible_features: u32,
    /// Admitted incompatibility features with the transient RECOVER bit removed.
    pub incompatible_features: u32,
    /// Admitted read-only compatibility features.
    pub readonly_features: u32,
    /// Filesystem UUID inspected during admission.
    pub uuid: [u8; 16],
}

/// A regular-file observation bound to one owner and session generation.
///
/// Mutation and recovery invalidate existing handles. Obtain a fresh handle by
/// path after each successful operation; handles cannot authorize physical writes.
pub struct ExtJournalFile {
    inner: session::File,
}
impl ExtJournalFile {
    /// Identity including owner, session generation and native inode observation.
    pub fn identity(&self) -> &ObjectId {
        &self.inner.identity
    }
    /// Native inode number observed when this handle was opened.
    pub fn inode_number(&self) -> u32 {
        self.inner.inode_number()
    }
    /// Logical byte length at the generation in which this handle was opened.
    pub fn len(&self) -> u64 {
        self.inner.len()
    }
    /// Whether this observation has zero logical bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Exclusively owned ordered classic-ext3 editing with explicit recovery.
///
/// The caller must ensure that no other backend handle or mounted filesystem
/// changes this storage for the lifetime of the session. Moving a shared backend
/// into this object does not itself establish exclusive access. Length guards do
/// not detect every external modification that preserves storage length.
///
/// The admitted profile uses 128-byte inodes, an internal checksumless journal,
/// FILETYPE and SPARSE_SUPER. Regular append/creation and namespace operations
/// are supported. Namespace edits journal metadata, including directory bodies.
/// File data becomes durable before metadata commit; old visible bytes are never
/// overwritten by append. Modern ext4, ACL/xattr edits and foreign-log recovery
/// require separate capabilities. This API is available with the `std` feature.
pub struct ExtJournalSession<S: Storage> {
    inner: session::Session<S>,
    profile: ExtJournalProfile,
    limits: ExtJournalLimits,
}
impl<S: Storage> ExtJournalSession<S> {
    /// Inspect and completely audit clean storage without automatic recovery.
    ///
    /// Unsupported profiles and incomplete audits fail before writes. Backend,
    /// cancellation and budget errors preserve their original causes.
    pub fn open(storage: S, limits: ExtJournalLimits, resources: &Resources) -> io::Result<Self> {
        let profile = admit(&storage, limits, resources)?;
        let inner = session::Session::open(storage, limits.into(), resources)?;
        Ok(Self {
            inner,
            profile,
            limits,
        })
    }

    /// Admit bounded storage for explicit partmgr-authored journal recovery.
    ///
    /// Admission performs no writes and always returns `NeedsRecovery`, even for
    /// clean bytes. Foreign unsealed transactions are never an automatic fallback.
    /// The ownership audit is deferred until explicit [`Self::recover`].
    pub fn open_for_recovery(
        storage: S,
        limits: ExtJournalLimits,
        resources: &Resources,
    ) -> io::Result<Self> {
        let profile = admit(&storage, limits, resources)?;
        let inner = session::Session::open_for_recovery(storage, limits.into(), resources)?;
        Ok(Self {
            inner,
            profile,
            limits,
        })
    }

    /// Current authorization state, including conservative prewrite refusals.
    pub fn state(&self) -> ExtJournalState {
        self.inner.state().into()
    }

    /// Profile admitted before constructing the session.
    pub fn profile(&self) -> ExtJournalProfile {
        self.profile
    }

    /// Resolve an exact byte-name path to a regular-file observation.
    pub fn file_at(
        &self,
        path: &[NativeName],
        cancellation: &Cancellation,
    ) -> io::Result<ExtJournalFile> {
        self.inner
            .file_at(path, cancellation)
            .map(|inner| ExtJournalFile { inner })
    }

    /// Read an exact native target without following it or interpreting its bytes.
    pub fn read_symlink(
        &self,
        path: &[NativeName],
        cancellation: &Cancellation,
    ) -> io::Result<crate::fs_core::Budgeted<Vec<u8>>> {
        self.inner.read_symlink(path, cancellation)
    }

    /// Read a bounded range through a current owner-bound file handle.
    pub fn read_at(
        &self,
        file: &ExtJournalFile,
        at: u64,
        out: &mut [u8],
        cancellation: &Cancellation,
    ) -> io::Result<usize> {
        self.inner.read_at(&file.inner, at, out, cancellation)
    }

    /// Create an exact, unfollowed symlink target; target resolution is never performed.
    pub fn create_symlink(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        target: &[u8],
        metadata: &ExtCreateMetadata,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::CreateSymlink {
                parent,
                name,
                target,
                metadata,
            },
            planning,
            cancellation,
        )
    }
    /// Replace a symlink's exact target through its final unfollowed name.
    /// Native identity/times and all existing aliases are preserved.
    pub fn replace_symlink_target(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        target: &[u8],
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::ReplaceSymlinkTarget {
                parent,
                name,
                target,
            },
            planning,
            cancellation,
        )
    }
    /// Unlink a symlink without following it; final deletion requires explicit native time.
    pub fn unlink_symlink(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        deletion_time: u32,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::UnlinkSymlink {
                parent,
                name,
                deletion_time,
            },
            planning,
            cancellation,
        )
    }

    /// Extend logical length with zeros, preserving the current visible prefix.
    ///
    /// Requires a strictly larger length through a current owner-bound handle.
    /// Newly visible complete blocks remain holes; this reserves no capacity.
    /// A mapped partial old EOF is copied into originally free storage with its
    /// invisible suffix zeroed before metadata publication. Original physical
    /// payload stays unchanged, so this case may refuse for lack of free space.
    /// All aliases share the new length; native metadata and times are preserved.
    /// Successful mutation invalidates prior handles. Inspect state after errors:
    /// uncertain publication retains `NeedsRecovery` until explicit recovery.
    pub fn extend_sparse(
        &mut self,
        file: &ExtJournalFile,
        new_length: u64,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::SparseExtend {
                file: &file.inner,
                length: new_length,
            },
            planning,
            cancellation,
        )
    }

    /// Replace a nonempty exact input range within the existing EOF.
    ///
    /// Copies touched blocks into originally free storage. Preserves length,
    /// unaffected bytes, native metadata and every original physical payload
    /// block. Holes are materialized only where touched. All aliases share the
    /// new mapping. No implicit extension or short success is permitted.
    /// Success returns the input's complete declared length after durable commit;
    /// errors return no partial count and may retain `NeedsRecovery`.
    pub fn write_at(
        &mut self,
        file: &ExtJournalFile,
        offset: u64,
        input: &dyn FileRead,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<u64> {
        let input_length = input.len();
        self.inner.operate_ordered(
            session::Operation::Overwrite {
                file: &file.inner,
                offset,
                input,
                input_length,
            },
            planning,
            cancellation,
        )?;
        Ok(input_length)
    }

    /// Append the complete immutable input using ordered data publication.
    ///
    /// Planning is bounded and finishes before publication. Once dispatch
    /// invalidates handles, any error can conservatively retain `NeedsRecovery`,
    /// including a late prewrite refusal. Inspect [`Self::state`] after failure.
    pub fn append(
        &mut self,
        file: &ExtJournalFile,
        input: &dyn FileRead,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::Extend {
                file: &file.inner,
                input,
            },
            planning,
            cancellation,
        )
    }

    /// Shrink a regular file while preserving its native identity and metadata.
    ///
    /// Every hardlink sees the new size. A mapped partial EOF block is copied
    /// into originally free storage, with a zeroed suffix, before metadata
    /// publication; original payload blocks are never overwritten or journaled.
    /// This can require free space even when the operation releases blocks.
    /// Equal or larger lengths are refused. Existing handles become stale after
    /// dispatch; inspect [`Self::state`] after any failure.
    pub fn truncate(
        &mut self,
        file: &ExtJournalFile,
        length: u64,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::Truncate {
                file: &file.inner,
                length,
            },
            planning,
            cancellation,
        )
    }

    /// Create a regular file with exact native byte name and ordered payload.
    ///
    /// Parent names, metadata and the complete prospective allocation are checked
    /// before publication. The operation invalidates prior handles on dispatch.
    pub fn create_file(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        metadata: &ExtCreateMetadata,
        payload: &[u8],
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::CreateFile {
                parent,
                name,
                metadata,
                payload,
            },
            planning,
            cancellation,
        )
    }

    /// Create a directory with exact native byte names and caller-native metadata.
    ///
    /// Empty parent denotes root. No host clock, ownership or ACL inheritance is
    /// inferred. Directory bodies are journaled metadata. Successful mutation
    /// invalidates existing file handles; inspect [`Self::state`] after errors.
    pub fn create_directory(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        metadata: &ExtCreateMetadata,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::CreateDirectory {
                parent,
                name,
                metadata,
            },
            planning,
            cancellation,
        )
    }

    /// Add an exact name for an existing regular file, without replacing a destination.
    ///
    /// Both parent paths are resolved from this session; symlinks are not followed.
    /// Directories and other nonregular sources are refused. The resulting inode
    /// may have at most 32000 links. Native timestamps, ownership, mapping and
    /// payload are preserved; later append/truncate through any alias changes the
    /// shared inode. Success invalidates existing handles. Inspect state on error.
    pub fn hard_link(
        &mut self,
        source_parent: &[NativeName],
        source_name: &[u8],
        destination_parent: &[NativeName],
        destination_name: &[u8],
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::HardLink {
                source: source_parent,
                name: source_name,
                destination: destination_parent,
                new_name: destination_name,
            },
            planning,
            cancellation,
        )
    }

    /// Rename or move a regular file or directory, preserving its native metadata.
    ///
    /// Names are exact bytes without symlink following. Existing destinations,
    /// including aliases of the source and identical source/destination names,
    /// are rejected. Directory moves update parent links and `..` and reject
    /// ancestry cycles. No overwrite or exchange is implicit. Successful mutation
    /// invalidates existing file handles; inspect [`Self::state`] after errors.
    pub fn rename(
        &mut self,
        source_parent: &[NativeName],
        source_name: &[u8],
        destination_parent: &[NativeName],
        destination_name: &[u8],
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner.operate_ordered(
            session::Operation::Rename {
                source: source_parent,
                name: source_name,
                destination: destination_parent,
                new_name: destination_name,
            },
            planning,
            cancellation,
        )
    }

    /// Unlink exactly one regular-file name; directories are rejected before writes.
    ///
    /// Remaining hardlinks retain allocation and native timestamps. Final unlink
    /// releases inode/data/indirect allocation without wiping payload bytes.
    /// `deletion_time` is explicit native Unix seconds and must be nonzero and at
    /// least the filesystem inode count, avoiding the native orphan-number domain.
    /// Successful mutation invalidates handles; inspect [`Self::state`] on error.
    pub fn unlink_file(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        deletion_time: u32,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner
            .delete_kind(parent, name, deletion_time, false, planning, cancellation)
    }

    /// Remove an empty directory; regular files and nonempty directories are refused.
    ///
    /// No recursive deletion is implicit. The same explicit native deletion-time
    /// restriction as [`Self::unlink_file`] applies. Parent links and native
    /// allocation are updated transactionally. Successful mutation invalidates
    /// handles; inspect [`Self::state`] after errors.
    pub fn remove_directory(
        &mut self,
        parent: &[NativeName],
        name: &[u8],
        deletion_time: u32,
        planning: ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.inner
            .delete_kind(parent, name, deletion_time, true, planning, cancellation)
    }

    /// Explicitly recover partmgr-authored transactions and establish a fresh audit.
    ///
    /// Failure retains `NeedsRecovery` and its original backend or policy cause.
    /// No file handles are usable until this method succeeds.
    pub fn recover(&mut self, cancellation: &Cancellation) -> io::Result<()> {
        self.inner.recover_ordered(cancellation)?;
        let expected = self.profile;
        let limits = self.limits;
        self.inner.revalidate(cancellation, |storage, resources| {
            if admit(storage, limits, resources)? != expected {
                return Err(super::invalid("recovered ordered ext profile changed"));
            }
            Ok(())
        })
    }

    /// Release storage with its outstanding recovery obligation.
    pub fn into_storage(self) -> (S, ExtJournalState) {
        let (storage, state) = self.inner.into_storage();
        (storage, state.into())
    }
}

fn admit(
    storage: &dyn Storage,
    limits: ExtJournalLimits,
    resources: &Resources,
) -> io::Result<ExtJournalProfile> {
    let boot = bootstrap::Bootstrap::read(storage, 65536, limits.audit.work, resources)?;
    let sb = &boot.primary;
    validate_primary(sb)?;
    if !matches!(boot.geometry.checksums, Checksums::None)
        || boot.geometry.revoke
        || boot.geometry.first != 1
    {
        return Err(super::unsupported(
            "ordered ext journal profile requires classic 128-byte inodes, HAS_JOURNAL/FILETYPE/SPARSE_SUPER and a checksumless internal journal without revoke",
        ));
    }
    resources.cancellation.check().map_err(io::Error::other)?;
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&sb[104..120]);
    Ok(ExtJournalProfile {
        version: 7,
        block_bytes: boot.geometry.block_bytes as u32,
        volume_blocks: super::super::u32le(sb, 4),
        inode_bytes: super::super::u16le(sb, 88),
        journal_blocks: boot.geometry.maximum,
        compatible_features: super::super::u32le(sb, 92),
        incompatible_features: super::super::u32le(sb, 96) & !4,
        readonly_features: super::super::u32le(sb, 100),
        uuid,
    })
}

pub(super) fn validate_primary(sb: &[u8]) -> io::Result<()> {
    if sb.len() != 1024 {
        return Err(super::invalid("ordered ext journal primary size"));
    }
    if super::super::u32le(sb, 76) != 1
        || super::super::u32le(sb, 72) != 0
        || super::super::u32le(sb, 232) != 0
        || super::super::u16le(sb, 88) != 128
        || super::super::u32le(sb, 92) != 4
        || super::super::u32le(sb, 96) & !4 != 2
        || super::super::u32le(sb, 100) != 1
    {
        return Err(super::unsupported(
            "ordered ext journal profile requires Linux revision one, no orphan chain, classic 128-byte inodes and HAS_JOURNAL/FILETYPE/SPARSE_SUPER",
        ));
    }
    Ok(())
}
