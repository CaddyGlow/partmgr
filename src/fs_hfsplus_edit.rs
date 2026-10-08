//! Exclusive bare nonjournaled HFS+/HFSX fork range writes and COW resize.
//! The caller must exclude other writers and use a physically disjoint journal.
//! Failed uncertain commits require dropping the session and cold recovery.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_core::{NativeName, Resources, Result, StreamKind},
    fs_hfsplus::{
        HfsPlusReadLimits,
        authoring_node::owned_prepare::{self, Prepared},
    },
    fs_hfsplus_audit::HfsPlusAuditLimits,
    fs_undo::{UndoBinding, UndoFailure, UndoLimits, UndoStatus},
    storage::Storage,
};
/// Explicit preparation, range and external-undo ceilings.
#[derive(Clone, Copy)]
pub struct HfsPlusEditLimits {
    /// Maximum retained 512-byte metadata pages.
    pub pages: usize,
    /// Maximum decoder/audit restart attempts.
    pub attempts: usize,
    /// Cumulative conservative decoder/audit and actual read work.
    pub work: u64,
    /// Maximum replacement or recovery selection length.
    pub range_bytes: u64,
    /// Native reader ceilings.
    pub read: HfsPlusReadLimits,
    /// Complete ownership-audit ceilings.
    pub audit: HfsPlusAuditLimits,
    /// External journal patch/body ceilings.
    pub undo: UndoLimits,
}
impl HfsPlusEditLimits {
    fn native(self) -> owned_prepare::Limits {
        owned_prepare::Limits {
            pages: self.pages,
            attempts: self.attempts,
            work: self.work,
            range_bytes: self.range_bytes,
            read: self.read,
            audit: self.audit,
        }
    }
}
/// Same-session generation-bound exact before/after range plan.
pub struct HfsPlusRangePlan(owned_prepare::RangePlan);
/// Exclusive audited storage; no mutable storage is exposed as an immutable reader.
pub struct HfsPlusEditSession<S: Storage> {
    prepared: Prepared<S>,
    limits: HfsPlusEditLimits,
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Require a complete clean audit of the exact bare-volume storage.
    pub fn open(storage: S, limits: HfsPlusEditLimits, r: &Resources) -> Result<Self> {
        Ok(Self {
            prepared: Prepared::open(storage, limits.native(), r)?,
            limits,
        })
    }
    /// Plan allocated DATA/resource-fork bytes within existing EOF.
    pub fn plan_range(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        offset: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<HfsPlusRangePlan> {
        self.prepared
            .plan_range(path, kind, offset, bytes, r)
            .map(HfsPlusRangePlan)
    }
    /// Publish durable external undo, fence dirty states, write and verify payload.
    pub fn commit_range(
        &mut self,
        plan: HfsPlusRangePlan,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
        self.prepared
            .commit_range(plan.0, journal, binding, self.limits.undo, r)
    }
    /// Whether further plans require cold recovery.
    pub fn needs_recovery(&self) -> bool {
        self.prepared.needs_recovery()
    }
    /// Consume the session, preserving uncertain storage for cold recovery.
    pub fn into_storage(self) -> S {
        self.prepared.into_storage()
    }
}
/// Caller-bound exact native fork range expected in the external journal.
pub struct HfsPlusRecoverySelection<'a> {
    /// Exact native path from the volume root.
    pub path: &'a [NativeName],
    /// DATA or resource fork.
    pub kind: &'a StreamKind,
    /// Logical fork offset.
    pub offset: u64,
    /// Exact originally planned byte count.
    pub length: u64,
    /// Caller-verified volume/session/transaction binding.
    pub binding: UndoBinding,
}
/// Recover through the exclusively held target; success grants no edit session.
pub fn recover_range(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    selection: HfsPlusRecoverySelection<'_>,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::transaction::recovery::recover_range(
        target,
        journal,
        owned_prepare::transaction::recovery::Selection {
            path: selection.path,
            kind: selection.kind,
            offset: selection.offset,
            length: selection.length,
            binding: selection.binding,
        },
        limits.native(),
        limits.undo,
        r,
    )
}

/// Requested final EOF and replacement within the resized fork.
pub struct HfsPlusResizeRequest<'a> {
    /// Exact native path.
    pub path: &'a [NativeName],
    /// DATA or resource fork.
    pub kind: &'a StreamKind,
    /// Final logical EOF.
    pub length: u64,
    /// Replacement offset within final EOF.
    pub offset: u64,
    /// Replacement bytes; retained bytes outside this range are copied, gaps zeroed.
    pub replacement: &'a [u8],
}
/// Consumed-session failure retains exclusive storage for cold recovery.
pub struct HfsPlusResizeFailure<S> {
    /// Original exclusively held target, possibly partially mutated.
    pub storage: S,
    /// Exact underlying failure and recovery requirement.
    pub failure: UndoFailure,
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// COW resize, returning freshly audited metadata after durable success.
    pub fn resize(
        self,
        request: HfsPlusResizeRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusResizeFailure<S>> {
        let Self { prepared, limits } = self;
        let request = owned_prepare::resize::commit::ResizeRequest {
            path: request.path,
            kind: request.kind,
            length: request.length,
            offset: request.offset,
            replacement: request.replacement,
        };
        prepared
            .commit_resize(request, journal, binding, limits.undo, r)
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusResizeFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold COW resize proof and recovery, retaining original request/binding.
pub fn recover_resize(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusResizeRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::resize::recovery::recover_resize(
        target,
        journal,
        owned_prepare::resize::commit::ResizeRequest {
            path: request.path,
            kind: request.kind,
            length: request.length,
            offset: request.offset,
            replacement: request.replacement,
        },
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}

/// Same-parent rename of one existing file or directory.
pub struct HfsPlusRenameRequest<'a> {
    /// Original exact native path; root cannot be renamed.
    pub path: &'a [NativeName],
    /// New final component, interpreted under the volume's native name profile.
    pub name: &'a [u16],
}
/// Consumed-session rename failure retains exclusive storage for cold recovery.
pub struct HfsPlusRenameFailure<S> {
    /// Original target, possibly partially mutated.
    pub storage: S,
    /// Failure and whether recovery is required.
    pub failure: UndoFailure,
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Rename within existing catalog capacity, returning a freshly audited session.
    pub fn rename(
        self,
        request: HfsPlusRenameRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusRenameFailure<S>> {
        let Self { prepared, limits } = self;
        prepared
            .commit_rename(
                owned_prepare::namespace::RenameRequest {
                    deleting: false,
                    destination: None,
                    path: request.path,
                    name: request.name,
                },
                journal,
                binding,
                limits.undo,
                r,
            )
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusRenameFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold rename recovery; retain the original path, new name and binding.
pub fn recover_rename(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusRenameRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::namespace::recover_rename(
        target,
        journal,
        owned_prepare::namespace::RenameRequest {
            deleting: false,
            destination: None,
            path: request.path,
            name: request.name,
        },
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}

/// Cross-parent move or same-parent rename of one file or directory.
pub struct HfsPlusMoveRequest<'a> {
    /// Original exact native path; root cannot be moved.
    pub path: &'a [NativeName],
    /// Existing destination directory path; empty selects root.
    pub destination: &'a [NativeName],
    /// New final native component.
    pub name: &'a [u16],
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Move/rename a file or directory, returning a freshly audited session.
    pub fn move_entry(
        self,
        request: HfsPlusMoveRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusRenameFailure<S>> {
        let Self { prepared, limits } = self;
        prepared
            .commit_rename(
                owned_prepare::namespace::RenameRequest {
                    deleting: false,
                    destination: Some(request.destination),
                    path: request.path,
                    name: request.name,
                },
                journal,
                binding,
                limits.undo,
                r,
            )
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusRenameFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold move recovery; retain original path, destination, name and binding.
pub fn recover_move(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusMoveRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::namespace::recover_rename(
        target,
        journal,
        owned_prepare::namespace::RenameRequest {
            deleting: false,
            destination: Some(request.destination),
            path: request.path,
            name: request.name,
        },
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}

/// Regular-file or empty-directory deletion; root and nonempty directories reject.
pub struct HfsPlusDeleteRequest<'a> {
    /// Exact original native path.
    pub path: &'a [NativeName],
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Delete a regular file or empty directory, returning a freshly audited session.
    pub fn delete_entry(
        self,
        request: HfsPlusDeleteRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusRenameFailure<S>> {
        let Self { prepared, limits } = self;
        prepared
            .commit_rename(
                owned_prepare::namespace::RenameRequest {
                    deleting: true,
                    destination: None,
                    path: request.path,
                    name: &[],
                },
                journal,
                binding,
                limits.undo,
                r,
            )
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusRenameFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold deletion recovery; retain the original native path and binding.
pub fn recover_delete(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusDeleteRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::namespace::recover_rename(
        target,
        journal,
        owned_prepare::namespace::RenameRequest {
            deleting: true,
            destination: None,
            path: request.path,
            name: &[],
        },
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}

/// UID, GID, permissions and five native unsigned dates since 1904-01-01 GMT.
pub use crate::fs_hfsplus::authoring_node::metadata_builder::CatalogMetadata as HfsPlusCreateMetadata;
/// Empty-object creation with a native parent path and UTF-16 name.
pub struct HfsPlusCreateRequest<'a> {
    /// Exact native directory path; empty selects root.
    pub parent: &'a [NativeName],
    /// Native UTF-16 name, subject to catalog name validation.
    pub name: &'a [u16],
    /// True creates a directory; false creates an empty regular file.
    pub directory: bool,
    /// None selects documented native builder defaults.
    pub metadata: Option<&'a HfsPlusCreateMetadata>,
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Create an empty regular file or directory within existing catalog capacity.
    pub fn create_entry(
        self,
        request: HfsPlusCreateRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusRenameFailure<S>> {
        let Self { prepared, limits } = self;
        prepared
            .commit_create_entry(
                owned_prepare::namespace::create::CreateRequest {
                    parent: request.parent,
                    name: request.name,
                    directory: request.directory,
                    metadata: request.metadata,
                },
                journal,
                binding,
                limits.undo,
                r,
            )
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusRenameFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold creation recovery requires the exact original request and binding.
pub fn recover_create(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusCreateRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::namespace::create::recover_create_entry(
        target,
        journal,
        owned_prepare::namespace::create::CreateRequest {
            parent: request.parent,
            name: request.name,
            directory: request.directory,
            metadata: request.metadata,
        },
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}

/// Bounded populated regular-file creation; both forks publish in one transaction.
pub struct HfsPlusCreateFileRequest<'a> {
    /// Exact native parent directory path; empty selects root.
    pub parent: &'a [NativeName],
    /// Native UTF-16 filename.
    pub name: &'a [u16],
    /// Explicit native metadata, or documented builder defaults.
    pub metadata: Option<&'a HfsPlusCreateMetadata>,
    /// Complete initial DATA fork bytes within configured transaction ceilings.
    pub data: &'a [u8],
    /// Complete initial resource fork bytes within configured transaction ceilings.
    pub resource: &'a [u8],
}
impl<S: Storage> HfsPlusEditSession<S> {
    /// Create a regular file and both initialized forks as one recoverable transaction.
    pub fn create_file(
        self,
        request: HfsPlusCreateFileRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, HfsPlusRenameFailure<S>> {
        let Self { prepared, limits } = self;
        prepared
            .commit_populated_birth(
                (
                    owned_prepare::namespace::create::CreateRequest {
                        parent: request.parent,
                        name: request.name,
                        directory: false,
                        metadata: request.metadata,
                    },
                    request.data,
                    request.resource,
                ),
                journal,
                binding,
                limits.undo,
                r,
            )
            .map(|prepared| Self { prepared, limits })
            .map_err(|error| HfsPlusRenameFailure {
                storage: error.target,
                failure: error.error,
            })
    }
}
/// Cold populated-file creation recovery requires the exact request and binding.
pub fn recover_create_file(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: HfsPlusCreateFileRequest<'_>,
    binding: UndoBinding,
    limits: HfsPlusEditLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    owned_prepare::namespace::create::recover_populated_birth(
        target,
        journal,
        (
            owned_prepare::namespace::create::CreateRequest {
                parent: request.parent,
                name: request.name,
                directory: false,
                metadata: request.metadata,
            },
            request.data,
            request.resource,
        ),
        binding,
        limits.native(),
        limits.undo,
        r,
    )
}
