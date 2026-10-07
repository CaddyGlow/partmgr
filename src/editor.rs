//! Reviewable editing over owned layouts, with explicit filesystem prerequisites.
use crate::{
    error::Error,
    layout::{DiskLayout, LbaRange},
    payload::FilesystemResize,
};
use std::io;
/// A boundary change and the payload work it requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    slot: u32,
    old: LbaRange,
    new: LbaRange,
}
impl Change {
    /// Partition table slot.
    pub fn slot(&self) -> u32 {
        self.slot
    }
    /// Previous half-open sector range.
    pub fn old_range(&self) -> LbaRange {
        self.old
    }
    /// Proposed half-open sector range.
    pub fn new_range(&self) -> LbaRange {
        self.new
    }
    /// Whether the filesystem must shrink before a managed commit.
    pub fn requires_filesystem_shrink(&self) -> bool {
        self.new.sectors() < self.old.sectors()
    }
    /// Whether existing payloads require a separately completed movement operation.
    pub fn requires_payload_move(&self) -> bool {
        self.old.start() != self.new.start()
    }
}
/// Immutable original metadata and an independent editable proposal.
pub struct Editor {
    original: DiskLayout,
    committed: DiskLayout,
    proposed: DiskLayout,
    changes: Vec<Change>,
    pending: bool,
    requires_reinspection: bool,
}
fn invalid(message: &'static str) -> Error {
    Error::edit(io::Error::new(io::ErrorKind::InvalidInput, message))
}
impl Editor {
    /// Begin editing a previously validated owned layout, without I/O.
    pub fn new(original: DiskLayout) -> Self {
        Self {
            proposed: original.clone(),
            committed: original.clone(),
            original,
            changes: Vec::new(),
            pending: false,
            requires_reinspection: false,
        }
    }
    /// Inspected state retained unchanged for stale-plan preconditions.
    pub fn original(&self) -> &DiskLayout {
        &self.original
    }
    /// Current owned proposal.
    pub fn proposed(&self) -> &DiskLayout {
        &self.proposed
    }
    /// Explicit reviewed boundary changes in edit order.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
    fn range(&self, slot: u32) -> Result<LbaRange, Error> {
        match &self.proposed {
            DiskLayout::Gpt(g) => g
                .entries()
                .iter()
                .find(|e| e.slot() == slot)
                .and_then(|e| e.range()),
            DiskLayout::Mbr(m) => m
                .entries()
                .iter()
                .find(|e| e.slot() == slot)
                .map(|e| e.range()),
        }
        .ok_or_else(|| invalid("partition slot absent"))
    }
    /// Change only partition boundaries. This performs no data movement or
    /// filesystem work; review `changes` before committing a boundary-only plan.
    pub fn set_boundary(&mut self, slot: u32, new: LbaRange) -> Result<(), Error> {
        self.ensure_editable()?;
        let old = self.range(slot)?;
        match &mut self.proposed {
            DiskLayout::Gpt(g) => g.set_range(slot, new),
            DiskLayout::Mbr(m) => m.set_range(slot, new),
        }
        .map_err(Error::edit)?;
        self.changes.push(Change { slot, old, new });
        self.pending = true;
        Ok(())
    }
    /// Produce a metadata-only plan. Callers explicitly take responsibility for
    /// all payload and filesystem prerequisites described by the review.
    pub fn boundary_only_plan(&self) -> Result<crate::storage::WritePlan, Error> {
        self.ensure_editable()?;
        crate::codec::edit_plan(&self.committed, &self.proposed).map_err(Error::edit)
    }
    fn ensure_editable(&self) -> Result<(), Error> {
        if self.requires_reinspection {
            return Err(invalid(
                "partial commit requires fresh storage inspection and a new editor",
            ));
        }
        Ok(())
    }
    /// Commit explicit boundary-only edits and adopt the strictly reread layout
    /// as the next commit baseline. Payload prerequisites remain the caller's
    /// responsibility. A partial failure prevents further use of this editor.
    pub fn commit_boundary_only<S: crate::storage::Storage + Send + Sync>(
        &mut self,
        storage: &mut S,
    ) -> Result<(), Error> {
        let plan = self.boundary_only_plan()?;
        let sector = match &self.proposed {
            DiskLayout::Gpt(g) => g.geometry().sector_size(),
            DiskLayout::Mbr(m) => m.geometry().sector_size(),
        };
        match crate::codec::commit_and_inspect(&plan, storage, sector) {
            Ok(layout) => {
                self.committed = layout.clone();
                self.proposed = layout;
                self.pending = false;
                Ok(())
            }
            Err(error) => {
                self.requires_reinspection = matches!(error, Error::PartialCommit(_));
                Err(error)
            }
        }
    }
    /// Resize a same-start partition using a filesystem adapter and an explicit
    /// commit callback. Shrink finishes filesystem work before metadata commit;
    /// grow commits metadata first. Movement requires a separate payload plan.
    ///
    /// On filesystem growth failure, the successful larger proposal is retained.
    /// On shrink commit failure, the filesystem may already be smaller and the
    /// commit error must be inspected for partial storage writes.
    /// Callback success must mean the exact plan committed and strict storage
    /// reinspection passed, for example through `codec::commit_and_inspect`.
    /// Report uncertain writes as `Error::PartialCommit`; this prevents reuse.
    pub fn managed_resize(
        &mut self,
        slot: u32,
        new: LbaRange,
        filesystem: &mut dyn FilesystemResize,
        commit: impl FnOnce(&crate::storage::WritePlan) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ensure_editable()?;
        if self.pending {
            return Err(invalid(
                "managed resize requires a committed proposal without pending boundary edits",
            ));
        }
        let old = self.range(slot)?;
        if old.start() != new.start() {
            return Err(invalid("managed resize cannot move payload"));
        }
        let mut candidate = Self::new(self.proposed.clone());
        candidate.set_boundary(slot, new)?;
        let plan = candidate.boundary_only_plan()?;
        let sector = match &self.proposed {
            DiskLayout::Gpt(g) => g.geometry().sector_size(),
            DiskLayout::Mbr(m) => m.geometry().sector_size(),
        };
        let bytes = new
            .sectors()
            .checked_mul(u64::from(sector))
            .ok_or_else(|| invalid("filesystem length overflow"))?;
        if new.sectors() < old.sectors() {
            filesystem.shrink(bytes).map_err(Error::Io)?;
            if let Err(error) = commit(&plan) {
                self.requires_reinspection = matches!(error, Error::PartialCommit(_));
                return Err(error);
            }
            self.proposed = candidate.proposed;
            self.committed = self.proposed.clone();
            self.changes.extend(candidate.changes);
        } else {
            if let Err(error) = commit(&plan) {
                self.requires_reinspection = matches!(error, Error::PartialCommit(_));
                return Err(error);
            }
            self.proposed = candidate.proposed;
            self.committed = self.proposed.clone();
            self.changes.extend(candidate.changes);
            filesystem.grow(bytes).map_err(Error::Io)?;
        }
        Ok(())
    }
}
