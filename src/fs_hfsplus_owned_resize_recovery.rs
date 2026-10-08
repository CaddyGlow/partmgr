//! Cold resize proof through original preimages and regenerated closed patches.
use super::*;
use crate::fs_undo::{
    self, UndoBinding, UndoFailure, UndoLimits, UndoRecoveryValidator, UndoStatus,
};
struct Collector {
    patches: Vec<WriteRange>,
}
impl UndoRecoveryValidator for Collector {
    fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
        let mut before = vector(old.len())?;
        before.extend_from_slice(old);
        let mut after = vector(new.len())?;
        after.extend_from_slice(new);
        self.patches.push(
            WriteRange::new(at, before, after)
                .map_err(|e| Error::io("HFS+ resize saved patch", e))?,
        );
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}
struct Original<'a> {
    target: &'a dyn Storage,
    patches: &'a [WriteRange],
}
impl Storage for Original<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)?;
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        // Saved patches were proved sorted and disjoint by the shared parser.
        // Skip preceding ranges instead of scanning the entire journal per page.
        let start = self
            .patches
            .partition_point(|patch| patch.offset() + patch.expected().len() as u64 <= at);
        for patch in &self.patches[start..] {
            if patch.offset() >= end {
                break;
            }
            let first = at.max(patch.offset());
            let last = end.min(patch.offset() + patch.expected().len() as u64);
            if first < last {
                out[(first - at) as usize..(last - at) as usize].copy_from_slice(
                    &patch.expected()
                        [(first - patch.offset()) as usize..(last - patch.offset()) as usize],
                );
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
fn fail(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "HFS+ cold resize proof",
        recovery_required: true,
        target_may_have_changed: false,
        source,
    }
}
pub(crate) fn recover_resize(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: super::commit::ResizeRequest<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    let length = target
        .len()
        .map_err(|e| fail(Error::io("HFS+ cold resize length", e)))?;
    let _lease = r
        .memory
        .reserve(
            undo.body_bytes
                .checked_mul(3)
                .and_then(|n| n.checked_add(u64::from(undo.patches) * 256))
                .ok_or_else(|| fail(budget("HFS+ cold resize collection charge")))?,
        )
        .map_err(fail)?;
    let mut saved = Collector {
        patches: vector(undo.patches as usize).map_err(fail)?,
    };
    let status =
        fs_undo::validate_recovery(journal, length, binding, undo, r, &mut saved).map_err(fail)?;
    let original = Prepared::open(
        Original {
            target,
            patches: &saved.patches,
        },
        limits,
        r,
    )
    .map_err(fail)?;
    if saved.patches.is_empty() {
        drop(original);
        return Ok(status);
    }
    let super::commit::ResizeRequest {
        path,
        kind,
        length: new_length,
        offset,
        replacement,
    } = request;
    let allocation = original
        .plan_resize_allocation(path, kind, new_length, r)
        .map_err(fail)?;
    let payload = original
        .stage_resize_payload(&allocation, offset, replacement, r)
        .map_err(fail)?;
    let metadata = original
        .stage_resize_metadata(path, kind, &allocation, r)
        .map_err(fail)?;
    let mut expected = vector(payload.patches.len() + metadata.patches.len() + 2).map_err(fail)?;
    expected.extend(payload.patches);
    expected.extend(metadata.patches);
    let clean = original.volume.header()[6];
    for at in [1030, length - 1018] {
        expected.push(
            WriteRange::new(at, vec![clean], vec![clean])
                .map_err(|e| fail(Error::io("HFS+ cold resize states", e)))?,
        );
    }
    expected.sort_unstable_by_key(WriteRange::offset);
    if expected.len() != saved.patches.len()
        || expected.iter().zip(&saved.patches).any(|(a, b)| {
            a.offset() != b.offset()
                || a.expected() != b.expected()
                || a.replacement() != b.replacement()
        })
    {
        return Err(fail(bad(
            "HFS+ saved resize differs from regenerated operation",
        )));
    }
    drop((original, allocation));
    super::super::transaction::recovery::recover_patches(
        target, journal, binding, limits, undo, r, &expected,
    )
}
