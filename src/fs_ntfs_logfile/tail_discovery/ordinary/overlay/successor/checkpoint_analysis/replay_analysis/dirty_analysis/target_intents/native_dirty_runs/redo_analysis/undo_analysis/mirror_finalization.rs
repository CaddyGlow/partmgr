//! Pinned post-undo contiguous mirror shadow copy; never a durable writer.
use super::*;
/// Independent finite bounds for retained native mirror block observations.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogMirrorLimits {
    /// Maximum block attempts retained, including an incomplete final read.
    pub blocks: usize,
    /// Maximum total original/after bytes across source and destination buffers.
    pub bytes: usize,
    /// Combined analysis, redo, undo, mirror work and repeated source guards.
    pub work: usize,
}
/// One native ordered mirror block attempt and explicit preimage instrumentation.
pub struct NtfsLogMirrorBlock {
    source: u64,
    destination: u64,
    original: Vec<u8>,
    source_after: Vec<u8>,
    destination_original: Vec<u8>,
    after: Vec<u8>,
    source_read: bool,
    source_ready: bool,
    destination_guard_read: bool,
    copied: bool,
    _lease: Reservation,
}
impl NtfsLogMirrorBlock {
    /// Native contiguous primary MFT byte address, in sb_bread order.
    pub fn source_offset(&self) -> u64 {
        self.source
    }
    /// Native contiguous mirror byte address, independent of DATA mapping runs.
    pub fn destination_offset(&self) -> u64 {
        self.destination
    }
    /// Completed original-byte provenance acquisition before prior shadow overlays.
    /// Native sb_bread may instead use an uptodate cache buffer; this extra
    /// physical acquisition is not evidence of an actual native cold read.
    pub fn source_original(&self) -> Option<&[u8]> {
        self.source_read.then_some(&self.original)
    }
    /// Source bytes after the charged ordered prior-effect overlays.
    pub fn source_after(&self) -> Option<&[u8]> {
        self.source_ready.then_some(&self.source_after)
    }
    /// Extra provenance read; native sb_getblk itself performs no destination read.
    pub fn destination_original(&self) -> Option<&[u8]> {
        self.destination_guard_read
            .then_some(&self.destination_original)
    }
    /// Native copied destination shadow; present only after the copy branch.
    pub fn after(&self) -> Option<&[u8]> {
        self.copied.then_some(&self.after)
    }
}
/// Source-owned post-undo mirror attempt; no active-window or write authority.
pub struct NtfsLogMirrorReport {
    undo: NtfsLogUndoReport,
    blocks: Vec<NtfsLogMirrorBlock>,
    error: Option<Error>,
    returned: bool,
    complete: bool,
    work: usize,
    _lease: Reservation,
}
impl NtfsLogMirrorReport {
    /// Entire retained source-owned undo prefix and prior native shadows.
    pub fn undo(&self) -> &NtfsLogUndoReport {
        &self.undo
    }
    /// Exact native block order, including incomplete attempts.
    pub fn blocks(&self) -> &[NtfsLogMirrorBlock] {
        &self.blocks
    }
    /// Model admission or provenance failure; independent of native void return.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error.as_ref().or_else(|| self.undo.stopping_error())
    }
    /// Whether the admitted native copy branch reached its modeled return.
    pub fn native_returned(&self) -> bool {
        self.returned
    }
    /// Whether all native block copies completed and pending was cleared.
    pub fn mirror_copy_complete(&self) -> bool {
        self.complete
    }
    /// Combined bounded work through the final repeated original-source guards.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Other FILE/index operation classes remain mandatory.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Shadow copies grant no durable recovery authority.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn repeat_mirror(report: &NtfsLogMirrorReport, w: &mut Work, r: &Resources) -> Result<()> {
    guard_undo(&report.undo, w, r)?;
    let context = report.undo.redo.input.input.analysis().context();
    for block in &report.blocks {
        for (offset, expected) in [
            (block.source, block.source_original()),
            (block.destination, block.destination_original()),
        ] {
            let Some(expected) = expected else {
                continue;
            };
            charge(
                w,
                expected
                    .len()
                    .checked_mul(3)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| exhausted("NTFS mirror source guard work"))?,
                r,
            )?;
            let _lease = r.memory.reserve(expected.len() as u64)?;
            let mut current = bytes(expected.len())?;
            context.read_native_physical(offset, &mut current, r)?;
            if current != expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS mirror original physical source changed",
                ));
            }
        }
    }
    r.cancellation.check()
}
fn overlay_block(
    destination: &mut [u8],
    offset: u64,
    prior: &[u8],
    prior_offset: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    charge(w, 1, r)?;
    let end = offset
        .checked_add(destination.len() as u64)
        .ok_or_else(|| unsupported("NTFS mirror source range overflow"))?;
    let prior_end = prior_offset
        .checked_add(prior.len() as u64)
        .ok_or_else(|| unsupported("NTFS mirror previous range overflow"))?;
    let lo = offset.max(prior_offset);
    let hi = end.min(prior_end);
    if lo < hi {
        charge(w, (hi - lo) as usize, r)?;
        destination[(lo - offset) as usize..(hi - offset) as usize]
            .copy_from_slice(&prior[(lo - prior_offset) as usize..(hi - prior_offset) as usize]);
    }
    Ok(())
}
/// Model native ntfs_update_mftmirr(wait=0) only after actual admitted undo.
///
/// Both source and destination original-byte acquisitions are additional
/// provenance instrumentation. Native sb_bread may use an uptodate buffer and
/// sb_getblk does not read the destination. An acquisition failure therefore
/// stops model admission; it never invents a native cold-read failure or return.
/// Memory, cancellation, stale-source and unmodeled operation failures stay explicit.
pub fn inspect_logfile_native_mirror(
    undo: NtfsLogUndoReport,
    limits: NtfsLogMirrorLimits,
    r: &Resources,
) -> Result<NtfsLogMirrorReport> {
    let (blocks, lease) = vector(limits.blocks, r)?;
    let mut w = Work {
        used: undo.work(),
        maximum: limits.work,
    };
    charge(&mut w, 0, r)?;
    let mut report = NtfsLogMirrorReport {
        undo,
        blocks,
        error: None,
        returned: false,
        complete: false,
        work: w.used,
        _lease: lease,
    };
    let result = (|| -> Result<bool> {
        repeat_mirror(&report, &mut w, r)?;
        if !report.undo.admitted_undo_complete() {
            return Ok(false);
        }
        let Some(mirror) = &report.undo.redo.mirror else {
            report.returned = true;
            return Ok(true);
        };
        if !mirror.pending {
            report.returned = true;
            return Ok(true);
        }
        let context = report.undo.redo.input.input.analysis().context();
        let blocksize = context.geometry().cluster_bytes().min(PAGE as u64);
        let copy_bytes = mirror
            .records
            .checked_mul(context.geometry().record_bytes() as u64)
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or_else(|| unsupported("NTFS mirror native u32 copy width"))?;
        let count = copy_bytes / blocksize;
        let count =
            usize::try_from(count).map_err(|_| exhausted("NTFS mirror block inventory width"))?;
        if count > limits.blocks {
            return Err(exhausted("NTFS mirror block ceiling"));
        }
        let size = usize::try_from(blocksize).map_err(|_| exhausted("NTFS mirror block width"))?;
        let retained = count
            .checked_mul(size)
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| exhausted("NTFS mirror byte width"))?;
        if retained > limits.bytes {
            return Err(exhausted("NTFS mirror retained byte ceiling"));
        }
        let primary = mirror.primary / blocksize * blocksize;
        let destination = mirror.mirror / blocksize * blocksize;
        for ordinal in 0..count {
            charge(
                &mut w,
                size.checked_mul(8)
                    .ok_or_else(|| exhausted("NTFS mirror block work"))?,
                r,
            )?;
            let offset = (ordinal as u64)
                .checked_mul(blocksize)
                .ok_or_else(|| unsupported("NTFS mirror block progression"))?;
            let source = primary
                .checked_add(offset)
                .ok_or_else(|| unsupported("NTFS mirror primary progression"))?;
            let destination = destination
                .checked_add(offset)
                .ok_or_else(|| unsupported("NTFS mirror destination progression"))?;
            let lease = r.memory.reserve(
                (size as u64)
                    .checked_mul(4)
                    .ok_or_else(|| exhausted("NTFS mirror block memory"))?,
            )?;
            let block = NtfsLogMirrorBlock {
                source,
                destination,
                original: bytes(size)?,
                source_after: bytes(size)?,
                destination_original: bytes(size)?,
                after: bytes(size)?,
                source_read: false,
                source_ready: false,
                destination_guard_read: false,
                copied: false,
                _lease: lease,
            };
            report.blocks.push(block);
            let index = report.blocks.len() - 1;
            let block = &mut report.blocks[index];
            let read = context.read_native_physical_observed(
                source,
                &mut block.original,
                r,
                &mut block.source_read,
            );
            // The retained block already owns a completed provenance read before any error,
            // cancellation or charged overlay can interrupt its interpretation.
            if block.source_read {
                block.source_after.copy_from_slice(&block.original);
            }
            read?;
            for prior in &report.undo.redo.fragments {
                if prior.written {
                    overlay_block(
                        &mut block.source_after,
                        source,
                        &prior.after,
                        prior.offset,
                        &mut w,
                        r,
                    )?;
                }
            }
            let (previous, current) = report.blocks.split_at_mut(index);
            let block = &mut current[0];
            for prior in previous {
                if prior.copied {
                    overlay_block(
                        &mut block.source_after,
                        source,
                        &prior.after,
                        prior.destination,
                        &mut w,
                        r,
                    )?;
                }
            }
            block.source_ready = true;
            native_file::reject_log_overlap(
                destination,
                size,
                report
                    .undo
                    .redo
                    .capture
                    .iter()
                    .chain(report.undo.steps.iter().map(|step| &step.capture))
                    .flat_map(|capture| capture.ranges()),
                &mut w,
                r,
            )?;
            let read = context.read_native_physical_observed(
                destination,
                &mut block.destination_original,
                r,
                &mut block.destination_guard_read,
            );
            if block.destination_guard_read {
                block.after.copy_from_slice(&block.destination_original);
            }
            read?;
            charge(&mut w, size, r)?;
            block.after.copy_from_slice(&block.source_after);
            block.copied = true;
        }
        report.returned = true;
        if let Some(mirror) = &mut report.undo.redo.mirror {
            mirror.pending = false;
        }
        Ok(true)
    })();
    let done = match result {
        Ok(done) => done,
        Err(error) => {
            report.error = Some(error);
            false
        }
    };
    if let Err(error) = repeat_mirror(&report, &mut w, r) {
        report.error.get_or_insert(error);
    }
    report.complete = done && report.stopping_error().is_none();
    report.work = w.used;
    Ok(report)
}
