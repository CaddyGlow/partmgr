//! Exact native redo entry and source-owned nonresident shadow effects.
use super::*;
mod native_file;
mod undo_analysis;
use crate::fs_ntfs_logfile::client_record::inspect_native_analysis_record;
use crate::fs_ntfs_logfile::native_analysis_context::NativeReadCapture;
pub use undo_analysis::*;
/// Finite native redo observations, shadow bytes, and combined work ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogRedoLimits {
    /// Exact-start physical traversal ceilings; all skipped envelopes are retained.
    pub traversal: NtfsLogPhysicalTraversalLimits,
    /// Exact physical provenance consumed by the new redo traversal.
    pub capture: crate::fs_ntfs_logfile::NtfsLogNativeContextLimits,
    /// Maximum retained physical source/write fragments.
    pub fragments: usize,
    /// Maximum retained original bytes, plus an equal ceiling of shadow bytes.
    pub bytes: usize,
    /// Maximum copied native runtime attribute-header bytes.
    pub runtime_bytes: usize,
    /// Maximum source-derived runtime run entries across all open slots.
    pub runtime_runs: usize,
    /// Maximum retained native FILE cache/preparation entries.
    pub files: usize,
    /// Maximum retained unprotected native FILE bytes.
    pub file_bytes: usize,
    /// Combined earlier analysis, traversal, source effects and final guards.
    pub work: usize,
}
/// One exact physical fragment of a native in-memory write effect.
pub struct NtfsLogRedoFragment {
    lsn: u64,
    offset: u64,
    original: Vec<u8>,
    after: Vec<u8>,
    written: bool,
    _lease: Reservation,
}
impl NtfsLogRedoFragment {
    /// Native record LSN causing this effect.
    pub fn lsn(&self) -> u64 {
        self.lsn
    }
    /// Source-owned physical offset, derived exclusively from sealed native runs.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Exact original physical source bytes before any shadow effects.
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    /// Whether native action would write this fragment (false for observed dirty_vol).
    pub fn is_write(&self) -> bool {
        self.written
    }
    /// Resulting in-memory bytes after all preceding overlapping native effects.
    pub fn after(&self) -> &[u8] {
        &self.after
    }
}
/// Mutable native in-memory target projection, retaining original source separately.
pub struct NtfsLogRuntimeTarget {
    slot: u32,
    reference: u64,
    raw: Vec<u8>,
    runs: Vec<NtfsLogNativeRun>,
    private_run0: bool,
    provisional: bool,
    _raw_lease: Reservation,
    _runs_lease: Reservation,
}
impl NtfsLogRuntimeTarget {
    /// Original allocated source open-slot offset.
    pub fn open_slot_offset(&self) -> u32 {
        self.slot
    }
    /// Original source open-slot FILE reference, without fabricated owner identity.
    pub fn file_reference(&self) -> u64 {
        self.reference
    }
    /// Exact copied native attribute header after modeled in-memory effects.
    pub fn attribute_bytes(&self) -> &[u8] {
        &self.raw
    }
    /// Active source-derived runtime map, without disk allocation authority.
    pub fn runs(&self) -> &[NtfsLogNativeRun] {
        &self.runs
    }
    /// Whether the native active map refers to its private run0.
    pub fn private_run0(&self) -> bool {
        self.private_run0
    }
    /// Whether this remains a source-derived fake-attribute intent.
    pub fn provisional(&self) -> bool {
        self.provisional
    }
}
/// Source-derived native unprotected FILE cache state, without write authority.
pub struct NtfsLogRuntimeFile {
    number: u64,
    cached: bool,
    loaded: bool,
    fixup_mismatch: bool,
    raw: Vec<u8>,
    segments: Vec<(u64, usize, usize, usize)>,
    _lease: Reservation,
    _segments_lease: Reservation,
}
impl NtfsLogRuntimeFile {
    /// Native FILE number derived from the operation virtual byte address.
    pub fn number(&self) -> u64 {
        self.number
    }
    /// Whether a source-loaded OpenAttr inode establishes a cached FILE object.
    pub fn cached(&self) -> bool {
        self.cached
    }
    /// Whether native simple-USA restoration and total validation completed.
    pub fn loaded(&self) -> bool {
        self.loaded
    }
    /// Whether native mi_read admitted mismatched sector tails as dirty.
    pub fn fixup_mismatch(&self) -> bool {
        self.fixup_mismatch
    }
    /// Unprotected in-memory FILE bytes, distinct from protected disk fragments.
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
}
/// Source-owned native mirror state retained until post-undo finalization.
pub struct NtfsLogRuntimeMirror {
    source: NtfsLogNativeTargetEvidence,
    records: u64,
    primary: u64,
    mirror: u64,
    pending: bool,
}
impl NtfsLogRuntimeMirror {
    /// Native mirror record count derived from the source mirror inode size.
    pub fn records(&self) -> u64 {
        self.records
    }
    /// Boot-derived contiguous primary MFT byte address used by native copy.
    pub fn primary_offset(&self) -> u64 {
        self.primary
    }
    /// Boot-derived contiguous mirror byte address used by native copy.
    pub fn mirror_offset(&self) -> u64 {
        self.mirror
    }
    /// Whether successful FILE writes require the native post-undo mirror copy.
    pub fn pending(&self) -> bool {
        self.pending
    }
}
/// Retained exact redo traversal and bounded native source effects; never a writer.
pub struct NtfsLogRedoReport {
    limits: NtfsLogRedoLimits,
    input: NtfsLogDirtyRunReport,
    traversal: Option<NtfsLogPhysicalTraversalReport>,
    fragments: Vec<NtfsLogRedoFragment>,
    capture: Option<NativeReadCapture>,
    runtime: Vec<NtfsLogRuntimeTarget>,
    files: Vec<NtfsLogRuntimeFile>,
    mirror: Option<NtfsLogRuntimeMirror>,
    dirty_volume: bool,
    processed: usize,
    derived: bool,
    error: Option<Error>,
    work: usize,
    _lease: Reservation,
    _runtime_lease: Reservation,
    _files_lease: Reservation,
}
impl NtfsLogRedoReport {
    /// Original dirty mappings, provisional intents and complete source evidence.
    pub fn input(&self) -> &NtfsLogDirtyRunReport {
        &self.input
    }
    /// Actual traversal beginning at native redo LSN, including skipped envelopes.
    pub fn traversal(&self) -> Option<&NtfsLogPhysicalTraversalReport> {
        self.traversal.as_ref()
    }
    /// Physical shadow effects in exact observed native execution order.
    pub fn fragments(&self) -> &[NtfsLogRedoFragment] {
        &self.fragments
    }
    /// Source-owned native runtime target copies in allocated slot order.
    pub fn runtime_targets(&self) -> &[NtfsLogRuntimeTarget] {
        &self.runtime
    }
    /// Retained native FILE cache and preparation observations.
    pub fn runtime_files(&self) -> &[NtfsLogRuntimeFile] {
        &self.files
    }
    /// Source-owned mirror metadata and pending native finalization state.
    pub fn runtime_mirror(&self) -> Option<&NtfsLogRuntimeMirror> {
        self.mirror.as_ref()
    }
    /// Whether a modeled native action reached dirty_vol and continued the scan.
    pub fn dirty_volume_observed(&self) -> bool {
        self.dirty_volume
    }
    /// Native physical envelopes successfully considered before refusal.
    pub fn processed_records(&self) -> usize {
        self.processed
    }
    /// Whether all admitted redo classes and repeated source guards completed.
    pub fn admitted_redo_complete(&self) -> bool {
        self.derived
    }
    /// Original unsupported class, source, cancellation or budget failure.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error
            .as_ref()
            .or_else(|| self.input.stopping_error())
            .or_else(|| self.mirror.as_ref().and_then(|m| m.source.stopping_error()))
            .or_else(|| self.traversal.as_ref().and_then(|t| t.stopping_error()))
    }
    /// Combined prior and current consumed work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Full native active-window qualification remains unavailable.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Shadow effects do not authorize allocation, durable writes or recovery.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn skip(op: u16) -> bool {
    matches!(op, 0 | 1 | 10 | 23..=32)
}
fn bitmap(
    raw: &mut [u8],
    offset: usize,
    bits: usize,
    set: bool,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let end = offset
        .checked_add(bits)
        .filter(|n| *n <= raw.len().saturating_mul(8))
        .ok_or_else(|| unsupported("NTFS native bitmap actual buffer bounds"))?;
    if bits == 0 {
        return Ok(());
    }
    for (byte, value) in raw
        .iter_mut()
        .enumerate()
        .take(end.div_ceil(8))
        .skip(offset / 8)
    {
        charge(w, 1, r)?;
        let low = offset.saturating_sub(byte * 8).min(8);
        let high = end.saturating_sub(byte * 8).min(8);
        let mask = ((0xffu16 >> (8 - high)) & (0xffu16 << low)) as u8;
        if set {
            *value |= mask;
        } else {
            *value &= !mask;
        }
    }
    Ok(())
}
fn allocated_bytes(i: u64, cluster: u64) -> Result<u64> {
    i.checked_sub(1)
        .and_then(|n| n.checked_mul(cluster))
        .filter(|n| *n <= u64::from(u32::MAX))
        .ok_or_else(|| unsupported("NTFS native redo u32 allocated-byte truncation"))
}
fn bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| exhausted("NTFS redo bytes allocation"))?;
    if v.capacity() > n {
        return Err(exhausted("NTFS redo bytes capacity"));
    }
    v.resize(n, 0);
    Ok(v)
}
fn repeat(report: &NtfsLogRedoReport, w: &mut Work, r: &Resources) -> Result<()> {
    guards(&report.input.input, w, r)?;
    let context = report.input.input.analysis().context();
    for fragment in &report.fragments {
        charge(
            w,
            fragment
                .original
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| exhausted("NTFS redo guard work"))?,
            r,
        )?;
        let _lease = r.memory.reserve(fragment.original.len() as u64)?;
        let mut raw = bytes(fragment.original.len())?;
        context.read_native_physical(fragment.offset, &mut raw, r)?;
        if raw != fragment.original {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS redo consumed physical source changed",
            ));
        }
    }
    if let Some(mirror) = &report.mirror {
        charge(w, mirror.source.physical_work()?, r)?;
        mirror.source.check_source(r)?;
    }
    if let Some(capture) = &report.capture {
        charge(w, capture.work()?, r)?;
        capture.check(context, r)?;
    }
    // New exact redo record restart/page observations are independent of the
    // earlier analysis traversal and must remain bound through effect reads.
    if let Some(traversal) = &report.traversal {
        charge(w, PAGE, r)?;
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS redo record guard capacity"));
        }
        for step in traversal.steps() {
            for (offset, expected) in step
                .record()
                .restart()
                .copies()
                .iter()
                .filter(|c| c.read_complete())
                .map(|c| (c.offset(), c.raw()))
                .chain(
                    step.record()
                        .pages()
                        .iter()
                        .filter(|c| c.read_complete())
                        .map(|c| (c.offset(), c.raw())),
                )
            {
                charge(w, 2 * PAGE, r)?;
                traversal
                    .overlay
                    .read_exact_at(offset, &mut raw)
                    .map_err(|e| Error::io("NTFS redo exact record guard", e))?;
                r.cancellation.check()?;
                if raw != expected {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "NTFS redo exact record changed",
                    ));
                }
            }
        }
    }
    r.cancellation.check()
}
/// Derive exact native redo observations and admitted nonresident byte effects.
/// Other actual native mutation classes stop explicitly; undo and durability remain open.
pub fn inspect_logfile_native_redo(
    input: NtfsLogDirtyRunReport,
    limits: NtfsLogRedoLimits,
    r: &Resources,
) -> Result<NtfsLogRedoReport> {
    r.cancellation.check()?;
    let (fragments, lease) = vector(limits.fragments, r)?;
    let (runtime, runtime_lease) = vector(input.input.targets().len(), r)?;
    let (files, files_lease) = vector(limits.files, r)?;
    let mut w = Work {
        used: input.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogRedoReport {
        limits,
        input,
        traversal: None,
        fragments,
        capture: None,
        runtime,
        files,
        mirror: None,
        dirty_volume: false,
        processed: 0,
        derived: false,
        error: None,
        work: w.used,
        _lease: lease,
        _runtime_lease: runtime_lease,
        _files_lease: files_lease,
    };
    let result = (|| -> Result<bool> {
        repeat(&report, &mut w, r)?;
        if !report.input.dirty_runs_complete() {
            return Ok(false);
        }
        let mut raw_total = 0usize;
        let mut run_total = 0usize;
        for (i, evidence) in report.input.input.targets().iter().enumerate() {
            charge(&mut w, 1, r)?;
            let raw = if let Some(winner) = evidence.selected_occurrence() {
                &evidence
                    .attributes()
                    .ok_or_else(|| unsupported("NTFS runtime original attributes unavailable"))?
                    [winner]
                    .raw[..]
            } else {
                evidence
                    .provisional_attribute()
                    .ok_or_else(|| unsupported("NTFS runtime provisional header unavailable"))?
            };
            raw_total = raw_total
                .checked_add(raw.len())
                .filter(|n| *n <= limits.runtime_bytes)
                .ok_or_else(|| exhausted("NTFS runtime attribute byte ceiling"))?;
            let source_runs = report.input.targets()[i].runs();
            run_total = run_total
                .checked_add(source_runs.len())
                .filter(|n| *n <= limits.runtime_runs)
                .ok_or_else(|| exhausted("NTFS runtime run ceiling"))?;
            charge(
                &mut w,
                raw.len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(source_runs.len()))
                    .ok_or_else(|| exhausted("NTFS runtime copy work"))?,
                r,
            )?;
            let raw_lease = r.memory.reserve(raw.len() as u64)?;
            let mut copied = bytes(raw.len())?;
            copied.copy_from_slice(raw);
            if let Some(sizes) = report.input.targets()[i].nonresident_sizes() {
                charge(&mut w, 24, r)?;
                for (offset, size) in [40usize, 48, 56].into_iter().zip(sizes) {
                    copied[offset..offset + 8].copy_from_slice(&size.to_le_bytes());
                }
            }
            let (mut runs, runs_lease) = vector(source_runs.len(), r)?;
            runs.extend_from_slice(source_runs);
            let shared = (!evidence.is_directory()
                && evidence.attribute_type() == 0x80
                && evidence.name().is_empty())
                || (evidence.is_directory()
                    && evidence.attribute_type() == 0xa0
                    && evidence.name() == [36u16, 73, 51, 48]);
            let private_run0 = evidence.selected_occurrence().is_none() || !shared;
            report.runtime.push(NtfsLogRuntimeTarget {
                slot: evidence.open_slot_offset(),
                reference: evidence.file_reference(),
                raw: copied,
                runs,
                private_run0,
                provisional: evidence.selected_occurrence().is_none(),
                _raw_lease: raw_lease,
                _runs_lease: runs_lease,
            });
        }
        let dirty = report.input.input.analysis().dirty_table_bytes();
        if dirty.is_empty() || le16(dirty, 4) == 0 {
            return Ok(true);
        }
        let lsn = report
            .input
            .redo_lsn()
            .ok_or_else(|| unsupported("NTFS native redo seed unavailable"))?;
        let overlay = report
            .input
            .input
            .analysis()
            .replay()
            .checkpoint()
            .traversal()
            .overlay
            .clone();
        charge(&mut w, limits.capture.work, r)?;
        let mut traversal_limits = limits.traversal;
        traversal_limits.work = traversal_limits.work.min(
            limits
                .work
                .checked_sub(w.used)
                .ok_or_else(|| exhausted("NTFS redo traversal work"))?,
        );
        let (query, capture) = report
            .input
            .input
            .analysis()
            .context()
            .capture_native_reads(limits.capture, r, || {
                inspect_physical_traversal_from(overlay, traversal_limits, lsn, r)
            })?;
        report.capture = Some(capture);
        let traversal = query?;
        charge(&mut w, traversal.work(), r)?;
        let complete = traversal.physical_traversal_complete();
        report.traversal = Some(traversal);
        if !complete {
            return Ok(false);
        }
        let steps = report
            .traversal
            .as_ref()
            .expect("retained traversal")
            .steps();
        for (index, step) in steps.iter().enumerate() {
            charge(&mut w, 1, r)?;
            let record = step.record();
            let header = record
                .header()
                .ok_or_else(|| unsupported("NTFS redo exact header unavailable"))?;
            if header.record_type != 1 {
                report.processed += 1;
                continue;
            }
            if step.disposition() != Some(NtfsLogPhysicalDisposition::ClientRecord) {
                if index == 0 {
                    return Err(unsupported(
                        "NTFS native initial redo foreign client invariant",
                    ));
                }
                report.processed += 1;
                continue;
            }
            let client = inspect_native_analysis_record(record)?;
            if client.lcn_count == 0 {
                report.processed += 1;
                continue;
            }
            let target = usize::from(client.target_attribute);
            let vcn = client.target_vcn as u64;
            if vcn >= (1u64 << 32) {
                return Err(unsupported(
                    "NTFS native redo lookup cluster-width configuration",
                ));
            }
            let mut page = None;
            for i in 0..slots(dirty) {
                charge(&mut w, 1, r)?;
                if !allocated(dirty, i) {
                    continue;
                }
                let at = offset(dirty, i);
                let first = le64(dirty, at + 16);
                if le32(dirty, at + 4) as usize == target
                    && vcn >= first
                    && vcn - first < u64::from(le32(dirty, at + 12))
                {
                    page = Some(at);
                    break;
                }
            }
            let Some(at) = page else {
                report.processed += 1;
                continue;
            };
            if header.this_lsn < le64(dirty, at + 24) {
                report.processed += 1;
                continue;
            }
            let mut target_index = None;
            for (i, t) in report.input.targets().iter().enumerate() {
                charge(&mut w, 1, r)?;
                if t.open_slot_offset() as usize == target {
                    target_index = Some(i);
                    break;
                }
            }
            let target_index = target_index
                .ok_or_else(|| unsupported("NTFS native redo allocated target unavailable"))?;
            let map = &report.runtime[target_index].runs;
            if mapped_lcn(map, vcn, &mut w, r)?.is_none() {
                report.processed += 1;
                continue;
            }
            let geometry = report.input.input.analysis().context().geometry();
            let cluster = geometry.cluster_bytes();
            let raw = client.raw();
            let origin = usize::from(le16(raw, 4));
            let mut length = usize::from(le16(raw, 6));
            let mut saved = length;
            let base = vcn - le64(dirty, at + 16);
            let count = u64::from(client.lcn_count);
            if base
                .checked_add(count)
                .is_none_or(|end| end > u64::from(le32(dirty, at + 12)))
            {
                return Err(unsupported("NTFS native redo trailing LCN source bounds"));
            }
            let voff = u64::from(client.record_offset)
                + u64::from(client.attribute_offset)
                + (u64::from(client.cluster_offset) << 9);
            for i in (1..=count).rev() {
                charge(&mut w, 1, r)?;
                if le64(dirty, at + 32 + (base + i - 1) as usize * 8) != 0 {
                    break;
                }
                if saved == 0 {
                    saved = 1;
                }
                let allocated = allocated_bytes(i, cluster)?;
                if voff >= allocated {
                    length = 0;
                } else if voff + length as u64 > allocated {
                    length = (allocated - voff) as usize;
                }
            }
            if length == 0 && saved != 0 || skip(client.redo_operation) {
                report.processed += 1;
                continue;
            }
            if matches!(client.redo_operation, 2 | 3) {
                let vbo = vcn
                    .checked_mul(cluster)
                    .and_then(|n| n.checked_add(u64::from(client.cluster_offset) << 9))
                    .ok_or_else(|| unsupported("NTFS native FILE virtual byte overflow"))?;
                let number = vbo / geometry.record_bytes() as u64;
                if number > u64::from(u32::MAX) {
                    return Err(unsupported("NTFS native FILE cluster-width configuration"));
                }
                let mut cached = false;
                for target in &report.runtime {
                    charge(&mut w, 1, r)?;
                    cached |= target.reference & 0x0000_ffff_ffff_ffff == number;
                }
                if !cached {
                    return Err(unsupported(
                        "NTFS native FILE cold versus preloaded inode origin unresolved",
                    ));
                }
                if report.mirror.is_none() {
                    let context = report.input.input.analysis().context();
                    let streams = context.native_stream_limits();
                    let envelope = limits
                        .capture
                        .work
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(streams.work.checked_mul(2)?))
                        .ok_or_else(|| exhausted("NTFS mirror source work"))?;
                    charge(&mut w, envelope, r)?;
                    let source = context.inspect_target(
                        (0, (1u64 << 48) | 1, 0x80),
                        &[],
                        streams,
                        limits.capture,
                        r,
                    )?;
                    report.mirror = Some(NtfsLogRuntimeMirror {
                        source,
                        records: 0,
                        primary: 0,
                        mirror: 0,
                        pending: false,
                    });
                    let mirror = report.mirror.as_mut().expect("retained mirror observation");
                    if mirror.source.stopping_error().is_some() {
                        return Ok(false);
                    }
                    let winner = mirror
                        .source
                        .selected_occurrence()
                        .ok_or_else(|| unsupported("NTFS native MFTMirr DATA missing"))?;
                    let attribute = &mirror
                        .source
                        .attributes()
                        .ok_or_else(|| unsupported("NTFS native MFTMirr attributes missing"))?
                        [winner];
                    charge(&mut w, 64, r)?;
                    if !attribute.nonresident || attribute.raw.len() < 64 || attribute.flags != 0 {
                        return Err(unsupported(
                            "NTFS native MFTMirr ordinary nonresident DATA required",
                        ));
                    }
                    let size = le64(&attribute.raw, 48);
                    let rounded = size
                        .checked_add(cluster - 1)
                        .map(|n| n & !(cluster - 1))
                        .ok_or_else(|| unsupported("NTFS native MFTMirr size rounding overflow"))?;
                    mirror.records = rounded / geometry.record_bytes() as u64;
                    let bytes = mirror
                        .records
                        .checked_mul(geometry.record_bytes() as u64)
                        .filter(|n| *n <= u64::from(u32::MAX))
                        .ok_or_else(|| unsupported("NTFS native MFTMirr u32 copy width"))?;
                    (mirror.primary, mirror.mirror) = context.native_mirror_physical()?;
                    if mirror
                        .primary
                        .checked_add(bytes)
                        .is_none_or(|n| n > geometry.volume_bytes())
                        || mirror
                            .mirror
                            .checked_add(bytes)
                            .is_none_or(|n| n > geometry.volume_bytes())
                    {
                        return Err(unsupported("NTFS native MFTMirr physical copy range"));
                    }
                }
                let mutation = if client.redo_operation == 2 {
                    let data = raw
                        .get(origin..origin + length)
                        .ok_or_else(|| unsupported("NTFS initialize redo payload range"))?;
                    native_file::Mutation::Initialize {
                        offset: usize::from(client.record_offset),
                        data,
                    }
                } else {
                    native_file::Mutation::Deallocate
                };
                let written = native_file::apply(
                    report.input.input.analysis().context(),
                    report.capture.iter(),
                    &mut report.files,
                    &mut report.fragments,
                    vbo,
                    cached,
                    mutation,
                    &mut report.dirty_volume,
                    header.this_lsn,
                    Some(header.this_lsn),
                    limits,
                    &mut w,
                    r,
                )?;
                if written && let Some(mirror) = &mut report.mirror {
                    mirror.pending |= number < mirror.records;
                }
                report.processed += 1;
                continue;
            }
            if !matches!(client.redo_operation, 8 | 21 | 22) {
                return Err(unsupported(
                    "NTFS native redo operation effects not yet implemented",
                ));
            }
            apply_nonresident(
                report.input.input.analysis().context(),
                &report.runtime[target_index],
                &mut report.fragments,
                &mut report.dirty_volume,
                report.capture.iter(),
                &client,
                client.redo_operation,
                header.this_lsn,
                origin,
                length,
                limits,
                &mut w,
                r,
            )?;
            report.processed += 1;
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
    if let Err(error) = repeat(&report, &mut w, r) {
        report.error.get_or_insert(error);
    }
    report.derived = done && report.stopping_error().is_none();
    report.work = w.used;
    Ok(report)
}

#[expect(
    clippy::too_many_arguments,
    reason = "shared native redo/undo interpreter keeps source, effects, captures and bounds explicit"
)]
fn apply_nonresident<'a>(
    context: &NtfsLogNativeAnalysisContext,
    runtime: &NtfsLogRuntimeTarget,
    fragments: &mut Vec<NtfsLogRedoFragment>,
    dirty_volume: &mut bool,
    captures: impl Iterator<Item = &'a NativeReadCapture> + Clone,
    client: &crate::fs_ntfs_logfile::NtfsLogClientRecord<'_>,
    operation: u16,
    lsn: u64,
    origin: usize,
    length: usize,
    limits: NtfsLogRedoLimits,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let raw = client.raw();
    let count = u64::from(client.lcn_count);
    let cluster = context.geometry().cluster_bytes();
    let vcn = u64::try_from(client.target_vcn)
        .map_err(|_| unsupported("NTFS native negative nonresident VCN"))?;
    let map = &runtime.runs;
    let mut retained = 0usize;
    for fragment in fragments.iter() {
        charge(w, 1, r)?;
        retained = retained
            .checked_add(fragment.original.len())
            .ok_or_else(|| exhausted("NTFS combined native fragment bytes"))?;
    }
    if le32(&runtime.raw, 0) == 0xa0 {
        return Err(unsupported(
            "NTFS native index buffer USA effect not yet implemented",
        ));
    }
    let data = raw
        .get(
            origin
                ..origin
                    .checked_add(if operation == 8 { length } else { 8 })
                    .ok_or_else(|| unsupported("NTFS redo data overflow"))?,
        )
        .ok_or_else(|| unsupported("NTFS native redo data actual payload bounds"))?;
    let cbo = u64::from(client.cluster_offset) << 9;
    let roff = usize::from(client.record_offset);
    let lco = count
        .checked_mul(cluster)
        .ok_or_else(|| unsupported("NTFS redo transfer overflow"))?;
    if cbo > lco {
        return Err(unsupported(
            "NTFS native buffer transfer unsigned underflow",
        ));
    }
    let size = if operation != 8 || length == 0 {
        usize::try_from(lco - cbo).map_err(|_| unsupported("NTFS redo buffer width"))?
    } else {
        length
    };
    let size = size
        .checked_add(roff)
        .ok_or_else(|| unsupported("NTFS redo buffer overflow"))?;
    if size > u32::MAX as usize {
        return Err(unsupported("NTFS native redo u32 buffer-size overflow"));
    }
    retained
        .checked_add(size)
        .filter(|n| *n <= limits.bytes)
        .ok_or_else(|| exhausted("NTFS redo retained bytes"))?;
    charge(
        w,
        size.checked_mul(8)
            .ok_or_else(|| exhausted("NTFS redo buffer work"))?,
        r,
    )?;
    let _buffer_lease = r.memory.reserve(
        (size as u64)
            .checked_mul(2)
            .ok_or_else(|| exhausted("NTFS redo buffer memory"))?,
    )?;
    let mut original = bytes(size)?;
    let mut after = bytes(size)?;
    let mut cursor = vcn
        .checked_mul(cluster)
        .and_then(|n| n.checked_add(cbo))
        .ok_or_else(|| unsupported("NTFS redo virtual buffer overflow"))?;
    let mut done = 0usize;
    let mut segments = Vec::new();
    // Fragment metadata is bounded by the global fragment ceiling.
    let segment_bytes = limits
        .fragments
        .checked_mul(core::mem::size_of::<(u64, usize, usize, usize)>())
        .ok_or_else(|| exhausted("NTFS redo segments"))?;
    let _segments_lease = r.memory.reserve(segment_bytes as u64)?;
    segments
        .try_reserve_exact(limits.fragments)
        .map_err(|_| exhausted("NTFS redo segments allocation"))?;
    if segments.capacity() > limits.fragments {
        return Err(exhausted("NTFS redo segments capacity"));
    }
    while done < size {
        let current = cursor / cluster;
        if current >= (1u64 << 32) {
            return Err(unsupported("NTFS native redo cluster-width configuration"));
        }
        let inside = cursor % cluster;
        let mut found = None;
        for run in map {
            charge(w, 1, r)?;
            if current >= run.vcn && current - run.vcn < run.clusters {
                found = Some(*run);
                break;
            }
        }
        let run =
            found.ok_or_else(|| unsupported("NTFS native redo read missing contiguous run"))?;
        let physical = run
            .lcn
            .ok_or_else(|| unsupported("NTFS native redo read sparse run"))?
            .checked_add(current - run.vcn)
            .and_then(|n| n.checked_mul(cluster))
            .and_then(|n| n.checked_add(inside))
            .ok_or_else(|| unsupported("NTFS redo physical overflow"))?;
        let available = (run.clusters - (current - run.vcn))
            .checked_mul(cluster)
            .and_then(|n| n.checked_sub(inside))
            .ok_or_else(|| unsupported("NTFS redo physical run extent"))?;
        let n = (size - done).min(usize::try_from(available).unwrap_or(usize::MAX));
        if n == 0 || fragments.len() >= limits.fragments {
            return Err(exhausted("NTFS redo fragment ceiling"));
        }
        for capture in captures.clone() {
            for (query_offset, query_bytes) in capture.ranges() {
                charge(w, 1, r)?;
                if physical < query_offset + query_bytes as u64
                    && query_offset < physical + n as u64
                {
                    return Err(unsupported(
                        "NTFS redo effect overlaps exact log query physical source; shadow log reader required",
                    ));
                }
            }
        }
        charge(
            w,
            n.checked_mul(4)
                .ok_or_else(|| exhausted("NTFS redo retained fragment work"))?,
            r,
        )?;
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(2)
                .ok_or_else(|| exhausted("NTFS redo retained fragment memory"))?,
        )?;
        let mut source_fragment = bytes(n)?;
        let mut shadow_fragment = bytes(n)?;
        let mut read_complete = false;
        let read = context.read_native_physical_observed(
            physical,
            &mut source_fragment,
            r,
            &mut read_complete,
        );
        if !read_complete {
            read?;
            return Err(unsupported(
                "NTFS native physical read completion unavailable",
            ));
        }
        // No charged/cancellable operation may precede publication of a full read.
        shadow_fragment.copy_from_slice(&source_fragment);
        let fragment = fragments.len();
        fragments.push(NtfsLogRedoFragment {
            lsn,
            offset: physical,
            original: source_fragment,
            after: shadow_fragment,
            written: false,
            _lease: lease,
        });
        read?;
        original[done..done + n].copy_from_slice(&fragments[fragment].original);
        after[done..done + n].copy_from_slice(&original[done..done + n]);
        for prior_index in 0..fragment {
            charge(w, 1, r)?;
            let prior = &fragments[prior_index];
            let start = physical.max(prior.offset);
            let end = (physical + n as u64).min(prior.offset + prior.after.len() as u64);
            if start < end {
                let count = (end - start) as usize;
                charge(w, count, r)?;
                after[done + (start - physical) as usize..done + (end - physical) as usize]
                    .copy_from_slice(
                        &prior.after
                            [(start - prior.offset) as usize..(end - prior.offset) as usize],
                    );
                fragments[fragment].after[(start - physical) as usize..(end - physical) as usize]
                    .copy_from_slice(
                        &after
                            [done + (start - physical) as usize..done + (end - physical) as usize],
                    );
            }
        }
        segments.push((physical, done, n, fragment));
        done += n;
        cursor = cursor
            .checked_add(n as u64)
            .ok_or_else(|| unsupported("NTFS redo virtual progression"))?;
    }
    let mut written = true;
    if operation == 8
        && cbo
            .checked_add(roff as u64)
            .and_then(|n| n.checked_add(length as u64))
            .is_none_or(|n| n > lco)
    {
        *dirty_volume = true;
        written = false;
    }
    if operation == 8 {
        if written {
            after[roff..roff + length].copy_from_slice(data);
        }
    } else {
        let off = u64::from(le32(data, 0));
        let bits = u64::from(le32(data, 4));
        let first = off
            .checked_add(7)
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or_else(|| unsupported("NTFS native bitmap u32 first boundary"))?
            / 8;
        let last = off
            .checked_add(bits)
            .and_then(|n| n.checked_add(7))
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or_else(|| unsupported("NTFS native bitmap u32 last boundary"))?
            / 8;
        if cbo + first > lco || cbo + last > lco {
            *dirty_volume = true;
            written = false;
        }
        if written {
            bitmap(
                &mut after[roff..],
                off as usize,
                bits as usize,
                operation == 21,
                w,
                r,
            )?;
        }
    }
    for (_physical, start, n, index) in segments {
        charge(w, n, r)?;
        fragments[index]
            .after
            .copy_from_slice(&after[start..start + n]);
        fragments[index].written = written;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_trailing_zero_allocation_width_is_checked_before_comparison() {
        assert_eq!(
            allocated_bytes(2, u64::from(u32::MAX)).unwrap(),
            u64::from(u32::MAX)
        );
        assert_eq!(
            allocated_bytes(2, 1u64 << 32).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            allocated_bytes(3, u64::MAX).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }
}
