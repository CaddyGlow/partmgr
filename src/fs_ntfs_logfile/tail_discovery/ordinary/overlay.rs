//! Sealed read-only overlay decisions from actual ordinary discovery.
use super::*;
/// Overlay creation and repeat-guard ceilings, combined with discovery work.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogOverlayLimits {
    /// Actual source-owned ordinary scanner ceilings.
    pub discovery: NtfsLogOrdinaryDiscoveryLimits,
    /// Maximum retained replacement pages.
    pub pages: usize,
    /// Maximum retained normalized and original-target bytes plus vectors.
    pub retained_bytes: usize,
    /// Combined scan, normalization and final byte-guard work.
    pub work: usize,
}
/// Immutable one-page overlay and its exact native winner provenance.
pub struct NtfsLogOverlayPage {
    target: u64,
    source_index: usize,
    original: Vec<u8>,
    normalized: Vec<u8>,
    partial_consumption: NtfsLogPartialConsumption,
    _lease: Reservation,
}
impl NtfsLogOverlayPage {
    /// Original ordinary destination; never an on-disk mutation instruction.
    pub fn target(&self) -> u64 {
        self.target
    }
    /// Exact selected physical candidate index in discovery.tail_report().
    pub fn source_candidate_index(&self) -> usize {
        self.source_index
    }
    /// Original raw ordinary home bytes.
    pub fn original_target_raw(&self) -> &[u8] {
        &self.original
    }
    /// Exact native partial-count comparison for this selected winner.
    pub fn partial_consumption(&self) -> &NtfsLogPartialConsumption {
        &self.partial_consumption
    }
    /// Native-normalized protected bytes, suitable only for this read-only view.
    pub fn normalized_raw(&self) -> &[u8] {
        &self.normalized
    }
}
/// Sealed same-source view; construction requires a successfully guarded boundary.
/// No caller supplied page mappings, arbitrary bytes or winner indices are admitted.
pub struct NtfsLogReadOnlyOverlay {
    source: Arc<dyn ReadAt>,
    discovery: NtfsLogOrdinaryDiscoveryReport,
    pages: Vec<NtfsLogOverlayPage>,
    work: usize,
    partial_residual: NtfsLogPartialResidual,
    _vectors: Reservation,
}
impl NtfsLogReadOnlyOverlay {
    /// Entire original discovery, including raw/rejected candidates and probes.
    pub fn discovery(&self) -> &NtfsLogOrdinaryDiscoveryReport {
        &self.discovery
    }
    /// Source-owned typed replacements in native transfer order, never LSN sorting.
    pub fn pages(&self) -> &[NtfsLogOverlayPage] {
        &self.pages
    }
    /// Native partial-transfer remainder; never a cleanup or erasure plan.
    pub fn partial_residual(&self) -> &NtfsLogPartialResidual {
        &self.partial_residual
    }
    /// Actual combined work charged through final construction guards.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: numerical ordering and source semantics are not native proof.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: this view never performs transaction analysis/replay.
    pub fn recovery_complete(&self) -> bool {
        false
    }
    /// Repeat every original restart/candidate/ordinary read against the same source.
    /// Caller keeps the source immutable for all subsequent reads.
    pub fn check_source(&self, work_limit: usize, r: &Resources) -> Result<usize> {
        let mut work = Work {
            used: 0,
            maximum: work_limit,
        };
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS overlay guard capacity"));
        }
        let originals = self
            .discovery
            .tail
            .seed
            .selection()
            .restart()
            .copies()
            .iter()
            .map(|c| (c.offset(), c.raw()))
            .chain(
                self.discovery
                    .tail
                    .candidates
                    .iter()
                    .map(|c| (c.source_offset, c.raw.as_slice())),
            )
            .chain(
                self.discovery
                    .pages
                    .iter()
                    .map(|c| (c.offset, c.raw.as_slice())),
            );
        for (offset, want) in originals {
            charge(&mut work, 2 * PAGE, r)?;
            self.source
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS overlay source guard read", e))?;
            r.cancellation.check()?;
            if raw != want {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS overlay original source bytes changed",
                ));
            }
        }
        r.cancellation.check()?;
        if self.source.len()
            != self
                .discovery
                .tail
                .seed
                .selection()
                .restart()
                .source_bytes()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS overlay source length changed",
            ));
        }
        r.cancellation.check()?;
        Ok(work.used)
    }
}
impl ReadAt for NtfsLogReadOnlyOverlay {
    fn len(&self) -> u64 {
        self.discovery
            .tail
            .seed
            .selection()
            .restart()
            .source_bytes()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or(crate::io::ErrorKind::InvalidInput)?;
        if end > self.len() {
            return Err(crate::io::ErrorKind::UnexpectedEof.into());
        }
        let mut at = offset;
        let mut consumed = 0usize;
        while consumed < out.len() {
            let page = at / PAGE as u64 * PAGE as u64;
            let inside = (at - page) as usize;
            let n = (PAGE - inside).min(out.len() - consumed);
            if let Some(replacement) = self.pages.iter().find(|p| p.target == page) {
                out[consumed..consumed + n]
                    .copy_from_slice(&replacement.normalized[inside..inside + n]);
            } else {
                self.source
                    .read_exact_at(at, &mut out[consumed..consumed + n])?;
            }
            at += n as u64;
            consumed += n;
        }
        Ok(())
    }
}
fn normalized(
    candidate: &NtfsLogTailCandidate,
    version: (u16, u16),
    data_offset: u16,
    work: &mut Work,
    r: &Resources,
) -> Result<Vec<u8>> {
    charge(work, 2 * PAGE, r)?;
    let mut raw = page_buffer()?;
    if raw.capacity() > PAGE {
        return Err(exhausted("NTFS overlay normalized capacity"));
    }
    raw.copy_from_slice(&candidate.raw);
    let usa = usize::from(le16(&raw, 4));
    let count = usize::from(le16(&raw, 6));
    if count != 9
        || usa < 8
        || !usa.is_multiple_of(2)
        || usa + 2 * count > usize::from(data_offset)
        || usa + 2 * count > 512
        || (version == (2, 0) && usa + 2 * count > 60)
    {
        return Err(unsupported("NTFS overlay USA profile"));
    }
    let marker = le16(&raw, usa);
    for sector in 1..count {
        charge(work, 1, r)?;
        let at = sector * 512 - 2;
        if le16(&raw, at) != marker {
            return Err(invalid("NTFS overlay candidate torn USA"));
        }
        let saved = [raw[usa + 2 * sector], raw[usa + 2 * sector + 1]];
        raw[at..at + 2].copy_from_slice(&saved);
    }
    if version == (1, 1) {
        raw[8..16].copy_from_slice(&candidate.header.unwrap().last_end_lsn.to_le_bytes());
    } else {
        raw[60..64].fill(0);
    }
    raw[20..22].copy_from_slice(&1u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1u16.to_le_bytes());
    // Native ntfs_fix_pre_write: advance marker, reset at0x7fff, then save/replace trailers.
    let marker = if marker >= 0x7fff { 1 } else { marker + 1 };
    raw[usa..usa + 2].copy_from_slice(&marker.to_le_bytes());
    for sector in 1..count {
        charge(work, 1, r)?;
        let at = sector * 512 - 2;
        let saved = [raw[at], raw[at + 1]];
        raw[usa + 2 * sector..usa + 2 * sector + 2].copy_from_slice(&saved);
        raw[at..at + 2].copy_from_slice(&marker.to_le_bytes());
    }
    Ok(raw)
}
/// Build only actual native discovery replacements from a guarded structural
/// boundary. This does not choose an active checkpoint or establish replayability.
pub fn inspect_logfile_read_only_overlay(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogOverlayLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsLogReadOnlyOverlay> {
    let mut dl = limits.discovery;
    dl.work = dl.work.min(limits.work);
    let discovery = inspect_logfile_ordinary_discovery(source.clone(), dl, ordering, r)?;
    if discovery.stopping_error().is_some()
        || discovery.stop != NtfsLogOrdinaryStop::BoundaryObserved
    {
        return Err(unsupported(
            "NTFS overlay requires guarded observed boundary",
        ));
    }
    let area = *discovery
        .tail
        .seed
        .selection()
        .selected_context()
        .ok_or_else(|| unsupported("NTFS overlay restart context missing"))?;
    let maximum = discovery.tail.chain.len().max(1);
    if maximum > limits.pages {
        return Err(exhausted("NTFS overlay page ceiling"));
    }
    let vectorbytes = maximum
        .checked_mul(core::mem::size_of::<NtfsLogOverlayPage>())
        .ok_or_else(|| exhausted("NTFS overlay vector overflow"))?;
    if vectorbytes > limits.retained_bytes {
        return Err(exhausted("NTFS overlay retained ceiling"));
    }
    let vectors = r.memory.reserve(vectorbytes as u64)?;
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(maximum)
        .map_err(|_| exhausted("NTFS overlay vector allocation"))?;
    if pages.capacity() > maximum {
        return Err(exhausted("NTFS overlay vector capacity"));
    }
    let mut work = Work {
        used: discovery.work,
        maximum: limits.work,
    };
    let start = discovery
        .replacement_start
        .map(|target| {
            discovery
                .tail
                .chain
                .iter()
                .position(|i| discovery.tail.candidates[*i].target == Some(target))
                .ok_or_else(|| invalid("NTFS overlay replacement start provenance"))
        })
        .transpose()?;
    let count = if let Some(start) = start {
        discovery
            .tail
            .chain
            .len()
            .checked_sub(start)
            .and_then(|n| n.checked_sub(usize::from(discovery.boundary_tail.is_none())))
            .ok_or_else(|| invalid("NTFS overlay native replacement count"))?
    } else {
        usize::from(discovery.boundary_tail.is_some())
    };
    let partial = discovery
        .partial_transfer()
        .ok_or_else(|| unsupported("NTFS overlay partial-transfer trace missing"))?;
    if !partial.complete_native_branch() {
        return Err(unsupported("NTFS overlay partial native branch incomplete"));
    }
    let mut residual_start = u32::try_from(partial.original_start())
        .map_err(|_| unsupported("NTFS partial native offset width"))?;
    let mut residual_count = partial.pre_overlay_count();
    for position in 0..count {
        let source_index = if let Some(start) = start {
            discovery.tail.chain[start + position]
        } else {
            discovery.boundary_tail.unwrap()
        };
        let candidate = &discovery.tail.candidates[source_index];
        let target = candidate
            .target
            .ok_or_else(|| invalid("NTFS overlay target absent"))?;
        if pages
            .iter()
            .any(|p: &NtfsLogOverlayPage| p.target == target)
        {
            return Err(invalid("NTFS overlay duplicate target"));
        }
        let bytes = vectorbytes
            .checked_add(
                (pages.len() + 1)
                    .checked_mul(2 * PAGE)
                    .ok_or_else(|| exhausted("NTFS overlay retained overflow"))?,
            )
            .ok_or_else(|| exhausted("NTFS overlay retained overflow"))?;
        if bytes > limits.retained_bytes {
            return Err(exhausted("NTFS overlay retained ceiling"));
        }
        let lease = r.memory.reserve((2 * PAGE) as u64)?;
        let normalized = normalized(candidate, area.version, area.page_data_offset, &mut work, r)?;
        let observed = discovery
            .pages
            .iter()
            .find(|p| p.offset == target)
            .ok_or_else(|| unsupported("NTFS overlay original target unobserved"))?;
        let mut original = page_buffer()?;
        if original.capacity() > PAGE {
            return Err(exhausted("NTFS overlay original capacity"));
        }
        charge(&mut work, PAGE, r)?;
        original.copy_from_slice(&observed.raw);
        // The native-normalized page must re-enter the actual ordinary page codec.
        pages::frame_header(
            &normalized,
            NtfsLogPageRole::Ordinary,
            area.page_data_offset,
            &mut work,
            r,
        )?;
        charge(&mut work, 1, r)?;
        let partial_consumption = consume_partial(residual_start, residual_count, target)?;
        residual_start = partial_consumption.after_start;
        residual_count = partial_consumption.after_count;
        pages.push(NtfsLogOverlayPage {
            target,
            source_index,
            original,
            normalized,
            partial_consumption,
            _lease: lease,
        });
    }
    let mut overlay = NtfsLogReadOnlyOverlay {
        source,
        discovery,
        pages,
        work: work.used,
        partial_residual: NtfsLogPartialResidual {
            start: residual_start,
            count: residual_count,
        },
        _vectors: vectors,
    };
    let remaining = limits
        .work
        .checked_sub(work.used)
        .ok_or_else(|| exhausted("NTFS overlay work ceiling"))?;
    overlay.work = overlay
        .work
        .checked_add(overlay.check_source(remaining, r)?)
        .ok_or_else(|| exhausted("NTFS overlay work overflow"))?;
    Ok(overlay)
}

mod successor;
pub use successor::*;

/// Source-owned native comparison and optional decrement for one overlay winner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogPartialConsumption {
    before_start: u32,
    before_count: u32,
    consumed: bool,
    after_start: u32,
    after_count: u32,
}
impl NtfsLogPartialConsumption {
    /// Native second_off before this winner comparison.
    pub fn before_start(&self) -> u64 {
        u64::from(self.before_start)
    }
    /// Partial count before this winner comparison.
    pub fn before_count(&self) -> u32 {
        self.before_count
    }
    /// True only if count was positive and winner target exactly equaled second_off.
    pub fn consumed(&self) -> bool {
        self.consumed
    }
    /// Native second_off after a checked increment WITHOUT physical wrap.
    pub fn after_start(&self) -> u64 {
        u64::from(self.after_start)
    }
    /// Partial count after the optional single decrement.
    pub fn after_count(&self) -> u32 {
        self.after_count
    }
}
/// Native residual diagnostic; no residual bytes are read, allocated or erased.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogPartialResidual {
    start: u32,
    count: u32,
}
impl NtfsLogPartialResidual {
    /// Native second_off after exact selected-winner consumption.
    pub fn start(&self) -> u64 {
        u64::from(self.start)
    }
    /// Remaining native partial count.
    pub fn count(&self) -> u32 {
        self.count
    }
    /// Native readonly path would return EROFS for a positive residual.
    pub fn readonly_native_would_refuse(&self) -> bool {
        self.count > 0
    }
}

fn consume_partial(start: u32, count: u32, target: u64) -> Result<NtfsLogPartialConsumption> {
    let consumed = count > 0 && u64::from(start) == target;
    let after_start = if consumed {
        start
            .checked_add(PAGE as u32)
            .ok_or_else(|| unsupported("NTFS partial consumption offset overflow without wrap"))?
    } else {
        start
    };
    Ok(NtfsLogPartialConsumption {
        before_start: start,
        before_count: count,
        consumed,
        after_start,
        after_count: count - u32::from(consumed),
    })
}
#[cfg(test)]
mod partial_consumption_tests {
    use super::*;
    #[test]
    fn adjacent_exact_winners_consume_without_wrap_or_erase() {
        let first = consume_partial(4096, 2, 4096).unwrap();
        assert!(first.consumed());
        assert_eq!((first.after_start(), first.after_count()), (8192, 1));
        let next = consume_partial(first.after_start, first.after_count, 8192).unwrap();
        assert_eq!((next.after_start(), next.after_count()), (12288, 0));
        let wrong = consume_partial(4096, 2, 8192).unwrap();
        assert!(!wrong.consumed());
        assert_eq!((wrong.after_start(), wrong.after_count()), (4096, 2));
        let eof = consume_partial(63 * 4096, 1, 63 * 4096).unwrap();
        assert_eq!(eof.after_start(), 64 * 4096); // NO wrap to first ordinary page.
        assert!(consume_partial(u32::MAX - 4095, 1, u64::from(u32::MAX - 4095)).is_err());
    }
}
