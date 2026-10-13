//! Native tail/fast candidate discovery. No ordinary-page overlay authority.
use super::*;

/// Combined seed plus candidate scan ceilings; no public defaults are widened.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogTailDiscoveryLimits {
    /// Restart selection and declared endpoint observation ceilings.
    pub seed: NtfsLogDiscoverySeedLimits,
    /// Retained physical candidates, including rejected mates.
    pub candidates: usize,
    /// Raw candidates plus retained vector storage, excluding seed reservations.
    pub retained_bytes: usize,
    /// Aggregate seed, read, frame, comparison and final guard work.
    pub work: usize,
}
/// Why native candidate assembly stopped; none establishes an active endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogTailDiscoveryStop {
    /// No selected source-owned seed survived validation.
    SeedUnavailable,
    /// Neither mate passed supported local framing.
    NoUsablePair,
    /// Observed transfer positions, generation, targets or ranks do not continue.
    TransferDiscontinuity,
    /// Equal numeric ranks retain conflicting candidate bytes or identity.
    EqualRankConflict,
    /// All bounded reserved physical pairs were visited; discovery remains incomplete.
    CandidateAreaExhausted,
    /// Ordinary generation/reuse/lookahead validation remains compulsory.
    OrdinaryValidationRequired,
}
/// Retains one original physical candidate, including rejected framing evidence.
pub struct NtfsLogTailCandidate {
    source_offset: u64,
    role: NtfsLogPageRole,
    raw: Vec<u8>,
    header: Option<NtfsLogPageHeader>,
    target: Option<u64>,
    rank: Option<u64>,
    error: Option<Error>,
    _lease: Reservation,
}
impl NtfsLogTailCandidate {
    /// Original physical source slot in the supplied log stream.
    pub fn source_offset(&self) -> u64 {
        self.source_offset
    }
    /// Original reserved-slot role, independent of candidate authority.
    pub fn role(&self) -> NtfsLogPageRole {
        self.role
    }
    /// Original bytes before USA fixups, including rejected evidence.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Locally decoded header when supported framing passed.
    pub fn header(&self) -> Option<&NtfsLogPageHeader> {
        self.header.as_ref()
    }
    /// Locally checked ordinary destination; never overlay authority.
    pub fn target_offset(&self) -> Option<u64> {
        self.target
    }
    /// Numeric Linux base_lsn for fast copies; last_end_lsn for1.1 tails.
    /// Caller excludes sequence rollover, as required by seed selection.
    pub fn numeric_rank(&self) -> Option<u64> {
        self.rank
    }
    /// Original candidate read/framing/semantic failure, if any.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
}
/// Immutable source-owned candidates. Chosen indices are discovery provenance,
/// never permission to replace ordinary pages or iterate/replay records.
pub struct NtfsLogTailDiscoveryReport {
    seed: NtfsLogDiscoverySeedReport,
    candidates: Vec<NtfsLogTailCandidate>,
    chain: Vec<usize>,
    stop: NtfsLogTailDiscoveryStop,
    error: Option<Error>,
    source_error: Option<Error>,
    work: usize,
    _vectors: Reservation,
}
impl NtfsLogTailDiscoveryReport {
    /// Complete selected/rejected restart seed provenance.
    pub fn seed_report(&self) -> &NtfsLogDiscoverySeedReport {
        &self.seed
    }
    /// All observed reserved copies, including rejected mates.
    pub fn candidates(&self) -> &[NtfsLogTailCandidate] {
        &self.candidates
    }
    /// Withheld after any source guard failure; indices reference original slots.
    pub fn candidate_chain(&self) -> &[usize] {
        if self.source_error.is_some() || self.error.is_some() {
            &[]
        } else {
            &self.chain
        }
    }
    /// Explicit discovery boundary or failure classification.
    pub fn stop(&self) -> NtfsLogTailDiscoveryStop {
        self.stop
    }
    /// Source, seed, resource or I/O stopping error, if any.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.seed
            .stopping_error()
            .or(self.error.as_ref())
            .or(self.source_error.as_ref())
    }
    /// Actual charged seed, scan and final guard work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: ordinary-page discovery remains required.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: no transaction analysis or replay authority.
    pub fn recovery_complete(&self) -> bool {
        false
    }
    /// Explicitly reject active-window authority from these candidates.
    pub fn require_active_window(&self) -> Result<()> {
        Err(unsupported(
            "NTFS ordinary generation/reuse/lookahead discovery not established",
        ))
    }
}
fn charge(work: &mut Work, amount: usize, r: &Resources) -> Result<()> {
    r.cancellation.check()?;
    work.used = work
        .used
        .checked_add(amount)
        .filter(|n| *n <= work.maximum)
        .ok_or_else(|| exhausted("NTFS tail discovery work ceiling"))?;
    r.cancellation.check()
}
fn rank_fast(area: &NtfsRestartArea, h: &NtfsLogPageHeader, target: u64) -> Result<u64> {
    let bits = 64 - area.sequence_bits;
    let mask = (1u64 << bits) - 1;
    let original = (h.raw_lsn_or_file_offset & mask)
        .checked_mul(8)
        .ok_or_else(|| invalid("NTFS fast original address overflow"))?;
    if original >= area.file_bytes {
        return Err(invalid("NTFS fast original address outside log"));
    }
    let generation = (h.raw_lsn_or_file_offset >> bits)
        .checked_add(u64::from(target < original / PAGE as u64 * PAGE as u64))
        .ok_or_else(|| invalid("NTFS fast base generation overflow"))?;
    if generation > u64::MAX >> bits {
        return Err(unsupported("NTFS fast base generation rollover"));
    }
    let length = if h.flags & 1 != 0 && h.raw_lsn_or_file_offset <= h.last_end_lsn {
        u64::from(h.next_record_offset)
    } else {
        PAGE as u64
    };
    let low = target
        .checked_add(length)
        .ok_or_else(|| invalid("NTFS fast base address overflow"))?
        / 8;
    // Linux allows an endpoint at EOF; low==2^bits would carry generation.
    // Preserve that checked numeric computation without claiming physical wrap.
    (generation << bits)
        .checked_add(low)
        .ok_or_else(|| unsupported("NTFS fast base numeric overflow"))
}
#[derive(Clone, Copy, Debug)]
struct Transfer {
    generation: u64,
    saved: u64,
    rank: u64,
    count: u16,
    position: u16,
}
fn advance(
    t: Option<Transfer>,
    h: &NtfsLogPageHeader,
    target: u64,
    rank: u64,
    bits: u32,
) -> Option<Transfer> {
    match t {
        None => (h.page_position == 1).then_some(Transfer {
            generation: rank >> bits,
            saved: target,
            rank,
            count: h.page_count,
            position: if h.page_count > 1 { 2 } else { 1 },
        }),
        Some(t) => {
            if t.generation != rank >> bits
                || t.saved.checked_add(PAGE as u64) != Some(target)
                || t.rank >= rank
                || !(t.position != t.count || h.page_position == t.position || h.page_position == 1)
                || !(t.position >= t.count || h.page_position == t.position)
            {
                return None;
            }
            let (count, position) = if h.page_position != h.page_count {
                (
                    h.page_count,
                    if h.page_count > 1 {
                        h.page_position + 1
                    } else {
                        h.page_position
                    },
                )
            } else {
                (1, 1)
            };
            Some(Transfer {
                generation: t.generation,
                saved: target,
                rank,
                count,
                position,
            })
        }
    }
}
/// Read only physical reserved candidates from the selected seed's version.
/// Source must remain immutable. Exact repeated guards detect drift of all read
/// restart/candidate bytes, but cannot establish historical generation ordering.
pub fn inspect_logfile_tail_discovery(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogTailDiscoveryLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsLogTailDiscoveryReport> {
    r.cancellation.check()?;
    let mut sl = limits.seed;
    sl.work = sl.work.min(limits.work);
    let seed = inspect_logfile_discovery_seed(source.clone(), sl, ordering, r)?;
    let length = seed.selection().restart().source_bytes();
    r.cancellation.check()?;
    let version = seed.selection().selected_context().map(|a| a.version);
    let maximum = if version == Some((2, 0)) { 32usize } else { 2 };
    let vector_bytes = maximum
        .checked_mul(core::mem::size_of::<NtfsLogTailCandidate>() + core::mem::size_of::<usize>())
        .ok_or_else(|| exhausted("NTFS tail vector bytes overflow"))?;
    if vector_bytes > limits.retained_bytes {
        return Err(exhausted("NTFS tail retained ceiling"));
    }
    let vectors = r.memory.reserve(vector_bytes as u64)?;
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(maximum)
        .map_err(|_| exhausted("NTFS tail vector allocation"))?;
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(maximum)
        .map_err(|_| exhausted("NTFS tail chain allocation"))?;
    if candidates.capacity() > maximum || chain.capacity() > maximum {
        return Err(exhausted("NTFS tail vector capacity exceeds lease"));
    }
    let mut work = Work {
        used: seed.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogTailDiscoveryReport {
        seed,
        candidates,
        chain,
        stop: NtfsLogTailDiscoveryStop::SeedUnavailable,
        error: None,
        source_error: None,
        work: 0,
        _vectors: vectors,
    };
    let scan = (|| -> Result<()> {
        let Some(area) = report.seed.selection().selected_context() else {
            return Ok(());
        };
        if report.seed.stopping_error().is_some() {
            return Ok(());
        }
        let area = *area;
        let first = if area.version == (1, 1) { 4 } else { 34 };
        let bits = 64 - area.sequence_bits;
        let pairs = if area.version == (1, 1) { 1 } else { 16 };
        let mut transfer = None;
        for pair in 0..pairs {
            let start = report.candidates.len();
            // Match native second-then-first reads while retaining physical identity.
            for bank in [1usize, 0] {
                if report.candidates.len() == limits.candidates {
                    return Err(exhausted("NTFS tail candidate ceiling"));
                }
                let bytes = vector_bytes
                    .checked_add((report.candidates.len() + 1) * PAGE)
                    .ok_or_else(|| exhausted("NTFS tail retained overflow"))?;
                if bytes > limits.retained_bytes {
                    return Err(exhausted("NTFS tail retained ceiling"));
                }
                let slot = if area.version == (1, 1) {
                    2 + bank
                } else {
                    2 + bank * 16 + pair
                };
                let offset = slot as u64 * PAGE as u64;
                let role = if area.version == (1, 1) {
                    NtfsLogPageRole::TailCopy { index: bank as u8 }
                } else {
                    NtfsLogPageRole::FastCopy {
                        index: (bank * 16 + pair) as u8,
                    }
                };
                let lease = r.memory.reserve(PAGE as u64)?;
                let mut raw = page_buffer()?;
                if raw.capacity() > PAGE {
                    return Err(exhausted("NTFS tail page capacity exceeds lease"));
                }
                charge(&mut work, PAGE, r)?;
                if let Err(error) = source.read_exact_at(offset, &mut raw) {
                    report.candidates.push(NtfsLogTailCandidate {
                        source_offset: offset,
                        role,
                        raw,
                        header: None,
                        target: None,
                        rank: None,
                        error: Some(Error::io("NTFS tail candidate read", error)),
                        _lease: lease,
                    });
                    return Err(invalid("NTFS tail candidate read incomplete"));
                }
                r.cancellation.check()?;
                let decoded = (|| -> Result<(NtfsLogPageHeader, u64, u64)> {
                    charge(&mut work, PAGE, r)?;
                    if &raw[..4] != b"RCRD" {
                        return Err(invalid("NTFS tail candidate signature"));
                    }
                    let mut h =
                        pages::frame_header(&raw, role, area.page_data_offset, &mut work, r)?;
                    if h.flags & !1 != 0 {
                        return Err(unsupported("NTFS tail candidate flags"));
                    }
                    let target = if area.version == (1, 1) {
                        h.raw_lsn_or_file_offset
                    } else {
                        u64::from(h.fast_copy_target.unwrap())
                    };
                    if target < first * PAGE as u64
                        || target >= area.file_bytes
                        || !target.is_multiple_of(PAGE as u64)
                    {
                        return Err(invalid("NTFS tail candidate target"));
                    }
                    h.fast_copy_target_checked = area.version == (2, 0);
                    let rank = if area.version == (1, 1) {
                        h.last_end_lsn
                    } else {
                        rank_fast(&area, &h, target)?
                    };
                    Ok((h, target, rank))
                })();
                let (header, target, rank, error) = match decoded {
                    Ok((h, t, l)) => (Some(h), Some(t), Some(l), None),
                    Err(e) => (None, None, None, Some(e)),
                };
                report.candidates.push(NtfsLogTailCandidate {
                    source_offset: offset,
                    role,
                    raw,
                    header,
                    target,
                    rank,
                    error,
                    _lease: lease,
                });
            }
            let second = start;
            let first = start + 1;
            let a = &report.candidates[first];
            let b = &report.candidates[second];
            charge(&mut work, PAGE, r)?;
            let chosen = match (a.rank, b.rank) {
                (None, None) => {
                    report.stop = NtfsLogTailDiscoveryStop::NoUsablePair;
                    break;
                }
                (Some(_), None) => first,
                (None, Some(_)) => second,
                (Some(x), Some(y)) => {
                    if x == y && (a.target != b.target || a.header != b.header || a.raw != b.raw) {
                        report.stop = NtfsLogTailDiscoveryStop::EqualRankConflict;
                        break;
                    }
                    if area.version == (1, 1) {
                        if x < y { second } else { first }
                    } else if x > y {
                        first
                    } else {
                        second
                    }
                }
            };
            if area.version == (1, 1) {
                report.chain.push(chosen);
                report.stop = NtfsLogTailDiscoveryStop::OrdinaryValidationRequired;
                break;
            }
            let c = &report.candidates[chosen];
            // Native !tails does not stop on a nonstarting fragment: keep
            // scanning later physical pairs for a first-position candidate.
            if transfer.is_none() && c.header.as_ref().unwrap().page_position != 1 {
                report.stop = if pair == 15 {
                    NtfsLogTailDiscoveryStop::CandidateAreaExhausted
                } else {
                    NtfsLogTailDiscoveryStop::TransferDiscontinuity
                };
                continue;
            }
            let next = advance(
                transfer,
                c.header.as_ref().unwrap(),
                c.target.unwrap(),
                c.rank.unwrap(),
                bits,
            );
            let Some(next) = next else {
                report.stop = NtfsLogTailDiscoveryStop::TransferDiscontinuity;
                break;
            };
            transfer = Some(next);
            report.chain.push(chosen);
            report.stop = if pair == 15 {
                NtfsLogTailDiscoveryStop::CandidateAreaExhausted
            } else {
                NtfsLogTailDiscoveryStop::OrdinaryValidationRequired
            };
        }
        Ok(())
    })();
    report.error = scan.err();
    // Guard every original read byte, including rejected mates/restart copies.
    let guard = (|| -> Result<()> {
        let _scratch = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS tail page capacity exceeds lease"));
        }
        for copy in report.seed.selection().restart().copies() {
            charge(&mut work, 2 * PAGE, r)?;
            source
                .read_exact_at(copy.offset(), &mut raw)
                .map_err(|e| Error::io("NTFS tail restart guard read", e))?;
            r.cancellation.check()?;
            if raw != copy.raw() {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS tail restart source bytes changed",
                ));
            }
        }
        for copy in &report.candidates {
            charge(&mut work, 2 * PAGE, r)?;
            source
                .read_exact_at(copy.source_offset, &mut raw)
                .map_err(|e| Error::io("NTFS tail candidate guard read", e))?;
            r.cancellation.check()?;
            if raw != copy.raw {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS tail candidate source bytes changed",
                ));
            }
        }
        r.cancellation.check()?;
        if source.len() != length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS tail source length changed",
            ));
        }
        r.cancellation.check()
    })();
    report.source_error = guard.err();
    report.work = work.used;
    Ok(report)
}

/// Native base-record2 provenance plus read-only discovery diagnostics.
pub struct NtfsVolumeLogTailDiscoveryReport {
    /// Source-owned native base-record2 identity.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Complete candidate and sourceguard diagnostics.
    pub report: NtfsLogTailDiscoveryReport,
}
/// Resolve the native DATA source and suppress all candidate-chain observations
/// after final volume identity/length/cancellation failure.
pub fn inspect_ntfs_logfile_tail_discovery(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogTailDiscoveryLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsVolumeLogTailDiscoveryReport> {
    r.cancellation.check()?;
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_tail_discovery(Arc::new(native), limits, ordering, r)?;
    if let Err(error) = volume
        .audit_check_source(r)
        .and_then(|()| r.cancellation.check())
    {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeLogTailDiscoveryReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
mod ordinary;
pub use ordinary::*;

#[cfg(test)]
mod tests {
    use super::*;
    fn h(count: u16, position: u16) -> NtfsLogPageHeader {
        NtfsLogPageHeader {
            raw_lsn_or_file_offset: 0,
            fast_copy_target: Some(0),
            fast_copy_target_checked: true,
            flags: 0,
            page_count: count,
            page_position: position,
            next_record_offset: 0,
            last_end_lsn: 0,
            next_record_offset_checked: false,
        }
    }
    #[test]
    fn transfer_starts_only_at_first_position() {
        assert!(advance(None, &h(3, 2), 34 * 4096, 10, 32).is_none());
        let t = advance(None, &h(3, 1), 34 * 4096, 10, 32).unwrap();
        assert_eq!((t.count, t.position), (3, 2));
        // Independent expected progression: positions1,2,3 complete one transfer;
        // the subsequent first page starts another, without changing generation.
        let t = advance(Some(t), &h(3, 2), 35 * 4096, 11, 32).unwrap();
        assert_eq!((t.count, t.position), (3, 3));
        let t = advance(Some(t), &h(3, 3), 36 * 4096, 12, 32).unwrap();
        assert_eq!((t.count, t.position), (1, 1));
        assert!(advance(Some(t), &h(2, 1), 37 * 4096, 13, 32).is_some());
    }
    #[test]
    fn transfer_refuses_skips_stale_ranks_and_generation_changes() {
        let t = advance(None, &h(3, 1), 34 * 4096, 10, 32).unwrap();
        assert!(advance(Some(t), &h(3, 3), 35 * 4096, 11, 32).is_none());
        assert!(advance(Some(t), &h(3, 2), 36 * 4096, 11, 32).is_none());
        assert!(advance(Some(t), &h(3, 2), 35 * 4096, 10, 32).is_none());
        assert!(advance(Some(t), &h(3, 2), 35 * 4096, (1u64 << 32) + 11, 32).is_none());
    }
    #[test]
    fn finishing_transfer_may_restart_at_first_position() {
        let t = advance(None, &h(2, 1), 34 * 4096, 10, 32).unwrap();
        let t = advance(Some(t), &h(4, 1), 35 * 4096, 11, 32).unwrap();
        assert_eq!((t.count, t.position), (4, 2));
    }
}
