//! Source-derived bounded ordinary-page progression, without replay authority.
use super::*;
/// Combined candidate and ordinary discovery ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogOrdinaryDiscoveryLimits {
    /// Reserved-copy and restart discovery ceilings.
    pub tail: NtfsLogTailDiscoveryLimits,
    /// Maximum retained ordinary reads, including boundary probes.
    pub pages: usize,
    /// Maximum ordinary raw/vector retained capacity.
    pub retained_bytes: usize,
    /// Combined candidate, ordinary and repeated-guard work.
    pub work: usize,
}
/// Explicit ordinary state-machine boundary; no exhaustion implies completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogOrdinaryStop {
    /// Seed/candidate authority was unavailable or ambiguous.
    CandidateFailure,
    /// Read/framing/flag/source failure retained in diagnostics.
    UnsupportedPage,
    /// Native subsequent-generation predicate found an inconsistent boundary.
    SubsequentGenerationConflict,
    /// Literal pinned lookahead would repeat a physical probe without progress.
    AmbiguousNativeLookahead,
    /// One supported probe observed a structural boundary, not an active proof.
    BoundaryObserved,
    /// Finite physical page ceiling reached before boundary discovery.
    PageCeiling,
}
/// Original ordinary read, including its boundary/probe identity and error.
pub struct NtfsLogOrdinaryPage {
    offset: u64,
    raw: Vec<u8>,
    header: Option<NtfsLogPageHeader>,
    error: Option<Error>,
    read_complete: bool,
    usa_error: bool,
    partial_transition: Option<NtfsLogPartialProbeTransition>,
    _lease: Reservation,
}
impl NtfsLogOrdinaryPage {
    /// Original physical ordinary page offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Original raw read buffer, never normalized; read_complete distinguishes
    /// complete protected bytes from a failed backend buffer.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Supported locally fixed-up header, if available.
    pub fn header(&self) -> Option<&NtfsLogPageHeader> {
        self.header.as_ref()
    }
    /// Whether the backend returned all raw bytes, independent of later framing.
    pub fn read_complete(&self) -> bool {
        self.read_complete
    }
    /// Native USA failure boundary, distinguished from unrelated codec failures.
    pub fn usa_error(&self) -> bool {
        self.usa_error
    }
    /// Sealed decision made for this exact physical probe and original result.
    pub fn partial_transition(&self) -> Option<NtfsLogPartialProbeTransition> {
        self.partial_transition
    }
    /// Original read/frame/semantic failure.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
}
/// Immutable endpoint observation reached by source-derived transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogOrdinaryEndpoint {
    /// Observed last-ended LSN; not permission to iterate or replay.
    pub last_lsn: u64,
    /// Source-derived generation after checked wrap transitions.
    pub generation: u64,
    /// Pinned source next-page convention; never a successor-record LSN.
    pub next_page: u64,
    /// Whether native spare-byte arithmetic selected page reuse.
    pub reuse: bool,
}
/// Exact literal native remaining-loop trace: target does not progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogLookaheadTrace {
    /// Original boundary page retained by native curpage_off.
    pub fixed_current: u64,
    /// Actual repeated final probe target.
    pub target: u64,
    /// Generation before native remaining-loop arithmetic.
    pub initial_generation: u64,
    /// Generation after every literal repeated wrap increment.
    pub final_generation: u64,
    /// Native transfer count entering check_valid.
    pub count: u32,
    /// Native transfer position entering check_valid.
    pub position: u32,
    /// Charged remaining-loop iterations, without invented page advancement.
    pub arithmetic_steps: u32,
    /// Whether a matching first probe led to actual same-address reread.
    pub matched_first_probe: bool,
}
struct RepeatInput {
    current: u64,
    target: u64,
    expected: u64,
    count: u32,
    position: u32,
    first: u64,
    bits: u32,
    matched: bool,
}
fn repeat_trace(
    input: RepeatInput,
    work: &mut Work,
    r: &Resources,
    retained: &mut Option<NtfsLogLookaheadTrace>,
) -> Result<NtfsLogLookaheadTrace> {
    let steps = input
        .count
        .checked_sub(input.position)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| invalid("NTFS native lookahead remaining count underflow"))?;
    let mut trace = NtfsLogLookaheadTrace {
        fixed_current: input.current,
        target: input.target,
        initial_generation: input.expected,
        final_generation: input.expected,
        count: input.count,
        position: input.position,
        arithmetic_steps: 0,
        matched_first_probe: input.matched,
    };
    *retained = Some(trace);
    for _ in 0..steps {
        charge(work, 1, r)?;
        trace.arithmetic_steps += 1;
        *retained = Some(trace);
        if input.target == input.first {
            trace.final_generation = bump_generation(trace.final_generation, input.bits)?;
        }
        *retained = Some(trace);
    }
    Ok(trace)
}
/// Full source-owned candidate and ordinary diagnostics, without an overlay.
pub struct NtfsLogOrdinaryDiscoveryReport {
    tail: NtfsLogTailDiscoveryReport,
    pages: Vec<NtfsLogOrdinaryPage>,
    endpoint: Option<NtfsLogOrdinaryEndpoint>,
    lookahead: Option<NtfsLogLookaheadTrace>,
    replacement_start: Option<u64>,
    boundary_tail: Option<usize>,
    partial: Option<NtfsLogPartialTransferTrace>,
    stop: NtfsLogOrdinaryStop,
    error: Option<Error>,
    source_error: Option<Error>,
    work: usize,
    _vectors: Reservation,
}
impl NtfsLogOrdinaryDiscoveryReport {
    /// Original reserved-copy discovery and both restart contexts.
    pub fn tail_report(&self) -> &NtfsLogTailDiscoveryReport {
        &self.tail
    }
    /// All original ordinary reads including boundary probes.
    pub fn pages(&self) -> &[NtfsLogOrdinaryPage] {
        &self.pages
    }
    /// Observed endpoint withheld after I/O, source or resource failure.
    pub fn endpoint(&self) -> Option<&NtfsLogOrdinaryEndpoint> {
        if self.stopping_error().is_none() {
            self.endpoint.as_ref()
        } else {
            None
        }
    }
    /// Source-owned native partial-transfer accounting, never erase authority.
    pub fn partial_transfer(&self) -> Option<&NtfsLogPartialTransferTrace> {
        self.partial.as_ref()
    }
    /// Exact bounded literal repeat arithmetic; diagnostic, never active proof.
    pub fn lookahead_trace(&self) -> Option<&NtfsLogLookaheadTrace> {
        self.lookahead.as_ref()
    }
    /// Explicit structural boundary or unresolved state.
    pub fn stop(&self) -> NtfsLogOrdinaryStop {
        self.stop
    }
    /// Native branch interruption, independent of any earlier retained I/O error.
    pub fn branch_error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
    /// Original failure requiring diagnostic handling.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.tail
            .stopping_error()
            .or_else(|| {
                self.pages
                    .iter()
                    .filter_map(|p| p.error.as_ref())
                    .find(|e| !matches!(e.kind, ErrorKind::InvalidData | ErrorKind::Unsupported))
            })
            .or(self.error.as_ref())
            .or(self.source_error.as_ref())
    }
    /// Actual combined charged work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: active ordering, overlay and ambiguous lookahead remain open.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: no transactions are replayed.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
fn next(page: u64, first: u64, end: u64) -> Result<u64> {
    let n = page
        .checked_add(PAGE as u64)
        .ok_or_else(|| invalid("NTFS ordinary page advance overflow"))?;
    Ok(if n >= end { first } else { n })
}
fn record_start_next(
    start: u64,
    end: u64,
    first: u64,
    file: u64,
    header: u16,
) -> Result<(u64, bool, bool)> {
    let reuse = PAGE as u64 - end % PAGE as u64 > u64::from(header);
    let page = start / PAGE as u64 * PAGE as u64;
    Ok((
        if reuse {
            page
        } else {
            next(page, first, file)?
        },
        reuse,
        end <= start,
    ))
}
fn bump_generation(generation: u64, bits: u32) -> Result<u64> {
    generation
        .checked_add(1)
        .filter(|n| *n <= u64::MAX >> bits)
        .ok_or_else(|| unsupported("NTFS ordinary generation rollover"))
}
fn seed_position(
    area: &NtfsRestartArea,
    seed: &NtfsLogDiscoverySeed,
) -> Result<(NtfsLogOrdinaryEndpoint, bool)> {
    let bits = 64 - area.sequence_bits;
    let mut generation = area.current_lsn >> bits;
    let first = seed.ordinary_start();
    let (next_page, reuse, no_last) = match seed.current_address() {
        NtfsLogSeedAddress::Ordinary { byte_offset, .. } => {
            let end = seed
                .declared_endpoint()
                .ok_or_else(|| invalid("NTFS ordinary seed endpoint missing"))?
                .final_byte_offset();
            let (page, reuse, wrapped) = record_start_next(
                byte_offset,
                end,
                first,
                area.file_bytes,
                area.record_header_bytes,
            )?;
            if wrapped {
                generation = generation
                    .checked_add(1)
                    .ok_or_else(|| unsupported("NTFS ordinary seed generation overflow"))?;
            }
            (page, reuse, false)
        }
        _ => (first, false, true),
    };
    if generation > u64::MAX >> bits {
        return Err(unsupported("NTFS ordinary generation rollover"));
    }
    Ok((
        NtfsLogOrdinaryEndpoint {
            last_lsn: area.current_lsn,
            generation,
            next_page,
            reuse,
        },
        no_last,
    ))
}
fn follows(h: &NtfsLogPageHeader, count: u16, position: u16, reuse: bool) -> bool {
    if count == position {
        h.page_position == 1 || reuse && h.page_position == h.page_count
    } else {
        h.page_count == count && position.checked_add(1) == Some(h.page_position)
    }
}
fn subseq(h: &NtfsLogPageHeader, offset: u64, expected: u64, bits: u32, first: u64) -> bool {
    let sequence = h.raw_lsn_or_file_offset >> bits;
    let encoded =
        ((h.raw_lsn_or_file_offset & ((1u64 << bits) - 1)) * 8) / PAGE as u64 * PAGE as u64;
    sequence >= expected
        || expected.checked_sub(1) == Some(sequence) && offset == first && encoded != first
}
fn endpoint(
    h: &NtfsLogPageHeader,
    page: u64,
    next: u64,
    generation: u64,
    header: u16,
    data_offset: u16,
) -> Result<NtfsLogOrdinaryEndpoint> {
    if !h.next_record_offset.is_multiple_of(8)
        || h.next_record_offset < data_offset
        || usize::from(h.next_record_offset) > PAGE
    {
        return Err(unsupported("NTFS ordinary endpoint offset unvalidated"));
    }
    let reuse = PAGE - usize::from(h.next_record_offset) >= usize::from(header);
    Ok(NtfsLogOrdinaryEndpoint {
        last_lsn: h.last_end_lsn,
        generation,
        next_page: if reuse { page } else { next },
        reuse,
    })
}
fn read_page(
    source: &dyn ReadAt,
    offset: u64,
    area: &NtfsRestartArea,
    report: &mut NtfsLogOrdinaryDiscoveryReport,
    limits: NtfsLogOrdinaryDiscoveryLimits,
    work: &mut Work,
    r: &Resources,
) -> Result<usize> {
    if report.pages.len() == limits.pages {
        report.stop = NtfsLogOrdinaryStop::PageCeiling;
        return Err(exhausted("NTFS ordinary page ceiling"));
    }
    let bytes = limits
        .pages
        .checked_mul(core::mem::size_of::<NtfsLogOrdinaryPage>())
        .and_then(|n| n.checked_add((report.pages.len() + 1) * PAGE))
        .ok_or_else(|| exhausted("NTFS ordinary retained overflow"))?;
    if bytes > limits.retained_bytes {
        return Err(exhausted("NTFS ordinary retained ceiling"));
    }
    let lease = r.memory.reserve(PAGE as u64)?;
    let mut raw = page_buffer()?;
    if raw.capacity() > PAGE {
        return Err(exhausted("NTFS ordinary raw capacity"));
    }
    charge(work, PAGE, r)?;
    let mut error = source
        .read_exact_at(offset, &mut raw)
        .map_err(|e| Error::io("NTFS ordinary page read", e))
        .err();
    let read_complete = error.is_none();
    let mut usa_error = false;
    if let Err(e) = r.cancellation.check()
        && error.is_none()
    {
        error = Some(e);
    }
    let header = if error.is_none() {
        let decoded = (|| -> Result<NtfsLogPageHeader> {
            charge(work, PAGE, r)?;
            if &raw[..4] != b"RCRD" {
                return Err(unsupported("NTFS ordinary unsupported signature"));
            }
            let usa = usize::from(le16(&raw, 4));
            let count = usize::from(le16(&raw, 6));
            usa_error = usa < 40
                || !usa.is_multiple_of(2)
                || count != 9
                || usa + count * 2 > 510
                || usa + count * 2 > usize::from(area.page_data_offset);
            if !usa_error {
                for sector in 1..count {
                    charge(work, 1, r)?;
                    if le16(&raw, sector * 512 - 2) != le16(&raw, usa) {
                        usa_error = true;
                    }
                }
            }
            let h = pages::frame_header(
                &raw,
                NtfsLogPageRole::Ordinary,
                area.page_data_offset,
                work,
                r,
            )?;
            if h.flags & !1 != 0 {
                return Err(unsupported("NTFS ordinary flags"));
            }
            Ok(h)
        })();
        match decoded {
            Ok(h) => Some(h),
            Err(e) => {
                error = Some(e);
                None
            }
        }
    } else {
        None
    };
    let index = report.pages.len();
    report.pages.push(NtfsLogOrdinaryPage {
        offset,
        raw,
        header,
        error,
        read_complete,
        usa_error,
        partial_transition: None,
        _lease: lease,
    });
    Ok(index)
}
/// Follow source-derived generation/transfer/reuse transitions with exact raw
/// guards. Ambiguous native nonprogress lookahead stops visibly, never skips.
pub fn inspect_logfile_ordinary_discovery(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogOrdinaryDiscoveryLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsLogOrdinaryDiscoveryReport> {
    let mut tl = limits.tail;
    tl.work = tl.work.min(limits.work);
    let tail = inspect_logfile_tail_discovery(source.clone(), tl, ordering, r)?;
    let vectorbytes = limits
        .pages
        .checked_mul(core::mem::size_of::<NtfsLogOrdinaryPage>())
        .ok_or_else(|| exhausted("NTFS ordinary vector overflow"))?;
    if vectorbytes > limits.retained_bytes {
        return Err(exhausted("NTFS ordinary vector ceiling"));
    }
    let vectors = r.memory.reserve(vectorbytes as u64)?;
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(limits.pages)
        .map_err(|_| exhausted("NTFS ordinary vector allocation"))?;
    if pages.capacity() > limits.pages {
        return Err(exhausted("NTFS ordinary vector capacity"));
    }
    let mut work = Work {
        used: tail.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogOrdinaryDiscoveryReport {
        tail,
        pages,
        endpoint: None,
        lookahead: None,
        replacement_start: None,
        boundary_tail: None,
        partial: None,
        stop: NtfsLogOrdinaryStop::CandidateFailure,
        error: None,
        source_error: None,
        work: 0,
        _vectors: vectors,
    };
    let scan = (|| -> Result<()> {
        if report.tail.stopping_error().is_some()
            || report.tail.stop == NtfsLogTailDiscoveryStop::EqualRankConflict
        {
            return Ok(());
        }
        let Some(area) = report.tail.seed.selection().selected_context().copied() else {
            return Ok(());
        };
        let Some(seed) = report.tail.seed.seed().copied() else {
            return Ok(());
        };
        if area.flags & 1 != 0 {
            return Err(unsupported("NTFS ordinary single-page IO restart flag"));
        }
        let first = seed.ordinary_start();
        let bits = 64 - area.sequence_bits;
        let (initial, no_last) = seed_position(&area, &seed)?;
        report.endpoint = Some(initial);
        let mut page = initial.next_page;
        if let Some(index) = report.tail.chain.first() {
            let c = &report.tail.candidates[*index];
            if c.rank.unwrap() >> bits == initial.generation {
                page = page.min(c.target.unwrap());
            }
        }
        let mut expected = initial.generation;
        let mut reuse = initial.reuse;
        let mut last = if reuse { initial.last_lsn } else { 0 };
        let (mut count, mut position) = (1u16, 1u16);
        let mut replacing = false;
        if page == first && !no_last && !reuse {
            expected = bump_generation(expected, bits)?;
        }
        loop {
            if report.pages.len() == limits.pages {
                report.stop = NtfsLogOrdinaryStop::PageCeiling;
                break;
            }
            charge(&mut work, 1, r)?;
            let subsequent = next(page, first, area.file_bytes)?;
            let wrapped = subsequent == first;
            let index = read_page(
                source.as_ref(),
                page,
                &area,
                &mut report,
                limits,
                &mut work,
                r,
            )?;
            let ordinary = report.pages[index].header;
            let mut tail = None;
            let mut force_boundary = false;
            let multi = report.tail.chain.len() > 1;
            if multi {
                if let Some(c) = report
                    .tail
                    .chain
                    .iter()
                    .map(|i| &report.tail.candidates[*i])
                    .find(|c| c.target == Some(page))
                {
                    let h = c.header.unwrap();
                    let last_target = report.tail.candidates[*report.tail.chain.last().unwrap()]
                        .target
                        .unwrap();
                    let keep = page != last_target
                        && report.replacement_start.is_none()
                        && ordinary.is_some_and(|o| {
                            o.raw_lsn_or_file_offset == h.raw_lsn_or_file_offset
                                && o.next_record_offset == h.next_record_offset
                                && follows(&o, count, position, false)
                        });
                    if page == last_target {
                        tail = Some(h);
                    } else if !keep {
                        let first_target = report
                            .tail
                            .chain
                            .first()
                            .and_then(|i| report.tail.candidates[*i].target)
                            .ok_or_else(|| {
                                invalid("NTFS replacement first-chain target missing")
                            })?;
                        report.replacement_start.get_or_insert(first_target);
                        let source_page = ((h.raw_lsn_or_file_offset & ((1u64 << bits) - 1)) * 8)
                            / PAGE as u64
                            * PAGE as u64;
                        let generation = (h.raw_lsn_or_file_offset >> bits)
                            .checked_add(u64::from(page < source_page))
                            .ok_or_else(|| unsupported("NTFS ordinary fast generation overflow"))?;
                        if last == h.last_end_lsn || generation == expected {
                            if h.flags & 1 != 0 {
                                report.endpoint = Some(endpoint(
                                    &h,
                                    page,
                                    subsequent,
                                    expected,
                                    area.record_header_bytes,
                                    area.page_data_offset,
                                )?);
                                last = h.last_end_lsn;
                            } else {
                                last = h.raw_lsn_or_file_offset;
                            }
                            page = subsequent;
                            if wrapped {
                                expected = bump_generation(expected, bits)?;
                            }
                            reuse = false;
                            continue;
                        }
                        force_boundary = true;
                    }
                }
            } else if count == position || position.checked_add(1) == Some(count) {
                let pair = report.tail.chain.last().map(|i| i / 2 * 2);
                let mates = pair
                    .and_then(|i| report.tail.candidates.get(i..i + 2))
                    .unwrap_or(&[]);
                for c in mates
                    .iter()
                    .rev()
                    .filter(|c| c.target == Some(page) && c.error.is_none())
                {
                    let h = c.header.unwrap();
                    if tail.is_none_or(|t: NtfsLogPageHeader| h.last_end_lsn > t.last_end_lsn) {
                        tail = Some(h);
                    }
                }
            }
            tail = tail.filter(|h| {
                last == h.last_end_lsn
                    || last < h.last_end_lsn && h.last_end_lsn >> bits == expected
            });
            let valid = !force_boundary
                && ordinary.is_some_and(|h| {
                    (h.raw_lsn_or_file_offset == last
                        || h.raw_lsn_or_file_offset >> bits == expected)
                        && follows(&h, count, position, reuse)
                });
            if valid
                && tail.is_some_and(|t| t.last_end_lsn > ordinary.unwrap().raw_lsn_or_file_offset)
            {
                replacing = true;
            }
            if valid
                && tail.is_none_or(|t| t.last_end_lsn <= ordinary.unwrap().raw_lsn_or_file_offset)
            {
                let h = ordinary.unwrap();
                if h.flags & 1 != 0 {
                    report.endpoint = Some(endpoint(
                        &h,
                        page,
                        subsequent,
                        expected,
                        area.record_header_bytes,
                        area.page_data_offset,
                    )?);
                }
                count = h.page_count;
                position = h.page_position;
                last = h.raw_lsn_or_file_offset;
                page = subsequent;
                if wrapped {
                    expected = bump_generation(expected, bits)?;
                }
                reuse = false;
                continue;
            }
            if report.pages[index]
                .error
                .as_ref()
                .is_some_and(|e| !matches!(e.kind, ErrorKind::InvalidData | ErrorKind::Unsupported))
            {
                return Err(Error::new(
                    ErrorKind::Io,
                    "NTFS ordinary source read failed",
                ));
            }
            if let Some(h) = tail {
                let selected = if multi {
                    report.tail.chain.last().copied()
                } else {
                    let pair = report.tail.chain.last().map(|i| i / 2 * 2);
                    pair.and_then(|base| {
                        (base..base + 2).rev().find(|i| {
                            report.tail.candidates[*i].target == Some(page)
                                && report.tail.candidates[*i].header == Some(h)
                        })
                    })
                };
                report.boundary_tail =
                    Some(selected.ok_or_else(|| invalid("NTFS boundary tail provenance missing"))?);
                report.endpoint = Some(endpoint(
                    &h,
                    page,
                    subsequent,
                    expected,
                    area.record_header_bytes,
                    area.page_data_offset,
                )?);
            }
            report.partial = Some(NtfsLogPartialTransferTrace {
                original_start: subsequent,
                initial_count: 0,
                read_error_increments: 0,
                planned_remaining: 0,
                final_pre_overlay_count: 0,
                retry_attempts: 0,
                complete_native_branch: false,
            });
            if wrapped {
                expected = bump_generation(expected, bits)?;
            }
            let direct = replacing || position != count || wrapped;
            let (boundary_count, boundary_position) = if replacing || wrapped && position == count {
                (2, 1)
            } else {
                (count, position)
            };
            partial_boundary(
                source.as_ref(),
                &area,
                &mut report,
                limits,
                &mut work,
                r,
                PartialInput {
                    current: page,
                    target: subsequent,
                    expected,
                    count: u32::from(boundary_count),
                    position: u32::from(boundary_position),
                    first,
                    bits,
                    direct,
                },
            )?;
            break;
        }
        Ok(())
    })();
    report.error = scan.err();
    let guard = (|| -> Result<()> {
        let _lease = r.memory.reserve(PAGE as u64)?;
        let mut raw = page_buffer()?;
        if raw.capacity() > PAGE {
            return Err(exhausted("NTFS ordinary guard capacity"));
        }
        let length = report.tail.seed.selection().restart().source_bytes();
        let originals = report
            .tail
            .seed
            .selection()
            .restart()
            .copies()
            .iter()
            .map(|c| (c.offset(), c.raw()))
            .chain(
                report
                    .tail
                    .candidates
                    .iter()
                    .map(|c| (c.source_offset, c.raw.as_slice())),
            )
            .chain(
                report
                    .pages
                    .iter()
                    .filter(|c| c.read_complete)
                    .map(|c| (c.offset, c.raw.as_slice())),
            );
        for (offset, want) in originals {
            charge(&mut work, 2 * PAGE, r)?;
            source
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS ordinary final guard read", e))?;
            r.cancellation.check()?;
            if raw != want {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS ordinary source bytes changed",
                ));
            }
        }
        r.cancellation.check()?;
        if source.len() != length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS ordinary source length changed",
            ));
        }
        r.cancellation.check()
    })();
    report.source_error = guard.err();
    report.work = work.used;
    Ok(report)
}

/// Native base-record2 provenance and complete ordinary discovery diagnostics.
pub struct NtfsVolumeLogOrdinaryDiscoveryReport {
    /// Source-owned native base-record2 identity.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Sourceguarded read-only ordinary state-machine report.
    pub report: NtfsLogOrdinaryDiscoveryReport,
}
/// Resolve native record2 DATA and suppress observations after final volumeguard.
pub fn inspect_ntfs_logfile_ordinary_discovery(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogOrdinaryDiscoveryLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsVolumeLogOrdinaryDiscoveryReport> {
    r.cancellation.check()?;
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_ordinary_discovery(Arc::new(native), limits, ordering, r)?;
    if let Err(error) = volume
        .audit_check_source(r)
        .and_then(|()| r.cancellation.check())
    {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeLogOrdinaryDiscoveryReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}

mod partial;
pub use partial::{NtfsLogPartialProbeTransition, NtfsLogPartialTransferTrace};
use partial::{PartialInput, partial_boundary};

mod overlay;
pub use overlay::*;

#[cfg(test)]
mod tests {
    use super::*;
    fn h(count: u16, position: u16) -> NtfsLogPageHeader {
        NtfsLogPageHeader {
            raw_lsn_or_file_offset: 0,
            fast_copy_target: None,
            fast_copy_target_checked: false,
            flags: 0,
            page_count: count,
            page_position: position,
            next_record_offset: 0,
            last_end_lsn: 0,
            next_record_offset_checked: false,
        }
    }
    #[test]
    fn multipage_current_uses_original_start_page() {
        // Start at page5, inclusive endpoint on page7 with space: native reuse
        // returns page5. Intuitive endpoint-based page7 would be incorrect here.
        assert_eq!(
            record_start_next(5 * 4096 + 64, 7 * 4096 + 100, 4 * 4096, 12 * 4096, 48).unwrap(),
            (5 * 4096, true, false)
        );
        assert_eq!(
            record_start_next(5 * 4096 + 64, 8 * 4096 - 1, 4 * 4096, 12 * 4096, 48).unwrap(),
            (6 * 4096, false, false)
        );
    }
    #[test]
    fn inclusive_end_and_physical_wrap_are_distinct() {
        assert_eq!(
            record_start_next(11 * 4096 + 64, 5 * 4096 + 100, 4 * 4096, 12 * 4096, 48).unwrap(),
            (11 * 4096, true, true)
        );
        assert_eq!(
            record_start_next(11 * 4096 + 64, 12 * 4096 - 1, 4 * 4096, 12 * 4096, 48).unwrap(),
            (4 * 4096, false, false)
        );
    }
    #[test]
    fn only_initial_reuse_allows_completed_nonfirst_transfer() {
        assert!(follows(&h(3, 3), 1, 1, true));
        assert!(!follows(&h(3, 3), 1, 1, false));
        assert!(follows(&h(3, 2), 3, 1, false));
        assert!(!follows(&h(4, 2), 3, 1, false));
        assert!(!follows(&h(3, 3), 3, 1, false));
    }
    #[test]
    fn subsequent_previous_generation_exception_requires_first_page() {
        let mut page = h(1, 1);
        page.raw_lsn_or_file_offset = (4u64 << 32) + (8 * 4096 / 8);
        assert!(subseq(&page, 4 * 4096, 5, 32, 4 * 4096));
        assert!(!subseq(&page, 5 * 4096, 5, 32, 4 * 4096));
        page.raw_lsn_or_file_offset = (4u64 << 32) + (4 * 4096 / 8);
        assert!(!subseq(&page, 4 * 4096, 5, 32, 4 * 4096));
    }
}
