//! Sealed native partial-transfer accounting; never an erase/cleanup plan.
use super::*;
/// Source-derived decision for one retained actual boundary probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogPartialProbeTransition {
    /// Native USA error selects file_is_valid without incrementing partial count.
    UsaBoundary,
    /// A successful supported header does not continue the expected transfer.
    SuccessfulMismatch,
    /// Matching native probe promotes page_count before remaining arithmetic.
    MatchingCount,
    /// Backend error increments partial count and retries the same address.
    ReadErrorRetry,
    /// Backend error reaches native wrapped retry forcing, without progressive skip.
    WrappedReadError,
    /// Native u16 cur_pos would wrap; progression remains explicitly unsupported.
    UnsupportedPositionOverflow,
    /// Actual final check_valid read does not establish a subsequent generation.
    FinalBoundary,
    /// Actual final check_valid read contradicts the expected boundary.
    SubsequentConflict,
}
/// Immutable accounting retained even if a finite work/read ceiling interrupts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogPartialTransferTrace {
    pub(super) original_start: u64,
    pub(super) initial_count: u32,
    pub(super) read_error_increments: u32,
    pub(super) planned_remaining: u32,
    pub(super) final_pre_overlay_count: u32,
    pub(super) retry_attempts: u32,
    pub(super) complete_native_branch: bool,
}
impl NtfsLogPartialTransferTrace {
    /// Native second_off at check_tail, independent of reusable endpoint.next_page.
    pub fn original_start(&self) -> u64 {
        self.original_start
    }
    /// Native initial partial count, always zero.
    pub fn initial_count(&self) -> u32 {
        self.initial_count
    }
    /// Completed read-error increments, distinct from remaining-loop steps.
    pub fn read_error_increments(&self) -> u32 {
        self.read_error_increments
    }
    /// Full count-position-1 charged once BEFORE repeated arithmetic.
    pub fn planned_remaining(&self) -> u32 {
        self.planned_remaining
    }
    /// Native count before immutable overlay consumption; partial on refusal.
    pub fn pre_overlay_count(&self) -> u32 {
        self.final_pre_overlay_count
    }
    /// Actual backend-error transitions selecting another fixed-address attempt.
    pub fn retry_attempts(&self) -> u32 {
        self.retry_attempts
    }
    /// Native branch reached file_is_valid; original I/O errors remain fatal.
    pub fn complete_native_branch(&self) -> bool {
        self.complete_native_branch
    }
}
pub(super) struct PartialInput {
    pub(super) current: u64,
    pub(super) target: u64,
    pub(super) expected: u64,
    pub(super) count: u32,
    pub(super) position: u32,
    pub(super) first: u64,
    pub(super) bits: u32,
    pub(super) direct: bool,
}
fn add_remaining(
    report: &mut NtfsLogOrdinaryDiscoveryReport,
    count: u32,
    position: u32,
) -> Result<()> {
    let remaining = count
        .checked_sub(position)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| invalid("NTFS partial remaining count underflow"))?;
    let trace = report
        .partial
        .as_mut()
        .ok_or_else(|| invalid("NTFS partial trace missing"))?;
    trace.planned_remaining = remaining;
    trace.final_pre_overlay_count = trace
        .final_pre_overlay_count
        .checked_add(remaining)
        .ok_or_else(|| unsupported("NTFS partial count overflow"))?;
    Ok(())
}
fn mark_boundary(report: &mut NtfsLogOrdinaryDiscoveryReport) {
    report.partial.as_mut().unwrap().complete_native_branch = true;
    report.stop = NtfsLogOrdinaryStop::BoundaryObserved;
}
pub(super) fn partial_boundary(
    source: &dyn ReadAt,
    area: &NtfsRestartArea,
    report: &mut NtfsLogOrdinaryDiscoveryReport,
    limits: NtfsLogOrdinaryDiscoveryLimits,
    work: &mut Work,
    r: &Resources,
    mut input: PartialInput,
) -> Result<()> {
    let mut current_position = 2u16;
    let mut matched = false;
    if !input.direct {
        loop {
            let probe = read_page(source, input.target, area, report, limits, work, r)?;
            if report.pages[probe].usa_error {
                report.pages[probe].partial_transition =
                    Some(NtfsLogPartialProbeTransition::UsaBoundary);
                mark_boundary(report);
                return Ok(());
            }
            if let Some(h) = report.pages[probe].header {
                charge(work, 1, r)?;
                if h.page_position == current_position
                    && subseq(&h, input.target, input.expected, input.bits, input.first)
                {
                    report.pages[probe].partial_transition =
                        Some(NtfsLogPartialProbeTransition::MatchingCount);
                    input.count = u32::from(h.page_count) + 1;
                    input.position = u32::from(h.page_position);
                    matched = true;
                    break;
                }
                report.pages[probe].partial_transition =
                    Some(NtfsLogPartialProbeTransition::SuccessfulMismatch);
                mark_boundary(report);
                return Ok(());
            }
            if report.pages[probe]
                .error
                .as_ref()
                .is_some_and(|e| e.kind == ErrorKind::Io)
            {
                // Literal native next_page_off(curpage_off), NOT a moving target.
                charge(work, 1, r)?;
                let wrapped = input.target == input.first;
                report.pages[probe].partial_transition = Some(if wrapped {
                    NtfsLogPartialProbeTransition::WrappedReadError
                } else {
                    NtfsLogPartialProbeTransition::ReadErrorRetry
                });
                if wrapped {
                    input.expected = bump_generation(input.expected, input.bits)?;
                    input.count = 2;
                    input.position = 1;
                }
                current_position = match current_position.checked_add(1) {
                    Some(n) => n,
                    None => {
                        report.pages[probe].partial_transition =
                            Some(NtfsLogPartialProbeTransition::UnsupportedPositionOverflow);
                        return Err(unsupported(
                            "NTFS native u16 partial probe position rollover",
                        ));
                    }
                };
                let trace = report.partial.as_mut().unwrap();
                trace.read_error_increments = trace
                    .read_error_increments
                    .checked_add(1)
                    .ok_or_else(|| unsupported("NTFS partial read-error count overflow"))?;
                trace.final_pre_overlay_count = trace
                    .final_pre_overlay_count
                    .checked_add(1)
                    .ok_or_else(|| unsupported("NTFS partial count overflow"))?;
                trace.retry_attempts = trace
                    .retry_attempts
                    .checked_add(1)
                    .ok_or_else(|| unsupported("NTFS partial retry count overflow"))?;

                if wrapped {
                    break;
                }
                continue;
            }
            report.stop = NtfsLogOrdinaryStop::UnsupportedPage;
            return Ok(());
        }
    }
    charge(work, 1, r)?;
    add_remaining(report, input.count, input.position)?;
    let trace = repeat_trace(
        RepeatInput {
            current: input.current,
            target: input.target,
            expected: input.expected,
            count: input.count,
            position: input.position,
            first: input.first,
            bits: input.bits,
            matched,
        },
        work,
        r,
        &mut report.lookahead,
    )?;
    let probe = read_page(source, input.target, area, report, limits, work, r)?;
    if let Some(h) = report.pages[probe].header {
        charge(work, 1, r)?;
        if subseq(
            &h,
            input.target,
            trace.final_generation,
            input.bits,
            input.first,
        ) {
            report.pages[probe].partial_transition =
                Some(NtfsLogPartialProbeTransition::SubsequentConflict);
            report.stop = NtfsLogOrdinaryStop::SubsequentGenerationConflict;
            return Err(invalid(
                "NTFS ordinary subsequent-generation boundary conflict",
            ));
        }
    } else if !report.pages[probe].usa_error
        && !report.pages[probe]
            .error
            .as_ref()
            .is_some_and(|e| e.kind == ErrorKind::Io)
    {
        report.stop = NtfsLogOrdinaryStop::UnsupportedPage;
        return Ok(());
    }
    report.pages[probe].partial_transition = Some(NtfsLogPartialProbeTransition::FinalBoundary);
    mark_boundary(report);
    Ok(())
}
