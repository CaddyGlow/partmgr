//! Streaming candidate extraction with explicit gaps and current reuse evidence.
//!
//! Maps are evidence inputs, not proof of historical content. A completed hash
//! identifies the exported logical bytes only; it never authenticates a deleted file.
use crate::forensics::{
    ByteRange, CoverageEvent, CoverageKind, ForensicSource, ScanControl, ScanLimits, ScanOutcome,
    StopReason,
};
use crate::fs_core::Resources;
use crate::io::{self, ReadAt};
use sha2::{Digest, Sha256};

/// Current evidence about one candidate range, independent of historical reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseEvidence {
    /// Allocation or owner coverage is unavailable or incomplete.
    Unknown,
    /// Current bitmap says free; original content is still unproven.
    CurrentlyFree,
    /// Current allocation is known but ownership is unresolved.
    AllocatedOwnerUnknown,
    /// A current stream owns this range; candidate content may be overwritten.
    ConflictingOwner,
    /// Complete current ownership evidence identifies the selected live stream.
    SelectedLiveOwner,
}

/// Meaning of exported bytes; unavailable evidence is never zero-filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionKind {
    /// Ordinary candidate bytes at this volume-relative offset.
    Data(u64),
    /// Filesystem-validated sparse logical zeros.
    Sparse,
    /// Filesystem-validated allocated but uninitialized logical zeros.
    Unwritten,
    /// Missing evidence; extraction must stop at this range.
    Unavailable,
}

/// One complete, ordered candidate map entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionRange {
    /// Logical stream range.
    pub logical: ByteRange,
    /// Physical mapping or explicit logical zero/gap semantics.
    pub kind: ExtractionKind,
    /// Current evidence, never a verified historical-content claim.
    pub reuse: ReuseEvidence,
}

/// Streaming extraction output; callers retain native names and source identity.
pub enum ExtractionEvent<'a> {
    /// Metadata delivered before bytes from this range.
    Range(ExtractionRange),
    /// Logical bytes, emitted in order without concatenating across gaps.
    Bytes {
        /// Stream byte offset.
        offset: u64,
        /// Borrowed output chunk, valid for this callback only.
        bytes: &'a [u8],
    },
    /// Exact inspected logical coverage.
    Coverage(CoverageEvent),
}

/// Extraction terminal record. Persist it even when no bytes were exported.
#[derive(Debug)]
pub struct ExtractionOutcome {
    /// Shared traversal and delivery outcome.
    pub scan: ScanOutcome,
    /// Number of bytes successfully delivered.
    pub output_bytes: u64,
    /// Hash of the delivered prefix, explicitly incomplete unless scan completed.
    pub prefix_sha256: [u8; 32],
}

/// Export a checked map through a bounded visitor without opening host files.
///
/// The input map is caller-owned and must have been collected under its own
/// resource budget. Every nonempty range must cover the stream exactly in order.
/// Callback errors preserve the last fully delivered coverage boundary. Failed
/// callbacks may have external side effects; the terminal result is incomplete.
pub fn extract_ranges(
    source: &ForensicSource,
    length: u64,
    ranges: &[ExtractionRange],
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
    visitor: &mut dyn FnMut(ExtractionEvent<'_>) -> io::Result<()>,
) -> ExtractionOutcome {
    let mut scan = ScanOutcome::new(ByteRange { offset: 0, length }, "candidate-extraction-v1")
        .with_coordinate_space(crate::forensics::CoordinateSpace::LogicalStreamBytes);
    let mut hash = Sha256::new();
    let mut output_bytes = 0u64;
    let mut run = |scan: &mut ScanOutcome,
                   hash: &mut Sha256,
                   output_bytes: &mut u64|
     -> Result<(), StopReason> {
        if control.cancelled() || resources.cancellation.check().is_err() {
            return Err(StopReason::Cancelled);
        }
        source
            .check_stability()
            .map_err(StopReason::SourceStability)?;
        if ranges.len() as u64 > limits.records {
            return Err(StopReason::ResourceLimit("records"));
        }
        let mut end = 0u64;
        for range in ranges {
            if control.cancelled() || resources.cancellation.check().is_err() {
                return Err(StopReason::Cancelled);
            }
            if range.logical.offset != end || range.logical.length == 0 {
                return Err(StopReason::InvalidBootstrap(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "candidate map is not ordered and complete",
                )));
            }
            end = end
                .checked_add(range.logical.length)
                .filter(|end| *end <= length)
                .ok_or_else(|| {
                    StopReason::InvalidBootstrap(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "candidate map exceeds stream",
                    ))
                })?;
            if let ExtractionKind::Data(offset) = range.kind {
                ByteRange::checked(offset, range.logical.length, source.len())
                    .map_err(StopReason::InvalidBootstrap)?;
            }
        }
        if end != length {
            return Err(StopReason::InvalidBootstrap(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate map has missing suffix",
            )));
        }
        if length == 0 {
            return Ok(());
        }
        let scratch = limits.memory_bytes.min(64 * 1024).min(length) as usize;
        if scratch == 0 {
            return Err(StopReason::ResourceLimit("memory_bytes"));
        }
        let _reservation = resources
            .memory
            .reserve(scratch as u64)
            .map_err(|_| StopReason::ResourceLimit("shared_memory"))?;
        let mut buffer = alloc::vec::Vec::new();
        buffer
            .try_reserve_exact(scratch)
            .map_err(|_| StopReason::ResourceLimit("memory_bytes"))?;
        buffer.resize(scratch, 0);
        let mut read_bytes = 0u64;
        for (index, range) in ranges.iter().enumerate() {
            if control.cancelled() || resources.cancellation.check().is_err() {
                return Err(StopReason::Cancelled);
            }
            if index as u64 >= limits.records {
                return Err(StopReason::ResourceLimit("records"));
            }
            visitor(ExtractionEvent::Range(*range)).map_err(StopReason::DeliveryFailed)?;
            scan.observations += 1;
            if range.kind == ExtractionKind::Unavailable {
                visitor(ExtractionEvent::Coverage(CoverageEvent {
                    range: range.logical,
                    kind: CoverageKind::Unreadable,
                }))
                .map_err(StopReason::DeliveryFailed)?;
                scan.coverage_events += 1;
                return Err(StopReason::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "candidate evidence unavailable",
                )));
            }
            let mut done = 0u64;
            while done < range.logical.length {
                if control.cancelled() || resources.cancellation.check().is_err() {
                    return Err(StopReason::Cancelled);
                }
                source
                    .check_stability()
                    .map_err(StopReason::SourceStability)?;
                let count = (range.logical.length - done).min(buffer.len() as u64) as usize;
                if (count as u64) > limits.output_bytes.saturating_sub(*output_bytes) {
                    return Err(StopReason::ResourceLimit("output_bytes"));
                }
                let bytes = &mut buffer[..count];
                match range.kind {
                    ExtractionKind::Data(offset) => {
                        if count as u64 > limits.read_bytes.saturating_sub(read_bytes) {
                            return Err(StopReason::ResourceLimit("read_bytes"));
                        }
                        read_bytes += count as u64;
                        if let Err(error) = source.read_exact_at(offset + done, bytes) {
                            visitor(ExtractionEvent::Coverage(CoverageEvent {
                                range: ByteRange {
                                    offset: range.logical.offset + done,
                                    length: count as u64,
                                },
                                kind: CoverageKind::Unreadable,
                            }))
                            .map_err(StopReason::DeliveryFailed)?;
                            scan.coverage_events += 1;
                            return Err(match source.check_stability() {
                                Err(cause) => StopReason::SourceStability(cause),
                                Ok(()) => StopReason::Io(error),
                            });
                        }
                    }
                    ExtractionKind::Sparse | ExtractionKind::Unwritten => bytes.fill(0),
                    ExtractionKind::Unavailable => {
                        return Err(StopReason::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "candidate evidence unavailable",
                        )));
                    }
                }
                let position = range.logical.offset + done;
                visitor(ExtractionEvent::Bytes {
                    offset: position,
                    bytes,
                })
                .map_err(StopReason::DeliveryFailed)?;
                hash.update(&*bytes);
                *output_bytes += count as u64;
                visitor(ExtractionEvent::Coverage(CoverageEvent {
                    range: ByteRange {
                        offset: position,
                        length: count as u64,
                    },
                    kind: CoverageKind::Inspected,
                }))
                .map_err(StopReason::DeliveryFailed)?;
                scan.coverage_events += 1;
                done += count as u64;
                scan.advance(position + count as u64);
            }
        }
        source
            .check_stability()
            .map_err(StopReason::SourceStability)?;
        Ok(())
    };
    if let Err(reason) = run(&mut scan, &mut hash, &mut output_bytes) {
        scan.stop_reason = reason;
    }
    ExtractionOutcome {
        scan,
        output_bytes,
        prefix_sha256: hash.finalize().into(),
    }
}
