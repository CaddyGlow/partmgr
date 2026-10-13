//! Logical NTFS stream export with retained acquisition stability and bounded reads.
//! Resident and compressed data have logical provenance without an invented
//! physical byte mapping. A completed hash identifies exported bytes only.
use crate::{
    forensics::*,
    forensics_extract::ExtractionOutcome,
    forensics_ntfs::{MeteredSource, scan_resources, stop_for_metered_error},
    fs_core::*,
    fs_ntfs::{NtfsCompressionLimits, NtfsReadLimits, NtfsStreamLimits, NtfsVolume},
    io::{self, ReadAt},
    platform::sync::Arc,
};
use sha2::{Digest, Sha256};
/// Streaming logical evidence, independent of physical container offsets.
pub enum StreamExtractionEvent<'a> {
    /// Native logical extent semantics, before its output bytes.
    Extent(&'a LogicalExtent),
    /// Decoded stream bytes, preserving ordered logical offsets.
    Bytes {
        /// Logical stream offset.
        offset: u64,
        /// Borrowed bytes from resident, mapped or decoded content.
        bytes: &'a [u8],
    },
    /// Successfully delivered logical coverage.
    Coverage(CoverageEvent),
}
fn interrupted() -> Error {
    Error::new(ErrorKind::InvalidOperation, "NTFS extraction stopped")
}
/// Extract one validated live stream or ADS. All backing reads, including MFT
/// bootstrap and compressed-unit expansion, share `read_bytes`. Logical output
/// has its independent ceiling. The stable source and memory lease remain alive
/// until the terminal outcome is produced; incomplete output is a hashed prefix.
#[allow(clippy::too_many_arguments)]
pub fn extract_live_stream(
    source: &ForensicSource,
    slot: u64,
    name: &[u16],
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    compression: Option<NtfsCompressionLimits>,
    limits: ScanLimits,
    resources: &Resources,
    control: &dyn ScanControl,
    mut visitor: impl FnMut(StreamExtractionEvent<'_>) -> io::Result<()>,
) -> ExtractionOutcome {
    let mut scan = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: source.len(),
        },
        "ntfs-live-stream/bootstrap",
    )
    .with_source_id(source.id());
    let mut hash = Sha256::new();
    let mut output_bytes = 0;
    let mut stop = None;
    let metered = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));
    let result = (|| -> Result<()> {
        if control.cancelled() {
            stop = Some(StopReason::Cancelled);
            return Err(interrupted());
        }
        let (r, _lease) = scan_resources(resources, limits)?;

        let volume = NtfsVolume::open_for_forensics(metered.clone(), read, streams, &r)?;
        let object = volume.stream_identity(slot, &r)?;
        let file = match compression {
            Some(c) => volume.open_stream_with_compression(&object, name, streams, c, &r)?,
            None => volume.open_stream(&object, name, streams, &r)?,
        };
        scan = ScanOutcome::new(
            ByteRange {
                offset: 0,
                length: file.len(),
            },
            "ntfs-live-stream/logical-bytes",
        )
        .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
        .with_source_id(source.id());
        if file.is_empty() {
            return Ok(());
        }
        let size = limits.memory_bytes.min(64 * 1024).min(file.len()) as usize;
        if size == 0 {
            stop = Some(StopReason::ResourceLimit("memory_bytes"));
            return Err(interrupted());
        }
        let _scratch = r.memory.reserve(size as u64)?;
        let mut scratch = alloc::vec::Vec::new();
        scratch
            .try_reserve_exact(size)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS output scratch"))?;
        scratch.resize(size, 0);
        let mut extents = 0;
        let mut end = 0;
        file.visit_extents(&r, &mut |extent| {
            if control.cancelled() {
                stop = Some(StopReason::Cancelled);
                return Err(interrupted());
            }
            if extents >= limits.records {
                stop = Some(StopReason::ResourceLimit("records"));
                return Err(interrupted());
            }
            extents += 1;
            if extent.offset != end || extent.length == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "NTFS logical extent continuity",
                ));
            }
            end = end
                .checked_add(extent.length)
                .filter(|end| *end <= file.len())
                .ok_or_else(|| {
                    Error::new(ErrorKind::InvalidData, "NTFS logical extent overflow")
                })?;
            if let Err(e) = visitor(StreamExtractionEvent::Extent(&extent)) {
                stop = Some(StopReason::DeliveryFailed(e));
                return Err(interrupted());
            }
            scan.observations += 1;
            scan.last_delivered = Some(extent.offset);
            let mut done = 0;
            while done < extent.length {
                if control.cancelled() {
                    stop = Some(StopReason::Cancelled);
                    return Err(interrupted());
                }
                r.cancellation.check()?;
                source
                    .check_stability()
                    .map_err(|e| Error::io("NTFS extraction stability", e))?;
                let take = (extent.length - done)
                    .min(scratch.len() as u64)
                    .min(limits.output_bytes.saturating_sub(output_bytes))
                    as usize;
                if take == 0 {
                    stop = Some(StopReason::ResourceLimit("output_bytes"));
                    return Err(interrupted());
                }
                let offset = extent.offset + done;
                let count = match file.read_at(offset, &mut scratch[..take], &r) {
                    Ok(n) => n,
                    Err(e) => {
                        if e.kind == ErrorKind::Io {
                            let coverage = CoverageEvent {
                                range: ByteRange {
                                    offset,
                                    length: take as u64,
                                },
                                kind: CoverageKind::Unreadable,
                            };
                            if let Err(delivery) =
                                visitor(StreamExtractionEvent::Coverage(coverage))
                            {
                                stop = Some(StopReason::DeliveryFailed(delivery));
                                return Err(interrupted());
                            }
                            scan.coverage_events += 1;
                        }
                        return Err(e);
                    }
                };
                if count != take {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "NTFS extraction short stream read",
                    ));
                }
                if let Err(e) = visitor(StreamExtractionEvent::Bytes {
                    offset,
                    bytes: &scratch[..take],
                }) {
                    stop = Some(StopReason::DeliveryFailed(e));
                    return Err(interrupted());
                }
                hash.update(&scratch[..take]);
                output_bytes += take as u64;
                scan.last_delivered = Some(offset + take as u64);
                done += take as u64;
                let coverage = CoverageEvent {
                    range: ByteRange {
                        offset,
                        length: take as u64,
                    },
                    kind: CoverageKind::Inspected,
                };
                if let Err(e) = visitor(StreamExtractionEvent::Coverage(coverage)) {
                    stop = Some(StopReason::DeliveryFailed(e));
                    return Err(interrupted());
                }
                scan.coverage_events += 1;
                scan.advance(offset + take as u64);
            }
            Ok(())
        })?;
        if end != file.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "NTFS missing logical extent suffix",
            ));
        }
        Ok(())
    })();
    if let Err(e) = result {
        let bootstrap = scan.profile.ends_with("bootstrap");
        scan.stop_reason =
            stop.unwrap_or_else(|| stop_for_metered_error(e, source, bootstrap, &metered));
    }
    if let Err(e) = source.check_stability() {
        scan.stop_reason = StopReason::SourceStability(e);
    }
    ExtractionOutcome {
        scan,
        output_bytes,
        prefix_sha256: hash.finalize().into(),
    }
}
