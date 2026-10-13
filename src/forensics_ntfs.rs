//! Read-only NTFS FILE-slot evidence. Raw bytes survive failed validation.
//!
//! Free FILE slots are evidence of unused, stale or deleted structures; neither
//! their in-use flag nor a currently free allocation bit proves deletion history.
#[cfg(not(feature = "std"))]
use crate::platform::prelude::*;
use crate::{
    fs_core::*,
    fs_ntfs::{self, NtfsVolume},
};

/// An attribute framed within a fixup-validated FILE record.
#[derive(Debug)]
pub struct AttributeObservation<'a> {
    /// Offset inside the fixed-up FILE record.
    pub offset: usize,
    /// Native attribute type.
    pub kind: u32,
    /// Complete native encoding, including unknown fields and native names.
    pub raw: &'a [u8],
    /// Resident value, when present; no nonresident mapping is inferred here.
    pub resident: Option<&'a [u8]>,
}
impl AttributeObservation<'_> {
    /// Typed native STANDARD_INFORMATION with all four FILETIME timestamps.
    pub fn standard_information(&self) -> Option<fs_ntfs::NtfsNativeStandardInformation<'_>> {
        if self.kind != 0x10 {
            return None;
        }
        fs_ntfs::stream::standard_view(self.resident?)
    }
    /// Independent FILE_NAME timestamps, parent reference, namespace and raw UTF16.
    pub fn file_name(&self) -> Option<fs_ntfs::NtfsNativeFileName<'_>> {
        if self.kind != 0x30 {
            return None;
        }
        fs_ntfs::stream::filename_view(self.resident?)
    }
    /// Exact native attribute-name UTF16 units, including unpaired surrogates.
    pub fn name(&self) -> impl Iterator<Item = u16> + '_ {
        let offset = usize::from(word(self.raw, 10));
        let length = usize::from(self.raw[9]);
        (0..length).map(move |n| word(self.raw, offset + n * 2))
    }
}
/// Validated framing is independent of historical authenticity.
#[derive(Debug)]
pub struct RecordObservation<'a> {
    _reservation: Reservation,
    /// Exact fixed-up bytes. The separate raw observation retains sector trailers.
    pub fixed: &'a [u8],
    /// Native sequence number, including stale values in free slots.
    pub sequence: u16,
    /// FILE in-use flag, independent of MFT bitmap allocation.
    pub in_use: bool,
    /// Exact base reference, retaining sequence bits even in unallocated slots.
    pub base_reference: u64,
    /// Attribute framing; timestamp values and UTF16 names remain native bytes.
    pub attributes: Vec<AttributeObservation<'a>>,
}
fn word(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes([b[n], b[n + 1]])
}
fn dword(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes([b[n], b[n + 1], b[n + 2], b[n + 3]])
}
fn invalid(s: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}

/// Validate FILE and attribute framing after applying USA fixups in place.
/// On error, this scratch copy may be partially fixed up; preserve raw bytes first.
/// All-zero unused slots are represented by `Ok(None)`.
pub fn decode_record<'a>(
    bytes: &'a mut [u8],
    attribute_limit: usize,
    r: &Resources,
) -> Result<Option<RecordObservation<'a>>> {
    r.cancellation.check()?;
    if bytes.len() < 512 || !bytes.len().is_multiple_of(512) {
        return Err(invalid("NTFS forensic FILE record size"));
    }
    fs_ntfs::audit_fixup(bytes, r)?;
    if bytes.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let start = usize::from(word(bytes, 20));
    let used = dword(bytes, 24) as usize;
    if start < 48
        || !start.is_multiple_of(8)
        || used > bytes.len()
        || start.checked_add(4).is_none_or(|n| n > used)
        || dword(bytes, 28) as usize != bytes.len()
    {
        return Err(invalid("NTFS forensic FILE framing"));
    }
    let _reservation = r.memory.reserve(
        (attribute_limit.min((used - start) / 24) as u64)
            .saturating_mul(core::mem::size_of::<AttributeObservation>() as u64),
    )?;
    let mut attributes = Vec::new();
    attributes
        .try_reserve(attribute_limit.min((used - start) / 24))
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS forensic attributes"))?;
    let mut at = start;
    loop {
        r.cancellation.check()?;
        if at.checked_add(4).is_none_or(|n| n > used) {
            return Err(invalid("NTFS missing attribute terminator"));
        }
        let kind = dword(bytes, at);
        if kind == u32::MAX {
            break;
        }
        if attributes.len() == attribute_limit {
            return Err(Error::new(
                ErrorKind::BudgetExhausted,
                "NTFS forensic attribute ceiling",
            ));
        }
        if at.checked_add(24).is_none_or(|n| n > used) {
            return Err(invalid("NTFS forensic attribute header"));
        }
        let len = dword(bytes, at + 4) as usize;
        if len < 24 || !len.is_multiple_of(8) || at.checked_add(len).is_none_or(|n| n > used) {
            return Err(invalid("NTFS forensic attribute bounds"));
        }
        let raw = &bytes[at..at + len];
        let header = match raw[8] {
            0 => 24,
            1 => 64,
            _ => return Err(invalid("NTFS forensic attribute form")),
        };
        if len < header {
            return Err(invalid("NTFS forensic nonresident header"));
        }
        let name_at = usize::from(word(raw, 10));
        let name_len = usize::from(raw[9]) * 2;
        if name_len != 0
            && (name_at < header || name_at.checked_add(name_len).is_none_or(|n| n > len))
        {
            return Err(invalid("NTFS forensic native attribute name"));
        }
        if raw[8] == 1 {
            let run_offset = usize::from(word(raw, 32));
            if run_offset < header
                || run_offset >= len
                || name_len != 0 && run_offset < name_at + name_len
            {
                return Err(invalid("NTFS forensic mapping-pairs framing"));
            }
        }
        let resident = if raw[8] == 0 {
            let off = usize::from(word(raw, 20));
            let size = dword(raw, 16) as usize;
            if off < header
                || off.checked_add(size).is_none_or(|n| n > len)
                || name_len != 0 && off < name_at + name_len
            {
                return Err(invalid("NTFS forensic resident value"));
            }
            Some(&raw[off..off + size])
        } else {
            None
        };
        attributes.push(AttributeObservation {
            offset: at,
            kind,
            raw,
            resident,
        });
        at += len;
    }
    Ok(Some(RecordObservation {
        _reservation,
        fixed: bytes,
        sequence: word(bytes, 16),
        in_use: word(bytes, 22) & 1 != 0,
        base_reference: u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| invalid("NTFS base reference"))?,
        ),
        attributes,
    }))
}

/// Read original sector bytes through the proven MFT mapping, without validating
/// the slot or losing damaged evidence. The returned storage holds a memory lease.
pub fn raw_record(volume: &NtfsVolume, slot: u64, r: &Resources) -> Result<Budgeted<Vec<u8>>> {
    volume.forensic_raw_record(slot, r)
}

use crate::fs_ntfs::{NtfsReadLimits, NtfsStreamLimits};
use crate::{
    forensics::*,
    io::{self, ReadAt},
    platform::sync::Arc,
};
/// Borrowed evidence delivered at an independently readable MFT boundary.
pub struct SlotObservation<'a> {
    /// Exact bounded source view; detached evidence may lack a binding.
    pub source_id: Option<SourceId>,
    /// Acquisition identity, never a claimed content digest.
    pub source: &'a SourceIdentity,
    /// Logical offset in the MFT stream (not a contiguous volume offset).
    pub stream_offset: u64,
    /// Exact physical volume fragments carrying this slot; never container offsets.
    pub volume_ranges: &'a [ByteRange],
    /// Mirror agreement for the mirrored prefix; unavailable mirrors retain errors.
    pub mirror_agrees: Result<Option<bool>>,
    /// Native MFT slot number.
    pub slot: u64,
    /// Original bytes before USA substitution.
    pub raw: &'a [u8],
    /// Fixup/framing result; failed records retain raw evidence.
    pub decoded: Result<Option<RecordObservation<'a>>>,
    /// Independent MFT allocation bit; missing mapping/read remains unknown.
    pub allocated: Result<Option<bool>>,
}
/// Inventory and coverage events share one fallible output boundary.
#[expect(
    clippy::large_enum_variant,
    reason = "borrowed slot carries raw and independent validation results without per-event allocation"
)]
pub enum InventoryEvent<'a> {
    /// Raw and independently validated evidence.
    Slot(SlotObservation<'a>),
    /// Logical MFT stream coverage; it is not a container byte mapping.
    Coverage(CoverageEvent),
}
pub(crate) struct MeteredSource {
    source: ForensicSource,
    remaining: spin::Mutex<(u64, bool)>,
}
impl MeteredSource {
    pub(crate) fn new(source: ForensicSource, read_bytes: u64) -> Self {
        Self {
            source,
            remaining: spin::Mutex::new((read_bytes, false)),
        }
    }
    pub(crate) fn exhausted(&self) -> bool {
        self.remaining.lock().1
    }
}
impl ReadAt for MeteredSource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        let mut state = self.remaining.lock();
        if let Some(remaining) = state.0.checked_sub(bytes.len() as u64) {
            state.0 = remaining;
        } else {
            state.1 = true;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                Error::new(ErrorKind::BudgetExhausted, "forensic read_bytes ceiling"),
            ));
        }
        drop(state);
        self.source.read_exact_at(offset, bytes)
    }
}
fn shared_failure(context: &'static str, error: &Arc<Error>) -> Error {
    let mut wrapped = Error::io(context, io::Error::new(io::ErrorKind::Other, error.clone()));
    wrapped.kind = error.kind;
    wrapped
}
pub(crate) fn scan_resources(
    r: &Resources,
    limits: ScanLimits,
) -> Result<(Resources, Reservation)> {
    let capacity = limits.memory_bytes.min(r.memory.remaining());
    let reservation = r.memory.reserve(capacity)?;
    Ok((
        Resources {
            memory: Budget::new(capacity),
            cancellation: r.cancellation.clone(),
        },
        reservation,
    ))
}
// These exact decoder tags identify configured ceilings. Unrecognized native
// budgets retain an explicit decoder_limit label rather than inventing memory usage.
fn resource_ceiling(context: &str) -> &'static str {
    match context {
        "shared resource budget exceeded"
        | "NTFS allocation failed"
        | "NTFS forensic attributes"
        | "NTFS fixed record scratch"
        | "NTFS mirror comparison scratch" => "memory_bytes",
        "NTFS resolution work envelope overflow"
        | "NTFS resolution work envelope ceiling"
        | "NTFS bootstrap list framing work"
        | "NTFS bootstrap reference work ceiling"
        | "NTFS bootstrap completeness work overflow"
        | "NTFS bootstrap completeness work"
        | "NTFS restart work limit"
        | "USN extraction work"
        | "NTFS compression work limit"
        | "NTFS compressed map work limit" => "work",
        "NTFS directory entry limit" => "directory_entries",
        "NTFS directory block limit" => "directory_blocks",
        "NTFS index depth limit" | "NTFS index depth overflow" => "directory_depth",
        "NTFS attribute limit"
        | "NTFS forensic attribute ceiling"
        | "NTFS resolved attribute ceiling"
        | "NTFS bootstrap aggregate attribute ceiling"
        | "NTFS bootstrap attributes" => "attributes",
        "NTFS native name limit" => "names",
        "NTFS allocation run limit"
        | "NTFS run limit overflow"
        | "NTFS stream run cap"
        | "NTFS aggregate stream runs"
        | "NTFS sparse segment run cap"
        | "NTFS bootstrap aggregate runs" => "runs",
        "NTFS ATTRIBUTE_LIST entry limit" => "list_entries",
        "NTFS ATTRIBUTE_LIST byte limit"
        | "NTFS bootstrap list byte ceiling"
        | "NTFS bootstrap list bytes" => "list_bytes",
        "NTFS extension record limit" | "NTFS bootstrap extension count" => "extension_records",
        "NTFS restart page ceiling" => "restart_page_bytes",
        "NTFS restart client ceiling" => "clients",
        "NTFS compression read unit limit" => "compression_units_per_read",
        "NTFS compressed unit byte limit" => "compression_unit_bytes",
        "USN extraction extent ceiling" => "extents",
        "USN extraction read ceiling" => "journal_read_bytes",
        "USN record/count ceiling" => "journal_records",
        "USN record byte ceiling" => "journal_record_bytes",
        _ => "decoder_limit",
    }
}
fn error_resource_ceiling(error: &Error) -> &'static str {
    let mut current = error;
    for _ in 0..16 {
        let ceiling = resource_ceiling(&current.context);
        if ceiling != "decoder_limit" {
            return ceiling;
        }
        let Some(source) = current.source.as_ref().and_then(|source| source.get_ref()) else {
            break;
        };
        if let Some(next) = source.downcast_ref::<Error>() {
            current = next;
        } else if let Some(next) = source.downcast_ref::<Arc<Error>>() {
            current = next;
        } else {
            break;
        }
    }
    "decoder_limit"
}
fn retain_budget_cause<T>(result: &mut Result<T>) -> Option<Arc<Error>> {
    if !result
        .as_ref()
        .is_err_and(|error| error.kind == ErrorKind::BudgetExhausted)
    {
        return None;
    }
    let original = core::mem::replace(result, Err(invalid("temporary budget transfer")))
        .err()
        .expect("checked error");
    let shared = Arc::new(original);
    *result = Err(shared_failure("NTFS observation resource ceiling", &shared));
    Some(shared)
}
pub(crate) fn stop_for_error(error: Error, source: &ForensicSource, bootstrap: bool) -> StopReason {
    if let Err(e) = source.check_stability() {
        return StopReason::SourceStability(e);
    }
    match error.kind {
        ErrorKind::BudgetExhausted => StopReason::ResourceCause {
            ceiling: error_resource_ceiling(&error),
            cause: io::Error::new(io::ErrorKind::Other, error),
        },
        ErrorKind::Cancelled => StopReason::Cancelled,
        ErrorKind::Unsupported => {
            StopReason::UnsupportedCause(io::Error::new(io::ErrorKind::Unsupported, error))
        }
        _ => {
            let e = io::Error::new(io::ErrorKind::Other, error);
            if bootstrap {
                StopReason::InvalidBootstrap(e)
            } else {
                StopReason::Io(e)
            }
        }
    }
}
pub(crate) fn stop_for_metered_error(
    error: Error,
    source: &ForensicSource,
    bootstrap: bool,
    meter: &MeteredSource,
) -> StopReason {
    if meter.exhausted() {
        if let Err(e) = source.check_stability() {
            return StopReason::SourceStability(e);
        }
        return StopReason::ResourceCause {
            ceiling: "read_bytes",
            cause: io::Error::new(io::ErrorKind::Other, error),
        };
    }
    stop_for_error(error, source, bootstrap)
}
/// Stream all declared MFT slots, including unallocated and damaged records.
/// Dirty volume flags are admitted without replay or writes. Bootstrap must be
/// validated; unsupported bootstrap mappings stop before slot enumeration.
/// This profile does not establish current cluster ownership or historical reuse.
pub fn inventory(
    source: &ForensicSource,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    r: &Resources,
    mut visitor: impl FnMut(InventoryEvent<'_>) -> io::Result<bool>,
) -> ScanOutcome {
    let mut outcome = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: source.len(),
        },
        "ntfs-mft-slots/bootstrap",
    )
    .with_source_id(source.id());
    if control.cancelled() {
        outcome.stop_reason = StopReason::Cancelled;
        return outcome;
    }
    let (scan_r, _scan_reservation) = match scan_resources(r, limits) {
        Ok(v) => v,
        Err(e) => {
            outcome.stop_reason = stop_for_error(e, source, true);
            return outcome;
        }
    };
    let r = &scan_r;
    let metered = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));

    if control.cancelled() {
        outcome.stop_reason = StopReason::Cancelled;
        return outcome;
    }
    let volume = match NtfsVolume::open_for_forensics(metered.clone(), read, streams, r) {
        Ok(v) => v,
        Err(e) => {
            outcome.stop_reason = stop_for_metered_error(e, source, true, &metered);
            return outcome;
        }
    };
    let size = volume.geometry().record_bytes() as u64;
    outcome = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: volume.record_count() * size,
        },
        "ntfs-mft-slots/logical-stream",
    )
    .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
    .with_source_id(source.id());
    let bitmap = volume
        .stream_identity(0, r)
        .and_then(|object| volume.open_native_attribute_stream(&object, 0xb0, &[], streams, r))
        .map_err(Arc::new);
    let mirror = volume
        .stream_identity(1, r)
        .and_then(|object| volume.open_native_attribute_stream(&object, 0x80, &[], streams, r))
        .map_err(Arc::new);
    for slot in 0..volume.record_count() {
        if control.cancelled() {
            outcome.stop_reason = StopReason::Cancelled;
            break;
        }
        if let Err(e) = source.check_stability() {
            outcome.stop_reason = StopReason::SourceStability(e);
            break;
        }
        if slot >= limits.records {
            outcome.stop_reason = StopReason::ResourceLimit("records");
            break;
        }

        if size.saturating_mul(slot + 1) > limits.output_bytes {
            outcome.stop_reason = StopReason::ResourceLimit("output_bytes");
            break;
        }
        if size.saturating_mul(2) > limits.memory_bytes {
            outcome.stop_reason = StopReason::ResourceLimit("memory_bytes");
            break;
        }
        let raw = match raw_record(&volume, slot, r) {
            Ok(b) => b,
            Err(e) => {
                let is_io = e.kind == ErrorKind::Io;
                outcome.stop_reason = stop_for_metered_error(e, source, false, &metered);
                if is_io {
                    match visitor(InventoryEvent::Coverage(CoverageEvent {
                        range: ByteRange {
                            offset: slot * size,
                            length: size,
                        },
                        kind: CoverageKind::Unreadable,
                    })) {
                        Ok(_) => outcome.coverage_events += 1,
                        Err(e) => outcome.stop_reason = StopReason::DeliveryFailed(e),
                    }
                }
                break;
            }
        };
        let scratch_reservation = match r.memory.reserve(size) {
            Ok(v) => v,
            Err(_) => {
                outcome.stop_reason = StopReason::ResourceLimit("memory_bytes");
                break;
            }
        };
        let fixed = (|| -> Result<Vec<u8>> {
            let mut v = Vec::new();
            v.try_reserve_exact(raw.len())
                .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS fixed record scratch"))?;
            v.extend_from_slice(&raw);
            Ok(v)
        })();
        let mut fixed = match fixed {
            Ok(v) => v,
            Err(_) => {
                outcome.stop_reason = StopReason::ResourceLimit("memory_bytes");
                break;
            }
        };
        let mut allocated = match &bitmap {
            Ok(file) => {
                let mut b = [0];
                match file.read_at(slot / 8, &mut b, r) {
                    Ok(1) => Ok(Some(b[0] & (1 << (slot % 8)) != 0)),
                    Ok(_) => Err(invalid("NTFS MFT bitmap truncated")),
                    Err(e) => Err(e),
                }
            }
            Err(error) => Err(shared_failure(
                "NTFS MFT bitmap bootstrap unavailable",
                error,
            )),
        };
        let _scratch_reservation = scratch_reservation;
        let map = volume.native_mft_map().0;
        let _range_reservation = match r
            .memory
            .reserve((map.len() as u64).saturating_mul(core::mem::size_of::<ByteRange>() as u64))
        {
            Ok(v) => v,
            Err(e) => {
                outcome.stop_reason = stop_for_metered_error(e, source, false, &metered);
                break;
            }
        };
        let mut volume_ranges = Vec::new();
        if volume_ranges.try_reserve(map.len()).is_err() {
            outcome.stop_reason = StopReason::ResourceLimit("memory_bytes");
            break;
        }
        for extent in map {
            let start = (slot * size).max(extent.offset);
            let end = ((slot + 1) * size).min(extent.offset + extent.length);
            if start < end
                && let crate::fs_file::ExtentKind::Data(at) = extent.kind
            {
                volume_ranges.push(ByteRange {
                    offset: at + start - extent.offset,
                    length: end - start,
                });
            }
        }
        let mirrored_count = (volume.geometry().cluster_bytes() / size).max(4);
        let mut mirror_agrees = if slot < mirrored_count {
            match &mirror {
                Ok(stream) => volume
                    .audit_mirror_bytes(stream, slot, r)
                    .and_then(|mirror_fixed| {
                        let _primary_reservation = r.memory.reserve(size)?;
                        let mut primary = Vec::new();
                        primary.try_reserve_exact(fixed.len()).map_err(|_| {
                            Error::new(ErrorKind::BudgetExhausted, "NTFS mirror comparison scratch")
                        })?;
                        primary.extend_from_slice(&fixed);
                        fs_ntfs::audit_fixup(&mut primary, r)?;
                        Ok(Some(primary.as_slice() == mirror_fixed.as_slice()))
                    }),
                Err(error) => Err(shared_failure(
                    "NTFS MFT mirror bootstrap unavailable",
                    error,
                )),
            }
        } else {
            Ok(None)
        };
        let mut decoded = decode_record(&mut fixed, read.attributes, r);
        let exhausted = retain_budget_cause(&mut decoded)
            .or_else(|| retain_budget_cause(&mut allocated))
            .or_else(|| retain_budget_cause(&mut mirror_agrees));
        match visitor(InventoryEvent::Slot(SlotObservation {
            source_id: Some(source.id()),
            source: source.identity(),
            stream_offset: slot * size,
            volume_ranges: &volume_ranges,
            mirror_agrees,
            slot,
            raw: &raw,
            decoded,
            allocated,
        })) {
            Ok(proceed) => {
                outcome.observations += 1;
                outcome.last_delivered = Some(slot * size);
                if !proceed {
                    outcome.stop_reason = StopReason::CallerStop;
                    break;
                }
            }
            Err(e) => {
                outcome.stop_reason = StopReason::DeliveryFailed(e);
                break;
            }
        }
        let event = CoverageEvent {
            range: ByteRange {
                offset: slot * size,
                length: size,
            },
            kind: CoverageKind::Inspected,
        };
        match visitor(InventoryEvent::Coverage(event)) {
            Ok(proceed) => {
                outcome.coverage_events += 1;
                outcome.advance((slot + 1) * size);
                if !proceed {
                    outcome.stop_reason = StopReason::CallerStop;
                    break;
                }
            }
            Err(e) => {
                outcome.stop_reason = StopReason::DeliveryFailed(e);
                break;
            }
        }
        if let Some(cause) = exhausted {
            outcome.stop_reason = StopReason::ResourceCause {
                ceiling: if metered.exhausted() {
                    "read_bytes"
                } else {
                    error_resource_ceiling(&cause)
                },
                cause: io::Error::new(io::ErrorKind::Other, cause),
            };
            break;
        }
    }
    if let Err(e) = source.check_stability() {
        outcome.stop_reason = StopReason::SourceStability(e);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(65536),
            cancellation: Cancellation::default(),
        }
    }
    fn record() -> Vec<u8> {
        let mut b = vec![0; 1024];
        b[..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&48u16.to_le_bytes());
        b[6..8].copy_from_slice(&3u16.to_le_bytes());
        b[16..18].copy_from_slice(&17u16.to_le_bytes());
        b[20..22].copy_from_slice(&56u16.to_le_bytes());
        b[24..28].copy_from_slice(&64u32.to_le_bytes());
        b[28..32].copy_from_slice(&1024u32.to_le_bytes());
        b[48..50].copy_from_slice(&7u16.to_le_bytes());
        b[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        b[510..512].copy_from_slice(&7u16.to_le_bytes());
        b[1022..1024].copy_from_slice(&7u16.to_le_bytes());
        b
    }
    #[test]
    fn free_slot_retains_stale_sequence_and_raw_trailers() {
        let raw = record();
        let mut fixed = raw.clone();
        let decoded = decode_record(&mut fixed, 1, &resources()).unwrap().unwrap();
        assert_eq!(decoded.sequence, 17);
        assert!(!decoded.in_use);
        assert_eq!(&raw[510..512], &7u16.to_le_bytes());
        assert_eq!(&decoded.fixed[510..512], &[0, 0]);
    }
    #[test]
    fn torn_record_is_rejected_without_decoding_attributes() {
        let mut b = record();
        b[1022] = 8;
        assert_eq!(
            decode_record(&mut b, 1, &resources()).unwrap_err().kind,
            ErrorKind::InvalidData
        );
    }
    #[test]
    fn empty_slot_is_distinct_from_validated_file() {
        let mut b = vec![0; 1024];
        assert!(decode_record(&mut b, 0, &resources()).unwrap().is_none());
    }
    #[test]
    fn malformed_attribute_is_never_validated() {
        let mut b = record();
        b[56..60].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(decode_record(&mut b, 3, &resources()).is_err());
    }
}

/// Current physical allocation claim, separate from allocation bitmap evidence.
#[derive(Debug, Clone, Copy)]
pub struct OwnershipObservation {
    /// Exact bounded source view carrying this claim.
    pub source_id: SourceId,
    /// Base record owning the logical stream.
    pub owner: u64,
    /// Physical carrying record (may be an ATTRIBUTE_LIST extension).
    pub carrier: u64,
    /// Attribute type; names remain available through native attribute inventory.
    pub kind: u32,
    /// Fixed-up attribute offset in the carrier.
    pub attribute_offset: usize,
    /// Volume byte range allocated to this stream, including allocation beyond EOF.
    pub range: ByteRange,
}
/// Current ownership findings and coverage in logical MFT coordinates.
pub enum OwnershipEvent {
    /// Current physical claim, independently of allocation bits.
    Claim(OwnershipObservation),
    /// Inspected MFT boundary; a complete domain is required for absence claims.
    Coverage(CoverageEvent),
}
fn deliver_coverage(
    out: &mut ScanOutcome,
    range: ByteRange,
    deliver: impl FnOnce(CoverageEvent) -> io::Result<bool>,
) -> bool {
    match deliver(CoverageEvent {
        range,
        kind: CoverageKind::Inspected,
    }) {
        Ok(proceed) => {
            out.coverage_events += 1;
            out.advance(range.offset + range.length);
            if !proceed {
                out.stop_reason = StopReason::CallerStop;
            }
            proceed
        }
        Err(e) => {
            out.stop_reason = StopReason::DeliveryFailed(e);
            false
        }
    }
}
/// Stream current owner claims from validated allocated base records.
/// Incomplete outcomes leave absence of a claim unknown. Claims may overlap;
/// consumers must compare ranges and must not collapse conflicting owners.
#[allow(clippy::too_many_arguments)]
pub fn current_owners(
    source: &ForensicSource,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    r: &Resources,
    mut visitor: impl FnMut(OwnershipEvent) -> io::Result<bool>,
) -> ScanOutcome {
    let mut out = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: source.len(),
        },
        "ntfs-current-owners/bootstrap",
    )
    .with_source_id(source.id());
    if control.cancelled() {
        out.stop_reason = StopReason::Cancelled;
        return out;
    }
    let (scan_r, _scan_reservation) = match scan_resources(r, limits) {
        Ok(v) => v,
        Err(e) => {
            out.stop_reason = stop_for_error(e, source, true);
            return out;
        }
    };
    let r = &scan_r;
    let metered = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));

    let volume = match NtfsVolume::open_for_forensics(metered.clone(), read, streams, r) {
        Ok(v) => v,
        Err(e) => {
            out.stop_reason = stop_for_metered_error(e, source, true, &metered);
            return out;
        }
    };
    let size = volume.geometry().record_bytes() as u64;
    out = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: volume.record_count() * size,
        },
        "ntfs-current-owners/logical-mft",
    )
    .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
    .with_source_id(source.id());
    let result = (|| -> Result<()> {
        let zero = volume.stream_identity(0, r)?;
        let bitmap = volume.open_native_attribute_stream(&zero, 0xb0, &[], streams, r)?;
        for slot in 0..volume.record_count() {
            if control.cancelled() {
                out.stop_reason = StopReason::Cancelled;
                return Ok(());
            }
            if slot >= limits.records {
                out.stop_reason = StopReason::ResourceLimit("records");
                return Ok(());
            }
            let mut bit = [0];
            if bitmap.read_at(slot / 8, &mut bit, r)? != 1 {
                return Err(invalid("NTFS ownership MFT bitmap truncated"));
            }
            let (in_use, sequence, base) = volume.audit_slot_reference(slot, r)?;
            if (bit[0] & (1 << (slot % 8)) != 0) != in_use {
                return Err(invalid("NTFS owner allocation bitmap disagreement"));
            }
            if in_use && base != 0 {
                let parent = volume.stream_identity(base & 0x0000_ffff_ffff_ffff, r)?;
                if parent.generation != base >> 48 {
                    return Err(invalid("NTFS extension base sequence mismatch"));
                }
                let resolved = volume.resolve_stream_record(&parent, streams, r)?;
                if !resolved.records.iter().any(|record| {
                    record.identity().native == slot.to_le_bytes()
                        && record.identity().generation == u64::from(sequence)
                }) {
                    return Err(invalid(
                        "NTFS allocated extension absent from base resolution",
                    ));
                }
            }
            if !in_use || base != 0 {
                if !deliver_coverage(
                    &mut out,
                    ByteRange {
                        offset: slot * size,
                        length: size,
                    },
                    |e| visitor(OwnershipEvent::Coverage(e)),
                ) {
                    return Ok(());
                }
                continue;
            }
            let object = volume.stream_identity(slot, r)?;
            let resolved = volume.resolve_stream_record(&object, streams, r)?;
            for carrier in &resolved.records {
                let carrier_slot = u64::from_le_bytes(
                    carrier
                        .identity()
                        .native
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid("NTFS carrier identity"))?,
                );
                let mut carrier_bit = [0];
                if bitmap.read_at(carrier_slot / 8, &mut carrier_bit, r)? != 1
                    || carrier_bit[0] & (1 << (carrier_slot % 8)) == 0
                {
                    return Err(invalid(
                        "NTFS resolved carrier bitmap allocation unavailable",
                    ));
                }
            }
            for (index, located) in resolved.attributes.iter().enumerate() {
                if !located.attribute.nonresident {
                    continue;
                }
                let name_bytes = fs_ntfs::stream::native_name(
                    &resolved.records[located.record],
                    located.attribute,
                );
                if resolved.attributes[..index].iter().any(|prev| {
                    prev.attribute.nonresident
                        && prev.attribute.kind == located.attribute.kind
                        && fs_ntfs::stream::native_name(
                            &resolved.records[prev.record],
                            prev.attribute,
                        ) == name_bytes
                }) {
                    continue;
                }
                let _name_reservation = r.memory.reserve(name_bytes.len() as u64)?;
                let name: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                let map = volume.native_map(
                    &resolved,
                    located.attribute.kind,
                    &name,
                    streams,
                    Some(fs_ntfs::NtfsCompressionLimits {
                        max_unit_bytes: 65536,
                        max_units_per_read: 1,
                        max_work: streams.work,
                    }),
                    r,
                )?;
                for claim in &map.claims {
                    if out.observations >= limits.output_bytes / 64 {
                        out.stop_reason = StopReason::ResourceLimit("output_bytes");
                        return Ok(());
                    }
                    let carrier = &resolved.records[claim.record];
                    let carrier_number = u64::from_le_bytes(
                        carrier
                            .identity()
                            .native
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid("NTFS owner identity"))?,
                    );
                    let observation = OwnershipObservation {
                        source_id: source.id(),
                        owner: slot,
                        carrier: carrier_number,
                        kind: claim.attribute.kind,
                        attribute_offset: claim.attribute.start,
                        range: ByteRange {
                            offset: claim.offset,
                            length: claim.length,
                        },
                    };
                    match visitor(OwnershipEvent::Claim(observation)) {
                        Ok(proceed) => {
                            out.observations += 1;
                            out.last_delivered = Some(slot * size);
                            if !proceed {
                                out.stop_reason = StopReason::CallerStop;
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            out.stop_reason = StopReason::DeliveryFailed(e);
                            return Ok(());
                        }
                    }
                }
            }
            if !deliver_coverage(
                &mut out,
                ByteRange {
                    offset: slot * size,
                    length: size,
                },
                |e| visitor(OwnershipEvent::Coverage(e)),
            ) {
                return Ok(());
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        let kind = match e.kind {
            ErrorKind::Io => Some(CoverageKind::Unreadable),
            ErrorKind::Unsupported | ErrorKind::InvalidData => Some(CoverageKind::Unsupported),
            _ => None,
        };
        out.stop_reason = stop_for_metered_error(e, source, false, &metered);
        if let Some(kind) = kind
            && out.unvisited.length > 0
        {
            match visitor(OwnershipEvent::Coverage(CoverageEvent {
                range: ByteRange {
                    offset: out.unvisited.offset,
                    length: size.min(out.unvisited.length),
                },
                kind,
            })) {
                Ok(_) => out.coverage_events += 1,
                Err(e) => out.stop_reason = StopReason::DeliveryFailed(e),
            }
        }
    }
    if let Err(e) = source.check_stability() {
        out.stop_reason = StopReason::SourceStability(e);
    }
    out
}

/// One available raw page of the current volume allocation bitmap.
/// Bit `n` describes cluster `n`, independently of current owner observations.
pub struct BitmapObservation<'a> {
    /// Exact bounded source view carrying these bytes.
    pub source_id: SourceId,
    /// Logical byte offset in `$Bitmap::$DATA`.
    pub offset: u64,
    /// Original bitmap bytes; padding bits must not be treated as clusters.
    pub bytes: &'a [u8],
    /// Number of clusters covered by filesystem geometry.
    pub cluster_count: u64,
}
/// Bitmap bytes and logical bitmap-stream coverage.
pub enum BitmapEvent<'a> {
    /// Current allocation evidence, preserving padding and raw bytes.
    Page(BitmapObservation<'a>),
    /// Delivered byte coverage; it is distinct from ownership-scan coverage.
    Coverage(CoverageEvent),
}
/// Stream bounded volume-bitmap pages; missing/truncated evidence stops with an
/// incomplete outcome and never becomes a free-allocation claim.
#[allow(clippy::too_many_arguments)]
pub fn volume_bitmap(
    source: &ForensicSource,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    r: &Resources,
    mut visitor: impl FnMut(BitmapEvent<'_>) -> io::Result<bool>,
) -> ScanOutcome {
    let mut out = ScanOutcome::new(
        ByteRange {
            offset: 0,
            length: source.len(),
        },
        "ntfs-volume-bitmap/bootstrap",
    )
    .with_source_id(source.id());
    if control.cancelled() {
        out.stop_reason = StopReason::Cancelled;
        return out;
    }
    let (scan_r, _scan_reservation) = match scan_resources(r, limits) {
        Ok(v) => v,
        Err(e) => {
            out.stop_reason = stop_for_error(e, source, true);
            return out;
        }
    };
    let r = &scan_r;
    let metered = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));

    let result = (|| -> Result<()> {
        let volume = NtfsVolume::open_for_forensics(metered.clone(), read, streams, r)?;
        let count = volume.geometry().volume_bytes() / volume.geometry().cluster_bytes();
        let length = count.div_ceil(8);
        out = ScanOutcome::new(
            ByteRange { offset: 0, length },
            "ntfs-volume-bitmap/logical-stream",
        )
        .with_coordinate_space(CoordinateSpace::LogicalStreamBytes)
        .with_source_id(source.id());
        let object = volume.stream_identity(6, r)?;
        let bitmap = volume.open_native_attribute_stream(&object, 0x80, &[], streams, r)?;
        let _reservation = r.memory.reserve(4096)?;
        let mut page = [0; 4096];
        let mut offset = 0;
        while offset < length {
            if control.cancelled() {
                out.stop_reason = StopReason::Cancelled;
                return Ok(());
            }
            if out.observations >= limits.records {
                out.stop_reason = StopReason::ResourceLimit("records");
                return Ok(());
            }
            let take = (length - offset).min(4096) as usize;
            if offset + take as u64 > limits.output_bytes {
                out.stop_reason = StopReason::ResourceLimit("output_bytes");
                return Ok(());
            }
            if bitmap.read_at(offset, &mut page[..take], r)? != take {
                return Err(invalid("NTFS volume bitmap truncated"));
            }
            match visitor(BitmapEvent::Page(BitmapObservation {
                source_id: source.id(),
                offset,
                bytes: &page[..take],
                cluster_count: count,
            })) {
                Ok(proceed) => {
                    out.observations += 1;
                    out.last_delivered = Some(offset + take as u64);
                    offset += take as u64;
                    if !deliver_coverage(
                        &mut out,
                        ByteRange {
                            offset: offset - take as u64,
                            length: take as u64,
                        },
                        |e| visitor(BitmapEvent::Coverage(e)),
                    ) {
                        return Ok(());
                    }
                    if !proceed {
                        out.stop_reason = StopReason::CallerStop;
                        return Ok(());
                    }
                }
                Err(e) => {
                    out.stop_reason = StopReason::DeliveryFailed(e);
                    return Ok(());
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        let kind = match e.kind {
            ErrorKind::Io => Some(CoverageKind::Unreadable),
            ErrorKind::Unsupported | ErrorKind::InvalidData => Some(CoverageKind::Unsupported),
            _ => None,
        };
        out.stop_reason =
            stop_for_metered_error(e, source, out.profile.ends_with("bootstrap"), &metered);
        if let Some(kind) = kind
            && out.unvisited.length > 0
        {
            match visitor(BitmapEvent::Coverage(CoverageEvent {
                range: ByteRange {
                    offset: out.unvisited.offset,
                    length: 4096.min(out.unvisited.length),
                },
                kind,
            })) {
                Ok(_) => out.coverage_events += 1,
                Err(e) => out.stop_reason = StopReason::DeliveryFailed(e),
            }
        }
    }
    if let Err(e) = source.check_stability() {
        out.stop_reason = StopReason::SourceStability(e);
    }
    out
}

/// Open one validated live DATA stream or ADS from a stable acquisition.
/// Resident, fragmented, sparse and supported LZNT1 streams use the existing
/// checked stream reader. The returned deferred handle retains the source lease.
pub fn open_live_stream(
    source: &ForensicSource,
    slot: u64,
    name: &[u16],
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    compression: Option<fs_ntfs::NtfsCompressionLimits>,
    r: &Resources,
) -> Result<fs_ntfs::NtfsFile> {
    let volume = NtfsVolume::open_for_forensics(Arc::new(source.clone()), read, streams, r)?;
    let object = volume.stream_identity(slot, r)?;
    match compression {
        Some(c) => volume.open_stream_with_compression(&object, name, streams, c, r),
        None => volume.open_stream(&object, name, streams, r),
    }
}

/// A native unallocated FILE slot's resident or single-segment candidate map.
/// This does not establish that the record is deleted or its bytes are original.
pub struct DeletedStreamCandidate {
    source: ForensicSource,
    raw_record: Vec<u8>,
    cluster_bytes: u64,
    /// Native record number.
    pub record: u64,
    /// Stale native sequence retained without promotion to a live identity.
    pub sequence: u16,
    /// Exact selected native ADS units; empty means unnamed DATA.
    pub name: Vec<u16>,
    /// Whether ranges source stale FILE metadata, including USA substitutions.
    /// Current ownership by `$MFT` is expected for resident metadata and does not
    /// establish that its retained payload was overwritten.
    pub resident: bool,
    /// Candidate logical size.
    pub length: u64,
    /// Physical ranges, sparse/unwritten semantics and explicit unknown reuse.
    pub ranges: Vec<crate::forensics_extract::ExtractionRange>,
}
/// Decode a candidate only when the independent MFT bit and FILE flag are both
/// unallocated. Resident payloads preserve USA substitutions through exact source
/// ranges. Attribute-list-dependent free records remain unsupported in this profile. Every data range initially has unknown current
/// reuse; consumers must retain separate bitmap and owner scan outcomes.
#[allow(clippy::too_many_arguments)]
pub fn deleted_stream_candidate(
    source: &ForensicSource,
    slot: u64,
    name: &[u16],
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    r: &Resources,
) -> Result<Budgeted<DeletedStreamCandidate>> {
    candidate_from_reader(
        source,
        Arc::new(source.clone()),
        slot,
        name,
        read,
        streams,
        r,
    )
}

/// Decode a deleted candidate with bootstrap-inclusive logical source-read limits.
/// The caller's shared Resources budget must have capacity at most memory_bytes;
/// this preserves accounting for the returned candidate's entire lifetime.
#[allow(clippy::too_many_arguments)]
pub fn bounded_deleted_stream_candidate(
    source: &ForensicSource,
    slot: u64,
    name: &[u16],
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: ScanLimits,
    r: &Resources,
) -> Result<Budgeted<DeletedStreamCandidate>> {
    if r.memory.capacity() > limits.memory_bytes {
        return Err(Error::new(
            ErrorKind::BudgetExhausted,
            "candidate Resources capacity exceeds memory_bytes",
        ));
    }
    if limits.records == 0 {
        return Err(Error::new(
            ErrorKind::BudgetExhausted,
            "candidate records ceiling",
        ));
    }
    let meter = Arc::new(MeteredSource::new(source.clone(), limits.read_bytes));
    let result = candidate_from_reader(source, meter.clone(), slot, name, read, streams, r);
    match result {
        Err(_) if meter.exhausted() => Err(Error::new(
            ErrorKind::BudgetExhausted,
            "candidate read_bytes ceiling",
        )),
        other => other,
    }
}
#[allow(clippy::too_many_arguments)]
fn copy_native_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS native evidence copy"))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
#[allow(clippy::too_many_arguments)]
fn candidate_from_reader(
    source: &ForensicSource,
    reader: Arc<dyn ReadAt>,
    slot: u64,
    name: &[u16],
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    r: &Resources,
) -> Result<Budgeted<DeletedStreamCandidate>> {
    use crate::forensics_extract::{ExtractionKind, ExtractionRange, ReuseEvidence};
    let volume = NtfsVolume::open_for_forensics(reader, read, streams, r)?;
    let zero = volume.stream_identity(0, r)?;
    let bitmap = volume.open_native_attribute_stream(&zero, 0xb0, &[], streams, r)?;
    let mut bit = [0];
    if bitmap.read_at(slot / 8, &mut bit, r)? != 1 {
        return Err(invalid("NTFS deleted candidate allocation bit unavailable"));
    }
    if bit[0] & (1 << (slot % 8)) != 0 {
        return Err(invalid("NTFS candidate MFT bit is allocated"));
    }
    let raw = raw_record(&volume, slot, r)?;
    let _scratch = r.memory.reserve(raw.len() as u64)?;
    let mut fixed = Vec::new();
    fixed
        .try_reserve_exact(raw.len())
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS deleted record scratch"))?;
    fixed.extend_from_slice(&raw);
    let record = decode_record(&mut fixed, read.attributes, r)?
        .ok_or_else(|| invalid("NTFS candidate slot has no FILE structure"))?;
    if record.in_use {
        return Err(invalid("NTFS candidate FILE in-use flag disagrees"));
    }
    if record.base_reference != 0 || record.attributes.iter().any(|a| a.kind == 0x20) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "NTFS free extension/attribute-list candidate",
        ));
    }
    let mut candidates = record.attributes.iter().filter(|a| {
        a.kind == 0x80 && {
            let raw = a.raw;
            let at = usize::from(word(raw, 10));
            let len = usize::from(raw[9]);
            len == name.len()
                && name
                    .iter()
                    .enumerate()
                    .all(|(n, v)| word(raw, at + n * 2) == *v)
        }
    });
    let attribute = candidates
        .next()
        .ok_or_else(|| invalid("NTFS candidate DATA stream absent"))?;
    if candidates.next().is_some() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "NTFS segmented free-record stream",
        ));
    }
    if let Some(value) = attribute.resident {
        let length = value.len() as u64;
        let value_start = attribute.offset + usize::from(word(attribute.raw, 20));
        let usa = usize::from(word(record.fixed, 4));
        let mft_map = volume.native_mft_map().0;
        let bound = value
            .len()
            .div_ceil(512)
            .saturating_mul(3)
            .saturating_add(mft_map.len())
            .saturating_add(4);
        let charge = (bound as u64)
            .saturating_mul(core::mem::size_of::<ExtractionRange>() as u64)
            .saturating_add((name.len() as u64).saturating_mul(2))
            .saturating_add(raw.len() as u64)
            .saturating_add(256);
        return Budgeted::try_new(&r.memory, charge, || {
            let mut ranges = Vec::new();
            ranges.try_reserve_exact(bound).map_err(|_| {
                Error::new(ErrorKind::BudgetExhausted, "NTFS resident candidate ranges")
            })?;
            let mut done = 0usize;
            while done < value.len() {
                let position = value_start + done;
                let sector = position / 512;
                let within = position % 512;
                // USA-protected trailers obtain their native content from the
                // validated update sequence array, not the raw marker bytes.
                let (native, take) = if within >= 510 {
                    (
                        usa + (sector + 1) * 2 + (within - 510),
                        (512 - within).min(value.len() - done),
                    )
                } else {
                    (position, (510 - within).min(value.len() - done))
                };
                let stream_offset =
                    slot * (volume.geometry().record_bytes() as u64) + native as u64;
                let end = stream_offset + take as u64;
                let mut covered = 0u64;
                for extent in mft_map {
                    let start = stream_offset.max(extent.offset);
                    let finish = end.min(extent.offset + extent.length);
                    if start >= finish {
                        continue;
                    }
                    let crate::fs_file::ExtentKind::Data(at) = extent.kind else {
                        return Err(invalid("NTFS resident candidate MFT storage unavailable"));
                    };
                    if ranges.len() == bound {
                        return Err(Error::new(
                            ErrorKind::BudgetExhausted,
                            "NTFS resident candidate range ceiling",
                        ));
                    }
                    ranges.push(ExtractionRange {
                        logical: ByteRange {
                            offset: done as u64 + start - stream_offset,
                            length: finish - start,
                        },
                        kind: ExtractionKind::Data(at + start - extent.offset),
                        reuse: ReuseEvidence::Unknown,
                    });
                    covered += finish - start;
                }
                if covered != take as u64 {
                    return Err(invalid("NTFS resident candidate mapping gap"));
                }
                if ranges.len() > bound {
                    return Err(Error::new(
                        ErrorKind::BudgetExhausted,
                        "NTFS resident candidate range ceiling",
                    ));
                }
                done += take;
            }
            let mut native_name = Vec::new();
            native_name
                .try_reserve_exact(name.len())
                .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS candidate name"))?;
            native_name.extend_from_slice(name);
            Ok(DeletedStreamCandidate {
                source: source.clone(),
                raw_record: copy_native_bytes(&raw)?,
                cluster_bytes: volume.geometry().cluster_bytes(),
                record: slot,
                sequence: record.sequence,
                name: native_name,
                resident: true,
                length,
                ranges,
            })
        });
    }
    let map = volume.forensic_mapping(attribute.raw, r)?;
    let charge = (map.extents.len() as u64)
        .saturating_mul(core::mem::size_of::<ExtractionRange>() as u64)
        .saturating_add((name.len() as u64).saturating_mul(2))
        .saturating_add(raw.len() as u64)
        .saturating_add(256);
    Budgeted::try_new(&r.memory, charge, || {
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(map.extents.len())
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS candidate extent storage"))?;
        for extent in &map.extents {
            let kind = match extent.kind {
                crate::fs_file::ExtentKind::Data(at) => ExtractionKind::Data(at),
                crate::fs_file::ExtentKind::Hole => ExtractionKind::Sparse,
                crate::fs_file::ExtentKind::Unwritten => ExtractionKind::Unwritten,
            };
            ranges.push(ExtractionRange {
                logical: ByteRange {
                    offset: extent.offset,
                    length: extent.length,
                },
                kind,
                reuse: ReuseEvidence::Unknown,
            });
        }
        let mut native_name = Vec::new();
        native_name
            .try_reserve_exact(name.len())
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "NTFS candidate name"))?;
        native_name.extend_from_slice(name);
        Ok(DeletedStreamCandidate {
            source: source.clone(),
            raw_record: copy_native_bytes(&raw)?,
            cluster_bytes: volume.geometry().cluster_bytes(),
            record: slot,
            sequence: record.sequence,
            name: native_name,
            resident: false,
            length: map.length,
            ranges,
        })
    })
}

impl core::fmt::Debug for DeletedStreamCandidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeletedStreamCandidate")
            .field("source", self.source.identity())
            .field("record", &self.record)
            .field("sequence", &self.sequence)
            .field("name", &self.name)
            .field("length", &self.length)
            .field("ranges", &self.ranges)
            .finish()
    }
}
impl DeletedStreamCandidate {
    /// Complete original FILE slot, including USA markers and replacement array.
    /// This supports validation of stale native attributes and candidate mappings.
    pub fn raw_record(&self) -> &[u8] {
        &self.raw_record
    }
    /// Stable acquisition retained by the candidate, including deferred reads.
    pub fn source(&self) -> &ForensicSource {
        &self.source
    }
    /// Validated cluster geometry needed to interpret allocation evidence.
    pub fn cluster_bytes(&self) -> u64 {
        self.cluster_bytes
    }
}
/// Independent allocation bits observed for all clusters intersecting a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeAllocation {
    /// At least one required allocation bit could not be inspected.
    Unknown,
    /// Every required current allocation bit is clear.
    Free,
    /// Every required current allocation bit is set.
    Allocated,
    /// Both current states are present; never collapse this into all-free.
    Mixed,
}
/// Current per-range evidence, retaining each independent scan's completion.
#[derive(Debug)]
pub struct RangeReuseAssessment {
    /// Current allocation, independently of owner claims.
    pub allocation: RangeAllocation,
    /// One observed conflicting current owner, even when traversal later stops.
    pub conflicting_owner: Option<OwnershipObservation>,
    /// Bitmap coverage; available per-range bits may survive a later stop.
    pub bitmap_outcome: ScanOutcome,
    /// Ownership coverage; absence of a claim requires this whole domain complete.
    pub ownership_outcome: ScanOutcome,
}
impl RangeReuseAssessment {
    /// Conservative shorthand for extraction manifests. Keep both scan outcomes
    /// and allocation state alongside this value; a hash never establishes history.
    pub fn reuse_evidence(&self) -> crate::forensics_extract::ReuseEvidence {
        use crate::forensics_extract::ReuseEvidence;
        if self.conflicting_owner.is_some() {
            return ReuseEvidence::ConflictingOwner;
        }
        if !self.ownership_outcome.is_complete() {
            return ReuseEvidence::Unknown;
        }
        match self.allocation {
            RangeAllocation::Free => ReuseEvidence::CurrentlyFree,
            RangeAllocation::Allocated => ReuseEvidence::AllocatedOwnerUnknown,
            _ => ReuseEvidence::Unknown,
        }
    }
}
/// Inspect allocation and current owners for one candidate physical extent.
/// `limits` applies independently to each subordinate scan, whose terminal states
/// are retained. A positive owner conflict survives partial scans; absence never
/// establishes conflict-free content unless the entire owner domain completes.
#[allow(clippy::too_many_arguments)]
pub fn assess_candidate_range(
    candidate: &DeletedStreamCandidate,
    index: usize,
    read: NtfsReadLimits,
    streams: NtfsStreamLimits,
    limits: ScanLimits,
    control: &dyn ScanControl,
    r: &Resources,
) -> Result<RangeReuseAssessment> {
    let extent = candidate
        .ranges
        .get(index)
        .ok_or_else(|| invalid("NTFS candidate extent index"))?;
    let crate::forensics_extract::ExtractionKind::Data(offset) = extent.kind else {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "NTFS reuse assessment requires stored physical bytes",
        ));
    };
    let end = offset
        .checked_add(extent.logical.length)
        .ok_or_else(|| invalid("NTFS candidate physical extent overflow"))?;
    let first = offset / candidate.cluster_bytes;
    let last = end.div_ceil(candidate.cluster_bytes);
    let mut inspected = 0;
    let mut set = 0;
    let bitmap_outcome = volume_bitmap(
        &candidate.source,
        read,
        streams,
        limits,
        control,
        r,
        |event| {
            if let BitmapEvent::Page(page) = event {
                let start = first.max(page.offset * 8);
                let end = last
                    .min((page.offset + page.bytes.len() as u64) * 8)
                    .min(page.cluster_count);
                for bit in start..end {
                    inspected += 1;
                    let local = bit - page.offset * 8;
                    if page.bytes[(local / 8) as usize] & (1 << (local % 8)) != 0 {
                        set += 1;
                    }
                }
            }
            Ok(true)
        },
    );
    let allocation = if inspected != last - first {
        RangeAllocation::Unknown
    } else if set == 0 {
        RangeAllocation::Free
    } else if set == inspected {
        RangeAllocation::Allocated
    } else {
        RangeAllocation::Mixed
    };
    let mut conflicting_owner = None;
    let ownership_outcome = current_owners(
        &candidate.source,
        read,
        streams,
        limits,
        control,
        r,
        |event| {
            if let OwnershipEvent::Claim(owner) = event
                && owner.range.offset < end
                && offset < owner.range.offset + owner.range.length
                && conflicting_owner.is_none()
            {
                conflicting_owner = Some(owner);
            }
            Ok(true)
        },
    );
    Ok(RangeReuseAssessment {
        allocation,
        conflicting_owner,
        bitmap_outcome,
        ownership_outcome,
    })
}
