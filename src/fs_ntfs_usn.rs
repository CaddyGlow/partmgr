//! Bounded, allocation-free decoding of framed USN V2/V3 evidence.
//! This is not extraction from NTFS, replay, recovery, or journal modification.
use crate::platform::fmt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

/// Caller-defined evidence identity and offset within that evidence stream.
/// Identity is a label, not a verified digest or proof of a stable source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// Caller-supplied evidence label; not a verified digest.
    pub evidence_id: [u8; 32],
    /// Byte offset within the supplied evidence stream.
    pub offset: u64,
}
/// Per-record ceilings, checked before any payload traversal.
#[derive(Clone, Copy, Debug)]
pub struct RecordLimits {
    /// Maximum encoded bytes per record.
    pub record_bytes: usize,
    /// Maximum UTF-16 code units in a name.
    pub name_units: usize,
}
/// Whole cursor work ceilings. The cursor retains no record collection.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// Per-record decoding limits.
    pub record: RecordLimits,
    /// Maximum records decoded by the cursor.
    pub records: usize,
    /// Maximum bytes consumed by the cursor.
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Typed forensic decoding failures.
pub enum ErrorKind {
    /// The encoded record is incomplete.
    Truncated,
    /// A native field violates the framing layout.
    InvalidFraming,
    /// The major record version is unsupported.
    UnsupportedVersion,
    /// A caller-selected work ceiling was exceeded.
    BudgetExhausted,
    /// A provenance offset overflowed.
    OffsetOverflow,
    /// The caller cancelled decoding.
    Cancelled,
}
/// Exact evidence position plus the offending field offset within its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// Typed decoding failure.
    pub kind: ErrorKind,
    /// Source label and record offset.
    pub provenance: Provenance,
    /// Byte offset of the offending field within the record.
    pub field_offset: usize,
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at evidence offset {} + {}",
            self.kind, self.provenance.offset, self.field_offset
        )
    }
}
impl crate::platform::error::Error for DecodeError {}

/// Native identifiers: V3 bytes are opaque, never reduced to an MFT slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileReference {
    /// Native 64-bit reference from a V2 record.
    V2(u64),
    /// Opaque 128-bit reference from a V3 record.
    V3([u8; 16]),
}
impl FileReference {
    /// NTFS interpretation of a V2 reference only: low48 record/high16 sequence.
    /// Does not establish that the reference still resolves to a live MFT record.
    pub fn ntfs_v2_parts(self) -> Option<(u64, u16)> {
        match self {
            Self::V2(raw) => Some((raw & 0x0000_ffff_ffff_ffff, (raw >> 48) as u16)),
            Self::V3(_) => None,
        }
    }
}
/// Raw flags and a documented interpretation mask; future bits remain visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    /// Original flag bits, including unknown bits.
    pub raw: u32,
    /// Documented interpretation mask; does not authenticate flags.
    pub recognized_mask: u32,
}
impl Flags {
    /// Return the bits covered by the documented mask.
    pub fn recognized(self) -> u32 {
        self.raw & self.recognized_mask
    }
    /// Return bits outside the documented mask.
    pub fn unknown(self) -> u32 {
        self.raw & !self.recognized_mask
    }
}
/// Recognized Win32 USN_REASON flags through INTEGRITY_CHANGE; not validation.
pub const REASON_MASK: u32 = 0x80ff_ff77;
/// Includes documented CLIENT_REPLICATION_MANAGEMENT in addition to FSCC flags.
pub const SOURCE_MASK: u32 = 0x0000_000f;

/// Borrowed exact native UTF16-LE units, including embedded NUL/unpaired surrogates.
#[derive(Clone, Copy, Debug)]
pub struct Name<'a>(&'a [u8]);
impl<'a> Name<'a> {
    /// Return exact borrowed name bytes.
    pub fn bytes(self) -> &'a [u8] {
        self.0
    }
    /// Iterate exact UTF-16 units without replacement or normalization.
    pub fn units(self) -> impl ExactSizeIterator<Item = u16> + 'a {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
}
/// One validated framing envelope, retaining all otherwise uninterpreted bytes.
#[derive(Clone, Copy, Debug)]
pub struct UsnRecord<'a> {
    /// Source label and record offset.
    pub provenance: Provenance,
    /// Native major record version.
    pub major: u16,
    /// Native minor record version.
    pub minor: u16,
    /// Native file reference; resolution is a separate operation.
    pub file: FileReference,
    /// Native parent reference; resolution is a separate operation.
    pub parent: FileReference,
    /// Native nonnegative signed USN; no equality with the supplied offset assumed.
    pub usn: i64,
    /// Native signed ticks, 100ns since1601-01-01UTC; zero is retained as zero.
    /// No host/calendar conversion or timestamp plausibility inference is made.
    pub timestamp_ticks: i64,
    /// Native change-reason bits.
    pub reason: Flags,
    /// Native source-information bits.
    pub source: Flags,
    /// Store-local index, not a decoded SID or authorization result.
    pub security_id: u32,
    /// Native attribute bits without inferred applicability.
    pub file_attributes: u32,
    /// Exact borrowed UTF-16 filename bytes.
    pub name: Name<'a>,
    raw: &'a [u8],
    header_bytes: usize,
    name_offset: usize,
}
impl<'a> UsnRecord<'a> {
    /// Return the complete encoded record bytes.
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    /// Minor-version extension/padding before the dynamic name offset.
    pub fn header_extension(self) -> &'a [u8] {
        &self.raw[self.header_bytes..self.name_offset]
    }
    /// Exact trailing bytes after the name, without assuming zero padding.
    pub fn trailing(self) -> &'a [u8] {
        &self.raw[self.name_offset + self.name.0.len()..]
    }
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn dword(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn qword(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
/// Decode the first record; bytes after RecordLength are left to the caller.
/// The supplied slice begins at a known record boundary, not a carving candidate.
/// Compatible minor versions retain opaque extensions using FileNameOffset.
pub fn decode_record<'a>(
    bytes: &'a [u8],
    provenance: Provenance,
    limits: RecordLimits,
) -> Result<UsnRecord<'a>, DecodeError> {
    let error = |kind, field_offset| DecodeError {
        kind,
        provenance,
        field_offset,
    };
    if bytes.len() < 8 {
        return Err(error(ErrorKind::Truncated, bytes.len()));
    }
    let length = dword(bytes, 0) as usize;
    if length < 8 || !length.is_multiple_of(8) {
        return Err(error(ErrorKind::InvalidFraming, 0));
    }
    if length > limits.record_bytes {
        return Err(error(ErrorKind::BudgetExhausted, 0));
    }
    if length > bytes.len() {
        return Err(error(ErrorKind::Truncated, 0));
    }
    provenance
        .offset
        .checked_add(length as u64)
        .ok_or_else(|| error(ErrorKind::OffsetOverflow, 0))?;
    let raw = &bytes[..length];
    let major = word(raw, 4);
    let minor = word(raw, 6);
    let (header_bytes, common, file, parent) = match major {
        2 if length >= 60 => (
            60,
            24,
            FileReference::V2(qword(raw, 8)),
            FileReference::V2(qword(raw, 16)),
        ),
        3 if length >= 76 => (
            76,
            40,
            FileReference::V3(raw[8..24].try_into().unwrap()),
            FileReference::V3(raw[24..40].try_into().unwrap()),
        ),
        2 | 3 => return Err(error(ErrorKind::Truncated, 0)),
        _ => return Err(error(ErrorKind::UnsupportedVersion, 4)),
    };
    let name_len = word(raw, common + 32) as usize;
    let name_offset = word(raw, common + 34) as usize;
    if !name_len.is_multiple_of(2)
        || !name_offset.is_multiple_of(2)
        || name_offset < header_bytes
        || name_offset > length
        || name_len > length - name_offset
    {
        return Err(error(ErrorKind::InvalidFraming, common + 32));
    }
    if name_len / 2 > limits.name_units {
        return Err(error(ErrorKind::BudgetExhausted, common + 32));
    }
    let usn = qword(raw, common) as i64;
    if usn < 0 {
        return Err(error(ErrorKind::InvalidFraming, common));
    }
    Ok(UsnRecord {
        provenance,
        major,
        minor,
        file,
        parent,
        usn,
        timestamp_ticks: qword(raw, common + 8) as i64,
        reason: Flags {
            raw: dword(raw, common + 16),
            recognized_mask: REASON_MASK,
        },
        source: Flags {
            raw: dword(raw, common + 20),
            recognized_mask: SOURCE_MASK,
        },
        security_id: dword(raw, common + 24),
        file_attributes: dword(raw, common + 28),
        name: Name(&raw[name_offset..name_offset + name_len]),
        raw,
        header_bytes,
        name_offset,
    })
}
/// Strict contiguous record cursor, with no hidden resynchronization or hole skips.
/// Extracted sparse $J ranges and DeviceIoControl's initial8-byte USN must be
/// separated by the caller. An error terminates the cursor permanently.
pub struct Records<'a> {
    bytes: &'a [u8],
    provenance: Provenance,
    limits: StreamLimits,
    consumed: usize,
    count: usize,
    stopped: bool,
}
impl<'a> Records<'a> {
    /// Create a borrowed cursor; input must start at a record boundary.
    pub fn new(bytes: &'a [u8], provenance: Provenance, limits: StreamLimits) -> Self {
        Self {
            bytes,
            provenance,
            limits,
            consumed: 0,
            count: 0,
            stopped: false,
        }
    }
    /// Return encoded bytes consumed successfully.
    pub fn consumed_bytes(&self) -> usize {
        self.consumed
    }
    /// Return the number of successfully decoded records.
    pub fn decoded_records(&self) -> usize {
        self.count
    }
    /// Cancellation is checked before every record, including an EOF request.
    pub fn next_record(
        &mut self,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<Option<UsnRecord<'a>>, DecodeError> {
        if self.stopped {
            return Ok(None);
        }
        let current = self.provenance.offset.checked_add(self.consumed as u64);
        let provenance = Provenance {
            offset: current.unwrap_or(self.provenance.offset),
            ..self.provenance
        };
        let fail = |kind| DecodeError {
            kind,
            provenance,
            field_offset: 0,
        };
        let result = (|| {
            if current.is_none() {
                return Err(fail(ErrorKind::OffsetOverflow));
            }
            if cancelled() {
                return Err(fail(ErrorKind::Cancelled));
            }
            if self.consumed == self.bytes.len() {
                return Ok(None);
            }
            if self.count >= self.limits.records {
                return Err(fail(ErrorKind::BudgetExhausted));
            }
            let available = self
                .limits
                .bytes
                .checked_sub(self.consumed)
                .ok_or_else(|| fail(ErrorKind::BudgetExhausted))?;
            let mut record_limits = self.limits.record;
            record_limits.record_bytes = record_limits.record_bytes.min(available);
            let record = decode_record(&self.bytes[self.consumed..], provenance, record_limits)?;
            self.consumed += record.raw.len();
            self.count += 1;
            Ok(Some(record))
        })();
        if result.is_err() || matches!(result, Ok(None)) {
            self.stopped = true;
        }
        result
    }
}
