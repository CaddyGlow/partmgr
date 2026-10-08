//! Source-bound extraction of a caller-selected NTFS `$J` stream.
//! Selection does not authenticate its namespace as `$Extend/$UsnJrnl`, establish
//! snapshot stability, decode `$Max`, or infer journal completeness/replay.
use crate::platform::fmt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    fs_core::*,
    fs_ntfs::{NtfsFile, NtfsStreamLimits, NtfsVolume},
    fs_ntfs_usn::{self as usn, Provenance, RecordLimits, UsnRecord},
};

/// Bounded extraction failure, retaining native decoder field provenance.
#[derive(Debug)]
pub enum ExtractError {
    /// Storage, identity, resource, framing or caller callback failure.
    Core(Error),
    /// Native record failure with exact stream and field offsets.
    Decode(usn::DecodeError),
}
impl From<Error> for ExtractError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}
impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => e.fmt(f),
            Self::Decode(e) => e.fmt(f),
        }
    }
}
impl crate::platform::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn crate::platform::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Decode(error) => Some(error),
        }
    }
}
/// Extraction result with causal storage or precise native framing errors.
pub type ExtractResult<T> = crate::platform::result::Result<T, ExtractError>;

/// Ceilings across one complete traversal; no collection of records is retained.
#[derive(Clone, Copy, Debug)]
pub struct JournalLimits {
    /// Individual record byte/name bounds.
    pub record: RecordLimits,
    /// Maximum native records delivered.
    pub records: usize,
    /// Maximum extents retained, including sparse/unwritten ranges.
    pub extents: usize,
    /// Maximum bytes actually requested from data mappings (prefixes included).
    pub read_bytes: u64,
    /// Maximum IO requests, extent comparisons and delivered events.
    pub work: u64,
}
/// Exact logical gap classification, without invented journal records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapKind {
    /// A validated unallocated extent; no backing data read.
    Sparse,
    /// Allocated but uninitialized logical bytes; no backing data read.
    Unwritten,
    /// Eight zero bytes observed at a record boundary in a data extent.
    ZeroPadding,
}
/// A borrowed extraction observation with source-scoped owner identity.
pub enum JournalEvent<'a> {
    /// Exact decoded bytes; valid only during the callback.
    Record {
        /// Source-scoped owning FILE reference.
        owner: &'a ObjectId,
        /// Borrowed exact native record and logical stream offset.
        record: UsnRecord<'a>,
    },
    /// Explicit missing/padding bytes; never silently joined across a record.
    Gap {
        /// Source-scoped owning FILE reference.
        owner: &'a ObjectId,
        /// Logical stream offset of the gap.
        offset: u64,
        /// Logical bytes represented by this observation.
        length: u64,
        /// Distinguishes allocation gaps from observed data padding.
        kind: GapKind,
    },
}
/// A retained exact named DATA stream. Caller must uphold source stability.
pub struct NtfsUsnReader {
    file: NtfsFile,
    owner: ObjectId,
    evidence_id: [u8; 32],
    limits: JournalLimits,
    _lease: Reservation,
}
const JOURNAL_NAME: &[u16] = &[36, 74];
fn failure(kind: ErrorKind, message: &str) -> Error {
    Error::new(kind, message)
}
impl NtfsUsnReader {
    /// Open exactly `$J` on a validated caller-selected FILE identity. The evidence
    /// ID is a caller label, not a verified hash. Other named streams are not read.
    pub fn open(
        volume: &NtfsVolume,
        owner: &ObjectId,
        streams: NtfsStreamLimits,
        limits: JournalLimits,
        evidence_id: [u8; 32],
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if limits.record.record_bytes < 8 || !limits.record.record_bytes.is_multiple_of(8) {
            return Err(failure(
                ErrorKind::InvalidData,
                "USN scratch record ceiling",
            ));
        }
        let lease = r.memory.reserve(
            (crate::platform::mem::size_of::<Self>() as u64)
                .checked_add(owner.native.len() as u64)
                .ok_or_else(|| failure(ErrorKind::BudgetExhausted, "USN identity charge"))?,
        )?;
        let file = volume.open_stream(owner, JOURNAL_NAME, streams, r)?;
        let mut native = Vec::new();
        native
            .try_reserve_exact(owner.native.len())
            .map_err(|_| failure(ErrorKind::BudgetExhausted, "USN owner allocation"))?;
        native.extend_from_slice(&owner.native);
        let owner = ObjectId {
            source: owner.source,
            generation: owner.generation,
            native,
        };
        Ok(Self {
            file,
            owner,
            limits,
            evidence_id,
            _lease: lease,
        })
    }
    /// Exact source-scoped FILE identity; the stream selector is always `$J`.
    pub fn owner(&self) -> &ObjectId {
        &self.owner
    }
    /// Fixed logical stream length, including sparse/unwritten ranges.
    pub fn len(&self) -> u64 {
        self.file.len()
    }
    /// Whether the selected stream has zero logical bytes.
    pub fn is_empty(&self) -> bool {
        self.file.is_empty()
    }
    /// Traverse from logical offset zero, reporting each gap explicitly. Does not
    /// search for plausible headers after a malformed record; failure terminates
    /// this traversal. Repeated calls restart with new independent ceilings.
    pub fn visit(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(JournalEvent<'_>) -> Result<()>,
    ) -> ExtractResult<()> {
        r.cancellation.check()?;
        let charge = (self.limits.extents as u64)
            .checked_mul(crate::platform::mem::size_of::<LogicalExtent>() as u64)
            .and_then(|n| n.checked_add(self.limits.record.record_bytes as u64))
            .ok_or_else(|| failure(ErrorKind::BudgetExhausted, "USN traversal charge"))?;
        let _scratch = r.memory.reserve(charge)?;
        let mut extents = Vec::<LogicalExtent>::new();
        extents
            .try_reserve_exact(self.limits.extents)
            .map_err(|_| failure(ErrorKind::BudgetExhausted, "USN extent allocation"))?;
        let mut work = self.limits.work;
        let mut reads = self.limits.read_bytes;
        let tick = |work: &mut u64| -> Result<()> {
            r.cancellation.check()?;
            *work = work
                .checked_sub(1)
                .ok_or_else(|| failure(ErrorKind::BudgetExhausted, "USN extraction work"))?;
            Ok(())
        };
        let mut covered = 0u64;
        self.file.visit_extents(r, &mut |e| {
            tick(&mut work)?;
            if extents.len() == self.limits.extents {
                return Err(failure(
                    ErrorKind::BudgetExhausted,
                    "USN extraction extent ceiling",
                ));
            }
            if e.offset != covered || e.length == 0 {
                return Err(failure(
                    ErrorKind::InvalidData,
                    "USN unordered/incomplete extents",
                ));
            }
            covered = e
                .offset
                .checked_add(e.length)
                .filter(|n| *n <= self.file.len())
                .ok_or_else(|| failure(ErrorKind::InvalidData, "USN extent bounds"))?;
            extents.push(e);
            Ok(())
        })?;
        if covered != self.file.len() {
            return Err(failure(ErrorKind::InvalidData, "USN extent coverage").into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.limits.record.record_bytes)
            .map_err(|_| failure(ErrorKind::BudgetExhausted, "USN scratch allocation"))?;
        bytes.resize(self.limits.record.record_bytes, 0);
        let mut offset = 0u64;
        let mut data_end = 0u64;
        let mut index = 0usize;
        let mut count = 0usize;
        let read = |at: u64, output: &mut [u8], work: &mut u64, reads: &mut u64| -> Result<()> {
            let mut done = 0usize;
            while done < output.len() {
                tick(work)?;
                let request = output.len() - done;
                *reads = reads.checked_sub(request as u64).ok_or_else(|| {
                    failure(ErrorKind::BudgetExhausted, "USN extraction read ceiling")
                })?;
                let n = self
                    .file
                    .read_at(at + done as u64, &mut output[done..], r)?;
                if n == 0 || n > request {
                    return Err(failure(
                        ErrorKind::InvalidData,
                        "USN short/invalid data read",
                    ));
                }
                done += n;
            }
            Ok(())
        };
        while offset < covered {
            tick(&mut work)?;
            while offset >= extents[index].offset + extents[index].length {
                tick(&mut work)?;
                index += 1;
            }
            let extent = &extents[index];
            if extent.kind != ExtentKind::Data {
                let end = extent.offset + extent.length;
                if !offset.is_multiple_of(8) || !end.is_multiple_of(8) {
                    return Err(
                        failure(ErrorKind::InvalidData, "USN unaligned evidence gap").into(),
                    );
                }
                visitor(JournalEvent::Gap {
                    owner: &self.owner,
                    offset,
                    length: end - offset,
                    kind: if extent.kind == ExtentKind::Hole {
                        GapKind::Sparse
                    } else {
                        GapKind::Unwritten
                    },
                })?;
                offset = end;
                continue;
            }
            // Contiguous data may have separate physical mappings; a native record
            // may cross those boundaries, but never a hole/unwritten range.
            if data_end <= offset {
                data_end = extent.offset + extent.length;
                for e in &extents[index + 1..] {
                    tick(&mut work)?;
                    if e.kind != ExtentKind::Data {
                        break;
                    }
                    data_end = e.offset + e.length;
                }
            }
            if data_end - offset < 8 {
                return Err(
                    failure(ErrorKind::InvalidData, "USN partial prefix before gap/EOF").into(),
                );
            }
            read(offset, &mut bytes[..8], &mut work, &mut reads)?;
            if bytes[..8] == [0; 8] {
                visitor(JournalEvent::Gap {
                    owner: &self.owner,
                    offset,
                    length: 8,
                    kind: GapKind::ZeroPadding,
                })?;
                offset += 8;
                continue;
            }
            let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            if length < 8 || !length.is_multiple_of(8) {
                return Err(failure(ErrorKind::InvalidData, "USN record length framing").into());
            }
            if length > bytes.len() || count == self.limits.records {
                return Err(failure(ErrorKind::BudgetExhausted, "USN record/count ceiling").into());
            }
            if length as u64 > data_end - offset {
                return Err(failure(ErrorKind::InvalidData, "USN record crosses gap/EOF").into());
            }
            read(offset + 8, &mut bytes[8..length], &mut work, &mut reads)?;
            let record = usn::decode_record(
                &bytes[..length],
                Provenance {
                    evidence_id: self.evidence_id,
                    offset,
                },
                self.limits.record,
            )
            .map_err(ExtractError::Decode)?;
            visitor(JournalEvent::Record {
                owner: &self.owner,
                record,
            })?;
            count += 1;
            offset += length as u64;
        }
        r.cancellation.check()?;
        if self.file.identity() != &self.owner || self.file.len() != covered {
            return Err(failure(ErrorKind::StalePlan, "USN stream identity/length changed").into());
        }
        Ok(())
    }
}
