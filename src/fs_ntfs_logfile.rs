//! Bounded read-only `$LogFile` restart-page observations.
//!
//! This profile inspects both restart copies at offsets 0 and 4096. It accepts
//! restart versions 1.1 and 2.0 with 4096-byte system/log pages and 512-byte USA transfer sectors.
//! Client framing follows the historical NTFS-3G 160-byte single-client layout.
//! Pinned format references are in `docs/filesystem-ntfs-logfile-design.md`.
//! A clean flag observation does not establish transaction recovery, an active
//! log window, or mutation readiness. Physical page headers can be inventoried
//! separately. Exact records, client envelopes and generic checkpoint dump links
//! and typed table bodies can be inspected structurally. Bounded previous/undo
//! link observations do not establish active-window selection or redo/undo execution. Checkpoint dump loading retains
//! one source and explicitly requested restart context; it never overlays recovery
//! copies or establishes transaction recovery readiness.
//! The caller must provide the exact immutable native stream; equal lengths do
//! not establish source identity or detect concurrent same-length writes.
use crate::fs_core::{Error, ErrorKind, Reservation, Resources, Result};
#[cfg(not(feature = "std"))]
use crate::platform::prelude::*;
use crate::platform::sync::Arc;
use virtdisk::ReadAt;

mod checkpoint;
mod checkpoint_dumps;
mod table_entries;
pub use table_entries::{
    NtfsLogDirtyPageEntry, NtfsLogDirtyPageOpenAttribute, NtfsLogOpenAttributeEntry,
    NtfsLogTransactionEntry,
};
mod client_record;
mod restart_table;
pub use checkpoint_dumps::*;
pub use client_record::{NtfsLogClientRecord, inspect_ntfs_log_client_record};
pub use restart_table::{
    NtfsLogRestartTable, NtfsLogRestartTableEntry, NtfsLogRestartTableKind,
    NtfsLogRestartTableLimits, inspect_ntfs_log_restart_table,
};
mod active_seed;
mod pages;
mod record;
mod record_links;
mod restart_selection;
pub use active_seed::*;
pub use checkpoint::{NtfsClientRestart, NtfsLogTableReference, inspect_ntfs_client_restart};
pub use pages::{
    NtfsLogPageHeader, NtfsLogPageKind, NtfsLogPageLimits, NtfsLogPageObservation,
    NtfsLogPageReport, NtfsLogPageRole, NtfsVolumeLogPageReport, inspect_logfile_pages,
    inspect_ntfs_logfile_pages,
};
pub use record_links::*;
pub use restart_selection::*;
// Includes immutable complete-record physical extents; no successor inference.
pub use record::*;

const PAGE: usize = 4096;
const NO_CLIENT: u16 = u16::MAX;
/// Independent ceilings for this exact restart-page inspection profile.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogFileLimits {
    /// Maximum page allocation; the supported profile requires at least 4096.
    pub restart_page_bytes: usize,
    /// Maximum encoded clients; this profile supports at most one.
    pub clients: usize,
    /// Aggregate work units across both copies (reads, fixups, client checks).
    pub work: usize,
}
/// Restart markers, without any transaction-analysis or replay claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogFileState {
    /// Both supported copies agree and carry the native clean flag.
    CleanFlagObserved,
    /// Both supported copies agree without the native clean flag.
    RecoveryRequired,
    /// At least one copy has an explicitly unsupported format/semantic feature.
    Unsupported,
    /// A failed scan, malformed copy, source change, or copy disagreement.
    Incomplete,
}
/// Raw signature class, independent of semantic validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsRestartPageKind {
    /// `RSTR` signature.
    Restart,
    /// Entire observed page contains zero bytes.
    UninitializedZero,
    /// Entire observed page contains `0xff` bytes.
    UninitializedOnes,
    /// `CHKD` recovery-tool signature, excluded by this profile.
    Chkdsk,
    /// Another signature, or a read that did not complete.
    Unknown,
}
/// Unvalidated fixed header observations, including unsupported versions.
/// These fields precede the first protected sector trailer. Their presence is
/// not a claim that USA fixups, geometry, or restart-area semantics are valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsRestartHeader {
    /// Native `(major, minor)` version pair.
    pub version: (u16, u16),
    /// Encoded system page bytes.
    pub system_page_bytes: u32,
    /// Encoded log page bytes.
    pub log_page_bytes: u32,
    /// Encoded restart-area offset.
    pub area_offset: u16,
    /// Encoded USA offset.
    pub usa_offset: u16,
    /// Encoded USA element count.
    pub usa_count: u16,
    /// Native recovery-tool LSN, without ordering or interpretation.
    pub chkdsk_lsn: u64,
}
/// Validated historical restart-area fields; LSN values are opaque observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsRestartArea {
    /// Native `(major, minor)` pair; accepted restart versions are `(1, 1)` and `(2, 0)`.
    pub version: (u16, u16),
    /// Native logical end marker; no ordering or active-window inference.
    pub current_lsn: u64,
    /// Declared payload length of current_lsn; not an assembled record proof.
    pub last_lsn_data_bytes: u32,
    /// Native flags; this profile permits only clean bit `0x0002`.
    pub flags: u16,
    /// Native usable log file bytes, bounded by the supplied stream.
    pub file_bytes: u64,
    /// Encoded sequence-bit count, validated against usable log size.
    pub sequence_bits: u32,
    /// Encoded client count, zero or one in this profile.
    pub client_count: u16,
    /// Free client-list head, or `0xffff`.
    pub free_head: u16,
    /// In-use client-list head, or `0xffff`.
    pub in_use_head: u16,
    /// Native LFS record header size; accepted value is 48.
    pub record_header_bytes: u16,
    /// Quad-aligned data offset within native log pages.
    pub page_data_offset: u16,
    /// Native open-log counter.
    pub open_count: u32,
    /// Oldest client LSN, if a client slot exists.
    pub client_oldest_lsn: Option<u64>,
    /// Client restart LSN, if a client slot exists.
    pub client_restart_lsn: Option<u64>,
    /// Client sequence, if a client slot exists.
    pub client_sequence: Option<u16>,
}
/// One independent candidate, retaining raw bytes and the original failure.
#[derive(Debug)]
pub struct NtfsRestartCopy {
    offset: u64,
    raw: Vec<u8>,
    read_complete: bool,
    kind: NtfsRestartPageKind,
    area: Result<NtfsRestartArea>,
}
impl NtfsRestartCopy {
    /// Exact native stream offset of this candidate.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Raw bytes before fixups; bytes from failed reads are not validated evidence.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Whether the backend completed the entire candidate read.
    pub fn read_complete(&self) -> bool {
        self.read_complete
    }
    /// Raw page signature classification.
    pub fn kind(&self) -> NtfsRestartPageKind {
        self.kind
    }
    /// Raw fixed header when an RSTR/CHKD candidate was completely read.
    pub fn header(&self) -> Option<NtfsRestartHeader> {
        if !self.read_complete || !matches!(&self.raw[..4], b"RSTR" | b"CHKD") {
            return None;
        }
        Some(NtfsRestartHeader {
            version: (le16(&self.raw, 28), le16(&self.raw, 26)),
            system_page_bytes: le32(&self.raw, 16),
            log_page_bytes: le32(&self.raw, 20),
            area_offset: le16(&self.raw, 24),
            usa_offset: le16(&self.raw, 4),
            usa_count: le16(&self.raw, 6),
            chkdsk_lsn: le64(&self.raw, 8),
        })
    }
    /// Validated supported restart area, or this copy's original failure.
    pub fn area(&self) -> core::result::Result<&NtfsRestartArea, &Error> {
        self.area.as_ref()
    }
}
/// Leased observations of both restart copies. No replay capability is exposed.
pub struct NtfsLogFileReport {
    copies: [NtfsRestartCopy; 2],
    source_bytes: u64,
    source_error: Option<Error>,
    state: NtfsLogFileState,
    disagree: bool,
    work: usize,
    _reservation: Reservation,
}
impl NtfsLogFileReport {
    #[cfg(feature = "forensics")]
    pub(crate) fn into_forensic_failure(self) -> Option<Error> {
        if let Some(error) = self.source_error {
            return Some(error);
        }
        self.copies.into_iter().find_map(|copy| copy.area.err())
    }
    /// Independent observations at offsets 0 and 4096, including failed copies.
    pub fn copies(&self) -> &[NtfsRestartCopy; 2] {
        &self.copies
    }
    /// Conservative aggregate restart observation state.
    pub fn state(&self) -> NtfsLogFileState {
        self.state
    }
    /// Whether two valid supported areas disagree in their decoded fields.
    pub fn copies_disagree(&self) -> bool {
        self.disagree
    }
    /// Final cancellation/source-length guard failure, if any.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref()
    }
    /// Supplied native stream length observed before any page read.
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    /// Work actually charged across both candidates.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: transaction tables, active records and redo/undo are unparsed.
    pub fn transaction_analysis_complete(&self) -> bool {
        false
    }
}
fn invalid(context: &str) -> Error {
    Error::new(ErrorKind::InvalidData, context)
}
fn unsupported(context: &str) -> Error {
    Error::new(ErrorKind::Unsupported, context)
}
fn exhausted(context: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, context)
}
fn page_buffer() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(PAGE)
        .map_err(|_| exhausted("NTFS restart allocation"))?;
    bytes.resize(PAGE, 0);
    Ok(bytes)
}
struct Work {
    used: usize,
    maximum: usize,
}
impl Work {
    fn tick(&mut self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.used == self.maximum {
            return Err(exhausted("NTFS restart work limit"));
        }
        self.used += 1;
        Ok(())
    }
}
/// Inspect two native restart candidates without selecting or replaying either.
///
/// Preflight limit/reservation failures return `Err`. Once candidate buffers are
/// allocated, read/format/work/cancellation failures remain in their respective
/// copies and produce an incomplete or unsupported report. Scratch reservations
/// are released before return; retained raw bytes stay leased by the report.
pub fn inspect_logfile(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogFileLimits,
    r: &Resources,
) -> Result<NtfsLogFileReport> {
    r.cancellation.check()?;
    if limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let reservation = r.memory.reserve((2 * PAGE + 2048) as u64)?;
    let first = page_buffer()?;
    let second = page_buffer()?;
    let source_bytes = source.len();
    let mut work = Work {
        used: 0,
        maximum: limits.work,
    };
    let mut inspect = |offset: u64, mut raw: Vec<u8>| {
        let mut complete = false;
        let mut kind = NtfsRestartPageKind::Unknown;
        let area = (|| {
            work.tick(r)?;
            if source.len() != source_bytes {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "NTFS logfile source length changed",
                ));
            }
            if offset + PAGE as u64 > source_bytes {
                return Err(invalid("NTFS truncated restart candidate"));
            }
            source
                .read_exact_at(offset, &mut raw)
                .map_err(|e| Error::io("NTFS restart page read", e))?;
            complete = true;
            r.cancellation.check()?;
            kind = if raw.iter().all(|b| *b == 0) {
                NtfsRestartPageKind::UninitializedZero
            } else if raw.iter().all(|b| *b == 0xff) {
                NtfsRestartPageKind::UninitializedOnes
            } else {
                match &raw[..4] {
                    b"RSTR" => NtfsRestartPageKind::Restart,
                    b"CHKD" => NtfsRestartPageKind::Chkdsk,
                    _ => NtfsRestartPageKind::Unknown,
                }
            };
            if kind != NtfsRestartPageKind::Restart {
                return Err(unsupported("NTFS restart signature/state profile"));
            }
            parse_restart(&raw, source_bytes, limits, &mut work, r)
        })();
        NtfsRestartCopy {
            offset,
            raw,
            read_complete: complete,
            kind,
            area,
        }
    };
    let copies = [inspect(0, first), inspect(PAGE as u64, second)];
    let source_error = r.cancellation.check().err().or_else(|| {
        (source.len() != source_bytes)
            .then(|| Error::new(ErrorKind::StalePlan, "NTFS logfile source length changed"))
    });
    let disagree = matches!((&copies[0].area, &copies[1].area), (Ok(a), Ok(b)) if a != b);
    let malformed = copies.iter().any(|copy| {
        copy.area
            .as_ref()
            .is_err_and(|error| !copy.read_complete || error.kind != ErrorKind::Unsupported)
    });
    let unsupported_copy = copies.iter().any(|copy| {
        copy.area
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::Unsupported)
    });
    let state = if source_error.is_some() || malformed || disagree {
        NtfsLogFileState::Incomplete
    } else if unsupported_copy {
        NtfsLogFileState::Unsupported
    } else if copies[0]
        .area
        .as_ref()
        .is_ok_and(|area| area.flags & 2 != 0)
    {
        NtfsLogFileState::CleanFlagObserved
    } else {
        NtfsLogFileState::RecoveryRequired
    };
    Ok(NtfsLogFileReport {
        copies,
        source_bytes,
        source_error,
        state,
        disagree,
        work: work.used,
        _reservation: reservation,
    })
}
fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}
fn parse_restart(
    raw: &[u8],
    source_bytes: u64,
    limits: NtfsLogFileLimits,
    work: &mut Work,
    r: &Resources,
) -> Result<NtfsRestartArea> {
    work.tick(r)?;
    if le32(raw, 16) != PAGE as u32 || le32(raw, 20) != PAGE as u32 {
        return Err(unsupported("NTFS restart page geometry profile"));
    }
    let usa = usize::from(le16(raw, 4));
    let count = usize::from(le16(raw, 6));
    let area_offset = usize::from(le16(raw, 24));
    if usa < 30
        || !usa.is_multiple_of(2)
        || count != 9
        || usa + count * 2 > 510
        || usa + count * 2 > area_offset
        || !area_offset.is_multiple_of(8)
        || area_offset + 44 > PAGE
        || area_offset + 24 > 510
    {
        return Err(invalid("NTFS restart USA/area placement"));
    }
    let _scratch = r.memory.reserve(PAGE as u64)?;
    let mut page = page_buffer()?;
    page.copy_from_slice(raw);
    for sector in 1..count {
        work.tick(r)?;
        let trailer = sector * 512 - 2;
        if le16(&page, trailer) != le16(raw, usa) {
            return Err(invalid("NTFS torn restart page USA"));
        }
        page[trailer..trailer + 2].copy_from_slice(&raw[usa + sector * 2..usa + sector * 2 + 2]);
    }
    let version = (le16(&page, 28), le16(&page, 26));
    if !matches!(version, (1, 1) | (2, 0)) {
        return Err(unsupported("NTFS restart version profile"));
    }
    if le64(&page, 8) != 0 {
        return Err(unsupported("NTFS restart chkdsk LSN profile"));
    }
    let b = &page[area_offset..];
    let client_count = le16(b, 8);
    if usize::from(client_count) > limits.clients {
        return Err(exhausted("NTFS restart client ceiling"));
    }
    if client_count > 1 {
        return Err(unsupported("NTFS restart multi-client profile"));
    }
    let free_head = le16(b, 10);
    let in_use_head = le16(b, 12);
    let flags = le16(b, 14);
    let area_length = usize::from(le16(b, 20));
    let client_offset = usize::from(le16(b, 22));
    if area_length < 44
        || area_length > b.len()
        || client_offset < 44
        || !client_offset.is_multiple_of(8)
        || area_offset + client_offset > 510
        || client_offset + usize::from(client_count) * 160 > area_length
    {
        return Err(invalid("NTFS restart area/client bounds"));
    }
    if [free_head, in_use_head]
        .iter()
        .any(|head| *head != NO_CLIENT && *head >= client_count)
        || client_count == 1 && (free_head == NO_CLIENT) == (in_use_head == NO_CLIENT)
    {
        return Err(invalid("NTFS restart client-list heads"));
    }
    if flags & !2 != 0 {
        return Err(unsupported("NTFS restart flags profile"));
    }
    let file_bytes = le64(b, 24);
    let sequence_bits = le32(b, 16);
    if file_bytes < (50 * PAGE) as u64
        || file_bytes > source_bytes
        || !file_bytes.is_multiple_of(PAGE as u64)
        || sequence_bits != 67 - (64 - file_bytes.leading_zeros())
    {
        return Err(invalid("NTFS restart file/sequence geometry"));
    }
    let record_header_bytes = le16(b, 36);
    let page_data_offset = le16(b, 38);
    if record_header_bytes != 48 {
        return Err(unsupported("NTFS LFS record-header profile"));
    }
    if page_data_offset < 48
        || usize::from(page_data_offset) >= PAGE
        || !page_data_offset.is_multiple_of(8)
        || usize::from(page_data_offset) + usize::from(record_header_bytes) > PAGE
    {
        return Err(invalid("NTFS restart record/data bounds"));
    }
    let (mut oldest, mut restart, mut sequence) = (None, None, None);
    if client_count == 1 {
        work.tick(r)?;
        let client = &b[client_offset..client_offset + 160];
        if le16(client, 16) != NO_CLIENT || le16(client, 18) != NO_CLIENT {
            return Err(invalid("NTFS restart client-list links"));
        }
        if in_use_head != NO_CLIENT && (le32(client, 28) != 8 || &client[32..40] != b"N\0T\0F\0S\0")
        {
            return Err(unsupported("NTFS restart client identity profile"));
        }
        oldest = Some(le64(client, 0));
        restart = Some(le64(client, 8));
        sequence = Some(le16(client, 20));
    }
    work.tick(r)?;
    Ok(NtfsRestartArea {
        version,
        current_lsn: le64(b, 0),
        last_lsn_data_bytes: le32(b, 32),
        flags,
        file_bytes,
        sequence_bits,
        client_count,
        free_head,
        in_use_head,
        record_header_bytes,
        page_data_offset,
        open_count: le32(b, 40),
        client_oldest_lsn: oldest,
        client_restart_lsn: restart,
        client_sequence: sequence,
    })
}

/// Native system-stream observations bound to the resolved base record 2.
/// Volume flags and restart markers remain independent observations; neither
/// authorizes replay or mutation, even when the native clean flag is present.
pub struct NtfsVolumeLogFileReport {
    /// Source-scoped identity of the native `$LogFile` base owner.
    pub owner: crate::fs_core::ObjectId,
    /// Exact native VOLUME_INFORMATION flags, including dirty/recovery markers.
    pub volume_flags: u16,
    /// Independently retained restart-copy observations.
    pub report: NtfsLogFileReport,
}
struct NativeLogFile {
    file: crate::fs_ntfs::NtfsFile,
    resources: Resources,
}
impl ReadAt for NativeLogFile {
    fn len(&self) -> u64 {
        crate::fs_core::FileRead::len(&self.file)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
        let count = crate::fs_core::FileRead::read_at(&self.file, offset, out, &self.resources)
            .map_err(crate::io::Error::other)?;
        if count != out.len() {
            return Err(crate::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}
/// Resolve and inspect record 2's exact unnamed ordinary initialized DATA stream.
///
/// The bounded resolved reader validates base/extension identity and native maps.
/// Resident, sparse, compressed, encrypted, or uninitialized native log streams
/// are excluded. Dirty volume flags are retained rather than cleared. The caller
/// must maintain immutable source contents throughout this read-only operation.
pub fn inspect_ntfs_logfile(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    log_limits: NtfsLogFileLimits,
    r: &Resources,
) -> Result<NtfsVolumeLogFileReport> {
    r.cancellation.check()?;
    if log_limits.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile(Arc::new(native), log_limits, r)?;
    if let Err(error) = volume.audit_check_source(r) {
        report.source_error = Some(error);
        report.state = NtfsLogFileState::Incomplete;
    }
    Ok(NtfsVolumeLogFileReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}

// Keep both public inspectors bound to one exact native system-stream profile.
fn select_native_logfile(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    r: &Resources,
) -> Result<(
    crate::fs_ntfs::NtfsVolume,
    crate::fs_core::ObjectId,
    crate::fs_ntfs::NtfsFile,
)> {
    use crate::fs_core::{ExtentKind, FileRead};
    let volume =
        crate::fs_ntfs::NtfsVolume::open_for_resolved_audit(source, read_limits, stream_limits, r)?;
    let owner = volume.stream_identity(2, r)?;
    let attributes = volume.native_attributes(&owner, stream_limits, r)?;
    let mut segments = 0;
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.kind == 0x80 && attribute.name.is_empty())
    {
        r.cancellation.check()?;
        if !attribute.nonresident || attribute.flags != 0 {
            return Err(unsupported(
                "NTFS logfile requires ordinary nonresident DATA",
            ));
        }
        segments += 1;
    }
    if segments == 0 {
        return Err(invalid("NTFS logfile unnamed DATA missing"));
    }
    drop(attributes);
    let file = volume.open_native_attribute_stream(&owner, 0x80, &[], stream_limits, r)?;
    let mut next = 0u64;
    file.visit_extents(r, &mut |extent| {
        if extent.kind != ExtentKind::Data || extent.offset != next {
            return Err(unsupported(
                "NTFS logfile requires initialized ordinary mapping",
            ));
        }
        next = next
            .checked_add(extent.length)
            .ok_or_else(|| invalid("NTFS logfile mapping overflow"))?;
        Ok(())
    })?;
    if next != file.len() {
        return Err(invalid("NTFS logfile mapping coverage"));
    }
    Ok((volume, owner, file))
}

mod tail_discovery;
pub use tail_discovery::*;

mod native_analysis_context;
pub use native_analysis_context::*;
