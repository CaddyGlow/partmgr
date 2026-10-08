//! Bounded external undo records for exclusive filesystem transactions.
//!
//! This is an undo protocol, not a filesystem ownership audit or a native journal.
//! Both stores must remain exclusively held, independently persistent and disjoint.
//! The caller verifies the volume binding against the actual selected volume.
use crate::{
    fs_core::{Error, ErrorKind, Reservation, Resources, Result},
    storage::{Storage, WriteRange},
};
use sha2::{Digest, Sha256};
use std::{fmt, io};

const HEADER: usize = 512;
const BODY: u64 = 1024;
const SCRATCH: usize = 65536;
const MAGIC: &[u8; 8] = b"PMFSUNDO";

/// Caller-verified volume/session binding and unique transaction identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoBinding {
    /// Volume identity plus bounded-region identity; never inferred from length alone.
    pub volume: [u8; 32],
    /// Generation of the exclusively opened editing session.
    pub generation: u64,
    /// Unique operation identifier retained by recovery orchestration.
    pub transaction: [u8; 16],
}
/// Bounds applied before retaining or decoding a journal.
#[derive(Clone, Copy, Debug)]
pub struct UndoLimits {
    /// Maximum distinct nonoverlapping patches.
    pub patches: u32,
    /// Maximum encoded old/new payload including patch headers.
    pub body_bytes: u64,
}
impl Default for UndoLimits {
    fn default() -> Self {
        Self {
            patches: 4096,
            body_bytes: 64 << 20,
        }
    }
}
/// Durable terminal records are distinct from a prepared rollback obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoState {
    /// No published transaction header.
    Empty,
    /// Saved bytes are published; target may require rollback.
    Prepared,
    /// Target replacement and its flush were verified before publishing this marker.
    Committed,
    /// Saved bytes were restored, flushed and verified before publishing this marker.
    RolledBack,
}
/// Observable journal state; inspection alone does not validate saved payload bytes.
#[derive(Clone, Copy, Debug)]
pub struct UndoStatus {
    /// Selected integrity-checked header state.
    pub state: UndoState,
    /// Native transaction binding, absent for an empty journal.
    pub binding: Option<UndoBinding>,
    /// Bound target length.
    pub target_bytes: u64,
    /// Retained body bytes.
    pub body_bytes: u64,
    /// Retained patch count.
    pub patches: u32,
}
/// Failure stage and recovery obligation, preserving the causal filesystem error.
#[derive(Debug)]
pub struct UndoFailure {
    /// Operation that failed.
    pub stage: &'static str,
    /// A prepared header may exist; inspect/recover before another edit.
    pub recovery_required: bool,
    /// Target writes were attempted; they may have partially succeeded.
    pub target_may_have_changed: bool,
    /// Original semantic or I/O failure.
    pub source: Error,
}
impl fmt::Display for UndoFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "external undo {}: {}", self.stage, self.source)
    }
}
impl std::error::Error for UndoFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
/// Exact bounded before/after patches; no filesystem validity is implied.
pub struct UndoPlan {
    binding: UndoBinding,
    length: u64,
    patches: Vec<WriteRange>,
    body_bytes: u64,
    staging: Option<UndoStages>,
    _reservation: Reservation,
}
struct UndoStages {
    order: Vec<usize>,
    ends: Vec<usize>,
    _reservation: Reservation,
}
fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn limit(message: &'static str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn read(s: &dyn Storage, offset: u64, out: &mut [u8]) -> Result<()> {
    s.read_exact_at(offset, out)
        .map_err(|e| Error::io("external undo read", e))
}
fn length(s: &dyn Storage) -> Result<u64> {
    s.len().map_err(|e| Error::io("external undo length", e))
}
fn flush(s: &mut dyn Storage) -> Result<()> {
    s.flush().map_err(|e| Error::io("external undo flush", e))
}
fn write(s: &mut dyn Storage, offset: u64, bytes: &[u8], r: &Resources) -> Result<()> {
    let mut done = 0;
    while done < bytes.len() {
        r.cancellation.check()?;
        let n = s
            .write_at(offset + done as u64, &bytes[done..])
            .map_err(|e| Error::io("external undo write", e))?;
        if n == 0 || n > bytes.len() - done {
            return Err(Error::io(
                "external undo short write",
                io::ErrorKind::WriteZero.into(),
            ));
        }
        done += n;
    }
    Ok(())
}
fn check(
    s: &dyn Storage,
    offset: u64,
    bytes: &[u8],
    scratch: &mut [u8],
    r: &Resources,
) -> Result<()> {
    for (i, expected) in bytes.chunks(scratch.len()).enumerate() {
        r.cancellation.check()?;
        read(
            s,
            offset + (i * scratch.len()) as u64,
            &mut scratch[..expected.len()],
        )?;
        if scratch[..expected.len()] != *expected {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "external undo target byte mismatch",
            ));
        }
    }
    Ok(())
}
fn patch_header(p: &WriteRange) -> [u8; 16] {
    let mut b = [0; 16];
    b[..8].copy_from_slice(&p.offset().to_le_bytes());
    b[8..16].copy_from_slice(&(p.expected().len() as u64).to_le_bytes());
    b
}
impl UndoPlan {
    /// Retain bounded sorted disjoint patches. The caller has already reserved any
    /// temporary planning storage; this charge covers ownership retained here.
    pub fn new(
        binding: UndoBinding,
        target_bytes: u64,
        mut patches: Vec<WriteRange>,
        limits: UndoLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if patches.is_empty() || patches.len() as u64 > u64::from(limits.patches) {
            return Err(limit("external undo patch count"));
        }
        patches.sort_unstable_by_key(WriteRange::offset);
        let mut end = 0;
        let mut body_bytes = 0u64;
        for p in &patches {
            r.cancellation.check()?;
            let next = p
                .offset()
                .checked_add(p.expected().len() as u64)
                .ok_or_else(|| invalid("external undo range overflow"))?;
            if p.offset() < end || next > target_bytes {
                return Err(invalid("external undo overlapping/outside patches"));
            }
            end = next;
            body_bytes = body_bytes
                .checked_add(16)
                .and_then(|n| n.checked_add((p.expected().len() as u64).checked_mul(2)?))
                .ok_or_else(|| limit("external undo body overflow"))?;
        }
        if body_bytes > limits.body_bytes {
            return Err(limit("external undo body limit"));
        }
        body_bytes
            .checked_add(BODY)
            .ok_or_else(|| limit("external undo journal length overflow"))?;
        let payload = patches
            .iter()
            .try_fold(0u128, |total, p| {
                total.checked_add(p.retained_payload_bytes())
            })
            .ok_or_else(|| limit("external undo retained payload overflow"))?;
        let charge = u64::try_from(
            payload + patches.capacity() as u128 * std::mem::size_of::<WriteRange>() as u128,
        )
        .map_err(|_| limit("external undo retained charge"))?;
        let reservation = r.memory.reserve(charge)?;
        Ok(Self {
            binding,
            length: target_bytes,
            patches,
            body_bytes,
            staging: None,
            _reservation: reservation,
        })
    }
    /// Retain disjoint patches grouped in caller-selected durable stages.
    /// Each nonempty stage length selects the next input patches; lengths must sum
    /// to the patch count. Every stage is flushed and verified before the next.
    /// The v1 saved body remains physically sorted, so recovery is unchanged and
    /// restores the complete original transaction without trusting stage metadata.
    /// The caller reserves its temporary patch planning storage as with `new`.
    pub fn new_staged(
        binding: UndoBinding,
        target_bytes: u64,
        patches: Vec<WriteRange>,
        stage_lengths: &[usize],
        limits: UndoLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let count = patches.len();
        if count == 0
            || count as u64 > u64::from(limits.patches)
            || stage_lengths.is_empty()
            || stage_lengths.len() > count
        {
            return Err(limit("external undo stage/patch count"));
        }
        let mut end = 0usize;
        for &length in stage_lengths {
            r.cancellation.check()?;
            if length == 0 {
                return Err(invalid("external undo empty stage"));
            }
            end = end
                .checked_add(length)
                .ok_or_else(|| limit("external undo stage length overflow"))?;
        }
        if end != count {
            return Err(invalid("external undo stage lengths do not cover patches"));
        }
        let charge = (count as u64)
            .checked_add(stage_lengths.len() as u64)
            .and_then(|n| n.checked_mul(std::mem::size_of::<usize>() as u64))
            .ok_or_else(|| limit("external undo stage charge overflow"))?;
        let reservation = r.memory.reserve(charge)?;
        let _temporary = r.memory.reserve(
            (count as u64)
                .checked_mul(8)
                .ok_or_else(|| limit("external undo stage scratch overflow"))?,
        )?;
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(count)
            .map_err(|_| limit("external undo stage scratch allocation"))?;
        if offsets.capacity() > count {
            return Err(limit("external undo stage scratch capacity"));
        }
        offsets.extend(patches.iter().map(WriteRange::offset));
        let mut plan = Self::new(binding, target_bytes, patches, limits, r)?;
        let mut order = Vec::new();
        order
            .try_reserve_exact(count)
            .map_err(|_| limit("external undo stage order allocation"))?;
        if order.capacity() > count {
            return Err(limit("external undo stage order capacity"));
        }
        for offset in offsets {
            r.cancellation.check()?;
            order.push(
                plan.patches
                    .binary_search_by_key(&offset, WriteRange::offset)
                    .map_err(|_| invalid("external undo stage mapping"))?,
            );
        }
        let mut ends = Vec::new();
        ends.try_reserve_exact(stage_lengths.len())
            .map_err(|_| limit("external undo stage ends allocation"))?;
        if ends.capacity() > stage_lengths.len() {
            return Err(limit("external undo stage ends capacity"));
        }
        let mut end = 0;
        for &length in stage_lengths {
            end += length;
            ends.push(end);
        }
        plan.staging = Some(UndoStages {
            order,
            ends,
            _reservation: reservation,
        });
        Ok(plan)
    }
    /// External medium capacity required; no full-volume snapshot is taken.
    pub fn journal_bytes(&self) -> u64 {
        BODY + self.body_bytes
    }
    /// Apply exact patches through an external undo transaction. All before-byte
    /// checks precede journal writes. Saved body, prepared marker, target writes,
    /// target verification and terminal marker each obey their declared barriers.
    /// The caller holds exclusive, disjoint stores for the complete call.
    pub fn commit(
        &self,
        target: &mut dyn Storage,
        journal: &mut dyn Storage,
        r: &Resources,
    ) -> std::result::Result<UndoStatus, UndoFailure> {
        let mut stage = "preflight";
        let mut published = false;
        let mut changed = false;
        let result = (|| {
            r.cancellation.check()?;
            let _scratch_charge = r.memory.reserve(SCRATCH as u64 + 1024)?;
            let mut scratch = [0; SCRATCH];
            if length(target)? != self.length || length(journal)? < self.journal_bytes() {
                return Err(invalid("external undo store geometry"));
            }
            if inspect(journal, r)?.state == UndoState::Prepared {
                published = true;
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "pending external undo requires recovery",
                ));
            }
            for p in &self.patches {
                check(target, p.offset(), p.expected(), &mut scratch, r)?;
            }
            stage = "clear terminal headers";
            write(journal, 0, &[0; 1024], r)?;
            flush(journal)?;
            stage = "save undo body";
            let mut digest = Sha256::new();
            let mut at = BODY;
            for p in &self.patches {
                for bytes in [&patch_header(p)[..], p.expected(), p.replacement()] {
                    write(journal, at, bytes, r)?;
                    digest.update(bytes);
                    at += bytes.len() as u64;
                }
            }
            flush(journal)?;
            // Read back all saved bytes before permitting any target mutation.
            let mut base = BODY;
            for p in &self.patches {
                r.cancellation.check()?;
                check(journal, base, &patch_header(p), &mut scratch, r)?;
                check(journal, base + 16, p.expected(), &mut scratch, r)?;
                check(
                    journal,
                    base + 16 + p.expected().len() as u64,
                    p.replacement(),
                    &mut scratch,
                    r,
                )?;
                base += 16 + 2 * p.expected().len() as u64;
            }
            let h = HeaderRecord {
                state: UndoState::Prepared,
                binding: self.binding,
                length: self.length,
                count: self.patches.len() as u32,
                bytes: self.body_bytes,
                digest: digest.finalize().into(),
            };
            stage = "publish prepared marker";
            published = true;
            write(journal, 0, &h.encode(), r)?;
            flush(journal)?;
            let mut header_check = [0; HEADER];
            read(journal, 0, &mut header_check)?;
            if header_check != h.encode() {
                return Err(invalid("prepared marker readback mismatch"));
            }
            stage = "target replacement";
            if length(target)? != self.length {
                return Err(invalid(
                    "external undo target length changed before mutation",
                ));
            }
            if let Some(stages) = &self.staging {
                let mut start = 0;
                for &end in &stages.ends {
                    stage = "target stage replacement";
                    r.cancellation.check()?;
                    if length(target)? != self.length {
                        return Err(invalid(
                            "external undo target changed length between stages",
                        ));
                    }
                    for &index in &stages.order[start..end] {
                        r.cancellation.check()?;
                        let p = &self.patches[index];
                        changed = true;
                        write(target, p.offset(), p.replacement(), r)?;
                    }
                    stage = "target stage flush and verification";
                    flush(target)?;
                    for &index in &stages.order[start..end] {
                        let p = &self.patches[index];
                        check(target, p.offset(), p.replacement(), &mut scratch, r)?;
                    }
                    start = end;
                }
            } else {
                for p in &self.patches {
                    r.cancellation.check()?;
                    changed = true;
                    write(target, p.offset(), p.replacement(), r)?;
                }
                stage = "target flush and verification";
                flush(target)?;
            }
            stage = if self.staging.is_some() {
                "complete target verification"
            } else {
                "target flush and verification"
            };
            for p in &self.patches {
                check(target, p.offset(), p.replacement(), &mut scratch, r)?;
            }
            if length(target)? != self.length {
                return Err(invalid("external undo target changed length"));
            }
            stage = "publish committed marker";
            let terminal = HeaderRecord {
                state: UndoState::Committed,
                ..h
            };
            write(journal, HEADER as u64, &terminal.encode(), r)?;
            flush(journal)?;
            read(journal, HEADER as u64, &mut header_check)?;
            if header_check != terminal.encode() {
                return Err(invalid("committed marker readback mismatch"));
            }
            Ok(terminal.status())
        })();
        result.map_err(|source| UndoFailure {
            stage,
            recovery_required: published,
            target_may_have_changed: changed,
            source,
        })
    }
}
#[derive(Clone, Copy)]
struct HeaderRecord {
    state: UndoState,
    binding: UndoBinding,
    length: u64,
    count: u32,
    bytes: u64,
    digest: [u8; 32],
}
impl HeaderRecord {
    fn encode(&self) -> [u8; HEADER] {
        let mut b = [0; HEADER];
        b[..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        b[12] = match self.state {
            UndoState::Prepared => 1,
            UndoState::Committed => 2,
            UndoState::RolledBack => 3,
            UndoState::Empty => unreachable!(),
        };
        b[16..48].copy_from_slice(&self.binding.volume);
        b[48..56].copy_from_slice(&self.binding.generation.to_le_bytes());
        b[56..72].copy_from_slice(&self.binding.transaction);
        b[72..80].copy_from_slice(&self.length.to_le_bytes());
        b[80..88].copy_from_slice(&self.bytes.to_le_bytes());
        b[88..92].copy_from_slice(&self.count.to_le_bytes());
        b[96..128].copy_from_slice(&self.digest);
        let hash = Sha256::digest(&b[..480]);
        b[480..].copy_from_slice(&hash);
        b
    }
    fn decode(b: &[u8; HEADER]) -> Option<Self> {
        if &b[..8] != MAGIC
            || b[8..12] != 1u32.to_le_bytes()
            || Sha256::digest(&b[..480])[..] != b[480..]
        {
            return None;
        }
        let state = match b[12] {
            1 => UndoState::Prepared,
            2 => UndoState::Committed,
            3 => UndoState::RolledBack,
            _ => return None,
        };
        if b[13..16]
            .iter()
            .chain(&b[92..96])
            .chain(&b[128..480])
            .any(|v| *v != 0)
        {
            return None;
        }
        Some(Self {
            state,
            binding: UndoBinding {
                volume: b[16..48].try_into().unwrap(),
                generation: u64::from_le_bytes(b[48..56].try_into().unwrap()),
                transaction: b[56..72].try_into().unwrap(),
            },
            length: u64::from_le_bytes(b[72..80].try_into().unwrap()),
            bytes: u64::from_le_bytes(b[80..88].try_into().unwrap()),
            count: u32::from_le_bytes(b[88..92].try_into().unwrap()),
            digest: b[96..128].try_into().unwrap(),
        })
    }
    fn status(self) -> UndoStatus {
        UndoStatus {
            state: self.state,
            binding: Some(self.binding),
            target_bytes: self.length,
            body_bytes: self.bytes,
            patches: self.count,
        }
    }
}
fn headers(journal: &dyn Storage, r: &Resources) -> Result<Option<HeaderRecord>> {
    r.cancellation.check()?;
    if length(journal)? < BODY {
        return Err(invalid("external undo journal shorter than headers"));
    }
    let _charge = r.memory.reserve(1024)?;
    let mut a = [0; HEADER];
    let mut b = [0; HEADER];
    read(journal, 0, &mut a)?;
    read(journal, HEADER as u64, &mut b)?;
    let first = HeaderRecord::decode(&a);
    let terminal = HeaderRecord::decode(&b);
    if let Some(h) = first {
        if h.state != UndoState::Prepared {
            return Err(invalid("unexpected first undo header state"));
        }
        if let Some(t) = terminal {
            if t.state == UndoState::Prepared
                || t.binding != h.binding
                || t.length != h.length
                || t.bytes != h.bytes
                || t.count != h.count
                || t.digest != h.digest
            {
                return Err(invalid("contradictory external undo headers"));
            }
            return Ok(Some(t));
        }
        return Ok(Some(h));
    }
    if let Some(t) = terminal {
        if t.state == UndoState::Prepared {
            return Err(invalid("unexpected terminal undo state"));
        }
        return Ok(Some(t));
    }
    if a.iter().chain(&b).all(|v| *v == 0) {
        Ok(None)
    } else {
        Err(invalid("no intact external undo header"))
    }
}
/// Inspect integrity-checked headers without granting mutation authority.
pub fn inspect(journal: &dyn Storage, r: &Resources) -> Result<UndoStatus> {
    Ok(headers(journal, r)?.map_or(
        UndoStatus {
            state: UndoState::Empty,
            binding: None,
            target_bytes: 0,
            body_bytes: 0,
            patches: 0,
        },
        HeaderRecord::status,
    ))
}
/// Restartable rollback under caller-verified identity and exclusive disjoint stores.
/// Validate the entire saved payload and every range before the first restoration.
/// A terminal transaction is verified but never rewritten. Interrupted restoration
/// leaves the prepared marker intact and can safely start again.
pub fn recover(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: UndoLimits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    recover_validated(
        target,
        journal,
        binding,
        limits,
        r,
        &mut NoopRecoveryValidator,
    )
}
/// Engine-specific read-only semantic validation, after complete wire preflight.
/// Implementations must not mutate target or journal; errors leave both unchanged.
pub(crate) trait UndoRecoveryValidator {
    fn validate_range(&mut self, offset: u64, old: &[u8], new: &[u8]) -> Result<()>;
    fn finish(&mut self) -> Result<()>;
}
struct NoopRecoveryValidator;
impl UndoRecoveryValidator for NoopRecoveryValidator {
    fn validate_range(&mut self, _: u64, _: &[u8], _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}
/// Validate format-specific recovery fences without duplicating the journal codec.
/// All wire checks finish before callbacks; all callbacks finish before target writes.
pub(crate) fn recover_validated(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: UndoLimits,
    r: &Resources,
    validator: &mut dyn UndoRecoveryValidator,
) -> std::result::Result<UndoStatus, UndoFailure> {
    let mut stage = "recovery preflight";
    let mut changed = false;
    let result = (|| {
        let Some(h) = headers(journal, r)? else {
            return inspect(journal, r);
        };
        if h.binding != binding || h.length != length(target)? {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "external undo recovery binding/geometry mismatch",
            ));
        }
        if h.count == 0
            || h.count > limits.patches
            || h.bytes > limits.body_bytes
            || h.bytes < u64::from(h.count) * 18
        {
            return Err(limit("external undo recovery limits"));
        }
        let journal_length = length(journal)?;
        if BODY
            .checked_add(h.bytes)
            .is_none_or(|end| end > journal_length)
        {
            return Err(invalid("external undo body outside journal"));
        }
        let size = usize::try_from(h.bytes).map_err(|_| limit("external undo host body limit"))?;
        let _charge = r.memory.reserve(
            h.bytes
                .checked_add(SCRATCH as u64 + 1024)
                .ok_or_else(|| limit("external undo scratch overflow"))?,
        )?;
        let mut body = Vec::new();
        body.try_reserve_exact(size)
            .map_err(|_| limit("external undo recovery allocation"))?;
        body.resize(size, 0);
        for (i, chunk) in body.chunks_mut(SCRATCH).enumerate() {
            r.cancellation.check()?;
            read(journal, BODY + (i * SCRATCH) as u64, chunk)?;
        }
        if Sha256::digest(&body)[..] != h.digest {
            return Err(invalid("external undo saved body digest"));
        }
        let mut cursor = 0;
        let mut last_end = 0;
        for _ in 0..h.count {
            r.cancellation.check()?;
            let (offset, old, _, next) = decode_patch(&body, cursor)?;
            let end = offset
                .checked_add(old.len() as u64)
                .ok_or_else(|| invalid("external undo restored range overflow"))?;
            if offset < last_end || end > h.length {
                return Err(invalid("external undo restored ranges overlap/outside"));
            }
            last_end = end;
            cursor = next;
        }
        if cursor != body.len() {
            return Err(invalid("external undo trailing body bytes"));
        }
        cursor = 0;
        for _ in 0..h.count {
            r.cancellation.check()?;
            let (offset, old, new, next) = decode_patch(&body, cursor)?;
            validator.validate_range(offset, old, new)?;
            cursor = next;
        }
        validator.finish()?;
        r.cancellation.check()?;
        let mut scratch = [0; SCRATCH];
        if h.state == UndoState::Prepared {
            stage = "restore saved bytes";
            cursor = 0;
            for _ in 0..h.count {
                let (offset, old, _, next) = decode_patch(&body, cursor)?;
                r.cancellation.check()?;
                changed = true;
                write(target, offset, old, r)?;
                cursor = next;
            }
            stage = "restoration flush";
            flush(target)?;
        }
        stage = "verify recovery target";
        cursor = 0;
        for _ in 0..h.count {
            let (offset, old, new, next) = decode_patch(&body, cursor)?;
            check(
                target,
                offset,
                if h.state == UndoState::Committed {
                    new
                } else {
                    old
                },
                &mut scratch,
                r,
            )?;
            cursor = next;
        }
        if length(target)? != h.length {
            return Err(invalid("external undo recovery target length changed"));
        }
        if h.state != UndoState::Prepared {
            return Ok(h.status());
        }
        stage = "publish rolled-back marker";
        let terminal = HeaderRecord {
            state: UndoState::RolledBack,
            ..h
        };
        write(journal, HEADER as u64, &terminal.encode(), r)?;
        flush(journal)?;
        let mut b = [0; HEADER];
        read(journal, HEADER as u64, &mut b)?;
        if b != terminal.encode() {
            return Err(invalid("rollback marker readback mismatch"));
        }
        Ok(terminal.status())
    })();
    result.map_err(|source| UndoFailure {
        stage,
        recovery_required: true,
        target_may_have_changed: changed,
        source,
    })
}
fn decode_patch(body: &[u8], cursor: usize) -> Result<(u64, &[u8], &[u8], usize)> {
    let header = body
        .get(
            cursor
                ..cursor
                    .checked_add(16)
                    .ok_or_else(|| invalid("undo cursor overflow"))?,
        )
        .ok_or_else(|| invalid("truncated undo patch header"))?;
    let offset = u64::from_le_bytes(header[..8].try_into().unwrap());
    let n = usize::try_from(u64::from_le_bytes(header[8..].try_into().unwrap()))
        .map_err(|_| limit("undo patch host limit"))?;
    if n == 0 {
        return Err(invalid("empty undo patch"));
    }
    let old_at = cursor + 16;
    let new_at = old_at
        .checked_add(n)
        .ok_or_else(|| invalid("undo old bytes overflow"))?;
    let end = new_at
        .checked_add(n)
        .ok_or_else(|| invalid("undo new bytes overflow"))?;
    let old = body
        .get(old_at..new_at)
        .ok_or_else(|| invalid("truncated undo old bytes"))?;
    let new = body
        .get(new_at..end)
        .ok_or_else(|| invalid("truncated undo new bytes"))?;
    Ok((offset, old, new, end))
}

#[cfg(test)]
mod semantic_recovery_tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    struct Memory {
        bytes: Vec<u8>,
        writes: usize,
        fail: bool,
    }
    impl Storage for Memory {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail {
                return Err(io::Error::other("modeled target interruption"));
            }
            let at = at as usize;
            self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Fence {
        offsets: Vec<u64>,
        reject: bool,
        cancellation: Option<Cancellation>,
    }
    impl UndoRecoveryValidator for Fence {
        fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
            self.offsets.push(at);
            if at == 10 && (old != [1, 0] || new != [1, 0]) {
                return Err(invalid("invalid test native clean fence"));
            }
            Ok(())
        }
        fn finish(&mut self) -> Result<()> {
            if self.offsets != [0, 10] || self.reject {
                return Err(invalid("missing or rejected test native clean fence"));
            }
            if let Some(cancellation) = &self.cancellation {
                cancellation.cancel();
            }
            Ok(())
        }
    }
    fn prepared() -> (Memory, Memory, UndoBinding, Resources) {
        let r = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let binding = UndoBinding {
            volume: [1; 32],
            generation: 4,
            transaction: [2; 16],
        };
        let mut bytes = vec![0; 64];
        bytes[10] = 1;
        let plan = UndoPlan::new(
            binding,
            64,
            vec![
                WriteRange::new(0, vec![0], vec![7]).unwrap(),
                WriteRange::new(10, vec![1, 0], vec![1, 0]).unwrap(),
            ],
            UndoLimits::default(),
            &r,
        )
        .unwrap();
        let mut target = Memory {
            bytes,
            writes: 0,
            fail: true,
        };
        let mut journal = Memory {
            bytes: vec![0; 4096],
            writes: 0,
            fail: false,
        };
        let error = plan.commit(&mut target, &mut journal, &r).unwrap_err();
        assert!(error.recovery_required);
        drop(plan);
        target.fail = false;
        target.bytes[0] = 7;
        assert_eq!(inspect(&journal, &r).unwrap().state, UndoState::Prepared);
        (target, journal, binding, r)
    }
    #[test]
    fn rejected_or_cancelled_fence_finishes_before_any_restore_or_marker_write() {
        for cancel in [false, true] {
            let (mut target, mut journal, binding, r) = prepared();
            let old_target = target.bytes.clone();
            let old_journal = journal.bytes.clone();
            let writes = (target.writes, journal.writes);
            let mut fence = Fence {
                offsets: vec![],
                reject: !cancel,
                cancellation: cancel.then(|| r.cancellation.clone()),
            };
            let error = recover_validated(
                &mut target,
                &mut journal,
                binding,
                UndoLimits::default(),
                &r,
                &mut fence,
            )
            .unwrap_err();
            assert_eq!(fence.offsets, [0, 10]);
            assert!(!error.target_may_have_changed);
            assert!(error.recovery_required);
            assert_eq!(
                error.source.kind,
                if cancel {
                    ErrorKind::Cancelled
                } else {
                    ErrorKind::InvalidData
                }
            );
            assert_eq!(target.bytes, old_target);
            assert_eq!(journal.bytes, old_journal);
            assert_eq!((target.writes, journal.writes), writes);
            assert_eq!(r.memory.used(), 0);
        }
        let (mut target, mut journal, binding, r) = prepared();
        let mut fence = Fence {
            offsets: vec![],
            reject: false,
            cancellation: None,
        };
        assert_eq!(
            recover_validated(
                &mut target,
                &mut journal,
                binding,
                UndoLimits::default(),
                &r,
                &mut fence
            )
            .unwrap()
            .state,
            UndoState::RolledBack
        );
        assert_eq!(target.bytes[0], 0);
        assert_eq!(&target.bytes[10..12], &[1, 0]);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn malformed_late_range_with_valid_digest_never_reaches_engine_validator() {
        let (mut target, mut journal, binding, r) = prepared();
        let mut header = headers(&journal, &r).unwrap().unwrap();
        let body = &mut journal.bytes[BODY as usize..BODY as usize + header.bytes as usize];
        let (_, _, _, second) = decode_patch(body, 0).unwrap();
        body[second..second + 8].copy_from_slice(&63u64.to_le_bytes());
        header.digest = Sha256::digest(body).into();
        journal.bytes[..HEADER].copy_from_slice(&header.encode());
        let old_target = target.bytes.clone();
        let old_journal = journal.bytes.clone();
        let writes = (target.writes, journal.writes);
        let mut fence = Fence {
            offsets: vec![],
            reject: false,
            cancellation: None,
        };
        let error = recover_validated(
            &mut target,
            &mut journal,
            binding,
            UndoLimits::default(),
            &r,
            &mut fence,
        )
        .unwrap_err();
        assert!(fence.offsets.is_empty());
        assert!(!error.target_may_have_changed);
        assert_eq!(error.source.kind, ErrorKind::InvalidData);
        assert_eq!(target.bytes, old_target);
        assert_eq!(journal.bytes, old_journal);
        assert_eq!((target.writes, journal.writes), writes);
        assert_eq!(r.memory.used(), 0);
    }
}
