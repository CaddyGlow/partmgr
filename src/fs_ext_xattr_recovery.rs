//! Private, scope-separated durable originals and cold COW derivation.
//! Payload is only admitted inside the new typed native preparation transaction;
//! ordinary preparation v1 and count-repair v2/scope1 must never dispatch here.
use super::{invalid, unsupported, xattr_plan, xattr_write};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use crate::platform::prelude::*;
use crate::{
    fs_core::{NativeName, Reservation, Resources},
    platform::io,
    storage::Storage,
};
use sha2::{Digest, Sha256};
const MAGIC: &[u8; 16] = b"PMGRXATTRCOW0003";
const VERSION: u32 = 3;
const SCOPE: u32 = 2;
const HEADER: usize = 1116;
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub capsule_bytes: usize,
    pub source_bytes: usize,
    pub homes: usize,
    pub journal_blocks: usize,
    pub path_depth: usize,
    pub intent_bytes: usize,
    pub work: usize,
    pub planning: xattr_plan::Limits,
}
pub(super) struct Capsule {
    binding: (u128, u64),
    intent: [u8; 32],
    original_digest: [u8; 32],
    bytes: Vec<u8>,
    _lease: Reservation,
}
impl Capsule {
    pub fn matches(&self, plan: &xattr_plan::Plan) -> bool {
        self.binding == plan.binding()
            && self.intent == *plan.intent()
            && self.original_digest == *plan.original_digest()
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
struct Work<'a> {
    used: usize,
    maximum: usize,
    r: &'a Resources,
}
impl Work<'_> {
    fn charge(&mut self, n: usize) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        self.used = self
            .used
            .checked_add(n)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| unsupported("xattr durable derivation work ceiling"))?;
        Ok(())
    }
}
fn allocate(n: usize, r: &Resources) -> io::Result<(Vec<u8>, Reservation)> {
    let lease = r.memory.reserve(n as u64).map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(n).map_err(io::Error::other)?;
    if bytes.capacity() > n {
        return Err(unsupported("xattr durable capacity"));
    }
    bytes.resize(n, 0);
    Ok((bytes, lease))
}
fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    let a = bytes
        .get(
            at..at
                .checked_add(4)
                .ok_or_else(|| invalid("xattr capsule offset"))?,
        )
        .ok_or_else(|| invalid("xattr capsule truncated word"))?;
    Ok(u32::from_le_bytes([a[0], a[1], a[2], a[3]]))
}
fn put32(bytes: &mut [u8], at: usize, n: usize) -> io::Result<()> {
    bytes[at..at + 4].copy_from_slice(&u32::try_from(n).map_err(io::Error::other)?.to_le_bytes());
    Ok(())
}
fn digest(source: &[u8], bs: usize, journal: &[u32], work: &mut Work<'_>) -> io::Result<[u8; 32]> {
    if !matches!(bs, 1024 | 2048 | 4096) || !source.len().is_multiple_of(bs) {
        return Err(invalid("xattr durable geometry"));
    }
    let mut hash = Sha256::new();
    hash.update(b"partmgr-xattr-original-nonjournal-v3");
    hash.update((source.len() as u64).to_le_bytes());
    hash.update((bs as u32).to_le_bytes());
    for (i, block) in source.chunks_exact(bs).enumerate() {
        work.charge(journal.len() + 1)?;
        if !journal.contains(&(i as u32)) {
            work.charge(bs)?;
            hash.update((i as u64).to_le_bytes());
            hash.update(block);
        }
    }
    Ok(hash.finalize().into())
}
fn operation<'a>(m: xattr_write::Mutation<'a>) -> (u32, &'a [u8]) {
    use xattr_write::{Mutation, SetPolicy};
    match m {
        Mutation::Remove => (0, &[]),
        Mutation::Set { value, policy } => (
            match policy {
                SetPolicy::Create => 1,
                SetPolicy::Replace => 2,
                SetPolicy::Upsert => 3,
            },
            value,
        ),
    }
}
/// Encode exact original affected homes, intent, and original journal mapping.
/// All arithmetic/work ceilings precede retained allocation and initialization.
#[allow(clippy::too_many_arguments)]
pub(super) fn seal(
    plan: &xattr_plan::Plan,
    path: &[NativeName],
    key: &[u8],
    mutation: xattr_write::Mutation<'_>,
    limits: Limits,
    r: &Resources,
) -> io::Result<Capsule> {
    let mut w = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    w.charge(1)?;
    if !plan.changed
        || plan.homes().is_empty()
        || plan.homes().len() > limits.homes
        || plan.journal_blocks().is_empty()
        || plan.journal_blocks().len() > limits.journal_blocks
        || path.len() > limits.path_depth
        || plan.source_bytes() > limits.source_bytes as u64
    {
        return Err(unsupported("xattr durable source/profile ceiling"));
    }
    // Bind caller-provided intent to the sealed plan before durable preparation.
    w.charge(limits.planning.work)?;
    let binding = plan.binding();
    let independently_derived = xattr_plan::plan(
        &Snapshot(plan.original_source()),
        binding.0,
        binding.1,
        path,
        key,
        mutation,
        limits.planning,
        r,
    )?;
    if independently_derived.homes().len() != plan.homes().len()
        || independently_derived.journal_blocks() != plan.journal_blocks()
        || independently_derived
            .homes()
            .iter()
            .zip(plan.homes())
            .any(|(a, b)| {
                a.block != b.block || a.original != b.original || a.replacement != b.replacement
            })
    {
        return Err(invalid("xattr capsule intent differs from sealed plan"));
    }
    drop(independently_derived);
    let (op, value) = operation(mutation);
    let mut intent = key
        .len()
        .checked_add(value.len())
        .ok_or_else(|| unsupported("xattr intent overflow"))?;
    for component in path {
        let NativeName::Bytes(name) = component else {
            return Err(unsupported("xattr durable native path"));
        };
        intent = intent
            .checked_add(4)
            .and_then(|n| n.checked_add(name.len()))
            .ok_or_else(|| unsupported("xattr intent overflow"))?;
    }
    if intent > limits.intent_bytes {
        return Err(unsupported("xattr durable intent ceiling"));
    }
    let bs = plan.block_bytes();
    let total = HEADER
        .checked_add(intent)
        .and_then(|n| {
            plan.journal_blocks()
                .len()
                .checked_mul(4)
                .and_then(|j| n.checked_add(j))
        })
        .and_then(|n| {
            plan.homes()
                .len()
                .checked_mul(bs + 4)
                .and_then(|h| n.checked_add(h))
        })
        .filter(|n| *n <= limits.capsule_bytes)
        .ok_or_else(|| unsupported("xattr capsule byte ceiling"))?;
    // Initialization + assembly, plus full original digest, are separately charged.
    w.charge(
        total
            .checked_mul(2)
            .ok_or_else(|| unsupported("xattr capsule work overflow"))?,
    )?;
    let original = digest(plan.original_source(), bs, plan.journal_blocks(), &mut w)?;
    let (mut bytes, lease) = allocate(total, r)?;
    bytes[..16].copy_from_slice(MAGIC);
    put32(&mut bytes, 16, VERSION as usize)?;
    put32(&mut bytes, 20, SCOPE as usize)?;
    put32(&mut bytes, 24, bs)?;
    bytes[28..36].copy_from_slice(&plan.source_bytes().to_le_bytes());
    put32(&mut bytes, 36, plan.homes().len())?;
    put32(&mut bytes, 40, plan.journal_blocks().len())?;
    put32(&mut bytes, 44, path.len())?;
    put32(&mut bytes, 48, key.len())?;
    put32(&mut bytes, 52, value.len())?;
    put32(&mut bytes, 56, op as usize)?;
    bytes[60..92].copy_from_slice(&original);
    let original_journal_at = plan.journal_blocks()[0] as usize * bs;
    bytes[92..1116]
        .copy_from_slice(&plan.original_source()[original_journal_at..original_journal_at + 1024]);
    let mut at = HEADER;
    for component in path {
        let NativeName::Bytes(name) = component else {
            return Err(invalid("xattr path changed"));
        };
        put32(&mut bytes, at, name.len())?;
        at += 4;
        bytes[at..at + name.len()].copy_from_slice(name);
        at += name.len();
    }
    bytes[at..at + key.len()].copy_from_slice(key);
    at += key.len();
    bytes[at..at + value.len()].copy_from_slice(value);
    at += value.len();
    for &block in plan.journal_blocks() {
        put32(&mut bytes, at, block as usize)?;
        at += 4;
    }
    for home in plan.homes() {
        put32(&mut bytes, at, home.block as usize)?;
        at += 4;
        bytes[at..at + bs].copy_from_slice(&home.original[..bs]);
        at += bs;
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(Capsule {
        binding: plan.binding(),
        intent: *plan.intent(),
        original_digest: *plan.original_digest(),
        bytes,
        _lease: lease,
    })
}
struct Snapshot<'a>(&'a [u8]);
impl Storage for Snapshot<'_> {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or_else(|| invalid("xattr snapshot range"))?;
        out.copy_from_slice(
            self.0
                .get(at..end)
                .ok_or_else(|| invalid("xattr snapshot range"))?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(unsupported("xattr reconstructed source is read-only"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(unsupported("xattr reconstructed source is read-only"))
    }
}
/// Redo bytes supplied by the independently validated native transaction parser.
/// These are never trusted simply because descriptor/commit checksums passed.
pub(super) struct Redo<'a> {
    pub block: u32,
    pub bytes: &'a [u8],
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| invalid("xattr capsule cursor"))?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| invalid("xattr capsule truncated"))?;
        self.at = end;
        Ok(out)
    }
    fn word(&mut self) -> io::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}
/// Cold pre-write authority: reconstruct OLD, bind its complete nonjournal bytes,
/// independently rederive the operation, and compare every original/redo home.
/// The returned plan remains private and must undergo actual controller guards.
/// This function performs no writes, even on malformed/foreign capsules.
pub(super) fn derive(
    observed: &[u8],
    capsule: &[u8],
    redo: Option<&[Redo<'_>]>,
    scope: u128,
    generation: u64,
    limits: Limits,
    r: &Resources,
) -> io::Result<xattr_plan::Plan> {
    let mut w = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    w.charge(1)?;
    if capsule.len() < HEADER
        || capsule.len() > limits.capsule_bytes
        || &capsule[..16] != MAGIC
        || u32_at(capsule, 16)? != VERSION
        || u32_at(capsule, 20)? != SCOPE
    {
        return Err(invalid("xattr scoped capsule identity"));
    }
    let bs = u32_at(capsule, 24)? as usize;
    let length = u64::from_le_bytes(capsule[28..36].try_into().map_err(io::Error::other)?);
    if !matches!(bs, 1024 | 2048 | 4096)
        || length != observed.len() as u64
        || observed.len() > limits.source_bytes
        || !observed.len().is_multiple_of(bs)
    {
        return Err(invalid("xattr capsule source geometry"));
    }
    let homes = u32_at(capsule, 36)? as usize;
    let journals = u32_at(capsule, 40)? as usize;
    let paths = u32_at(capsule, 44)? as usize;
    let keylen = u32_at(capsule, 48)? as usize;
    let vallen = u32_at(capsule, 52)? as usize;
    let op = u32_at(capsule, 56)?;
    if homes == 0
        || homes > limits.homes
        || redo.is_some_and(|records| records.len() != homes)
        || journals == 0
        || journals > limits.journal_blocks
        || paths > limits.path_depth
        || keylen == 0
        || keylen > 255
        || (op == 0 && vallen != 0)
        || op > 3
    {
        return Err(invalid("xattr capsule cardinality/intent"));
    }
    // Finite preflight before source-sized zeroing/copy and nested full audits.
    let envelope = observed
        .len()
        .checked_mul(4)
        .and_then(|n| capsule.len().checked_mul(2).and_then(|c| n.checked_add(c)))
        .and_then(|n| n.checked_add(limits.planning.work))
        .and_then(|n| {
            homes
                .checked_mul(homes)
                .and_then(|h| h.checked_mul(3))
                .and_then(|h| n.checked_add(h))
        })
        .and_then(|n| {
            journals
                .checked_mul(journals)
                .and_then(|j| n.checked_add(j))
        })
        .and_then(|n| {
            observed
                .len()
                .checked_div(bs)
                .and_then(|b| b.checked_mul(journals + 1))
                .and_then(|b| n.checked_add(b))
        })
        .ok_or_else(|| unsupported("xattr cold work overflow"))?;
    w.charge(envelope)?;
    let pathcharge = paths
        .checked_mul(core::mem::size_of::<NativeName>())
        .and_then(|n| n.checked_add(limits.intent_bytes))
        .ok_or_else(|| unsupported("xattr intent memory overflow"))?;
    let _intent_lease = r
        .memory
        .reserve(pathcharge as u64)
        .map_err(io::Error::other)?;
    let mut path = Vec::new();
    path.try_reserve_exact(paths).map_err(io::Error::other)?;
    if path.capacity() > paths {
        return Err(unsupported("xattr path capacity"));
    }
    let mut cursor = Cursor {
        bytes: capsule,
        at: HEADER,
    };
    let mut intent = keylen
        .checked_add(vallen)
        .ok_or_else(|| invalid("xattr intent overflow"))?;
    for _ in 0..paths {
        let len = cursor.word()? as usize;
        intent = intent
            .checked_add(
                len.checked_add(4)
                    .ok_or_else(|| invalid("xattr intent component overflow"))?,
            )
            .filter(|n| *n <= limits.intent_bytes)
            .ok_or_else(|| unsupported("xattr intent byte ceiling"))?;
        let name = cursor.take(len)?;
        let (mut owned, _name_lease) = allocate(len, r)?;
        owned.copy_from_slice(name);
        // Aggregate intent lease above owns all retained name bytes.
        path.push(NativeName::Bytes(owned));
    }
    if intent > limits.intent_bytes {
        return Err(unsupported("xattr intent byte ceiling"));
    }
    let key = cursor.take(keylen)?;
    let value = cursor.take(vallen)?;
    let journalcharge = journals
        .checked_mul(4)
        .ok_or_else(|| unsupported("xattr journal memory overflow"))?;
    let _journal_lease = r
        .memory
        .reserve(journalcharge as u64)
        .map_err(io::Error::other)?;
    let mut journal = Vec::new();
    journal
        .try_reserve_exact(journals)
        .map_err(io::Error::other)?;
    if journal.capacity() > journals {
        return Err(unsupported("xattr journal capacity"));
    }
    for _ in 0..journals {
        let block = cursor.word()?;
        if block as usize >= observed.len() / bs || journal.contains(&block) {
            return Err(invalid("xattr capsule journal map"));
        }
        journal.push(block);
    }
    let (mut original, _original_lease) = allocate(observed.len(), r)?;
    original.copy_from_slice(observed);
    // The journal is excluded from the volume digest, but its exact clean native
    // header is durable preparation evidence and required for rederivation.
    let journal_at = journal[0] as usize * bs;
    original[journal_at..journal_at + 1024].copy_from_slice(&capsule[92..1116]);
    let originals_start = cursor.at;
    for i in 0..homes {
        let block = cursor.word()?;
        if block as usize >= observed.len() / bs || journal.contains(&block) {
            return Err(invalid("xattr original home destination"));
        }
        // Reject duplicate homes without a second unbounded allocation.
        for j in 0..i {
            if u32_at(capsule, originals_start + j * (4 + bs))? == block {
                return Err(invalid("xattr duplicate original home"));
            }
        }
        let old = cursor.take(bs)?;
        let at = block as usize * bs;
        original[at..at + bs].copy_from_slice(old);
    }
    if cursor.at != capsule.len() {
        return Err(invalid("xattr capsule trailing bytes"));
    }
    // Envelope charged hash and membership work above; hash helper has its own
    // finite subordinate allowance and cancellation checks.
    let mut hashing = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    if digest(&original, bs, &journal, &mut hashing)? != capsule[60..92] {
        return Err(invalid("xattr reconstructed original digest"));
    }
    let mutation = match op {
        0 => xattr_write::Mutation::Remove,
        1 => xattr_write::Mutation::Set {
            value,
            policy: xattr_write::SetPolicy::Create,
        },
        2 => xattr_write::Mutation::Set {
            value,
            policy: xattr_write::SetPolicy::Replace,
        },
        _ => xattr_write::Mutation::Set {
            value,
            policy: xattr_write::SetPolicy::Upsert,
        },
    };
    let plan = xattr_plan::plan(
        &Snapshot(&original),
        scope,
        generation,
        &path,
        key,
        mutation,
        limits.planning,
        r,
    )?;
    if !plan.changed
        || plan.block_bytes() != bs
        || plan.journal_blocks() != journal
        || plan.homes().len() != homes
    {
        return Err(invalid("xattr cold independently derived shape"));
    }
    for (i, home) in plan.homes().iter().enumerate() {
        r.cancellation.check().map_err(io::Error::other)?;
        let at = originals_start + i * (4 + bs);
        if u32_at(capsule, at)? != home.block || capsule[at + 4..at + 4 + bs] != home.original[..bs]
        {
            return Err(invalid("xattr cold original home ordering/content"));
        }
        let record = if let Some(redo) = redo {
            let mut matching = redo.iter().filter(|record| record.block == home.block);
            let record = matching
                .next()
                .ok_or_else(|| invalid("xattr missing derived redo home"))?;
            if matching.next().is_some() || record.bytes.len() != bs {
                return Err(invalid("xattr duplicate/malformed redo home"));
            }
            Some(record)
        } else {
            None
        };
        let offset = home.block as usize * bs;
        for (inside, (&new, &old)) in home.replacement[..bs]
            .iter()
            .zip(&home.original[..bs])
            .enumerate()
        {
            let physical = offset + inside;
            let fence = if physical == 1120 { 4 } else { 0 };
            // All unrelated bytes remain exact even in partially checkpointed homes.
            if record.is_some_and(|record| record.bytes[inside] & !fence != new & !fence) {
                return Err(invalid("xattr redo differs from derived operation"));
            }
            let current = observed[physical] & !fence;
            if current != old & !fence && (record.is_none() || current != new & !fence) {
                return Err(invalid(
                    "xattr observed home is neither original nor derived",
                ));
            }
        }
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    #[test]
    fn original_digest_masks_only_exact_journal_blocks() {
        let r = resources();
        let mut original = vec![0u8; 4096];
        let calculate = |bytes: &[u8], journal: &[u32]| {
            digest(
                bytes,
                1024,
                journal,
                &mut Work {
                    used: 0,
                    maximum: 100000,
                    r: &r,
                },
            )
            .unwrap()
        };
        let expected = calculate(&original, &[2]);
        original[2048 + 17] = 3;
        assert_eq!(calculate(&original, &[2]), expected);
        original[1024 + 17] = 3;
        assert_ne!(calculate(&original, &[2]), expected);
        assert_ne!(calculate(&original, &[1, 2]), expected);
        assert_ne!(calculate(&original, &[3]), expected);
    }
    #[test]
    fn digest_finite_work_and_cancellation_are_enforced_before_hash_body() {
        let r = resources();
        let source = vec![0; 1024];
        let mut work = Work {
            used: 0,
            maximum: 1024,
            r: &r,
        };
        assert!(digest(&source, 1024, &[], &mut work).is_err());
        let mut work = Work {
            used: 0,
            maximum: 1025,
            r: &r,
        };
        assert!(digest(&source, 1024, &[], &mut work).is_ok());
        r.cancellation.cancel();
        let mut work = Work {
            used: 0,
            maximum: 1025,
            r: &r,
        };
        assert!(digest(&source, 1024, &[], &mut work).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn truncated_words_and_cursor_overflow_are_fatal() {
        assert!(u32_at(&[1, 2, 3], 0).is_err());
        assert!(u32_at(&[0; 4], usize::MAX).is_err());
        let mut cursor = Cursor {
            bytes: &[0; 4],
            at: 3,
        };
        assert!(cursor.take(2).is_err());
        assert_eq!(cursor.at, 3);
        cursor.at = usize::MAX;
        assert!(cursor.take(1).is_err());
    }
}
