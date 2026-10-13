//! Distinct classic EXT_ATTR clean-journal profile check for typed COW planning.
//! This grants no ordinary owned-open or replay authority.
use super::*;
pub(crate) fn clean_geometry(
    primary: &[u8; 1024],
    header: &[u8; 1024],
    mapped_blocks: usize,
) -> io::Result<Geometry> {
    if super::super::u16le(primary, 56) != 0xef53
        || super::super::u16le(primary, 58) != 1
        || super::super::u16le(primary, 88) != 128
        || super::super::u32le(primary, 92) != 12
        || super::super::u32le(primary, 96) != 2
        || super::super::u32le(primary, 100) & !3 != 0
        || super::super::u32le(primary, 224) != 8
        || super::super::u32le(primary, 228) != 0
        || primary[208..224].iter().any(|b| *b != 0)
    {
        return Err(unsupported("xattr typed classic clean journal profile"));
    }
    let log = super::super::u32le(primary, 24);
    if log > 2 {
        return Err(unsupported("xattr typed journal block size"));
    }
    let checksums = match be32(header, 40) & 0x18 {
        0 => Checksums::None,
        8 => Checksums::V2,
        16 => Checksums::V3,
        _ => return Err(unsupported("xattr typed journal checksums")),
    };
    let geometry = Geometry {
        block_bytes: 1024usize << log,
        first: be32(header, 20),
        maximum: be32(header, 16),
        start: be32(header, 28),
        sequence: be32(header, 24),
        uuid: primary[104..120].try_into().map_err(io::Error::other)?,
        checksums,
        revoke: be32(header, 40) & 1 != 0,
    };
    geometry.check()?;
    if geometry.start != 0 || geometry.maximum as usize != mapped_blocks {
        return Err(invalid("xattr typed journal is active or mapping differs"));
    }
    original_journal(&geometry, header)?;
    Ok(geometry)
}

use super::super::{xattr_plan, xattr_recovery};
use sha2::{Digest, Sha256};
const PREFIX: usize = 1116;
fn map_digest(blocks: &[u32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"partmgr-xattr-original-journal-map-v3");
    for n in blocks {
        hash.update(n.to_le_bytes());
    }
    hash.finalize().into()
}
fn word(bytes: &[u8], at: usize) -> io::Result<usize> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| invalid("xattr native capsule word offset"))?;
    let b = bytes
        .get(at..end)
        .ok_or_else(|| invalid("xattr native capsule word"))?;
    usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).map_err(io::Error::other)
}
/// Native preparation publishes original homes, with RECOVER set only in primary.
/// Intent/digests are metadata in native-ignored, CRC-covered padding, never fake
/// filesystem destinations. The physical footprint includes every native block.
pub(crate) fn prepare_xattr(
    geometry: &Geometry,
    plan: &xattr_plan::Plan,
    capsule: &xattr_recovery::Capsule,
    maximum_work: usize,
    maximum_bytes: u64,
    r: &Resources,
) -> io::Result<EncodedTransaction> {
    r.cancellation.check().map_err(io::Error::other)?;
    if !capsule.matches(plan) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "xattr preparation capsule belongs to another sealed plan",
        )));
    }
    if !matches!(geometry.checksums, Checksums::None)
        || plan.homes().is_empty()
        || plan.homes().len() > 8
    {
        return Err(unsupported("xattr preparation legacy bounded tag profile"));
    }
    let bs = geometry.block_bytes;
    let payload = capsule.bytes();
    let homes = word(payload, 36)?;
    let journals = word(payload, 40)?;
    if homes != plan.homes().len()
        || journals != plan.journal_blocks().len()
        || bs != plan.block_bytes()
    {
        return Err(invalid("xattr preparation plan/capsule shape"));
    }
    let suffix = journals
        .checked_mul(4)
        .and_then(|n| homes.checked_mul(bs + 4).and_then(|h| n.checked_add(h)))
        .ok_or_else(|| budget("xattr compact capsule suffix"))?;
    let intent_end = payload
        .len()
        .checked_sub(suffix)
        .filter(|n| *n >= PREFIX)
        .ok_or_else(|| invalid("xattr compact capsule length"))?;
    let metadata = 124usize
        .checked_add(intent_end - PREFIX)
        .ok_or_else(|| budget("xattr compact metadata overflow"))?;
    let first_space = bs - 4 - 640;
    let second_space = bs - 728;
    if metadata > first_space + second_space {
        return Err(budget("xattr native preparation intent padding ceiling"));
    }
    let footprint = (homes + 2)
        .checked_mul(bs)
        .and_then(|n| n.checked_add(2 * bs + 12))
        .ok_or_else(|| budget("xattr preparation physical overflow"))?;
    if footprint as u64 > maximum_bytes {
        return Err(budget("xattr preparation physical ceiling"));
    }
    let work = homes
        .checked_mul(4 * MAX_BLOCK)
        .and_then(|n| n.checked_add(metadata * 2))
        .ok_or_else(|| budget("xattr preparation work overflow"))?;
    if work > maximum_work {
        return Err(budget("xattr preparation work ceiling"));
    }
    let _records = r
        .memory
        .reserve((homes * core::mem::size_of::<ReplayBlock>()) as u64)
        .map_err(io::Error::other)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(homes)
        .map_err(|_| budget("xattr preparation allocation"))?;
    if records.capacity() > homes {
        return Err(budget("xattr preparation capacity"));
    }
    let primary = u32::from(bs == 1024);
    let mut seen_primary = false;
    for home in plan.homes() {
        r.cancellation.check().map_err(io::Error::other)?;
        let mut bytes = home.original;
        if home.block == primary {
            let inside = 1024 % bs;
            if super::super::u32le(&bytes, inside + 96) & 4 != 0 {
                return Err(invalid("xattr original primary already fenced"));
            }
            bytes[inside + 96] |= 4;
            seen_primary = true;
        }
        records.push(ReplayBlock {
            destination: home.block,
            bytes,
        });
    }
    if !seen_primary {
        return Err(invalid("xattr preparation missing primary original"));
    }
    let mut encoded = encode(geometry, &records, maximum_work, r, |block| {
        if plan.journal_blocks().contains(&block) {
            Err(invalid("xattr preparation aliases journal"))
        } else {
            Ok(())
        }
    })?;
    if encoded.blocks.len() != homes + 2 {
        return Err(invalid("xattr preparation descriptor count"));
    }
    let _metadata = r
        .memory
        .reserve(metadata as u64)
        .map_err(io::Error::other)?;
    let mut compact = Vec::new();
    compact
        .try_reserve_exact(metadata)
        .map_err(|_| budget("xattr compact allocation"))?;
    if compact.capacity() > metadata {
        return Err(budget("xattr compact capacity"));
    }
    compact.extend_from_slice(&payload[..92]);
    compact.extend_from_slice(&payload[PREFIX..intent_end]);
    compact.extend_from_slice(&map_digest(plan.journal_blocks()));
    let last = encoded.blocks.len() - 1;
    for (part, index) in [0, last].into_iter().enumerate() {
        let block = &mut encoded.blocks[index].bytes;
        block[96..112].copy_from_slice(CAPSULE_MAGIC);
        put32(block, 112, 3);
        put32(block, 116, 2);
        put32(block, 120, metadata as u32);
        put32(block, 124, homes as u32);
        block[128..640].copy_from_slice(&payload[92 + part * 512..92 + (part + 1) * 512]);
        let start = if part == 0 { 0 } else { first_space };
        let end = metadata.min(start + if part == 0 { first_space } else { second_space });
        if start < end {
            put_compact_fragment(block, part, &compact[start..end]);
        }
    }
    legacy::stamp(geometry, &mut encoded.blocks)?;
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(encoded)
}
pub(crate) struct NativeCapsule {
    pub(crate) bytes: Vec<u8>,
    pub(crate) next_logical: u32,
    _lease: Reservation,
}
/// Validate the complete first native preparation transaction and reconstruct
/// durable originals. Candidate map is source-resolved, then bound by digest and
/// independently rederived full ownership before any recovery write.
pub(crate) fn read_xattr_preparation(
    geometry: &Geometry,
    candidate_map: &[u32],
    maximum_bytes: usize,
    maximum_work: usize,
    r: &Resources,
    mut read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
) -> io::Result<NativeCapsule> {
    if !matches!(geometry.checksums, Checksums::None) {
        return Err(unsupported("xattr preparation checksum profile"));
    }
    geometry.check()?;
    r.cancellation.check().map_err(io::Error::other)?;
    let _scratch = r
        .memory
        .reserve((3 * MAX_BLOCK) as u64)
        .map_err(io::Error::other)?;
    let bs = geometry.block_bytes;
    let mut descriptor = [0; MAX_BLOCK];
    read(geometry.first, &mut descriptor[..bs])?;
    if descriptor[96..112] != *CAPSULE_MAGIC
        || be32(&descriptor, 112) != 3
        || be32(&descriptor, 116) != 2
    {
        return Err(invalid("xattr native preparation scope"));
    }
    let homes = be32(&descriptor, 124) as usize;
    let metadata = be32(&descriptor, 120) as usize;
    let first_space = bs - 4 - 640;
    let second_space = bs - 728;
    if homes == 0 || homes > 8 || metadata < 124 || metadata > first_space + second_space {
        return Err(invalid("xattr native preparation lengths"));
    }
    if homes + 2 >= (geometry.maximum - geometry.first) as usize {
        return Err(invalid("xattr preparation does not fit original ring"));
    }
    let mut commit_logical = geometry.first;
    for _ in 0..homes + 1 {
        commit_logical = geometry.next(commit_logical);
    }
    let next = geometry.next(commit_logical);
    let mut commit = [0; MAX_BLOCK];
    read(commit_logical, &mut commit[..bs])?;
    if commit[96..128] != descriptor[96..128] {
        return Err(invalid("xattr native preparation paired metadata"));
    }
    let mut scan_geometry = *geometry;
    scan_geometry.start = geometry.first;
    let parsed = scan_owned(
        &scan_geometry,
        homes,
        maximum_work,
        r,
        |logical, out| {
            if logical == next {
                out.fill(0);
                Ok(())
            } else {
                read(logical, out)
            }
        },
        |block| {
            if candidate_map.contains(&block) {
                Err(invalid("xattr native original aliases journal"))
            } else {
                Ok(())
            }
        },
    )?;
    if parsed.committed_transactions != 1
        || parsed.blocks.len() != homes
        || parsed.next_sequence != geometry.sequence.wrapping_add(1)
    {
        return Err(invalid("xattr native preparation transaction count"));
    }
    let total = PREFIX
        .checked_add(metadata - 124)
        .and_then(|n| {
            candidate_map
                .len()
                .checked_mul(4)
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| homes.checked_mul(bs + 4).and_then(|h| n.checked_add(h)))
        .filter(|n| *n <= maximum_bytes)
        .ok_or_else(|| budget("xattr reconstructed capsule ceiling"))?;
    let envelope = total
        .checked_mul(2)
        .and_then(|n| {
            candidate_map
                .len()
                .checked_mul(4)
                .and_then(|m| n.checked_add(m))
        })
        .ok_or_else(|| budget("xattr reconstruction work overflow"))?;
    if envelope > maximum_work {
        return Err(budget("xattr reconstruction work ceiling"));
    }
    let lease = r
        .memory
        .reserve((total + metadata) as u64)
        .map_err(io::Error::other)?;
    let mut compact = Vec::new();
    compact
        .try_reserve_exact(metadata)
        .map_err(|_| budget("xattr compact read allocation"))?;
    if compact.capacity() > metadata {
        return Err(budget("xattr compact read capacity"));
    }
    compact.extend_from_slice(compact_fragment(&descriptor, 0, metadata.min(first_space)));
    if metadata > first_space {
        compact.extend_from_slice(compact_fragment(&commit, 1, metadata - first_space));
    }
    if compact[metadata - 32..] != map_digest(candidate_map) {
        return Err(invalid("xattr native original journal-map digest"));
    }
    if word(&compact, 36)? != homes || word(&compact, 40)? != candidate_map.len() {
        return Err(invalid("xattr compact/native cardinality"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| budget("xattr capsule reconstruction allocation"))?;
    if bytes.capacity() > total {
        return Err(budget("xattr capsule reconstruction capacity"));
    }
    bytes.extend_from_slice(&compact[..92]);
    bytes.extend_from_slice(&descriptor[128..640]);
    bytes.extend_from_slice(&commit[128..640]);
    bytes.extend_from_slice(&compact[92..metadata - 32]);
    for block in candidate_map {
        bytes.extend_from_slice(&block.to_le_bytes());
    }
    let primary = u32::from(bs == 1024);
    let mut primary_seen = false;
    for record in &parsed.blocks {
        r.cancellation.check().map_err(io::Error::other)?;
        bytes.extend_from_slice(&record.destination.to_le_bytes());
        let start = bytes.len();
        bytes.extend_from_slice(&record.bytes[..bs]);
        if record.destination == primary {
            let inside = 1024 % bs;
            if bytes[start + inside + 96] & 4 == 0 {
                return Err(invalid("xattr preparation missing recovery fence"));
            }
            bytes[start + inside + 96] &= !4;
            primary_seen = true;
        }
    }
    if !primary_seen || bytes.len() != total {
        return Err(invalid("xattr native original primary/length"));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(NativeCapsule {
        bytes,
        next_logical: next,
        _lease: lease,
    })
}

use crate::storage::Storage;
#[derive(Clone, Copy)]
pub(crate) struct LifecycleLimits {
    pub(crate) proof: xattr_recovery::Limits,
    pub(crate) records: usize,
    pub(crate) work: usize,
    pub(crate) physical_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Old,
    New,
    Noop,
}
struct Source<'a>(&'a [u8]);
impl Storage for Source<'_> {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or_else(|| invalid("xattr lifecycle source range"))?;
        out.copy_from_slice(
            self.0
                .get(at..end)
                .ok_or_else(|| invalid("xattr lifecycle source range"))?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(unsupported("xattr lifecycle preflight source writes"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(unsupported("xattr lifecycle preflight source flush"))
    }
}
fn preflight_work(length: usize, limits: LifecycleLimits) -> io::Result<usize> {
    length
        .checked_mul(8)
        .and_then(|n| n.checked_add(limits.proof.work))
        .and_then(|n| {
            limits
                .records
                .checked_mul(12 * MAX_BLOCK)
                .and_then(|h| n.checked_add(h))
        })
        .and_then(|n| {
            limits
                .proof
                .journal_blocks
                .checked_mul(16 * MAX_BLOCK + 512)
                .and_then(|j| n.checked_add(j))
        })
        .ok_or_else(|| budget("xattr lifecycle work envelope overflow"))
}
fn preflight(length: usize, limits: LifecycleLimits) -> io::Result<()> {
    if length > limits.proof.source_bytes || limits.records > limits.proof.homes {
        return Err(budget("xattr lifecycle source/record ceiling"));
    }
    let work = preflight_work(length, limits)?;
    if work > limits.work {
        return Err(budget("xattr lifecycle work envelope ceiling"));
    }
    Ok(())
}
fn compare_source(storage: &dyn Storage, expected: &[u8], r: &Resources) -> io::Result<()> {
    let _lease = r
        .memory
        .reserve(MAX_BLOCK as u64)
        .map_err(io::Error::other)?;
    let mut bytes = [0; MAX_BLOCK];
    for (i, chunk) in expected.chunks(MAX_BLOCK).enumerate() {
        r.cancellation.check().map_err(io::Error::other)?;
        storage.read_exact_at(i as u64 * MAX_BLOCK as u64, &mut bytes[..chunk.len()])?;
        r.cancellation.check().map_err(io::Error::other)?;
        if bytes[..chunk.len()] != *chunk {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "xattr lifecycle observed source changed",
            )));
        }
    }
    let length = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    if length != expected.len() as u64 {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "xattr lifecycle source length changed",
        )));
    }
    Ok(())
}
fn write(
    storage: &mut dyn Storage,
    at: u64,
    bytes: &[u8],
    length: u64,
    r: &Resources,
) -> io::Result<()> {
    let end = at
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| invalid("xattr lifecycle write overflow"))?;
    let found = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    if found != length || end > length {
        return Err(invalid("xattr lifecycle write geometry changed"));
    }
    let mut done = 0;
    while done < bytes.len() {
        r.cancellation.check().map_err(io::Error::other)?;
        let n = storage.write_at(at + done as u64, &bytes[done..])?;
        if n == 0 || n > bytes.len() - done {
            return Err(io::ErrorKind::WriteZero.into());
        }
        done += n;
    }
    r.cancellation.check().map_err(io::Error::other)
}
fn flush_check(storage: &mut dyn Storage, at: u64, bytes: &[u8], r: &Resources) -> io::Result<()> {
    r.cancellation.check().map_err(io::Error::other)?;
    storage.flush()?;
    r.cancellation.check().map_err(io::Error::other)?;
    let _lease = r
        .memory
        .reserve(MAX_BLOCK as u64)
        .map_err(io::Error::other)?;
    let mut raw = [0; MAX_BLOCK];
    for (i, chunk) in bytes.chunks(MAX_BLOCK).enumerate() {
        storage.read_exact_at(at + i as u64 * MAX_BLOCK as u64, &mut raw[..chunk.len()])?;
        r.cancellation.check().map_err(io::Error::other)?;
        if raw[..chunk.len()] != *chunk {
            return Err(invalid("xattr lifecycle durable readback"));
        }
    }
    Ok(())
}
/// Actual private typed publication. Any error after the first attempted write
/// requires cold recovery; callers must retain storage exclusively throughout.
/// The same sealed full-source proof is checked at both real publication phases.
pub(crate) fn commit(
    storage: &mut dyn Storage,
    binding: (u128, u64),
    plan: &xattr_plan::Plan,
    capsule: Option<&xattr_recovery::Capsule>,
    limits: LifecycleLimits,
    r: &Resources,
) -> io::Result<Outcome> {
    r.cancellation.check().map_err(io::Error::other)?;
    if binding != plan.binding() {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "xattr controller foreign scope or generation",
        )));
    }
    let length = usize::try_from(plan.source_bytes()).map_err(io::Error::other)?;
    preflight(length, limits)?;
    if plan.homes().len() > limits.records {
        return Err(budget("xattr lifecycle home record ceiling"));
    }
    if !plan.changed {
        plan.check_source(storage, false, limits.work, r)?;
        return Ok(Outcome::Noop);
    }
    let source = Source(plan.original_source());
    let storage_view: &dyn Storage = &source;
    let decoder = super::super::ExtDecoder::open_reader(storage_view, plan.binding().0, r, true)?;
    let map = decoder.file_map(
        decoder.geometry().journal_inode,
        plan.journal_blocks().len(),
        r,
        false,
    )?;
    let bs = plan.block_bytes();
    let primary: &[u8; 1024] = plan.original_source()[1024..2048]
        .try_into()
        .map_err(io::Error::other)?;
    let journal_at = plan.journal_blocks()[0] as usize * bs;
    let original_header: &[u8; 1024] = plan.original_source()[journal_at..journal_at + 1024]
        .try_into()
        .map_err(io::Error::other)?;
    let initial = clean_geometry(primary, original_header, plan.journal_blocks().len())?;
    let mut proof = NativeJournalProof {
        geometry: initial,
        map,
    };
    let capsule =
        capsule.ok_or_else(|| invalid("xattr changed plan requires scoped durable capsule"))?;
    if !capsule.matches(plan) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "xattr controller capsule belongs to another sealed plan",
        )));
    }
    let prepared = prepare_xattr(
        &initial,
        plan,
        capsule,
        limits.work,
        limits.physical_bytes,
        r,
    )?;
    let _records = r
        .memory
        .reserve((plan.homes().len() * core::mem::size_of::<ReplayBlock>()) as u64)
        .map_err(io::Error::other)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(plan.homes().len())
        .map_err(|_| budget("xattr mutation record allocation"))?;
    if records.capacity() > plan.homes().len() {
        return Err(budget("xattr mutation record capacity"));
    }
    for home in plan.homes() {
        let mut bytes = home.replacement;
        if home.block == u32::from(bs == 1024) {
            bytes[1024 % bs + 96] |= 4;
        }
        records.push(ReplayBlock {
            destination: home.block,
            bytes,
        });
    }
    let mut mutation_geometry = initial;
    mutation_geometry.start = prepared.next_logical;
    mutation_geometry.sequence = initial.sequence.wrapping_add(1);
    let mutation = encode(&mutation_geometry, &records, limits.work, r, |block| {
        if plan.journal_blocks().contains(&block) {
            Err(invalid("xattr mutation destination aliases journal"))
        } else {
            Ok(())
        }
    })?;
    for block in &mutation.blocks {
        if prepared.blocks.iter().any(|p| p.logical == block.logical) {
            return Err(budget("xattr two-transaction ring overlap"));
        }
    }
    if prepared
        .blocks
        .iter()
        .any(|p| p.logical == mutation.next_logical)
    {
        return Err(budget(
            "xattr two-transaction clearing tail overlaps preparation",
        ));
    }
    let footprint = (prepared.blocks.len() + mutation.blocks.len() + plan.homes().len() + 6)
        .checked_mul(bs)
        .and_then(|n| n.checked_add(24))
        .ok_or_else(|| budget("xattr full lifecycle physical overflow"))?;
    publication_budget(
        preflight_work(length, limits)?,
        footprint,
        &prepared,
        &mutation,
        bs,
        limits.work,
        limits.physical_bytes,
    )?;
    // Phase 1, after every allocation/encoding/refusal but before any write.
    plan.check_source(storage, false, limits.work, r)?;
    proof.geometry.start = initial.first;
    publish_log(storage, &proof, &prepared, r)?;
    let mut active = *original_header;
    put32(&mut active, 28, initial.first);
    write(storage, journal_at as u64, &active, length as u64, r)?;
    flush_check(storage, journal_at as u64, &active, r)?;
    let primary_home = plan
        .homes()
        .iter()
        .find(|h| h.block == u32::from(bs == 1024))
        .ok_or_else(|| invalid("xattr phase2 primary home missing"))?;
    let mut fence = primary_home.original;
    fence[1024 % bs + 96] |= 4;
    let primary_at = primary_home.block as u64 * bs as u64;
    write(storage, primary_at, &fence[..bs], length as u64, r)?;
    flush_check(storage, primary_at, &fence[..bs], r)?;
    // Phase 2 is the real durable-preparation/fence boundary, not an outer check.
    plan.check_source(storage, true, limits.work, r)?;
    proof.geometry = mutation_geometry;
    publish_log(storage, &proof, &mutation, r)?;
    drop((proof, decoder));
    recover(storage, plan.binding().0, plan.binding().1, limits, r)
}

/// Cold restart validates the typed preparation, complete bounded native WAL,
/// durable OLD digest and canonical NEW derivation before its first write.
/// One committed preparation selects OLD; exactly one subsequent committed
/// mutation selects NEW. Foreign scopes/additional transactions are refused.
pub(crate) fn recover(
    storage: &mut dyn Storage,
    scope: u128,
    generation: u64,
    limits: LifecycleLimits,
    r: &Resources,
) -> io::Result<Outcome> {
    r.cancellation.check().map_err(io::Error::other)?;
    let length = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    let size = usize::try_from(length).map_err(io::Error::other)?;
    preflight(size, limits)?;
    let _snapshot = r.memory.reserve(length).map_err(io::Error::other)?;
    let mut observed = Vec::new();
    observed
        .try_reserve_exact(size)
        .map_err(|_| budget("xattr cold snapshot allocation"))?;
    if observed.capacity() > size {
        return Err(budget("xattr cold snapshot capacity"));
    }
    observed.resize(size, 0);
    for (i, chunk) in observed.chunks_mut(MAX_BLOCK).enumerate() {
        r.cancellation.check().map_err(io::Error::other)?;
        storage.read_exact_at(i as u64 * MAX_BLOCK as u64, chunk)?;
        r.cancellation.check().map_err(io::Error::other)?;
    }
    let source = Source(&observed);
    let bootstrap =
        bootstrap::Bootstrap::read(&source, limits.proof.journal_blocks, limits.work, r)?;
    if bootstrap.geometry.start == 0 && super::super::u32le(&bootstrap.primary, 96) & 4 == 0 {
        clean_geometry(
            &bootstrap.primary,
            &bootstrap.journal,
            bootstrap.physical_blocks.len(),
        )?;
        let storage_view: &dyn Storage = &source;
        let decoder = super::super::ExtDecoder::open_reader(storage_view, scope, r, true)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.proof.planning.audit, r)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(invalid(
                "xattr inactive recovery still requires complete clean ownership",
            ));
        }
        compare_source(storage, &observed, r)?;
        return Ok(Outcome::Noop);
    }
    if bootstrap.geometry.start != 0 && bootstrap.geometry.start != bootstrap.geometry.first {
        return Err(invalid(
            "xattr cold preparation start differs from original first",
        ));
    }
    let mut owned_geometry = bootstrap.geometry;
    let mut preparation_descriptor = [0; MAX_BLOCK];
    source.read_exact_at(
        bootstrap.physical(owned_geometry.first)?,
        &mut preparation_descriptor[..owned_geometry.block_bytes],
    )?;
    // A torn final sequence update cannot erase the durable preparation identity.
    owned_geometry.sequence = be32(&preparation_descriptor, 8);
    owned_geometry.start = owned_geometry.first;
    let capsule = read_xattr_preparation(
        &owned_geometry,
        &bootstrap.physical_blocks,
        limits.proof.capsule_bytes,
        limits.work,
        r,
        |logical, bytes| source.read_exact_at(bootstrap.physical(logical)?, bytes),
    )?;
    let parsed = scan_owned(
        &owned_geometry,
        limits.records,
        limits.work,
        r,
        |logical, bytes| source.read_exact_at(bootstrap.physical(logical)?, bytes),
        |block| bootstrap.destination(block),
    )?;
    if !matches!(parsed.committed_transactions, 1 | 2)
        || parsed.next_sequence
            != owned_geometry
                .sequence
                .wrapping_add(parsed.committed_transactions as u32)
    {
        return Err(invalid("xattr cold transaction scope/count"));
    }
    let new = parsed.committed_transactions == 2;
    let _redo = r
        .memory
        .reserve((parsed.blocks.len() * core::mem::size_of::<xattr_recovery::Redo<'_>>()) as u64)
        .map_err(io::Error::other)?;
    let mut redo = Vec::new();
    redo.try_reserve_exact(parsed.blocks.len())
        .map_err(|_| budget("xattr cold redo view allocation"))?;
    if redo.capacity() > parsed.blocks.len() {
        return Err(budget("xattr cold redo view capacity"));
    }
    for block in &parsed.blocks {
        redo.push(xattr_recovery::Redo {
            block: block.destination,
            bytes: &block.bytes[..bootstrap.geometry.block_bytes],
        });
    }
    let plan = xattr_recovery::derive(
        &observed,
        &capsule.bytes,
        if new { Some(&redo) } else { None },
        scope,
        generation,
        limits.proof,
        r,
    )?;
    // In OLD, even the parsed preparation's final home set must be exactly the
    // durable originals (only its own RECOVER bit may differ), never foreign redo.
    if !new {
        if parsed.blocks.len() != plan.homes().len() {
            return Err(invalid("xattr OLD preparation home cardinality"));
        }
        for home in plan.homes() {
            let mut matches = parsed.blocks.iter().filter(|b| b.destination == home.block);
            let record = matches
                .next()
                .ok_or_else(|| invalid("xattr OLD missing original home"))?;
            if matches.next().is_some() {
                return Err(invalid("xattr OLD duplicate original home"));
            }
            for (inside, (&actual, &old)) in record.bytes[..plan.block_bytes()]
                .iter()
                .zip(&home.original[..plan.block_bytes()])
                .enumerate()
            {
                let fence = if home.block as usize * plan.block_bytes() + inside == 1120 {
                    4
                } else {
                    0
                };
                if actual & !fence != old & !fence {
                    return Err(invalid("xattr OLD preparation changes unmanaged original"));
                }
            }
        }
    }
    let bs = plan.block_bytes();
    let mut final_header: [u8; 1024] = capsule.bytes[92..1116]
        .try_into()
        .map_err(io::Error::other)?;
    put32(&mut final_header, 24, parsed.next_sequence);
    put32(&mut final_header, 28, 0);
    let mut active_header: [u8; 1024] = capsule.bytes[92..1116]
        .try_into()
        .map_err(io::Error::other)?;
    put32(&mut active_header, 28, owned_geometry.first);
    for (i, &actual) in bootstrap.journal.iter().enumerate() {
        if actual != active_header[i] && actual != final_header[i] {
            return Err(invalid(
                "xattr current journal header is not original/final control prefix",
            ));
        }
    }
    // A fully completed retry validates the complete proof but writes nothing.
    let already_complete = bootstrap.journal == final_header
        && plan.homes().iter().all(|home| {
            let at = home.block as usize * bs;
            let expected = if new {
                &home.replacement[..bs]
            } else {
                &home.original[..bs]
            };
            &observed[at..at + bs] == expected
        });
    if already_complete {
        compare_source(storage, &observed, r)?;
        return Ok(if new { Outcome::New } else { Outcome::Old });
    }
    let footprint = (plan.homes().len() + 2)
        .checked_mul(bs)
        .ok_or_else(|| budget("xattr cold checkpoint physical overflow"))?;
    if footprint as u64 > limits.physical_bytes {
        return Err(budget("xattr cold checkpoint physical ceiling"));
    }
    // Complete captured physical input is rechecked after all native parsing,
    // original reconstruction and both complete audits, before any recovery write.
    compare_source(storage, &observed, r)?;
    let primary = u32::from(bs == 1024);
    for home in plan.homes() {
        let mut bytes = if new { home.replacement } else { home.original };
        if home.block == primary {
            bytes[1024 % bs + 96] |= 4;
        }
        write(
            storage,
            home.block as u64 * bs as u64,
            &bytes[..bs],
            length,
            r,
        )?;
    }
    r.cancellation.check().map_err(io::Error::other)?;
    storage.flush()?;
    r.cancellation.check().map_err(io::Error::other)?;
    for home in plan.homes() {
        let mut bytes = if new { home.replacement } else { home.original };
        if home.block == primary {
            bytes[1024 % bs + 96] |= 4;
        }
        flush_check(storage, home.block as u64 * bs as u64, &bytes[..bs], r)?;
    }
    // Every selected home is durable before the recovery flag can be cleared.
    // Keep the typed WAL active until the clean primary is itself durable; a cut
    // during either final control write remains reconstructible from preparation.
    let primary_home = plan
        .homes()
        .iter()
        .find(|home| home.block == primary)
        .ok_or_else(|| invalid("xattr cold primary missing"))?;
    let final_primary = if new {
        &primary_home.replacement
    } else {
        &primary_home.original
    };
    write(
        storage,
        primary as u64 * bs as u64,
        &final_primary[..bs],
        length,
        r,
    )?;
    flush_check(storage, primary as u64 * bs as u64, &final_primary[..bs], r)?;
    let mut inactive: [u8; 1024] = capsule.bytes[92..1116]
        .try_into()
        .map_err(io::Error::other)?;
    put32(&mut inactive, 24, parsed.next_sequence);
    put32(&mut inactive, 28, 0);
    let journal_at = bootstrap.physical(0)?;
    write(storage, journal_at, &inactive, length, r)?;
    flush_check(storage, journal_at, &inactive, r)?;
    let final_length = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    if final_length != length {
        return Err(invalid("xattr cold final source length changed"));
    }
    Ok(if new { Outcome::New } else { Outcome::Old })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::super::{xattr_session, xattr_write};
    use super::*;
    use crate::fs_core::{Budget, Cancellation, NativeName};
    struct Image {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
    }
    impl Storage for Image {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            Source(&self.bytes).read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let at = at as usize;
            self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
            self.writes += 1;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    fn le(bytes: &mut [u8], at: usize, n: u32) {
        bytes[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn short(bytes: &mut [u8], at: usize, n: u16) {
        bytes[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn fixture() -> Image {
        let mut bytes = bootstrap::tests::fixture().0;
        le(&mut bytes, 1024 + 92, 12);
        le(&mut bytes, 1024 + 12, 995);
        le(&mut bytes, 1024 + 16, 116);
        short(&mut bytes, 2048 + 12, 995);
        short(&mut bytes, 2048 + 14, 116);
        for block in [60usize, 61] {
            let bit = block - 1;
            bytes[3 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        bytes[4 * 1024 + 1] |= 0x0c;
        for (number, links, length, sectors) in [(11usize, 2, 123, 4), (12usize, 1, 0, 2)] {
            let at = 5 * 1024 + (number - 1) * 128;
            short(&mut bytes, at, 0o100644);
            short(&mut bytes, at + 26, links);
            le(&mut bytes, at + 4, length);
            le(&mut bytes, at + 28, sectors);
            le(&mut bytes, at + 104, 61);
            if number == 11 {
                le(&mut bytes, at + 40, 60);
            }
        }
        bytes[60 * 1024..61 * 1024].fill(0x64);
        let ea = &mut bytes[61 * 1024..62 * 1024];
        le(ea, 0, 0xea020000);
        le(ea, 4, 2);
        le(ea, 8, 1);
        le(ea, 12, 0x00780007);
        ea[32] = 1;
        ea[33] = 1;
        short(ea, 34, 1020);
        le(ea, 40, 1);
        le(ea, 44, 0x00780007);
        ea[48] = b'x';
        ea[1020] = 7;
        let dir = &mut bytes[30 * 1024..31 * 1024];
        dir.fill(0);
        let mut at = 0;
        for (i, (inode, name)) in [
            (2u32, &b"."[..]),
            (2, &b".."[..]),
            (11, &b"file"[..]),
            (11, &b"alias"[..]),
            (12, &b"other"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let size = if i == 4 {
                1024 - at
            } else {
                (8 + name.len()).next_multiple_of(4)
            };
            le(dir, at, inode);
            short(dir, at + 4, size as u16);
            dir[at + 6] = name.len() as u8;
            dir[at + 7] = if inode == 2 { 2 } else { 1 };
            dir[at + 8..at + 8 + name.len()].copy_from_slice(name);
            at += size;
        }
        let header = &mut bytes[100 * 1024..101 * 1024];
        put32(header, 40, 0);
        header[80] = 0;
        put32(header, 252, 0);
        Image {
            bytes,
            writes: 0,
            flushes: 0,
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(128 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> LifecycleLimits {
        let audit = crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 20_000_000,
            directory_blocks: 32,
            directory_entries: 128,
            findings: 128,
        };
        let planning = xattr_plan::Limits {
            source_bytes: 2 << 20,
            work: 200_000_000,
            records: 8,
            affected_bytes: 32 << 10,
            path_depth: 8,
            directory_entries: 128,
            audit,
            encoding: xattr_write::Limits {
                entries: 32,
                value_bytes: 512,
                work: 1_000_000,
            },
        };
        LifecycleLimits {
            proof: xattr_recovery::Limits {
                capsule_bytes: 64 << 10,
                source_bytes: 2 << 20,
                homes: 8,
                journal_blocks: 1024,
                path_depth: 8,
                intent_bytes: 512,
                work: 600_000_000,
                planning,
            },
            records: 8,
            work: 1_000_000_000,
            physical_bytes: 128 << 10,
        }
    }
    #[test]
    fn actual_private_session_shared_cow_remove_noop_and_cold_ready() {
        let r = resources();
        let original = fixture();
        let payload = original.bytes[60 * 1024..61 * 1024].to_vec();
        let other = original.bytes[5 * 1024 + 11 * 128..5 * 1024 + 12 * 128].to_vec();
        let mut session =
            xattr_session::Session::open_for_recovery(original, limits(), &r).unwrap();
        assert_eq!(session.state(), xattr_session::State::NeedsRecovery);
        assert_eq!(session.recover(&r.cancellation).unwrap(), Outcome::Noop);
        let path = [NativeName::Bytes(b"file".to_vec())];
        let mutation = xattr_write::Mutation::Set {
            value: b"changed",
            policy: xattr_write::SetPolicy::Replace,
        };
        let plan = session
            .plan(&path, b"x", mutation, &r.cancellation)
            .unwrap();
        assert!(plan.changed);
        let replacement = plan.new_external;
        assert_ne!(replacement, 61);
        assert_eq!(
            session
                .commit(plan, &path, b"x", mutation, &r.cancellation)
                .unwrap(),
            Outcome::New
        );
        let mut image = session.into_storage();
        assert!(image.writes > 0 && image.flushes > 0);
        assert_eq!(image.bytes[60 * 1024..61 * 1024], payload);
        assert_eq!(image.bytes[5 * 1024 + 11 * 128..5 * 1024 + 12 * 128], other);
        assert_eq!(super::super::super::u32le(&image.bytes, 61 * 1024 + 4), 1);
        let before = image.bytes.clone();
        image.writes = 0;
        image.flushes = 0;
        let mut session = xattr_session::Session::open_for_recovery(image, limits(), &r).unwrap();
        assert_eq!(session.recover(&r.cancellation).unwrap(), Outcome::Noop);
        let plan = session
            .plan(&path, b"x", mutation, &r.cancellation)
            .unwrap();
        assert!(!plan.changed);
        assert_eq!(
            session
                .commit(plan, &path, b"x", mutation, &r.cancellation)
                .unwrap(),
            Outcome::Noop
        );
        let image = session.into_storage();
        assert_eq!(image.bytes, before);
        assert_eq!((image.writes, image.flushes), (0, 0));
        let mut session = xattr_session::Session::open_for_recovery(image, limits(), &r).unwrap();
        session.recover(&r.cancellation).unwrap();
        let plan = session
            .plan(&path, b"x", xattr_write::Mutation::Remove, &r.cancellation)
            .unwrap();
        let empty = plan.new_external;
        assert_eq!(
            session
                .commit(
                    plan,
                    &path,
                    b"x",
                    xattr_write::Mutation::Remove,
                    &r.cancellation
                )
                .unwrap(),
            Outcome::New
        );
        let image = session.into_storage();
        assert_eq!(
            &image.bytes[empty as usize * 1024 + 32..empty as usize * 1024 + 36],
            &[0; 4]
        );
        assert_eq!(image.bytes[60 * 1024..61 * 1024], payload);
        drop(image);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn noop_plan_rejects_changed_value_and_changed_path_intent_without_writes() {
        for different_path in [false, true] {
            let r = resources();
            let source = fixture();
            let before = source.bytes.clone();
            let mut session =
                xattr_session::Session::open_for_recovery(source, limits(), &r).unwrap();
            session.recover(&r.cancellation).unwrap();
            let path = [NativeName::Bytes(b"file".to_vec())];
            let same = xattr_write::Mutation::Set {
                value: &[7],
                policy: xattr_write::SetPolicy::Replace,
            };
            let plan = session.plan(&path, b"x", same, &r.cancellation).unwrap();
            assert!(!plan.changed);
            let alias = [NativeName::Bytes(b"alias".to_vec())];
            let changed = xattr_write::Mutation::Set {
                value: &[9],
                policy: xattr_write::SetPolicy::Replace,
            };
            let error = session
                .commit(
                    plan,
                    if different_path { &alias } else { &path },
                    b"x",
                    if different_path { same } else { changed },
                    &r.cancellation,
                )
                .unwrap_err();
            assert!(error.to_string().contains("supplied intent differs"));
            assert_eq!(session.state(), xattr_session::State::Ready);
            let image = session.into_storage();
            assert_eq!((image.writes, image.flushes), (0, 0));
            assert_eq!(image.bytes, before);
            drop(image);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn actual_preparation_roundtrip_preserves_canonical_original_homes() {
        let r = resources();
        let source = fixture();
        let path = [NativeName::Bytes(b"file".to_vec())];
        let mutation = xattr_write::Mutation::Set {
            value: b"roundtrip",
            policy: xattr_write::SetPolicy::Replace,
        };
        let plan = xattr_plan::plan(
            &source,
            91,
            1,
            &path,
            b"x",
            mutation,
            limits().proof.planning,
            &r,
        )
        .unwrap();
        assert!(
            plan.homes()
                .windows(2)
                .all(|homes| homes[0].block < homes[1].block)
        );
        assert!(plan.homes().len() > 2);
        let capsule =
            xattr_recovery::seal(&plan, &path, b"x", mutation, limits().proof, &r).unwrap();
        let primary = plan.original_source()[1024..2048].try_into().unwrap();
        let at = plan.journal_blocks()[0] as usize * 1024;
        let header = plan.original_source()[at..at + 1024].try_into().unwrap();
        let geometry = clean_geometry(primary, header, plan.journal_blocks().len()).unwrap();
        let encoded = prepare_xattr(
            &geometry,
            &plan,
            &capsule,
            limits().work,
            limits().physical_bytes,
            &r,
        )
        .unwrap();
        let mut journal = plan.original_source().to_vec();
        for block in &encoded.blocks {
            let at = plan.journal_blocks()[block.logical as usize] as usize * 1024;
            journal[at..at + 1024].copy_from_slice(&block.bytes[..1024]);
        }
        let parsed = read_xattr_preparation(
            &geometry,
            plan.journal_blocks(),
            limits().proof.capsule_bytes,
            limits().work,
            &r,
            |logical, bytes| {
                let at = plan.journal_blocks()[logical as usize] as usize * 1024;
                bytes.copy_from_slice(&journal[at..at + bytes.len()]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(parsed.bytes, capsule.bytes());
        assert_eq!(parsed.next_logical, encoded.next_logical);
        drop((parsed, encoded, capsule, plan, source));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn valid_same_shape_cross_capsules_refuse_scope_generation_intent_and_source() {
        for variant in 0..4 {
            let r = resources();
            let mut source = fixture();
            let before = source.bytes.clone();
            let mut foreign = fixture();
            if variant == 3 {
                foreign.bytes[60 * 1024 + 11] ^= 1;
            }
            let path = [NativeName::Bytes(b"file".to_vec())];
            let mutation = xattr_write::Mutation::Set {
                value: b"first!",
                policy: xattr_write::SetPolicy::Replace,
            };
            let foreign_mutation = xattr_write::Mutation::Set {
                value: if variant == 2 { b"second" } else { b"first!" },
                policy: xattr_write::SetPolicy::Replace,
            };
            let plan = xattr_plan::plan(
                &source,
                77,
                1,
                &path,
                b"x",
                mutation,
                limits().proof.planning,
                &r,
            )
            .unwrap();
            let other = xattr_plan::plan(
                &foreign,
                if variant == 0 { 78 } else { 77 },
                if variant == 1 { 2 } else { 1 },
                &path,
                b"x",
                foreign_mutation,
                limits().proof.planning,
                &r,
            )
            .unwrap();
            assert_eq!(plan.homes().len(), other.homes().len());
            assert_eq!(
                plan.homes().iter().map(|h| h.block).collect::<Vec<_>>(),
                other.homes().iter().map(|h| h.block).collect::<Vec<_>>()
            );
            let capsule =
                xattr_recovery::seal(&other, &path, b"x", foreign_mutation, limits().proof, &r)
                    .unwrap();
            assert!(capsule.matches(&other));
            assert!(!capsule.matches(&plan));
            let error =
                commit(&mut source, (77, 1), &plan, Some(&capsule), limits(), &r).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("capsule belongs to another sealed plan")
            );
            assert_eq!((source.writes, source.flushes), (0, 0));
            assert_eq!(source.bytes, before);
            let primary: &[u8; 1024] = plan.original_source()[1024..2048].try_into().unwrap();
            let journal_at = plan.journal_blocks()[0] as usize * 1024;
            let header: &[u8; 1024] = plan.original_source()[journal_at..journal_at + 1024]
                .try_into()
                .unwrap();
            let geometry = clean_geometry(primary, header, plan.journal_blocks().len()).unwrap();
            assert!(
                prepare_xattr(
                    &geometry,
                    &plan,
                    &capsule,
                    limits().work,
                    limits().physical_bytes,
                    &r
                )
                .is_err()
            );
            drop((capsule, other, plan, foreign, source));
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn scoped_capsule_foreign_intent_and_controller_binding_refuse_without_writes() {
        let r = resources();
        let mut source = fixture();
        let path = [NativeName::Bytes(b"file".to_vec())];
        let mutation = xattr_write::Mutation::Set {
            value: b"changed",
            policy: xattr_write::SetPolicy::Replace,
        };
        let plan = xattr_plan::plan(
            &source,
            77,
            1,
            &path,
            b"x",
            mutation,
            limits().proof.planning,
            &r,
        )
        .unwrap();
        assert!(
            xattr_recovery::seal(&plan, &path, b"other", mutation, limits().proof, &r).is_err()
        );
        let capsule =
            xattr_recovery::seal(&plan, &path, b"x", mutation, limits().proof, &r).unwrap();
        assert!(commit(&mut source, (78, 1), &plan, Some(&capsule), limits(), &r).is_err());
        assert_eq!((source.writes, source.flushes), (0, 0));
        drop((capsule, plan, source));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn actual_controller_publication_reservations_have_exact_no_write_boundaries() {
        let r = resources();
        let original = fixture();
        let path = [NativeName::Bytes(b"file".to_vec())];
        let mutation = xattr_write::Mutation::Set {
            value: b"boundary",
            policy: xattr_write::SetPolicy::Replace,
        };
        let plan = xattr_plan::plan(
            &original,
            91,
            1,
            &path,
            b"x",
            mutation,
            limits().proof.planning,
            &r,
        )
        .unwrap();
        let capsule =
            xattr_recovery::seal(&plan, &path, b"x", mutation, limits().proof, &r).unwrap();
        for physical in [false, true] {
            let mut low = 0u64;
            let mut high = if physical {
                limits().physical_bytes
            } else {
                limits().work as u64
            };
            let attempt = |ceiling: u64| {
                let mut bound = limits();
                if physical {
                    bound.physical_bytes = ceiling;
                } else {
                    bound.work = ceiling as usize;
                }
                let mut image = Image {
                    bytes: original.bytes.clone(),
                    writes: 0,
                    flushes: 0,
                };
                let result = super::commit(&mut image, (91, 1), &plan, Some(&capsule), bound, &r);
                match result {
                    Err(_) => {
                        assert_eq!((image.writes, image.flushes), (0, 0));
                        assert_eq!(image.bytes, original.bytes);
                    }
                    Ok(outcome) => {
                        assert_eq!(outcome, Outcome::New);
                        assert!(image.writes > 0);
                    }
                }
                image.writes > 0
            };
            assert!(attempt(high));
            while low < high {
                let middle = low + (high - low) / 2;
                if attempt(middle) {
                    high = middle;
                } else {
                    low = middle + 1;
                }
            }
            assert!(low > 0);
            assert!(attempt(low));
            assert!(!attempt(low - 1));
        }
        drop((plan, capsule));
        assert_eq!(r.memory.used(), 0);
    }
}

fn put_compact_fragment(block: &mut [u8; MAX_BLOCK], part: usize, bytes: &[u8]) {
    let destination = if part == 0 { 640 } else { 728 };
    block[destination..destination + bytes.len()].copy_from_slice(bytes);
}
fn compact_fragment(block: &[u8; MAX_BLOCK], part: usize, length: usize) -> &[u8] {
    let destination = if part == 0 { 640 } else { 728 };
    &block[destination..destination + length]
}
#[cfg(all(test, feature = "std"))]
#[test]
fn compact_second_fragment_survives_actual_legacy_footer_all_block_sizes() {
    let r = Resources {
        memory: crate::fs_core::Budget::new(1 << 20),
        cancellation: crate::fs_core::Cancellation::default(),
    };
    for bs in [1024usize, 2048, 4096] {
        let geometry = Geometry {
            block_bytes: bs,
            first: 1,
            maximum: 64,
            start: 1,
            sequence: 37,
            uuid: [0x39; 16],
            checksums: Checksums::None,
            revoke: false,
        };
        let input = [ReplayBlock {
            destination: 61,
            bytes: [0x17; MAX_BLOCK],
        }];
        let mut encoded = encode(&geometry, &input, 100000, &r, |_| Ok(())).unwrap();
        let first_space = bs - 4 - 640;
        let expected: Vec<u8> = (0..first_space + 127)
            .map(|i| (i as u8).wrapping_mul(37))
            .collect();
        put_compact_fragment(&mut encoded.blocks[0].bytes, 0, &expected[..first_space]);
        put_compact_fragment(&mut encoded.blocks[2].bytes, 1, &expected[first_space..]);
        legacy::stamp(&geometry, &mut encoded.blocks).unwrap();
        assert_eq!(&encoded.blocks[2].bytes[640..656], b"PMGRJBD2SHA256V1");
        let mut actual = compact_fragment(&encoded.blocks[0].bytes, 0, first_space).to_vec();
        actual.extend_from_slice(compact_fragment(&encoded.blocks[2].bytes, 1, 127));
        assert_eq!(actual, expected);
        let parsed = scan_owned(
            &geometry,
            1,
            100000,
            &r,
            |logical, out| {
                if let Some(block) = encoded.blocks.iter().find(|b| b.logical == logical) {
                    out.copy_from_slice(&block.bytes[..bs]);
                } else {
                    out.fill(0);
                }
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(parsed.committed_transactions, 1);
        assert_eq!(parsed.blocks[0].destination, 61);
    }
    assert_eq!(r.memory.used(), 0);
}

#[cfg(all(test, feature = "std", target_pointer_width = "64"))]
#[path = "fs_ext_jbd_xattr_native_cuts.rs"]
mod native_cuts;
