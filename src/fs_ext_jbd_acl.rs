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
        return Err(unsupported("acl typed classic clean journal profile"));
    }
    let log = super::super::u32le(primary, 24);
    if log > 2 {
        return Err(unsupported("acl typed journal block size"));
    }
    let checksums = match be32(header, 40) & 0x18 {
        0 => Checksums::None,
        8 => Checksums::V2,
        16 => Checksums::V3,
        _ => return Err(unsupported("acl typed journal checksums")),
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
        return Err(invalid("acl typed journal is active or mapping differs"));
    }
    original_journal(&geometry, header)?;
    Ok(geometry)
}

use super::super::{acl_plan, acl_recovery};
use sha2::{Digest, Sha256};
const PREFIX: usize = 1116;
fn map_digest(blocks: &[u32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"partmgr-acl-original-journal-map-v4");
    for n in blocks {
        hash.update(n.to_le_bytes());
    }
    hash.finalize().into()
}
fn word(bytes: &[u8], at: usize) -> io::Result<usize> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| invalid("acl native capsule word offset"))?;
    let b = bytes
        .get(at..end)
        .ok_or_else(|| invalid("acl native capsule word"))?;
    usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).map_err(io::Error::other)
}
/// Native preparation publishes original homes, with RECOVER set only in primary.
/// Intent/digests are metadata in native-ignored, CRC-covered padding, never fake
/// filesystem destinations. The physical footprint includes every native block.
pub(crate) fn prepare_acl(
    geometry: &Geometry,
    plan: &acl_plan::Plan,
    capsule: &acl_recovery::Capsule,
    maximum_work: usize,
    maximum_bytes: u64,
    r: &Resources,
) -> io::Result<EncodedTransaction> {
    r.cancellation.check().map_err(io::Error::other)?;
    if !capsule.matches(plan) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "acl preparation capsule belongs to another sealed plan",
        )));
    }
    if !matches!(geometry.checksums, Checksums::None)
        || plan.homes().is_empty()
        || plan.homes().len() > 16
    {
        return Err(unsupported("acl preparation legacy bounded tag profile"));
    }
    let bs = geometry.block_bytes;
    let payload = capsule.bytes();
    let homes = word(payload, 36)?;
    let journals = word(payload, 40)?;
    if homes != plan.homes().len()
        || journals != plan.journal_blocks().len()
        || bs != plan.block_bytes()
    {
        return Err(invalid("acl preparation plan/capsule shape"));
    }
    let suffix = journals
        .checked_mul(4)
        .and_then(|n| homes.checked_mul(bs + 4).and_then(|h| n.checked_add(h)))
        .ok_or_else(|| budget("acl compact capsule suffix"))?;
    let intent_end = payload
        .len()
        .checked_sub(suffix)
        .filter(|n| *n >= PREFIX)
        .ok_or_else(|| invalid("acl compact capsule length"))?;
    let metadata = 124usize
        .checked_add(intent_end - PREFIX)
        .ok_or_else(|| budget("acl compact metadata overflow"))?;
    let first_space = bs - 4 - 704;
    let second_space = bs - 728;
    if metadata > first_space + second_space {
        return Err(budget("acl native preparation intent padding ceiling"));
    }
    let footprint = (homes + 2)
        .checked_mul(bs)
        .and_then(|n| n.checked_add(2 * bs + 12))
        .ok_or_else(|| budget("acl preparation physical overflow"))?;
    if footprint as u64 > maximum_bytes {
        return Err(budget("acl preparation physical ceiling"));
    }
    let work = homes
        .checked_mul(4 * MAX_BLOCK)
        .and_then(|n| n.checked_add(metadata * 2))
        .ok_or_else(|| budget("acl preparation work overflow"))?;
    if work > maximum_work {
        return Err(budget("acl preparation work ceiling"));
    }
    let _records = r
        .memory
        .reserve((homes * core::mem::size_of::<ReplayBlock>()) as u64)
        .map_err(io::Error::other)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(homes)
        .map_err(|_| budget("acl preparation allocation"))?;
    if records.capacity() > homes {
        return Err(budget("acl preparation capacity"));
    }
    let primary = u32::from(bs == 1024);
    let mut seen_primary = false;
    for home in plan.homes() {
        r.cancellation.check().map_err(io::Error::other)?;
        let mut bytes = home.original;
        if home.block == primary {
            let inside = 1024 % bs;
            if super::super::u32le(&bytes, inside + 96) & 4 != 0 {
                return Err(invalid("acl original primary already fenced"));
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
        return Err(invalid("acl preparation missing primary original"));
    }
    let mut encoded = encode(geometry, &records, maximum_work, r, |block| {
        if plan.journal_blocks().contains(&block) {
            Err(invalid("acl preparation aliases journal"))
        } else {
            Ok(())
        }
    })?;
    if encoded.blocks.len() != homes + 2 {
        return Err(invalid("acl preparation descriptor count"));
    }
    let _metadata = r
        .memory
        .reserve(metadata as u64)
        .map_err(io::Error::other)?;
    let mut compact = Vec::new();
    compact
        .try_reserve_exact(metadata)
        .map_err(|_| budget("acl compact allocation"))?;
    if compact.capacity() > metadata {
        return Err(budget("acl compact capacity"));
    }
    compact.extend_from_slice(&payload[..92]);
    compact.extend_from_slice(&payload[PREFIX..intent_end]);
    compact.extend_from_slice(&map_digest(plan.journal_blocks()));
    let last = encoded.blocks.len() - 1;
    for (part, index) in [0, last].into_iter().enumerate() {
        let block = &mut encoded.blocks[index].bytes;
        let marker = if part == 0 { 160 } else { 96 };
        block[marker..marker + 16].copy_from_slice(CAPSULE_MAGIC);
        put32(block, marker + 16, 4);
        put32(block, marker + 20, 3);
        put32(block, marker + 24, metadata as u32);
        put32(block, marker + 28, homes as u32);
        let original = marker + 32;
        block[original..original + 512]
            .copy_from_slice(&payload[92 + part * 512..92 + (part + 1) * 512]);
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
pub(crate) fn read_acl_preparation(
    geometry: &Geometry,
    candidate_map: &[u32],
    maximum_bytes: usize,
    maximum_work: usize,
    r: &Resources,
    mut read: impl FnMut(u32, &mut [u8]) -> io::Result<()>,
) -> io::Result<NativeCapsule> {
    if !matches!(geometry.checksums, Checksums::None) {
        return Err(unsupported("acl preparation checksum profile"));
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
    if descriptor[160..176] != *CAPSULE_MAGIC
        || be32(&descriptor, 176) != 4
        || be32(&descriptor, 180) != 3
    {
        return Err(invalid("acl native preparation scope"));
    }
    let homes = be32(&descriptor, 188) as usize;
    let metadata = be32(&descriptor, 184) as usize;
    let first_space = bs - 4 - 704;
    let second_space = bs - 728;
    if homes == 0 || homes > 16 || metadata < 124 || metadata > first_space + second_space {
        return Err(invalid("acl native preparation lengths"));
    }
    if homes + 2 >= (geometry.maximum - geometry.first) as usize {
        return Err(invalid("acl preparation does not fit original ring"));
    }
    let mut commit_logical = geometry.first;
    for _ in 0..homes + 1 {
        commit_logical = geometry.next(commit_logical);
    }
    let next = geometry.next(commit_logical);
    let mut commit = [0; MAX_BLOCK];
    read(commit_logical, &mut commit[..bs])?;
    if commit[96..128] != descriptor[160..192] {
        return Err(invalid("acl native preparation paired metadata"));
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
                Err(invalid("acl native original aliases journal"))
            } else {
                Ok(())
            }
        },
    )?;
    if parsed.committed_transactions != 1
        || parsed.blocks.len() != homes
        || parsed.next_sequence != geometry.sequence.wrapping_add(1)
    {
        return Err(invalid("acl native preparation transaction count"));
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
        .ok_or_else(|| budget("acl reconstructed capsule ceiling"))?;
    let envelope = total
        .checked_mul(2)
        .and_then(|n| {
            candidate_map
                .len()
                .checked_mul(4)
                .and_then(|m| n.checked_add(m))
        })
        .ok_or_else(|| budget("acl reconstruction work overflow"))?;
    if envelope > maximum_work {
        return Err(budget("acl reconstruction work ceiling"));
    }
    let lease = r
        .memory
        .reserve((total + metadata) as u64)
        .map_err(io::Error::other)?;
    let mut compact = Vec::new();
    compact
        .try_reserve_exact(metadata)
        .map_err(|_| budget("acl compact read allocation"))?;
    if compact.capacity() > metadata {
        return Err(budget("acl compact read capacity"));
    }
    compact.extend_from_slice(compact_fragment(&descriptor, 0, metadata.min(first_space)));
    if metadata > first_space {
        compact.extend_from_slice(compact_fragment(&commit, 1, metadata - first_space));
    }
    if compact[metadata - 32..] != map_digest(candidate_map) {
        return Err(invalid("acl native original journal-map digest"));
    }
    if word(&compact, 36)? != homes || word(&compact, 40)? != candidate_map.len() {
        return Err(invalid("acl compact/native cardinality"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| budget("acl capsule reconstruction allocation"))?;
    if bytes.capacity() > total {
        return Err(budget("acl capsule reconstruction capacity"));
    }
    bytes.extend_from_slice(&compact[..92]);
    bytes.extend_from_slice(&descriptor[192..704]);
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
                return Err(invalid("acl preparation missing recovery fence"));
            }
            bytes[start + inside + 96] &= !4;
            primary_seen = true;
        }
    }
    if !primary_seen || bytes.len() != total {
        return Err(invalid("acl native original primary/length"));
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
    pub(crate) proof: acl_recovery::Limits,
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
            .ok_or_else(|| invalid("acl lifecycle source range"))?;
        out.copy_from_slice(
            self.0
                .get(at..end)
                .ok_or_else(|| invalid("acl lifecycle source range"))?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(unsupported("acl lifecycle preflight source writes"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(unsupported("acl lifecycle preflight source flush"))
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
        // The phase2 guard scans original journal membership for EVERY source
        // block. Cold derive has its own separate cross-product allowance.
        .and_then(|n| {
            limits
                .proof
                .journal_blocks
                .checked_add(1)
                .and_then(|j| length.div_ceil(1024).checked_mul(j))
                .and_then(|guard| n.checked_add(guard))
        })
        .ok_or_else(|| budget("acl lifecycle work envelope overflow"))
}
fn preflight(length: usize, limits: LifecycleLimits) -> io::Result<()> {
    if length > limits.proof.source_bytes
        || limits.records > limits.proof.homes
        || limits.records > 16
    {
        return Err(budget("acl lifecycle source/record ceiling"));
    }
    // Inactive recovery performs an ownership audit directly instead of
    // derive(). Its bound must fit the proof allowance reserved by preflight.
    if limits.proof.work < limits.proof.planning.audit.work {
        return Err(budget(
            "acl inactive ownership work exceeds proof allowance",
        ));
    }
    let work = preflight_work(length, limits)?;
    if work > limits.work {
        return Err(budget("acl lifecycle work envelope ceiling"));
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
                "acl lifecycle observed source changed",
            )));
        }
    }
    let length = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    if length != expected.len() as u64 {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "acl lifecycle source length changed",
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
        .ok_or_else(|| invalid("acl lifecycle write overflow"))?;
    let found = storage.len()?;
    r.cancellation.check().map_err(io::Error::other)?;
    if found != length || end > length {
        return Err(invalid("acl lifecycle write geometry changed"));
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
            return Err(invalid("acl lifecycle durable readback"));
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
    plan: &acl_plan::Plan,
    capsule: Option<&acl_recovery::Capsule>,
    limits: LifecycleLimits,
    r: &Resources,
) -> io::Result<Outcome> {
    r.cancellation.check().map_err(io::Error::other)?;
    if binding != plan.binding() {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "acl controller foreign scope or generation",
        )));
    }
    let length = usize::try_from(plan.source_bytes()).map_err(io::Error::other)?;
    preflight(length, limits)?;
    if plan.homes().len() > limits.records {
        return Err(budget("acl lifecycle home record ceiling"));
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
        capsule.ok_or_else(|| invalid("acl changed plan requires scoped durable capsule"))?;
    if !capsule.matches(plan) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "acl controller capsule belongs to another sealed plan",
        )));
    }
    let prepared = prepare_acl(
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
        .map_err(|_| budget("acl mutation record allocation"))?;
    if records.capacity() > plan.homes().len() {
        return Err(budget("acl mutation record capacity"));
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
            Err(invalid("acl mutation destination aliases journal"))
        } else {
            Ok(())
        }
    })?;
    for block in &mutation.blocks {
        if prepared.blocks.iter().any(|p| p.logical == block.logical) {
            return Err(budget("acl two-transaction ring overlap"));
        }
    }
    if prepared
        .blocks
        .iter()
        .any(|p| p.logical == mutation.next_logical)
    {
        return Err(budget(
            "acl two-transaction clearing tail overlaps preparation",
        ));
    }
    let footprint = (prepared.blocks.len() + mutation.blocks.len() + plan.homes().len() + 6)
        .checked_mul(bs)
        .and_then(|n| n.checked_add(24))
        .ok_or_else(|| budget("acl full lifecycle physical overflow"))?;
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
        .ok_or_else(|| invalid("acl phase2 primary home missing"))?;
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
        .map_err(|_| budget("acl cold snapshot allocation"))?;
    if observed.capacity() > size {
        return Err(budget("acl cold snapshot capacity"));
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
                "acl inactive recovery still requires complete clean ownership",
            ));
        }
        compare_source(storage, &observed, r)?;
        return Ok(Outcome::Noop);
    }
    if bootstrap.geometry.start != 0 && bootstrap.geometry.start != bootstrap.geometry.first {
        return Err(invalid(
            "acl cold preparation start differs from original first",
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
    let capsule = read_acl_preparation(
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
        return Err(invalid("acl cold transaction scope/count"));
    }
    let new = parsed.committed_transactions == 2;
    let _redo = r
        .memory
        .reserve((parsed.blocks.len() * core::mem::size_of::<acl_recovery::Redo<'_>>()) as u64)
        .map_err(io::Error::other)?;
    let mut redo = Vec::new();
    redo.try_reserve_exact(parsed.blocks.len())
        .map_err(|_| budget("acl cold redo view allocation"))?;
    if redo.capacity() > parsed.blocks.len() {
        return Err(budget("acl cold redo view capacity"));
    }
    for block in &parsed.blocks {
        redo.push(acl_recovery::Redo {
            block: block.destination,
            bytes: &block.bytes[..bootstrap.geometry.block_bytes],
        });
    }
    let plan = acl_recovery::derive(
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
            return Err(invalid("acl OLD preparation home cardinality"));
        }
        for home in plan.homes() {
            let mut matches = parsed.blocks.iter().filter(|b| b.destination == home.block);
            let record = matches
                .next()
                .ok_or_else(|| invalid("acl OLD missing original home"))?;
            if matches.next().is_some() {
                return Err(invalid("acl OLD duplicate original home"));
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
                    return Err(invalid("acl OLD preparation changes unmanaged original"));
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
                "acl current journal header is not original/final control prefix",
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
        .ok_or_else(|| budget("acl cold checkpoint physical overflow"))?;
    if footprint as u64 > limits.physical_bytes {
        return Err(budget("acl cold checkpoint physical ceiling"));
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
        .ok_or_else(|| invalid("acl cold primary missing"))?;
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
        return Err(invalid("acl cold final source length changed"));
    }
    Ok(if new { Outcome::New } else { Outcome::Old })
}

fn put_compact_fragment(block: &mut [u8; MAX_BLOCK], part: usize, bytes: &[u8]) {
    let destination = if part == 0 { 704 } else { 728 };
    block[destination..destination + bytes.len()].copy_from_slice(bytes);
}
fn compact_fragment(block: &[u8; MAX_BLOCK], part: usize, length: usize) -> &[u8] {
    let destination = if part == 0 { 704 } else { 728 };
    &block[destination..destination + length]
}

// Private ACL planned-home and durable-controller regressions.
#[cfg(test)]
mod tests {
    use super::super::super::{acl as codec, acl_container, acl_plan, acl_semantics, acl_write};
    use super::super::*;
    use crate::fs_core::{Budget, Cancellation, NativeName, Resources};
    use crate::storage::Storage;
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
            let at = at as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _at: u64, _bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            panic!("ACL planning must never write")
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            panic!("ACL planning must never flush")
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
    fn limits() -> acl_plan::Limits {
        acl_plan::Limits {
            source_bytes: 2 << 20,
            work: 200_000_000,
            records: 16,
            affected_bytes: 64 << 10,
            path_depth: 8,
            directory_entries: 128,
            audit: crate::fs_ext_audit::ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 20_000_000,
                directory_blocks: 32,
                directory_entries: 128,
                findings: 128,
            },
            encoding: super::super::super::xattr_write::Limits {
                entries: 32,
                value_bytes: 512,
                work: 1_000_000,
            },
        }
    }
    const RAW: &[u8] = &[
        1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0,
    ];
    fn path() -> [NativeName; 1] {
        [NativeName::Bytes(b"file".to_vec())]
    }
    fn apply(source: &[u8], plan: &acl_plan::Plan) -> Vec<u8> {
        let mut out = source.to_vec();
        for h in plan.homes() {
            let at = h.block as usize * plan.block_bytes();
            out[at..at + plan.block_bytes()].copy_from_slice(&h.replacement[..plan.block_bytes()]);
        }
        out
    }
    struct Device {
        bytes: Vec<u8>,
        events: usize,
        fail_at: Option<usize>,
    }
    impl Storage for Device {
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
            let event = self.events;
            self.events += 1;
            if self.fail_at == Some(event) {
                return Err(io::Error::other("injected ACL publication failure"));
            }
            let at = at as usize;
            self.bytes
                .get_mut(at..at + bytes.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            let event = self.events;
            self.events += 1;
            if self.fail_at == Some(event) {
                return Err(io::Error::other("injected ACL flush failure"));
            }
            Ok(())
        }
    }
    fn lifecycle_limits() -> super::LifecycleLimits {
        super::LifecycleLimits {
            proof: recovery_limits(),
            records: 16,
            work: 1_000_000_000,
            physical_bytes: 1 << 20,
        }
    }
    #[test]
    fn lifecycle_prepared_guard_cross_product_has_exact_finite_admission() {
        let length = 2 << 20;
        let mut limits = lifecycle_limits();
        let linear = length * 8
            + limits.proof.work
            + limits.records * 12 * MAX_BLOCK
            + limits.proof.journal_blocks * (16 * MAX_BLOCK + 512);
        let exact = super::preflight_work(length, limits).unwrap();
        assert_eq!(
            exact - linear,
            length.div_ceil(1024) * (limits.proof.journal_blocks + 1)
        );
        limits.work = exact;
        super::preflight(length, limits).unwrap();
        limits.work -= 1;
        assert!(super::preflight(length, limits).is_err());
        assert!(super::preflight_work(usize::MAX, limits).is_err());
        let mut too_many = lifecycle_limits();
        too_many.records = 17;
        too_many.proof.homes = 17;
        assert!(super::preflight(length, too_many).is_err());
        let mut uncovered = lifecycle_limits();
        uncovered.proof.work = 0;
        assert!(uncovered.proof.planning.audit.work > 0);
        assert!(super::preflight(length, uncovered).is_err());
    }
    #[test]
    fn atomic_namespace_birth_inherits_source_default_without_double_umask() {
        use super::super::super::{ExtDecoder, acl_recovery, acl_session};
        let r = resources();
        let original = fixture();
        let parent_plan = acl_plan::plan(
            &original,
            11,
            1,
            &[],
            acl_plan::Operation::Default(Some(RAW)),
            120,
            limits(),
            &r,
        )
        .unwrap();
        let source = Image {
            bytes: apply(&original.bytes, &parent_plan),
            writes: 0,
            flushes: 0,
        };
        drop(parent_plan);
        for (source, has_default) in [(&original, false), (&source, true)] {
            for directory in [false, true] {
                let request = acl_plan::birth::Request {
                    name: if directory {
                        b"child-dir"
                    } else {
                        b"child-file"
                    },
                    directory,
                    mode: if directory { 0o40766 } else { 0o100766 },
                    umask: 0o077,
                    uid: 1001,
                    gid: 1002,
                    atime: 121,
                    mtime: 122,
                    inode_generation: 1,
                    payload: b"",
                };
                let operation = acl_plan::Operation::Create(request);
                let plan =
                    acl_plan::plan(source, 11, 1, &[], operation, 123, limits(), &r).unwrap();
                let after = apply(&source.bytes, &plan);
                let view: &dyn Storage = &Device {
                    bytes: after.clone(),
                    events: 0,
                    fail_at: None,
                };
                let decoder = ExtDecoder::open_reader(view, 11, &r, true).unwrap();
                let child = decoder.inode(plan.inode, &r).unwrap();
                assert_eq!(
                    child.mode(),
                    if has_default {
                        if directory { 0o40760 } else { 0o100760 }
                    } else if directory {
                        0o40700
                    } else {
                        0o100700
                    }
                );
                assert_eq!(
                    u32::from_le_bytes(child.raw_metadata()[12..16].try_into().unwrap()),
                    123
                );
                let parent = decoder.directory(2, 32, 128, &r).unwrap();
                assert!(parent.entries().iter().any(
                    |entry| matches!(&entry.name, NativeName::Bytes(name) if name==request.name)
                        && entry.inode == plan.inode
                ));
                if directory {
                    let dots = decoder.directory(plan.inode, 32, 128, &r).unwrap();
                    assert_eq!(dots.entries().len(), 2);
                }
                let ea =
                    u32::from_le_bytes(child.raw_metadata()[104..108].try_into().unwrap()) as usize;
                if has_default {
                    let ea_view = super::super::super::xattr::observe(
                        &after[ea * 1024..(ea + 1) * 1024],
                        0,
                        true,
                        super::super::super::xattr::ObservationLimits {
                            bytes: 1024,
                            entries: 32,
                            value_bytes: 512,
                            work: 1_000_000,
                        },
                        &r,
                    )
                    .unwrap();
                    assert_eq!(
                        ea_view
                            .entries()
                            .filter(|entry| matches!(entry.index, 2 | 3))
                            .count(),
                        if directory { 2 } else { 1 }
                    );
                } else {
                    assert_eq!(ea, 0);
                }
                let capsule =
                    acl_recovery::seal(&plan, &[], operation, 123, recovery_limits(), &r).unwrap();
                let redo: Vec<_> = plan
                    .homes()
                    .iter()
                    .map(|home| acl_recovery::Redo {
                        block: home.block,
                        bytes: &home.replacement[..1024],
                    })
                    .collect();
                let rederived = acl_recovery::derive(
                    &after,
                    capsule.bytes(),
                    Some(&redo),
                    11,
                    2,
                    recovery_limits(),
                    &r,
                )
                .unwrap();
                assert_eq!(rederived.inode, plan.inode);
                drop(rederived);
                drop(redo);
                drop(capsule);
                drop(plan);
                let mut session = acl_session::Session::open_for_recovery(
                    Device {
                        bytes: source.bytes.clone(),
                        events: 0,
                        fail_at: None,
                    },
                    lifecycle_limits(),
                    &r,
                )
                .unwrap();
                session.recover(&r.cancellation).unwrap();
                let plan = session.plan(&[], operation, 123, &r.cancellation).unwrap();
                assert_eq!(
                    session
                        .commit(plan, &[], operation, 123, &r.cancellation)
                        .unwrap(),
                    super::Outcome::New
                );
                let mut restarted = acl_session::Session::open_for_recovery(
                    session.into_storage(),
                    lifecycle_limits(),
                    &r,
                )
                .unwrap();
                assert_eq!(
                    restarted.recover(&r.cancellation).unwrap(),
                    super::Outcome::Noop
                );
            }
        }
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn acl_controller_restarts_after_every_write_and_flush_boundary() {
        use super::super::super::acl_session;
        let r = resources();
        let source = fixture();
        let operation = acl_plan::Operation::Access(Some(RAW));
        let p = acl_plan::plan(&source, 11, 1, &path(), operation, 123, limits(), &r).unwrap();
        let expected = apply(&source.bytes, &p);
        drop(p);
        let open = |fail_at| {
            acl_session::Session::open_for_recovery(
                Device {
                    bytes: source.bytes.clone(),
                    events: 0,
                    fail_at,
                },
                lifecycle_limits(),
                &r,
            )
            .unwrap()
        };
        let mut session = open(None);
        assert_eq!(
            session.recover(&r.cancellation).unwrap(),
            super::Outcome::Noop
        );
        let p = session
            .plan(&path(), operation, 123, &r.cancellation)
            .unwrap();
        assert_eq!(
            session
                .commit(p, &path(), operation, 123, &r.cancellation)
                .unwrap(),
            super::Outcome::New
        );
        let successful = session.into_storage();
        let events = successful.events;
        assert!(events > 0);
        for cut in 0..events {
            let mut session = open(Some(cut));
            session.recover(&r.cancellation).unwrap();
            let p = session
                .plan(&path(), operation, 123, &r.cancellation)
                .unwrap();
            assert!(
                session
                    .commit(p, &path(), operation, 123, &r.cancellation)
                    .is_err()
            );
            assert_eq!(session.state(), acl_session::State::NeedsRecovery);
            let mut storage = session.into_storage();
            storage.fail_at = None;
            let mut restarted =
                acl_session::Session::open_for_recovery(storage, lifecycle_limits(), &r).unwrap();
            let outcome = restarted.recover(&r.cancellation).unwrap();
            let after = restarted.into_storage();
            let p = acl_plan::plan(&source, 11, 1, &path(), operation, 123, limits(), &r).unwrap();
            let all_old = p.homes().iter().all(|home| {
                let at = home.block as usize * p.block_bytes();
                after.bytes[at..at + p.block_bytes()] == source.bytes[at..at + p.block_bytes()]
            });
            let all_new = p.homes().iter().all(|home| {
                let at = home.block as usize * p.block_bytes();
                after.bytes[at..at + p.block_bytes()] == expected[at..at + p.block_bytes()]
            });
            match outcome {
                super::Outcome::Old => assert!(all_old, "OLD, cut {cut}"),
                super::Outcome::New => assert!(all_new, "NEW, cut {cut}"),
                // The final inactive header may already have persisted before
                // its flush reports failure. Clean Noop means no redo work;
                // every home must still select ONE coherent OLD or NEW state.
                super::Outcome::Noop => {
                    assert!(all_old || all_new, "clean coherent OLD/NEW, cut {cut}")
                }
            }
            // Check every unmanaged byte, not only the planned destinations.
            for (block, original) in source.bytes.chunks(p.block_bytes()).enumerate() {
                if p.homes().iter().any(|home| home.block as usize == block)
                    || p.journal_blocks()
                        .iter()
                        .any(|&journal| journal as usize == block)
                {
                    continue;
                }
                let at = block * p.block_bytes();
                assert_eq!(
                    &after.bytes[at..at + original.len()],
                    original,
                    "unmanaged block {block}, cut {cut}"
                );
            }
            drop(p);
            let events = after.events;
            let mut second =
                acl_session::Session::open_for_recovery(after, lifecycle_limits(), &r).unwrap();
            assert_eq!(
                second.recover(&r.cancellation).unwrap(),
                super::Outcome::Noop,
                "second restart, cut {cut}"
            );
            let after_second = second.into_storage();
            assert_eq!(
                after_second.events, events,
                "second restart wrote or flushed, cut {cut}"
            );
        }
        assert_eq!(r.memory.used(), 0);
    }
    fn recovery_limits() -> super::super::super::acl_recovery::Limits {
        super::super::super::acl_recovery::Limits {
            capsule_bytes: 64 << 10,
            source_bytes: 2 << 20,
            homes: 16,
            journal_blocks: 1024,
            path_depth: 8,
            intent_bytes: 4096,
            work: 800_000_000,
            planning: limits(),
        }
    }
    #[test]
    fn scoped_acl_capsule_rederives_committed_mixed_homes_and_refuses_drift() {
        use super::super::super::acl_recovery;
        let r = resources();
        let source = fixture();
        for operation in [
            acl_plan::Operation::Access(Some(RAW)),
            acl_plan::Operation::Chmod(0o600),
        ] {
            let p = acl_plan::plan(&source, 11, 1, &path(), operation, 123, limits(), &r).unwrap();
            let capsule =
                acl_recovery::seal(&p, &path(), operation, 123, recovery_limits(), &r).unwrap();
            assert!(capsule.matches(&p));
            assert_eq!(&capsule.bytes()[..16], b"PMGRACLCOW000004");
            let derived = acl_recovery::derive(
                &source.bytes,
                capsule.bytes(),
                None,
                11,
                2,
                recovery_limits(),
                &r,
            )
            .unwrap();
            assert_eq!(derived.homes().len(), p.homes().len());
            drop(derived);
            let redo: Vec<_> = p
                .homes()
                .iter()
                .map(|h| acl_recovery::Redo {
                    block: h.block,
                    bytes: &h.replacement[..p.block_bytes()],
                })
                .collect();
            let mut mixed = source.bytes.clone();
            // Alternate changed bytes across every home models partial checkpoints.
            for h in p.homes() {
                let at = h.block as usize * p.block_bytes();
                for i in (0..p.block_bytes()).step_by(2) {
                    mixed[at + i] = h.replacement[i];
                }
            }
            mixed[1120] |= 4;
            let derived = acl_recovery::derive(
                &mixed,
                capsule.bytes(),
                Some(&redo),
                11,
                2,
                recovery_limits(),
                &r,
            )
            .unwrap();
            assert_eq!(derived.intent(), p.intent());
            drop(derived);
            mixed[60 * 1024] ^= 1;
            assert!(
                acl_recovery::derive(
                    &mixed,
                    capsule.bytes(),
                    Some(&redo),
                    11,
                    2,
                    recovery_limits(),
                    &r
                )
                .is_err()
            );
            let mut foreign = capsule.bytes().to_vec();
            foreign[16..20].copy_from_slice(&3u32.to_le_bytes());
            assert!(
                acl_recovery::derive(&source.bytes, &foreign, None, 11, 2, recovery_limits(), &r)
                    .is_err()
            );
            assert!(
                acl_recovery::seal(&p, &path(), operation, 124, recovery_limits(), &r).is_err()
            );
            drop(redo);
            drop(capsule);
            drop(p);
            assert_eq!(r.memory.used(), 0);
        }
        assert_eq!((source.writes, source.flushes), (0, 0));
    }
    #[test]
    fn atomic_shared_cow_acl_mode_ctime_and_mode_only_no_ea_churn() {
        let r = resources();
        let source = fixture();
        let p = acl_plan::plan(
            &source,
            11,
            1,
            &path(),
            acl_plan::Operation::Access(Some(RAW)),
            123,
            limits(),
            &r,
        )
        .unwrap();
        assert!(p.changed && p.new_external != p.old_external);
        let after = apply(&source.bytes, &p);
        let target = 5 * 1024 + 10 * 128;
        let other = 5 * 1024 + 11 * 128;
        assert_eq!(
            u16::from_le_bytes(after[target..target + 2].try_into().unwrap()),
            0o100761
        );
        assert_eq!(
            u32::from_le_bytes(after[target + 12..target + 16].try_into().unwrap()),
            123
        );
        assert_eq!(
            &after[other..other + 128],
            &source.bytes[other..other + 128]
        );
        assert_eq!(
            &after[60 * 1024..61 * 1024],
            &source.bytes[60 * 1024..61 * 1024]
        );
        assert_eq!(
            u32::from_le_bytes(after[61 * 1024 + 4..61 * 1024 + 8].try_into().unwrap()),
            1
        );
        drop(p);
        assert_eq!(r.memory.used(), 0);
        let p = acl_plan::plan(
            &source,
            11,
            1,
            &path(),
            acl_plan::Operation::Chmod(0o600),
            124,
            limits(),
            &r,
        )
        .unwrap();
        assert!(p.changed);
        assert_eq!(p.old_external, p.new_external);
        assert_eq!(p.homes().len(), 2);
        assert!(p.homes().iter().any(|h| h.block == 1));
        drop(p);
        assert_eq!(r.memory.used(), 0);
        assert_eq!((source.writes, source.flushes), (0, 0));
    }
    #[test]
    fn shared_last_acl_release_has_no_free_candidate_and_preserves_other_owner() {
        let r = resources();
        let mut source = fixture();
        let a = codec::decode(
            RAW,
            codec::Limits {
                bytes: 512,
                entries: 32,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let prepared = acl_write::prepare(
            acl_write::Request::Access(Some(&a)),
            acl_semantics::ChildKind::Regular,
            0o100644,
            acl_write::Limits {
                bytes: 512,
                entries: 32,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let rewritten = acl_container::rewrite(
            None,
            1024,
            &prepared,
            acl_container::Limits {
                entries: 32,
                value_bytes: 512,
                work: 1_000_000,
            },
            &r,
        )
        .unwrap();
        source.bytes[61 * 1024..62 * 1024]
            .copy_from_slice(rewritten.block.as_ref().unwrap().bytes());
        le(&mut source.bytes, 61 * 1024 + 4, 2);
        for number in [11usize, 12] {
            short(&mut source.bytes, 5 * 1024 + (number - 1) * 128, 0o100761);
        }
        drop((prepared, rewritten));
        let p = acl_plan::plan(
            &source,
            11,
            1,
            &path(),
            acl_plan::Operation::Access(None),
            125,
            limits(),
            &r,
        )
        .unwrap();
        assert!(p.changed);
        assert_eq!(p.new_external, 0);
        let after = apply(&source.bytes, &p);
        let target = 5 * 1024 + 10 * 128;
        assert_eq!(
            u32::from_le_bytes(after[target + 28..target + 32].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(after[61 * 1024 + 4..61 * 1024 + 8].try_into().unwrap()),
            1
        );
        assert!(!p.homes().iter().any(|h| h.block == 3));
        drop(p);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn actual_controller_publication_reservations_have_exact_no_write_boundaries() {
        let r = resources();
        let original = fixture();
        let operation = acl_plan::Operation::Access(Some(RAW));
        let plan = acl_plan::plan(&original, 11, 1, &path(), operation, 123, limits(), &r).unwrap();
        let capsule = super::super::super::acl_recovery::seal(
            &plan,
            &path(),
            operation,
            123,
            recovery_limits(),
            &r,
        )
        .unwrap();
        for physical in [false, true] {
            let mut low = 0u64;
            let mut high = if physical {
                lifecycle_limits().physical_bytes
            } else {
                lifecycle_limits().work as u64
            };
            let attempt = |ceiling: u64| {
                let mut bound = lifecycle_limits();
                if physical {
                    bound.physical_bytes = ceiling;
                } else {
                    bound.work = ceiling as usize;
                }
                let mut image = Device {
                    bytes: original.bytes.clone(),
                    events: 0,
                    fail_at: None,
                };
                let result = super::commit(&mut image, (11, 1), &plan, Some(&capsule), bound, &r);
                match result {
                    Err(_) => {
                        assert_eq!(image.events, 0);
                        assert_eq!(image.bytes, original.bytes);
                    }
                    Ok(outcome) => {
                        assert_eq!(outcome, super::Outcome::New);
                        assert!(image.events > 0);
                    }
                }
                image.events > 0
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
