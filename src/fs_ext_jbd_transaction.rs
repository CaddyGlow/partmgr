//! Private native transaction lifecycle; caller plans typed filesystem operations.
use super::*;
use crate::{fs_ext_audit::ExtAuditLimits, storage::Storage};

pub(crate) fn commit(
    storage: &mut dyn Storage,
    scope: u128,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    resources: &Resources,
) -> io::Result<recovery::Outcome> {
    if records.is_empty() || records.len() > maximum_records {
        return Err(budget("native transaction affected block ceiling"));
    }
    let (decoder, mut proof) =
        super::super::ExtDecoder::open_native_clean(storage, scope, resources)?;
    let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, resources)
        .map_err(io::Error::other)?;
    if !audit.is_clean() {
        return Err(invalid(
            "native transaction requires complete clean ownership audit",
        ));
    }
    drop((decoder, audit));
    let bootstrap = bootstrap::Bootstrap::read(storage, 65536, limits.work, resources)?;
    let initial = proof.geometry;
    proof.geometry.start = initial.first;
    let mut superblock = [0; MAX_BLOCK];
    storage.read_exact_at(
        if initial.block_bytes == 1024 { 1024 } else { 0 },
        &mut superblock[..initial.block_bytes],
    )?;
    let prepared = prepare(
        &proof.geometry,
        &superblock[..initial.block_bytes],
        &bootstrap.journal,
        resources,
    )?;
    let dirty = preparation(&proof.geometry, resources, |logical, bytes| {
        let record = prepared
            .blocks
            .iter()
            .find(|r| r.logical == logical)
            .ok_or_else(|| invalid("native preparation mapping"))?;
        bytes.copy_from_slice(&record.bytes[..bytes.len()]);
        Ok(())
    })?;
    let candidate_count = records
        .len()
        .checked_add(1)
        .ok_or_else(|| budget("native candidate count overflow"))?;
    let reservation = resources
        .memory
        .reserve(
            candidate_count
                .checked_mul(std::mem::size_of::<ReplayBlock>())
                .ok_or_else(|| budget("native candidate reservation overflow"))? as u64,
        )
        .map_err(io::Error::other)?;
    let mut candidate = Vec::new();
    candidate
        .try_reserve_exact(candidate_count)
        .map_err(|_| budget("native candidate allocation"))?;
    if candidate.capacity() > candidate_count {
        return Err(budget("native candidate allocator capacity"));
    }
    let primary = u32::from(initial.block_bytes == 1024);
    if !records.iter().any(|r| r.destination == primary) {
        candidate.push(ReplayBlock {
            destination: primary,
            bytes: dirty.superblock,
        });
    }
    for record in records {
        resources.cancellation.check().map_err(io::Error::other)?;
        bootstrap.destination(record.destination)?;
        candidate.push(ReplayBlock {
            destination: record.destination,
            bytes: record.bytes,
        });
    }
    candidate.sort_unstable_by_key(|r| r.destination);
    let fence = candidate
        .iter()
        .find(|r| r.destination == primary)
        .ok_or_else(|| invalid("native candidate missing dirty superblock"))?;
    let inside = if initial.block_bytes == 1024 { 0 } else { 1024 };
    if super::super::u32le(&fence.bytes, inside + 96) & 4 == 0 {
        return Err(invalid(
            "native candidate removes recovery fence before checkpoint",
        ));
    }
    let checked = overlay::Overlay::new(
        storage,
        &candidate,
        initial.block_bytes,
        Some(overlay::JournalControl {
            physical: bootstrap.physical(0)?,
            original: bootstrap.journal,
            geometry: initial,
            next_sequence: initial.sequence.wrapping_add(2),
        }),
        resources,
    )?
    .verify(scope, limits, Some(&bootstrap))?;
    drop((checked, candidate, reservation));
    proof.geometry.start = prepared.next_logical;
    proof.geometry.sequence = initial.sequence.wrapping_add(1);
    let encoded = encode(
        &proof.geometry,
        records,
        limits.work,
        resources,
        |physical| bootstrap.destination(physical),
    )?;
    // The two transactions and a durable stop must coexist without overwriting
    // the retained preparation, which is the restart authority for torn controls.
    let total = prepared
        .blocks
        .len()
        .checked_add(encoded.blocks.len())
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| budget("native combined ring use overflow"))?;
    if total >= (initial.maximum - initial.first) as usize {
        return Err(budget(
            "native preparation and mutation exceed journal ring",
        ));
    }
    let home_primary = usize::from(!records.iter().any(|r| r.destination == primary));
    let affected_blocks = prepared
        .blocks
        .len()
        .checked_add(encoded.blocks.len())
        .and_then(|n| n.checked_add(records.len()))
        .and_then(|n| n.checked_add(2 + home_primary))
        .ok_or_else(|| budget("native transaction physical footprint overflow"))?;
    if affected_blocks
        .checked_mul(initial.block_bytes)
        .is_none_or(|n| n as u64 > maximum_affected_bytes)
    {
        return Err(budget("native transaction physical affected byte ceiling"));
    }
    let length = storage.len()?;
    let publish_control = |storage: &mut dyn Storage, at: u64, bytes: &[u8]| -> io::Result<()> {
        let mut done = 0;
        while done < bytes.len() {
            resources.cancellation.check().map_err(io::Error::other)?;
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "native publication source length changed",
                )));
            }
            let count = storage.write_at(at + done as u64, &bytes[done..])?;
            if count == 0 || count > bytes.len() - done {
                return Err(io::ErrorKind::WriteZero.into());
            }
            done += count;
        }
        resources.cancellation.check().map_err(io::Error::other)?;
        storage.flush()?;
        let mut found = [0; MAX_BLOCK];
        storage.read_exact_at(at, &mut found[..bytes.len()])?;
        if found[..bytes.len()] != *bytes {
            return Err(invalid("native publication durable readback"));
        }
        Ok(())
    };
    proof.geometry.start = initial.first;
    proof.geometry.sequence = initial.sequence;
    publish_log(storage, &proof, &prepared, resources)?;
    let mut active = bootstrap.journal;
    put32(&mut active, 28, initial.first);
    put32(&mut active, 252, 0);
    let checksum = crc32c(!0, &active);
    put32(&mut active, 252, checksum);
    publish_control(storage, bootstrap.physical(0)?, &active)?;
    publish_control(
        storage,
        u64::from(primary) * initial.block_bytes as u64,
        &dirty.superblock[..initial.block_bytes],
    )?;
    proof.geometry.start = prepared.next_logical;
    proof.geometry.sequence = initial.sequence.wrapping_add(1);
    publish_log(storage, &proof, &encoded, resources)?;
    drop((proof, bootstrap, prepared, dirty, encoded));
    recovery::recover(
        storage,
        scope,
        limits,
        maximum_records
            .checked_add(1)
            .ok_or_else(|| budget("native replay ceiling overflow"))?,
        resources,
    )
}
