//! Private checksumless foreign checkpointing with bounded stale-ID exclusion.
use super::*;

pub(crate) struct Outcome {
    pub(crate) transactions: usize,
    pub(crate) blocks: usize,
    pub(crate) restart_sequence: u32,
}

fn guard(storage: &dyn Storage, length: u64, r: &Resources) -> io::Result<()> {
    r.cancellation.check().map_err(io::Error::other)?;
    if storage.len()? != length {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "foreign recovery source length changed",
        )));
    }
    Ok(())
}
fn write(
    storage: &mut dyn Storage,
    length: u64,
    mut at: u64,
    mut bytes: &[u8],
    changed: &mut bool,
    r: &Resources,
) -> io::Result<()> {
    while !bytes.is_empty() {
        guard(storage, length, r)?;
        *changed = true; // An error may still follow a partial or durable write.
        let count = storage.write_at(at, bytes)?;
        if count == 0 || count > bytes.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        at += count as u64;
        bytes = &bytes[count..];
    }
    Ok(())
}
fn barrier(storage: &mut dyn Storage, length: u64, r: &Resources) -> io::Result<()> {
    guard(storage, length, r)?;
    storage.flush()?;
    guard(storage, length, r)
}
fn verify(
    storage: &dyn Storage,
    length: u64,
    at: u64,
    bytes: &[u8],
    r: &Resources,
) -> io::Result<()> {
    guard(storage, length, r)?;
    let mut found = [0; MAX_BLOCK];
    storage.read_exact_at(at, &mut found[..bytes.len()])?;
    if found[..bytes.len()] != *bytes {
        return Err(invalid("foreign recovery durable readback"));
    }
    guard(storage, length, r)
}
fn profile(boot: &bootstrap::Bootstrap) -> io::Result<()> {
    if !matches!(boot.geometry.checksums, Checksums::None)
        || super::super::super::u32le(&boot.primary, 100) & 0x400 != 0
        || boot.geometry.first != 1
    {
        return Err(unsupported(
            "foreign recovery requires checksumless controls and first journal block one",
        ));
    }
    boot.geometry.check()
}
fn same_primary_geometry(original: &[u8], replacement: &[u8]) -> io::Result<()> {
    for range in [
        0..8,
        20..44,
        76..96,
        100..120,
        208..232,
        254..256,
        336..340,
        624..628,
    ] {
        if original[range.clone()] != replacement[range] {
            return Err(unsupported(
                "foreign recovery changes bootstrap filesystem geometry",
            ));
        }
    }
    if super::super::super::u32le(original, 96) & !4
        != super::super::super::u32le(replacement, 96) & !4
    {
        return Err(unsupported(
            "foreign recovery changes filesystem feature profile",
        ));
    }
    Ok(())
}

pub(super) fn same_bootstrap_inode_table(
    original: &[u8],
    replacement: &[u8],
    wide_descriptor: bool,
) -> io::Result<()> {
    // Cold recovery finds inode 8 through these raw group-zero pointers before
    // it can replay anything. Final inode/map equality alone cannot make a
    // torn relocation of its inode table recoverable.
    if original[8..12] != replacement[8..12]
        || wide_descriptor && original[40..44] != replacement[40..44]
    {
        return Err(unsupported(
            "foreign recovery changes bootstrap inode table",
        ));
    }
    Ok(())
}

fn charge_work(used: &mut usize, maximum: usize, amount: usize, r: &Resources) -> io::Result<()> {
    r.cancellation.check().map_err(io::Error::other)?;
    *used = used
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or_else(|| budget("foreign publication inventory work"))?;
    Ok(())
}

fn inventory_sequence(
    source: &dyn Storage,
    boot: &bootstrap::Bootstrap,
    initial: u32,
    maximum_records: usize,
    maximum_work: usize,
    r: &Resources,
) -> io::Result<u32> {
    let count = boot.geometry.maximum as usize;
    let charge = count
        .checked_mul(4)
        .and_then(|n| n.checked_add(MAX_BLOCK + 1024))
        .ok_or_else(|| budget("foreign publication inventory size"))?;
    let _reservation = r.memory.reserve(charge as u64).map_err(io::Error::other)?;
    let mut ids = Vec::new();
    ids.try_reserve_exact(count)
        .map_err(|_| budget("foreign publication inventory allocation"))?;
    if ids
        .capacity()
        .checked_mul(4)
        .is_none_or(|n| n.checked_add(MAX_BLOCK + 1024).is_none_or(|n| n > charge))
    {
        return Err(budget("foreign publication inventory capacity"));
    }
    let mut used = 0usize;

    let mut raw = [0; MAX_BLOCK];
    let mut first_sequence = None;
    for logical in 0..boot.geometry.maximum {
        charge_work(&mut used, maximum_work, 1, r)?;
        source.read_exact_at(
            boot.physical(logical)?,
            &mut raw[..boot.geometry.block_bytes],
        )?;
        if be32(&raw, 0) == MAGIC {
            let sequence = be32(&raw, 8);
            ids.push(sequence);
            if logical == boot.geometry.start {
                first_sequence = Some(sequence);
            }
        }
    }
    let probe_cost = ids.len().max(1);
    if first_sequence != Some(boot.geometry.sequence) {
        charge_work(&mut used, maximum_work, probe_cost, r)?;
        if !ids.contains(&boot.geometry.sequence) {
            return Ok(boot.geometry.sequence);
        }
        // A torn sequence can occur elsewhere in the ring. Before changing it
        // again, prove that matching the unchanged first record is idempotent.
        let first =
            first_sequence.ok_or_else(|| unsupported("foreign recovery missing first header"))?;
        let reserved = (count + 1)
            .checked_mul(probe_cost)
            .ok_or_else(|| budget("foreign publication probes"))?;
        let remaining = maximum_work
            .checked_sub(used)
            .and_then(|n| n.checked_sub(reserved))
            .and_then(|n| n.checked_sub(maximum_records))
            .ok_or_else(|| budget("foreign alternate sequence scan"))?;
        let mut geometry = boot.geometry;
        geometry.sequence = first;
        let alternate = scan(
            &geometry,
            maximum_records,
            remaining,
            r,
            |logical, bytes| source.read_exact_at(boot.physical(logical)?, bytes),
            |destination| boot.destination(destination),
        )?;
        let primary_block = u32::from(geometry.block_bytes == 1024);
        let inside = if primary_block == 1 { 0 } else { 1024 };
        for block in &alternate.blocks {
            r.cancellation.check().map_err(io::Error::other)?;
            source.read_exact_at(
                u64::from(block.destination) * geometry.block_bytes as u64,
                &mut raw[..geometry.block_bytes],
            )?;
            if block.destination == primary_block {
                raw[inside + 96] |= 4;
            }
            for (index, byte) in block.bytes[..geometry.block_bytes].iter().enumerate() {
                let expected = if block.destination == primary_block && index == inside + 96 {
                    *byte | 4
                } else {
                    *byte
                };
                if raw[index] != expected {
                    return Err(unsupported(
                        "foreign recovery alternate sequence changes durable homes",
                    ));
                }
            }
        }
        // The alternate scan consumed its entire allowance conservatively.
        used = maximum_work - reserved;
    }

    let mut candidate = initial;
    for _ in 0..=count {
        charge_work(&mut used, maximum_work, probe_cost, r)?;
        if !ids.contains(&candidate) {
            return Ok(candidate);
        }
        candidate = candidate.wrapping_add(1);
    }
    Err(budget("foreign publication sequence exclusion ceiling"))
}

/// The scan-work ceiling is split equally between log scanning and publication
/// inventory (all physical headers, linear candidate probes and any alternate
/// scan plus at most records full home comparisons). Bootstrap work is split
/// equally between the preliminary inspection and preflight. No private
/// preparation, footer or caller-supplied replay authority is admitted.
pub(crate) fn recover(
    storage: &mut dyn Storage,
    scope: u128,
    mut limits: Limits,
    r: &Resources,
) -> io::Result<Outcome> {
    let mut changed = false;
    let result = (|| {
        let length = storage.len()?;
        guard(storage, length, r)?;
        let mut primary = [0; 1024];
        storage.read_exact_at(1024, &mut primary)?;
        if super::super::super::u32le(&primary, 100) & 0x400 != 0 {
            return Err(unsupported(
                "foreign recovery filesystem metadata checksums",
            ));
        }
        limits.bootstrap_work /= 2;
        let boot =
            bootstrap::Bootstrap::read(storage, limits.journal_blocks, limits.bootstrap_work, r)?;
        profile(&boot)?;
        let dirty = super::super::super::u32le(&boot.primary, 96) & 4 != 0;
        if boot.geometry.start == 0 {
            // Inactive journal + dirty fence is a valid interrupted final close.
            // There are no published records to infer; audit the actual homes.
            original_journal(&boot.geometry, &boot.journal)?;
            let (_, audit) = overlay::Overlay::new(
                storage,
                &[],
                boot.geometry.block_bytes,
                Some(overlay::JournalControl {
                    physical: boot.physical(0)?,
                    original: boot.journal,
                    geometry: boot.geometry,
                    next_sequence: boot.geometry.sequence,
                }),
                r,
            )?
            .verify(scope, limits.audit, Some(&boot))?;
            drop(audit);
            verify(storage, length, 1024, &boot.primary, r)?;
            verify(storage, length, boot.physical(0)?, &boot.journal, r)?;
            if dirty {
                let byte = [boot.primary[96] & !4];
                write(storage, length, 1120, &byte, &mut changed, r)?;
                barrier(storage, length, r)?;
                verify(storage, length, 1120, &byte, r)?;
            }
            let (decoder, proof) =
                super::super::super::ExtDecoder::open_native_clean(storage, scope, r)?;
            let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, r)
                .map_err(io::Error::other)?;
            if !audit.is_clean() || proof.geometry.sequence != boot.geometry.sequence {
                return Err(invalid("foreign recovery inactive close audit"));
            }
            return Ok(Outcome {
                transactions: 0,
                blocks: 0,
                restart_sequence: boot.geometry.sequence,
            });
        }
        if !dirty {
            return Err(invalid(
                "foreign recovery active journal lacks recovery fence",
            ));
        }
        let publication_work = limits.scan_work / 2;
        limits.scan_work -= publication_work;
        let audit_limits = limits.audit;
        let maximum_records = limits.records;
        drop(boot);
        let plan = preflight(storage, scope, limits, r)?;
        profile(&plan.bootstrap)?;
        let primary_block = u32::from(plan.bootstrap.geometry.block_bytes == 1024);
        let inside = if primary_block == 1 { 0 } else { 1024 };
        if let Some(block) = plan
            .replay
            .blocks
            .iter()
            .find(|block| block.destination == primary_block)
        {
            same_primary_geometry(&plan.bootstrap.primary, &block.bytes[inside..inside + 1024])?;
        }
        let descriptor_block = super::super::super::u32le(&plan.bootstrap.primary, 20)
            .checked_add(1)
            .ok_or_else(|| invalid("foreign recovery descriptor block overflow"))?;
        if let Some(block) = plan
            .replay
            .blocks
            .iter()
            .find(|b| b.destination == descriptor_block)
        {
            let mut actual = [0; 64];
            storage.read_exact_at(
                u64::from(descriptor_block) * plan.bootstrap.geometry.block_bytes as u64,
                &mut actual,
            )?;
            same_bootstrap_inode_table(
                &actual,
                &block.bytes,
                super::super::super::u32le(&plan.bootstrap.primary, 96) & 0x80 != 0,
            )?;
        }
        let restart_sequence = inventory_sequence(
            storage,
            &plan.bootstrap,
            plan.restart_sequence,
            maximum_records,
            publication_work,
            r,
        )?;
        plan.check_source(r)?;
        let Plan {
            bootstrap: boot,
            mut replay,
            ..
        } = plan;
        if let Some(block) = replay
            .blocks
            .iter_mut()
            .find(|block| block.destination == primary_block)
        {
            block.bytes[inside + 96] |= 4; // Never publish a clean fence mid-checkpoint.
        }
        for block in &replay.blocks {
            write(
                storage,
                length,
                u64::from(block.destination) * boot.geometry.block_bytes as u64,
                &block.bytes[..boot.geometry.block_bytes],
                &mut changed,
                r,
            )?;
        }
        barrier(storage, length, r)?;
        for block in &replay.blocks {
            verify(
                storage,
                length,
                u64::from(block.destination) * boot.geometry.block_bytes as u64,
                &block.bytes[..boot.geometry.block_bytes],
                r,
            )?;
        }
        let journal_at = boot.physical(0)?;
        verify(storage, length, journal_at, &boot.journal, r)?;
        if restart_sequence != boot.geometry.sequence {
            let bytes = restart_sequence.to_be_bytes();
            write(storage, length, journal_at + 24, &bytes, &mut changed, r)?;
            barrier(storage, length, r)?;
            verify(storage, length, journal_at + 24, &bytes, r)?;
        }
        // All homes are durable and the published sequence is absent from EVERY
        // ring block. Even a partial start-word clear cannot select stale redo.
        write(storage, length, journal_at + 28, &[0; 4], &mut changed, r)?;
        barrier(storage, length, r)?;
        verify(storage, length, journal_at + 28, &[0; 4], r)?;
        let mut primary = [0; 1024];
        storage.read_exact_at(1024, &mut primary)?;
        let byte = [primary[96] & !4];
        write(storage, length, 1120, &byte, &mut changed, r)?;
        barrier(storage, length, r)?;
        verify(storage, length, 1120, &byte, r)?;
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(storage, scope, r)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, audit_limits, r)
            .map_err(io::Error::other)?;
        if !audit.is_clean() || proof.geometry.sequence != restart_sequence {
            return Err(invalid("foreign recovery final clean audit"));
        }
        guard(storage, length, r)?;
        Ok(Outcome {
            transactions: replay.committed_transactions,
            blocks: replay.blocks.len(),
            restart_sequence,
        })
    })();
    result.map_err(|source| {
        if changed {
            io::Error::other(Error {
                kind: ErrorKind::UncertainDurability,
                context: "foreign recovery mutation requires cold reinspection".into(),
                source: Some(source),
            })
        } else {
            source
        }
    })
}
