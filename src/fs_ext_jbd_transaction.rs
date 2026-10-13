//! Private native transaction lifecycle; caller plans typed filesystem operations.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{fs_ext_audit::ExtAuditLimits, storage::Storage};

/// Independently exclude every original regular-file payload block from
/// namespace redo, including bytes beyond a partial final EOF.
pub(crate) fn validate_namespace_destinations(
    decoder: &super::super::ExtDecoder<&dyn Storage>,
    records: &[ReplayBlock],
    file_blocks: usize,
    work_limit: usize,
    resources: &Resources,
) -> io::Result<()> {
    let geometry = decoder.geometry();
    if geometry.modern.is_some() || geometry.extent_profile {
        return Err(unsupported(
            "namespace destination guard requires classic maps",
        ));
    }
    let mut work = 0usize;
    let mut tick = || -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        work = work
            .checked_add(1)
            .filter(|n| *n <= work_limit)
            .ok_or_else(|| budget("namespace destination validation work ceiling"))?;
        Ok(())
    };
    let block_bytes = u64::from(geometry.block_size);
    for number in 11..=geometry.inodes {
        tick()?;
        let index = number - 1;
        tick()?;
        let descriptor = decoder.group(index / geometry.inodes_per_group)?;
        let bit = index % geometry.inodes_per_group;
        let bitmap_at = u64::from(descriptor[1])
            .checked_mul(block_bytes)
            .and_then(|at| at.checked_add(u64::from(bit / 8)))
            .ok_or_else(|| invalid("namespace inode bitmap offset overflow"))?;
        let mut allocated = [0u8; 1];
        tick()?;
        decoder.read_exact_at(bitmap_at, &mut allocated)?;
        if allocated[0] & (1 << (bit % 8)) == 0 {
            continue;
        }
        tick()?;
        let inode = decoder.inode(number, resources)?;
        if inode.mode() & 0xf000 != 0x8000 {
            continue;
        }
        let count = inode.length.div_ceil(block_bytes);
        if count > file_blocks as u64 || count > work_limit as u64 {
            return Err(budget("namespace original file map ceiling"));
        }
        // The decoder has fixed-depth classic traversal; charge each admitted
        // logical slot before invoking its separately bounded map decoder.
        for _ in 0..count {
            tick()?;
        }
        tick()?;
        let map = decoder.file_map(number, file_blocks, resources, false)?;
        for extent in &map.extents {
            tick()?;
            let physical = match extent.kind {
                super::super::ExtentKind::Data(at) => at,
                super::super::ExtentKind::Hole => continue,
                super::super::ExtentKind::Unwritten => {
                    return Err(unsupported("namespace original unwritten map"));
                }
            };
            if !physical.is_multiple_of(block_bytes) || extent.length == 0 {
                return Err(invalid("namespace original payload extent framing"));
            }
            let bytes = extent
                .length
                .div_ceil(block_bytes)
                .checked_mul(block_bytes)
                .ok_or_else(|| invalid("namespace original payload extent overflow"))?;
            let end = physical
                .checked_add(bytes)
                .filter(|end| *end <= u64::from(geometry.blocks) * block_bytes)
                .ok_or_else(|| invalid("namespace original payload outside filesystem"))?;
            for record in records {
                tick()?;
                let destination = u64::from(record.destination)
                    .checked_mul(block_bytes)
                    .ok_or_else(|| invalid("namespace redo destination overflow"))?;
                if destination >= physical && destination < end {
                    return Err(unsupported(
                        "namespace redo intersects original regular-file payload",
                    ));
                }
            }
        }
    }
    resources.cancellation.check().map_err(io::Error::other)
}

pub(crate) fn commit(
    storage: &mut dyn Storage,
    scope: u128,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    resources: &Resources,
) -> io::Result<recovery::Outcome> {
    commit_mode(
        storage,
        scope,
        limits,
        maximum_records,
        maximum_affected_bytes,
        records,
        None,
        None,
        None,
        resources,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "ordered publication adds sealed planner authority to the existing bounded controller"
)]
pub(crate) fn commit_ordered(
    storage: &mut dyn Storage,
    scope: u128,
    generation: u64,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    ordered: &crate::fs_ext_edit::NativeOrderedPatches,
    resources: &Resources,
) -> io::Result<recovery::Outcome> {
    if ordered.binding() != (scope, generation) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "ordered controller source or generation differs",
        )));
    }
    commit_mode(
        storage,
        scope,
        limits,
        maximum_records,
        maximum_affected_bytes,
        records,
        Some(ordered),
        None,
        None,
        resources,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "Typed namespace authority retains exact source guards through publication"
)]
pub(crate) fn commit_namespace(
    storage: &mut dyn Storage,
    scope: u128,
    generation: u64,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    plan: &crate::fs_ext_edit::NativeNamespacePatches,
    resources: &Resources,
) -> io::Result<recovery::Outcome> {
    if plan.binding() != (scope, generation) {
        return Err(io::Error::other(Error::new(
            ErrorKind::StalePlan,
            "namespace controller source/generation differs",
        )));
    }
    commit_mode(
        storage,
        scope,
        limits,
        maximum_records,
        maximum_affected_bytes,
        records,
        None,
        Some(plan),
        None,
        resources,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "sealed modern plan retains source guards and leases through publication"
)]
pub(super) fn commit_modern(
    storage: &mut dyn Storage,
    scope: u128,
    generation: u64,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    plan: &super::modern_plan::Plan,
    resources: &Resources,
) -> io::Result<recovery::Outcome> {
    commit_mode(
        storage,
        scope,
        limits,
        maximum_records,
        maximum_affected_bytes,
        records,
        None,
        None,
        Some((plan, generation)),
        resources,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "shared private controller keeps typed ordered authority separate from metadata redo"
)]
fn commit_mode(
    storage: &mut dyn Storage,
    scope: u128,
    limits: ExtAuditLimits,
    maximum_records: usize,
    maximum_affected_bytes: u64,
    records: &[ReplayBlock],
    ordered: Option<&crate::fs_ext_edit::NativeOrderedPatches>,
    namespace: Option<&crate::fs_ext_edit::NativeNamespacePatches>,
    modern: Option<(&super::modern_plan::Plan, u64)>,
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
    let modern_validation_work = if let Some((plan, generation)) = modern {
        plan.validate_source_guards(scope, generation, &decoder, resources, limits.work)?
    } else {
        0
    };
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
    let data = ordered.map_or(&[][..], |plan| plan.data());
    let candidate_count = records
        .len()
        .checked_add(data.len())
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| budget("native candidate count overflow"))?;
    if candidate_count
        > maximum_records
            .checked_add(1)
            .ok_or_else(|| budget("ordered candidate bound overflow"))?
    {
        return Err(budget("native combined candidate ceiling"));
    }
    let reservation = resources
        .memory
        .reserve(
            candidate_count
                .checked_mul(crate::platform::mem::size_of::<ReplayBlock>())
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
    let mut ordered_bytes = 0u64;
    let mut ordered_work = modern_validation_work;
    for patch in data {
        resources.cancellation.check().map_err(io::Error::other)?;
        ordered_work = ordered_work
            .checked_add(candidate_count)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| budget("ordered candidate work"))?;
        let bs = initial.block_bytes as u64;
        let end = patch
            .offset()
            .checked_add(patch.expected().len() as u64)
            .ok_or_else(|| invalid("ordered data bounds overflow"))?;
        if patch.expected().is_empty()
            || patch.expected().len() != patch.replacement().len()
            || patch.offset() / bs != (end - 1) / bs
        {
            return Err(invalid("ordered data must remain within one native block"));
        }
        let destination = u32::try_from(patch.offset() / bs)
            .map_err(|_| unsupported("ordered high data block"))?;
        bootstrap.destination(destination)?;
        if candidate.iter().any(|r| r.destination == destination) {
            return Err(invalid("ordered data and metadata destinations collide"));
        }
        let mut record = ReplayBlock {
            destination,
            bytes: [0; MAX_BLOCK],
        };
        storage.read_exact_at(
            u64::from(destination) * bs,
            &mut record.bytes[..initial.block_bytes],
        )?;
        let inside = (patch.offset() % bs) as usize;
        let stop = inside + patch.expected().len();
        if record.bytes[inside..stop] != *patch.expected() {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "ordered data expected bytes changed",
            )));
        }
        record.bytes[inside..stop].copy_from_slice(patch.replacement());
        candidate.push(record);
        ordered_bytes = ordered_bytes
            .checked_add(patch.replacement().len() as u64)
            .ok_or_else(|| budget("ordered byte accounting"))?;
    }
    if candidate.len()
        > maximum_records
            .checked_add(1)
            .ok_or_else(|| budget("ordered combined record ceiling"))?
    {
        return Err(budget("ordered combined affected block ceiling"));
    }
    if ordered.is_some() {
        crate::fs_ext_edit::allocation::bounded_sort(
            &mut candidate,
            |record| record.destination,
            &mut ordered_work,
            limits.work,
            resources,
        )
        .map_err(io::Error::other)?;
    } else {
        candidate.sort_unstable_by_key(|r| r.destination);
    }
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
    drop(checked);
    let checked_data = if ordered.is_some() {
        Some((candidate, reservation))
    } else {
        drop((candidate, reservation));
        None
    };
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
    let physical_bytes = affected_blocks
        .checked_mul(initial.block_bytes)
        .and_then(|bytes| bytes.checked_add(24))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| bytes.checked_add(ordered_bytes))
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| budget("native transaction physical affected byte ceiling"))?;
    // A backend may successfully write only one byte per attempt. Reserve the
    // complete finite work envelope before preparation can mutate storage.
    let data_bytes = usize::try_from(ordered_bytes).map_err(|_| budget("ordered I/O work size"))?;
    let guards = || {
        ordered
            .into_iter()
            .flat_map(|p| p.source_guards())
            .chain(namespace.into_iter().flat_map(|p| p.source_guards()))
            .chain(modern.into_iter().flat_map(|(p, _)| p.source_guards()))
    };
    let mut guard_work = 0usize;
    {
        for (_, bytes) in guards() {
            resources.cancellation.check().map_err(io::Error::other)?;
            guard_work = bytes
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(3))
                .and_then(|n| n.checked_mul(2))
                .and_then(|n| n.checked_add(guard_work))
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| budget("ordered source guard work ceiling"))?;
        }
    }
    let worst_ordered_work = candidate_count
        .checked_add(4)
        .and_then(|per_range| per_range.checked_mul(data.len()))
        .and_then(|n| {
            data_bytes
                .checked_mul(2)
                .and_then(|bytes| n.checked_add(bytes))
        })
        .and_then(|n| n.checked_add(usize::from(!data.is_empty())))
        .and_then(|n| n.checked_add(ordered_work))
        .and_then(|n| n.checked_add(guard_work))
        .ok_or_else(|| budget("ordered I/O work overflow"))?;
    publication_budget(
        worst_ordered_work,
        physical_bytes,
        &prepared,
        &encoded,
        initial.block_bytes,
        limits.work,
        maximum_affected_bytes,
    )?;
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
    {
        for (at, expected) in guards() {
            resources.cancellation.check().map_err(io::Error::other)?;
            ordered_work = ordered_work
                .checked_add(
                    expected
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| budget("source guard byte work"))?,
                )
                .and_then(|n| n.checked_add(3))
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| budget("ordered source guard comparison work"))?;
            if !((expected.len() == initial.block_bytes
                && at.is_multiple_of(initial.block_bytes as u64))
                || (expected.len() == 128 && at.is_multiple_of(128))
                || modern.is_some_and(|(plan, _)| plan.inode_guard_geometry(at, expected.len())))
            {
                return Err(invalid("ordered source guard geometry"));
            }
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered source guard length changed",
                )));
            }
            if expected.is_empty()
                || expected.len() > MAX_BLOCK
                || at
                    .checked_add(expected.len() as u64)
                    .is_none_or(|end| end > length)
            {
                return Err(invalid("source guard range"));
            }
            let mut actual = [0; MAX_BLOCK];
            storage.read_exact_at(at, &mut actual[..expected.len()])?;
            resources.cancellation.check().map_err(io::Error::other)?;
            if storage.len()? != length {
                return Err(invalid("source guard read changed length"));
            }
            resources.cancellation.check().map_err(io::Error::other)?;
            if actual[..expected.len()] != *expected {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered original payload changed before publication",
                )));
            }
            resources.cancellation.check().map_err(io::Error::other)?;
        }
    }
    proof.geometry.start = initial.first;
    proof.geometry.sequence = initial.sequence;
    publish_log(storage, &proof, &prepared, resources)?;
    let mut active = bootstrap.journal;
    put32(&mut active, 28, initial.first);
    journal_checksum(&initial, &mut active);
    publish_control(storage, bootstrap.physical(0)?, &active)?;
    publish_control(
        storage,
        u64::from(primary) * initial.block_bytes as u64,
        &dirty.superblock[..initial.block_bytes],
    )?;
    // Preparation and the home recovery fence are durable before data can change.
    // Exact suffix writes preserve every previously visible byte in an append tail.
    for patch in data {
        resources.cancellation.check().map_err(io::Error::other)?;
        ordered_tick(&mut ordered_work, limits.work, resources)?;
        if storage.len()? != length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "ordered publication source length changed",
            )));
        }
        let mut before = [0; MAX_BLOCK];
        ordered_tick(&mut ordered_work, limits.work, resources)?;
        storage.read_exact_at(patch.offset(), &mut before[..patch.expected().len()])?;
        if before[..patch.expected().len()] != *patch.expected() {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "ordered data changed before publication",
            )));
        }
        let mut done = 0;
        while done < patch.replacement().len() {
            resources.cancellation.check().map_err(io::Error::other)?;
            ordered_work = ordered_work
                .checked_add(1)
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| budget("ordered publication work"))?;
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered data source length changed",
                )));
            }
            ordered_tick(&mut ordered_work, limits.work, resources)?;
            let count =
                storage.write_at(patch.offset() + done as u64, &patch.replacement()[done..])?;
            if count == 0 || count > patch.replacement().len() - done {
                return Err(io::ErrorKind::WriteZero.into());
            }
            done += count;
        }
    }
    if !data.is_empty() {
        resources.cancellation.check().map_err(io::Error::other)?;
        ordered_tick(&mut ordered_work, limits.work, resources)?;
        storage.flush()?;
        for patch in data {
            resources.cancellation.check().map_err(io::Error::other)?;
            ordered_work = ordered_work
                .checked_add(candidate_count)
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| budget("ordered readback work"))?;
            ordered_tick(&mut ordered_work, limits.work, resources)?;
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered readback source length changed",
                )));
            }
            let destination = (patch.offset() / initial.block_bytes as u64) as u32;
            let (candidate, _) = checked_data
                .as_ref()
                .ok_or_else(|| invalid("ordered checked candidate missing"))?;
            let expected = candidate
                .iter()
                .find(|r| r.destination == destination)
                .ok_or_else(|| invalid("ordered readback lacks checked block"))?;
            let mut found = [0; MAX_BLOCK];
            ordered_tick(&mut ordered_work, limits.work, resources)?;
            storage.read_exact_at(
                u64::from(destination) * initial.block_bytes as u64,
                &mut found[..initial.block_bytes],
            )?;
            if found[..initial.block_bytes] != expected.bytes[..initial.block_bytes] {
                return Err(invalid("ordered durable block readback mismatch"));
            }
        }
    }
    // Ordered data is durable; original visible data must still match before mutation commit.
    {
        for (at, expected) in guards() {
            resources.cancellation.check().map_err(io::Error::other)?;
            ordered_work = ordered_work
                .checked_add(
                    expected
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| budget("source guard byte work"))?,
                )
                .and_then(|n| n.checked_add(3))
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| budget("ordered source guard comparison work"))?;
            if !((expected.len() == initial.block_bytes
                && at.is_multiple_of(initial.block_bytes as u64))
                || (expected.len() == 128 && at.is_multiple_of(128))
                || modern.is_some_and(|(plan, _)| plan.inode_guard_geometry(at, expected.len())))
            {
                return Err(invalid("ordered source guard geometry"));
            }
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered source guard length changed",
                )));
            }
            if expected.is_empty()
                || expected.len() > MAX_BLOCK
                || at
                    .checked_add(expected.len() as u64)
                    .is_none_or(|end| end > length)
            {
                return Err(invalid("source guard range"));
            }
            let mut actual = [0; MAX_BLOCK];
            storage.read_exact_at(at, &mut actual[..expected.len()])?;
            resources.cancellation.check().map_err(io::Error::other)?;
            if storage.len()? != length {
                return Err(invalid("source guard read changed length"));
            }
            resources.cancellation.check().map_err(io::Error::other)?;
            if actual[..expected.len()] != *expected {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "ordered original payload changed before publication",
                )));
            }
            resources.cancellation.check().map_err(io::Error::other)?;
        }
    }
    proof.geometry.start = prepared.next_logical;
    proof.geometry.sequence = initial.sequence.wrapping_add(1);
    publish_log(storage, &proof, &encoded, resources)?;
    drop((proof, bootstrap, prepared, dirty, encoded, checked_data));
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

fn ordered_tick(work: &mut usize, limit: usize, r: &Resources) -> io::Result<()> {
    r.cancellation.check().map_err(io::Error::other)?;
    *work = work
        .checked_add(1)
        .filter(|n| *n <= limit)
        .ok_or_else(|| budget("ordered candidate sort work"))?;
    Ok(())
}
