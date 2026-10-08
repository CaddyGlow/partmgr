//! Private pristine-page native checkpoint rollover; no filesystem home changes.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::storage::Storage;
use sha2::{Digest, Sha256};

pub(in super::super) struct Plan {
    before: [u8; PAGE],
    after: [u8; PAGE],
    logs: [u8; PAGE],
    page_at: u64,
    log_at: u64,
    log: super::super::super::Physical,
    end: u32,
    length: u64,
    digest: [u8; 32],
    read: super::super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    _lease: Reservation,
}
impl Plan {
    pub(in super::super) fn projection(&self) -> Result<[(u64, Vec<u8>); 2]> {
        let mut logs = self.logs;
        logs[32..36].copy_from_slice(&self.end.to_le_bytes());
        Ok([
            (self.page_at, super::super::super::copied(&self.after)?),
            (self.log_at, super::super::super::copied(&logs)?),
        ])
    }
}

fn possible<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
fn prefix(actual: &[u8], old: &[u8], new: &[u8]) -> bool {
    let mut boundary = 0;
    while boundary < actual.len() && actual[boundary] == new[boundary] {
        boundary += 1;
    }
    actual[boundary..] == old[boundary..]
}
fn empty(sequence: u32) -> [u8; PAGE] {
    let mut page = [0; PAGE];
    for at in [0, TRAILER] {
        page[at..at + 4].copy_from_slice(&sequence.to_le_bytes());
        page[at + 6..at + 8].copy_from_slice(&(HEADER as u16).to_le_bytes());
    }
    page
}
fn ring_digest(
    source: &dyn DecodeRead,
    log: super::super::super::Physical,
    read: super::super::super::JfsReadLimits,
    r: &Resources,
) -> Result<[u8; 32]> {
    if log.count > read.pages as u64
        || log
            .count
            .checked_mul((PAGE * 8) as u64)
            .is_none_or(|n| n > read.work)
    {
        return Err(budget("JFS rollover ring work/pages"));
    }
    let mut hash = Sha256::new();
    let mut page = [0; PAGE];
    for number in 1..log.count {
        r.cancellation.check()?;
        source.exact((log.start + number) * PAGE as u64, &mut page)?;
        hash.update(page);
    }
    for at in [32768, 61440] {
        source.exact(at, &mut page)?;
        hash.update(page);
    }
    Ok(hash.finalize().into())
}
pub(in super::super) fn prepare(
    storage: &dyn Storage,
    binding: [u8; 16],
    read: super::super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    recovering: bool,
) -> Result<Plan> {
    prepare_profile(
        storage,
        binding,
        read,
        audit,
        original,
        r,
        (recovering, false),
    )
}

pub(in super::super) fn prepare_recycling(
    storage: &dyn Storage,
    binding: [u8; 16],
    read: super::super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    recovering: bool,
) -> Result<Plan> {
    prepare_profile(
        storage,
        binding,
        read,
        audit,
        original,
        r,
        (recovering, true),
    )
}

fn prepare_profile(
    storage: &dyn Storage,
    binding: [u8; 16],
    read: super::super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    profile: (bool, bool),
) -> Result<Plan> {
    let (recovering, recycling) = profile;
    original.cancellation.check()?;
    r.cancellation.check()?;
    let lease = r.memory.reserve(65536)?;
    let baseline = super::super::inspect_with(storage, read, audit, original, r)?;
    drop(baseline);
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS rollover length", e))?;
    let source = super::super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut header = [0; PAGE];
    source.exact(32768, &mut header)?;
    if header[136..152] != binding || binding.iter().all(|b| *b == 0) {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rollover aggregate binding",
        ));
    }
    let log = pxd(&header, 72, length / PAGE as u64)?;
    let log_at = (log.start + 1) * PAGE as u64;
    let mut logs = [0; PAGE];
    source.exact(log_at, &mut logs)?;
    let digest = ring_digest(&source, log, read, r)?;
    if recovering
        && let Some(scanned) = possible(history(
            &source,
            log,
            HistoryLimits {
                pages: read.pages,
                records: 64,
                data: 8192,
                work: read.work,
            },
            r,
        ))?
        && scanned.records.first().is_some_and(|record| {
            record.end == le32(&logs, 32) && le16(&record.descriptor, 8) == SYNC
        })
    {
        let end = le32(&logs, 32);
        let page_at = (log.start + u64::from(end / PAGE as u32)) * PAGE as u64;
        let mut before = [0; PAGE];
        source.exact(page_at, &mut before)?;
        source.length()?;
        original.cancellation.check()?;
        r.cancellation.check()?;
        return Ok(Plan {
            before,
            after: before,
            logs,
            page_at,
            log_at,
            log,
            end,
            length,
            digest,
            read,
            audit,
            _lease: lease,
        });
    }
    let mut maximum = None;
    let mut torn = None;
    let mut page = [0; PAGE];
    for number in 2..log.count as u32 {
        r.cancellation.check()?;
        source.exact((log.start + u64::from(number)) * PAGE as u64, &mut page)?;
        if page[..HEADER] != page[TRAILER..] {
            if torn.replace(number).is_some() || !recovering {
                return Err(bad("JFS rollover multiple/unapproved torn pages"));
            }
            continue;
        }
        let sequence = framing(
            page[..HEADER].try_into().unwrap(),
            page[TRAILER..].try_into().unwrap(),
            false,
        )?
        .0;
        if maximum.is_none_or(|(seq, _)| sequence > seq) {
            maximum = Some((sequence, number));
        }
    }
    let (_, newest) = maximum.ok_or_else(|| bad("JFS rollover no durable anchor"))?;
    let predecessor = if newest == 2 {
        log.count as u32 - 1
    } else {
        newest - 1
    };
    let mut chosen = None;
    for anchor in [newest, predecessor] {
        source.exact((log.start + u64::from(anchor)) * PAGE as u64, &mut page)?;
        if page[..HEADER] != page[TRAILER..] {
            continue;
        }
        let sequence = le32(&page, 0);
        let Some(next_sequence) = sequence.checked_add(1) else {
            continue;
        };
        let Some(old_sequence) = next_sequence.checked_sub(log.count as u32 - 2) else {
            continue;
        };
        let number = if u64::from(anchor) + 1 == log.count {
            2
        } else {
            anchor + 1
        };
        if torn.is_some_and(|n| n != number) {
            continue;
        }
        let anchor_end = anchor * PAGE as u32 + u32::from(le16(&page, 6));
        let offset = usize::from(le16(&page, 6));
        if offset < HEADER + DESCRIPTOR {
            continue;
        }
        let descriptor: [u8; DESCRIPTOR] = page[offset - DESCRIPTOR..offset].try_into().unwrap();
        let mut expected = [0u8; DESCRIPTOR];
        expected[8..10].copy_from_slice(&SYNC.to_le_bytes());
        if descriptor != expected {
            continue;
        }
        let mut observed = [0; PAGE];
        source.exact((log.start + u64::from(number)) * PAGE as u64, &mut observed)?;
        // Native mkfs leaves unreachable log body bytes unspecified. This
        // profile requires its hidden canonical SYNC but never rewrites the
        // ignored bytes; cold proof authorizes framing only.
        if observed[HEADER..HEADER + DESCRIPTOR] != descriptor {
            continue;
        }
        let mut before = observed;
        let framing = empty(old_sequence);
        before[..HEADER].copy_from_slice(&framing[..HEADER]);
        before[TRAILER..].copy_from_slice(&framing[TRAILER..]);
        let mut after = before;
        let framing = empty(next_sequence);
        after[..HEADER].copy_from_slice(&framing[..HEADER]);
        after[TRAILER..].copy_from_slice(&framing[TRAILER..]);
        let end = append(&mut after, number, &descriptor, &[])?;
        let ends = if recycling {
            [8, le16(&observed, 6), le16(&observed, TRAILER + 6), 44]
        } else {
            [8; 4]
        };
        let mut compatible = false;
        for old_end in ends {
            if !(HEADER as u16..=TRAILER as u16).contains(&old_end) || !old_end.is_multiple_of(4) {
                continue;
            }
            before[6..8].copy_from_slice(&old_end.to_le_bytes());
            before[TRAILER + 6..].copy_from_slice(&old_end.to_le_bytes());
            if prefix(&observed, &before, &after) && (recovering || observed == before) {
                compatible = true;
                break;
            }
        }
        if !compatible || !prefix(&logs[32..36], &anchor_end.to_le_bytes(), &end.to_le_bytes()) {
            continue;
        }
        // Mask only the authorized successor with a compatible retired framing.
        // Every other page must still establish the native durable anchor.
        let patches = [(
            (log.start + u64::from(number)) * PAGE as u64,
            super::super::super::copied(&before)?,
        )];
        let overlay = super::super::Overlay {
            source: super::super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &patches,
        };
        let Some(history) = possible(history(
            &overlay,
            log,
            HistoryLimits {
                pages: read.pages,
                records: 64,
                data: 8192,
                work: read.work,
            },
            r,
        ))?
        else {
            continue;
        };
        if history
            .records
            .first()
            .is_none_or(|record| record.end != anchor_end || le16(&record.descriptor, 8) != SYNC)
        {
            continue;
        }
        if chosen.is_some() {
            return Err(bad("JFS rollover ambiguous native anchor"));
        }
        chosen = Some((observed, after, number, end));
    }
    let (before, after, number, end) = chosen.ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            "JFS rollover successor/anchor profile",
        )
    })?;
    source.length()?;
    original.cancellation.check()?;
    r.cancellation.check()?;
    Ok(Plan {
        before,
        after,
        logs,
        page_at: (log.start + u64::from(number)) * PAGE as u64,
        log_at,
        log,
        end,
        length,
        digest,
        read,
        audit,
        _lease: lease,
    })
}
pub(in super::super) fn publish(
    storage: &mut dyn Storage,
    plan: Plan,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let source = super::super::Borrowed {
        storage,
        length: plan.length,
        resources: original,
    };
    if ring_digest(&source, plan.log, plan.read, r)? != plan.digest {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rollover ring changed",
        ));
    }
    drop(super::super::inspect_with(
        storage, plan.read, plan.audit, original, r,
    )?);
    let mut logs = plan.logs;
    logs[32..36].copy_from_slice(&plan.end.to_le_bytes());
    if plan.before == plan.after && logs == plan.logs {
        return Ok(());
    }
    let result = (|| {
        if plan.before != plan.after {
            write_checked(storage, plan.page_at, &plan.after[..HEADER], original, r)?;
            write_checked(
                storage,
                plan.page_at + TRAILER as u64,
                &plan.after[TRAILER..],
                original,
                r,
            )?;
            flush_readback(storage, plan.page_at, &plan.after, original, r)?;
        }
        if logs != plan.logs {
            write_checked(storage, plan.log_at + 32, &logs[32..36], original, r)?;
            flush_readback(storage, plan.log_at, &logs, original, r)?;
        }
        drop(super::super::inspect_with(
            storage, plan.read, plan.audit, original, r,
        )?);
        let source = super::super::Borrowed {
            storage,
            length: plan.length,
            resources: original,
        };
        let scanned = history(
            &source,
            plan.log,
            HistoryLimits {
                pages: plan.read.pages,
                records: 64,
                data: 8192,
                work: plan.read.work,
            },
            r,
        )?;
        if scanned
            .records
            .first()
            .is_none_or(|record| record.end != plan.end || le16(&record.descriptor, 8) != SYNC)
        {
            return Err(bad("JFS rollover final native checkpoint"));
        }
        original.cancellation.check()?;
        r.cancellation.check()?;
        Ok(())
    })();
    result.map_err(|mut error: Error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!("JFS rollover requires explicit recovery: {}", error.context);
        error
    })
}
