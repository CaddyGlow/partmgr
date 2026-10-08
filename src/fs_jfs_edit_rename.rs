//! Private operation-specific inline-directory rename transaction.
use super::*;
pub(in super::super) struct Plan {
    base: Prepared,
    before: [u8; 512],
    after: [u8; 512],
}
pub(in super::super) fn prepare(
    storage: &dyn crate::storage::Storage,
    request: (u32, &[u16], &[u16]),
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    original: &Resources,
    r: &Resources,
) -> Result<Plan> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let (inode, old, new) = request;
    let (read, audit) = limits;
    let baseline = super::super::inspect_with(storage, read, audit, original, r)?;
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS rename directory absent"))?;
    if !node.directory || !node.pages.is_empty() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS rename inline directory profile",
        ));
    }
    let before: [u8; 512] = node
        .raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("JFS rename inode size"))?;
    let after = super::namespace::rename_inline(&before, &node.entries, old, new, r)?;
    drop(baseline);
    // Reuse checked clean-log bootstrap, binding and retained metadata lease.
    // This preparation emits nothing; its temporary UID recipe is replaced.
    let mut base = super::prepare_uid(storage, inode, le32(&before, 44), read, audit, original, r)?;
    if base.before != before[..128] {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rename inode changed during bootstrap",
        ));
    }
    let patches = [(base.home, super::super::super::copied(&after)?)];
    let overlay = super::super::Overlay {
        source: super::super::Borrowed {
            storage,
            length: base.length,
            resources: original,
        },
        patches: &patches,
    };
    let checked = super::super::super::decode(&overlay, read, r)?;
    if !crate::fs_jfs_audit::audit_decoded(&checked, audit, r)?.is_clean() {
        return Err(bad("JFS rename projection ownership"));
    }
    drop((checked, patches));
    let number = (base.page_at - base.log_at + 4096) / 4096;
    let mut page = base.before_page;
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut page, number as u32, &d, &[])?;
    let mut chain = 0u32;
    for image in [&before, &after] {
        for root in [false, true] {
            let descriptor = namespace_descriptor(image, inode, base.home / 4096, chain, root);
            let mut body = [0; 292];
            let length = namespace_body(&mut body, image, inode, root);
            chain = append(&mut page, number as u32, &descriptor, &body[..length])?;
        }
    }
    base.prepared = page;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&chain.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut page, number as u32, &d, &[])?;
    base.committed = page;
    d.fill(0);
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    base.end = append(&mut page, number as u32, &d, &[])?;
    base.checkpoint = page;
    original.cancellation.check()?;
    r.cancellation.check()?;
    Ok(Plan {
        base,
        before,
        after,
    })
}
fn namespace_descriptor(
    image: &[u8; 512],
    inode: u32,
    home_page: u64,
    chain: u32,
    root: bool,
) -> [u8; DESCRIPTOR] {
    let mut d = [0; DESCRIPTOR];
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&chain.to_le_bytes());
    d[8..10].copy_from_slice(&REDO.to_le_bytes());
    d[10..12].copy_from_slice(&(if root { 292u16 } else { 260 }).to_le_bytes());
    d[16..20].copy_from_slice(&le32(image, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&(if root { 0x14u16 } else { 1 }).to_le_bytes());
    d[26..28].copy_from_slice(&(if root { 5u16 } else { 7 }).to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((home_page >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(home_page as u32).to_le_bytes());
    d
}
fn namespace_body(body: &mut [u8; 292], image: &[u8; 512], inode: u32, root: bool) -> usize {
    if root {
        body[..288].copy_from_slice(&image[224..]);
        body[290..292].copy_from_slice(&9u16.to_le_bytes());
        292
    } else {
        body[..256].copy_from_slice(&image[..256]);
        body[256..258].copy_from_slice(&((inode & 7) as u16 * 4).to_le_bytes());
        body[258..260].copy_from_slice(&2u16.to_le_bytes());
        260
    }
}
pub(in super::super) fn publish(
    storage: &mut dyn crate::storage::Storage,
    plan: Plan,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    drop(super::super::inspect_with(
        storage,
        plan.base.read,
        plan.base.audit,
        original,
        r,
    )?);
    super::publish_inode_plan(storage, plan.base, &plan.before, &plan.after, original, r)
}
#[test]
fn bounded_owned_inline_rename_emits_native_redo_and_preserves_payload_and_native_identity() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut b = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut b);
    let mut backend = super::super::CowTestBackend {
        durable: b.clone(),
        bytes: b,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    let plan = prepare(&backend, (5, &old, &new), (read, audit), &r, &r).unwrap();
    assert_eq!((backend.writes, backend.flushes), (0, 0));
    publish(&mut backend, plan, &r, &r).unwrap();
    recover(&mut backend, [0xa5; 16], (read, audit), &r, &r).unwrap();
    let tree = super::super::inspect(&backend, read, audit, &r).unwrap();
    assert_eq!(tree.nodes[&5].entries[1].name, new);
    assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
    assert_eq!(&backend.bytes[112 * 4096..112 * 4096 + 7], b"nested!");
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}

pub(in super::super) fn recover(
    storage: &mut dyn crate::storage::Storage,
    binding: [u8; 16],
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let _lease = r.memory.reserve(98304)?;
    let (read, audit) = limits;
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS rename recovery length", e))?;
    let source = super::super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut headers = [[0; PAGE]; 2];
    for (at, h) in [32768u64, 61440].into_iter().zip(&mut headers) {
        source.exact(at, h)?;
    }
    if binding.iter().all(|b| *b == 0) || headers[0][136..152] != binding {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rename aggregate binding",
        ));
    }
    let log = pxd(&headers[0], 72, length / 4096)?;
    let log_at = (log.start + 1) * 4096;
    let mut logs = [0; PAGE];
    source.exact(log_at, &mut logs)?;
    let (serial, partial_serial) =
        activation_serial([le32(&headers[0], 68), le32(&headers[1], 68), le32(&logs, 8)])?;
    let active = logs[68..84] == binding;
    let inactive = logs[68..84].iter().all(|v| *v == 0);
    let activating = (0..=16).any(|cut| {
        logs[68..68 + cut] == binding[..cut] && logs[68 + cut..84].iter().all(|v| *v == 0)
    });
    let clearing = (0..=16).any(|cut| {
        logs[68..68 + cut].iter().all(|v| *v == 0) && logs[68 + cut..84] == binding[cut..]
    });
    if ![0, 1].contains(&le32(&logs, 28))
        || headers.iter().any(|h| ![0, 1].contains(&le32(h, 40)))
        || logs[84..68 + 128 * 16].iter().any(|v| *v != 0)
        || !(activating || clearing)
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS rename activation profile",
        ));
    }
    let mut scanned = history_framing(
        &source,
        log,
        HistoryLimits {
            pages: read.pages,
            records: 8,
            data: 2048,
            work: read.work,
        },
        r,
        true,
    )?;
    let newest = scanned
        .records
        .first()
        .ok_or_else(|| bad("JFS rename empty history"))?;
    let kind = le16(&newest.descriptor, 8);
    let mut committed = kind == COMMIT;
    let checkpointed = kind == SYNC;
    let newest_end = newest.end;
    let number = newest_end / PAGE as u32;
    if scanned.reconciled.iter().any(|p| *p != number) {
        return Err(bad("JFS rename older torn page"));
    }
    let repaired = !scanned.reconciled.is_empty();
    if ![REDO, COMMIT, SYNC].contains(&kind)
        || partial_serial && kind != REDO
        || !active
            && !inactive
            && !(kind == REDO && activating || checkpointed && clearing && le32(&logs, 28) == 1)
    {
        return Err(bad("JFS rename publication/activation ordering"));
    }
    if committed
        && (partial_serial
            || !active
            || le32(&logs, 28) != 0
            || headers.iter().any(|h| le32(h, 40) != 1))
    {
        return Err(bad("JFS rename COMMIT before activation"));
    }
    let mut projected = headers;
    for h in &mut projected {
        h[40..44].fill(0);
        h[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    let mut cleanlogs = logs;
    cleanlogs[8..12].copy_from_slice(&serial.to_le_bytes());
    cleanlogs[28..32].copy_from_slice(&1u32.to_le_bytes());
    cleanlogs[68..68 + 128 * 16].fill(0);
    let mut patches = vector(4)?;
    for (at, h) in [32768u64, 61440].into_iter().zip(&projected) {
        patches.push((at, super::super::super::copied(h)?));
    }
    patches.push((log_at, super::super::super::copied(&cleanlogs)?));
    let mut home = vector(1)?;
    let simple_checkpoint = checkpointed
        && le32(&logs, 28) == 1
        && le32(&logs, 32) == newest_end
        && headers.iter().all(|h| le32(h, 40) == 0)
        && inactive;
    let complete = simple_checkpoint && !repaired;
    if checkpointed && !simple_checkpoint {
        let mut prior = history_framing_profile(
            &source,
            log,
            HistoryLimits {
                pages: read.pages,
                records: 8,
                data: 2048,
                work: read.work,
            },
            r,
            true,
            true,
        )?;
        if prior.records.first().is_none_or(|e| e.end != newest_end) {
            return Err(bad("JFS rename checkpoint changed during reconstruction"));
        }
        prior.records.remove(0);
        committed = prior
            .records
            .first()
            .is_some_and(|e| le16(&e.descriptor, 8) == COMMIT);
        scanned = prior;
    }
    if simple_checkpoint {
        if le32(&logs, 28) == 1 && le32(&logs, 32) != newest_end {
            return Err(bad("JFS rename complete log-end mismatch"));
        }
        let overlay = super::super::Overlay {
            source: super::super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &patches,
        };
        let checked = super::super::super::decode(&overlay, read, r)?;
        if !crate::fs_jfs_audit::audit_decoded(&checked, audit, r)?.is_clean() {
            return Err(bad("JFS rename checkpoint ownership"));
        }
        drop(checked);
    } else {
        if scanned.records.len() != 5 + usize::from(committed) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS rename four-vector transaction profile",
            ));
        }
        let cursor = usize::from(committed);
        let new_root = &scanned.records[cursor];
        let new_inode = &scanned.records[cursor + 1];
        let old_root = &scanned.records[cursor + 2];
        let old_inode = &scanned.records[cursor + 3];
        let anchor = &scanned.records[cursor + 4];
        let inode = le32(&old_inode.descriptor, 20);
        let physical = pxd(&old_inode.descriptor, 28, length / 4096)?;
        if physical.count != 1 {
            return Err(bad("JFS rename home page count"));
        }
        let at = physical.start * 4096 + u64::from(inode & 7) * 512;
        let mut before = [0u8; 512];
        let mut after = [0u8; 512];
        for (image, base, root) in [
            (&mut before, old_inode, old_root),
            (&mut after, new_inode, new_root),
        ] {
            for (record, is_root) in [(base, false), (root, true)] {
                let expected_len = if is_root { 292 } else { 260 };
                if record.body.len() != expected_len
                    || le16(&record.descriptor, 24) != if is_root { 0x14 } else { 1 }
                    || le16(&record.descriptor, 26) != if is_root { 5 } else { 7 }
                {
                    return Err(bad("JFS rename native vector type/body"));
                }
                if is_root {
                    if le16(&record.body, 288) != 0 || le16(&record.body, 290) != 9 {
                        return Err(bad("JFS rename root vector bounds"));
                    }
                } else if le16(&record.body, 256) != (inode & 7) as u16 * 4
                    || le16(&record.body, 258) != 2
                {
                    return Err(bad("JFS rename inline-data vector bounds"));
                }
                redo_namespace_lines(
                    &Record {
                        end: record.end,
                        tid: le32(&record.descriptor, 0),
                        backchain: le32(&record.descriptor, 4),
                        aggregate: le32(&record.descriptor, 12),
                        kind: le16(&record.descriptor, 8),
                        detail: &record.descriptor[16..],
                        body: &record.body,
                    },
                    length / 4096,
                    r,
                    &mut |address, data| {
                        let offset = address
                            .checked_sub(at)
                            .ok_or_else(|| bad("JFS rename vector owner"))?
                            as usize;
                        if offset.checked_add(data.len()).is_none_or(|v| v > 512) {
                            return Err(bad("JFS rename vector span"));
                        }
                        image[offset..offset + data.len()].copy_from_slice(data);
                        Ok(())
                    },
                )?;
            }
            if base.body[224..256] != image[224..256] {
                return Err(bad("JFS rename discarded overlap contradicts ROOT"));
            }
        }
        let fileset = le32(&before, 4);
        let expected = [
            (old_inode, false, 0),
            (old_root, true, old_inode.end),
            (new_inode, false, old_root.end),
            (new_root, true, new_inode.end),
        ];
        for (record, root, chain) in expected {
            let image = if record.end == old_inode.end || record.end == old_root.end {
                &before
            } else {
                &after
            };
            let d = namespace_descriptor(image, inode, physical.start, chain, root);
            if record.descriptor != d {
                return Err(bad("JFS rename transaction membership/sequence"));
            }
        }
        if le32(&before, 8) != inode
            || le32(&after, 4) != fileset
            || le32(&after, 8) != inode
            || le16(&anchor.descriptor, 8) != SYNC
            || anchor
                .descriptor
                .iter()
                .enumerate()
                .any(|(i, b)| *b != if i == 9 { 0x40 } else { 0 })
            || !anchor.body.is_empty()
        {
            return Err(bad("JFS rename native identity/anchor"));
        }
        if committed {
            let mut d = [0; DESCRIPTOR];
            d[..4].copy_from_slice(&7u32.to_le_bytes());
            d[4..8].copy_from_slice(&new_root.end.to_le_bytes());
            d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
            if scanned.records[0].descriptor != d || !scanned.records[0].body.is_empty() {
                return Err(bad("JFS rename COMMIT membership"));
            }
        }
        let old_end = anchor
            .end
            .checked_sub(DESCRIPTOR as u32)
            .ok_or_else(|| bad("JFS rename old checkpoint address"))?;
        let observed = le32(&logs, 32).to_le_bytes();
        let before_end = old_end.to_le_bytes();
        let after_end = newest_end.to_le_bytes();
        if !(if checkpointed {
            (0..=4).any(|cut| {
                observed[..cut] == after_end[..cut] && observed[cut..] == before_end[cut..]
            })
        } else {
            le32(&logs, 32) == old_end
        }) || !checkpointed && le32(&logs, 28) == 1 && committed
        {
            return Err(bad("JFS rename established old log end"));
        }
        let mut actual = [0; 512];
        source.exact(at, &mut actual)?;
        if checkpointed && committed && actual != after {
            return Err(bad("JFS rename checkpoint before complete home"));
        }
        if committed {
            if !(0..=512).any(|cut| actual[..cut] == after[..cut] && actual[cut..] == before[cut..])
            {
                return Err(bad("JFS rename non-prefix home mutation"));
            }
        } else if actual != before {
            return Err(bad("JFS uncommitted rename touched home"));
        }
        patches.push((at, super::super::super::copied(&before)?));
        let overlay = super::super::Overlay {
            source: super::super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &patches,
        };
        let baseline = super::super::super::decode(&overlay, read, r)?;
        if !crate::fs_jfs_audit::audit_decoded(&baseline, audit, r)?.is_clean() {
            return Err(bad("JFS rename saved namespace ownership"));
        }
        let node = baseline
            .nodes
            .get(&inode)
            .ok_or_else(|| bad("JFS rename native parent absent"))?;
        if !node.directory
            || !node.pages.is_empty()
            || pxd(&before, 16, length / 4096)?.start + u64::from((inode & 31) / 8)
                != physical.start
        {
            return Err(bad("JFS rename saved inode location/type"));
        }
        let mut after_patches = vector(4)?;
        for (at, data) in &patches[..3] {
            after_patches.push((*at, super::super::super::copied(data)?));
        }
        after_patches.push((at, super::super::super::copied(&after)?));
        let overlay = super::super::Overlay {
            source: super::super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &after_patches,
        };
        let resulting = super::super::super::decode(&overlay, read, r)?;
        if !crate::fs_jfs_audit::audit_decoded(&resulting, audit, r)?.is_clean() {
            return Err(bad("JFS rename resulting ownership"));
        }
        let changed = resulting
            .nodes
            .get(&inode)
            .ok_or_else(|| bad("JFS renamed parent absent"))?;
        if node.entries.len() != changed.entries.len() {
            return Err(bad("JFS rename entry count"));
        }
        let mut rename = None;
        for new_entry in &changed.entries {
            let old_entry = node
                .entries
                .iter()
                .find(|e| e.index == new_entry.index)
                .ok_or_else(|| bad("JFS rename cookie identity"))?;
            if old_entry.ino != new_entry.ino {
                return Err(bad("JFS rename inode identity"));
            }
            if old_entry.name != new_entry.name
                && rename.replace((&old_entry.name, &new_entry.name)).is_some()
            {
                return Err(bad("JFS rename changes multiple names"));
            }
        }
        let (old, new) = rename.ok_or_else(|| bad("JFS rename has no native name change"))?;
        let regenerated = super::namespace::rename_inline(&before, &node.entries, old, new, r)?;
        if regenerated != after {
            return Err(bad("JFS rename semantic afterimage mismatch"));
        }
        drop((baseline, resulting, after_patches));
        if committed && !checkpointed {
            home.push((at, super::super::super::copied(&after)?));
        }
    }
    drop((scanned, patches));
    if complete {
        original.cancellation.check()?;
        r.cancellation.check()?;
        source.length()?;
        return Ok(());
    }
    let page_at = (log.start + u64::from(number)) * 4096;
    let mut page = [0; PAGE];
    source.exact(page_at, &mut page)?;
    if repaired {
        let end = (newest_end % PAGE as u32) as u16;
        page[6..8].copy_from_slice(&end.to_le_bytes());
        page[TRAILER + 6..].copy_from_slice(&end.to_le_bytes());
    }
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    let end = if checkpointed {
        newest_end
    } else {
        append(&mut page, number, &d, &[])?
    };
    cleanlogs[32..36].copy_from_slice(&end.to_le_bytes());
    original.cancellation.check()?;
    r.cancellation.check()?;
    source.length()?;
    finish_metadata_recovery(
        storage,
        &home,
        RecoveryCleanup {
            page: (!checkpointed || repaired).then_some((page_at, page)),
            log_at,
            logs: cleanlogs,
            headers: projected,
            read,
            audit,
        },
        original,
        r,
    )
}
#[test]
fn rename_all_program_and_barrier_cuts_cold_recover_four_persistence_profiles() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    let make = |bytes: Vec<u8>| super::super::CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    let planning = |backend: &super::super::CowTestBackend| {
        prepare(backend, (5, &old, &new), (read, audit), &r, &r).unwrap()
    };
    let mut normal = make(seed.clone());
    let plan = planning(&normal);
    publish(&mut normal, plan, &r, &r).unwrap();
    let programs = normal.writes;
    let barriers = normal.flushes;
    for retain in [false, true] {
        for second_retain in [false, true] {
            for cut in 0..programs + barriers {
                let mut backend = make(seed.clone());
                let plan = planning(&backend);
                if cut < programs {
                    backend.fail_write = Some(cut + 1);
                } else {
                    backend.fail_flush = Some(cut - programs + 1);
                }
                assert_eq!(
                    publish(&mut backend, plan, &r, &r).unwrap_err().kind,
                    ErrorKind::UncertainDurability,
                    "publication cut={cut}"
                );
                let bytes = if retain {
                    backend.bytes
                } else {
                    backend.durable
                };
                let mut first = make(bytes);
                first.fail_write = Some(1);
                if let Err(error) = recover(&mut first, [0xa5; 16], (read, audit), &r, &r) {
                    assert_eq!(
                        error.kind,
                        ErrorKind::UncertainDurability,
                        "first recover cut={cut} retain={retain}: {error:?}"
                    );
                }
                let bytes = if second_retain {
                    first.bytes
                } else {
                    first.durable
                };
                let mut recovered = make(bytes);
                recover(&mut recovered, [0xa5; 16], (read, audit), &r, &r).unwrap_or_else(|e| {
                    panic!("cut={cut} retain={retain} second={second_retain}: {e:?}")
                });
                let tree = super::super::inspect(&recovered, read, audit, &r).unwrap();
                let names: &[_] = &tree.nodes[&5].entries;
                let inode_at = 29 * 4096 + 5 * 512;
                let expected_old = &seed[inode_at..inode_at + 512];
                let expected_new = &normal.bytes[inode_at..inode_at + 512];
                assert!(
                    tree.nodes[&5].raw == expected_old || tree.nodes[&5].raw == expected_new,
                    "whole namespace inode old/new projection"
                );
                let allowed = [
                    (32768 + 40, 4),
                    (32768 + 68, 4),
                    (61440 + 40, 4),
                    (61440 + 68, 4),
                    (inode_at, 512),
                    (483 * 4096 + 8, 4),
                    (483 * 4096 + 28, 8),
                    (483 * 4096 + 68, 16),
                    (484 * 4096, 4096),
                ];
                let mut previous = 0usize;
                for (at, len) in allowed {
                    assert_eq!(&recovered.bytes[previous..at], &seed[previous..at]);
                    previous = at + len;
                }
                assert_eq!(&recovered.bytes[previous..], &seed[previous..]);

                assert!(names.iter().any(|e| e.name == old) || names.iter().any(|e| e.name == new));
                assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
                assert_eq!(&recovered.bytes[112 * 4096..112 * 4096 + 7], b"nested!");
                drop(tree);
                let counts = (recovered.writes, recovered.flushes);
                recover(&mut recovered, [0xa5; 16], (read, audit), &r, &r).unwrap();
                assert_eq!((recovered.writes, recovered.flushes), counts);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    eprintln!(
        "rename publication programs={programs} barriers={barriers} four persistence combinations with interrupted recovery passed"
    );
}
#[test]
fn rename_every_recovery_program_and_barrier_restarts_under_four_persistence_profiles() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    let make = |bytes: Vec<u8>| super::super::CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    for committed in [false, true] {
        let mut source = make(seed.clone());
        let plan = prepare(&source, (5, &old, &new), (read, audit), &r, &r).unwrap();
        source.fail_flush = Some(if committed { 4 } else { 2 });
        assert_eq!(
            publish(&mut source, plan, &r, &r).unwrap_err().kind,
            ErrorKind::UncertainDurability
        );
        for initial_retained in [false, true] {
            let bytes = if initial_retained {
                source.bytes.clone()
            } else {
                source.durable.clone()
            };
            let mut reference = make(bytes.clone());
            recover(&mut reference, [0xa5; 16], (read, audit), &r, &r).unwrap();
            let programs = reference.writes;
            let barriers = reference.flushes;
            for retain in [false, true] {
                for second in [false, true] {
                    for cut in 0..programs + barriers {
                        let mut trial = make(bytes.clone());
                        if cut < programs {
                            trial.fail_write = Some(cut + 1);
                        } else {
                            trial.fail_flush = Some(cut - programs + 1);
                        }
                        assert_eq!(
                            recover(&mut trial, [0xa5; 16], (read, audit), &r, &r)
                                .unwrap_err()
                                .kind,
                            ErrorKind::UncertainDurability,
                            "first recovery cut={cut} committed={committed} initial={initial_retained}"
                        );
                        let bytes = if retain { trial.bytes } else { trial.durable };
                        let mut retry = make(bytes);
                        retry.fail_write = Some(1);
                        if let Err(e) = recover(&mut retry, [0xa5; 16], (read, audit), &r, &r) {
                            assert_eq!(
                                e.kind,
                                ErrorKind::UncertainDurability,
                                "second cut={cut} committed={committed}: {e:?}"
                            );
                        }
                        let bytes = if second { retry.bytes } else { retry.durable };
                        let mut final_state = make(bytes);
                        recover(&mut final_state,[0xa5;16],(read,audit),&r,&r).unwrap_or_else(|e|panic!("restart cut={cut} committed={committed} initial={initial_retained} retain={retain} second={second}: {e:?}"));
                        let tree = super::super::inspect(&final_state, read, audit, &r).unwrap();
                        assert_eq!(
                            tree.nodes[&5].raw,
                            reference.bytes[29 * 4096 + 5 * 512..29 * 4096 + 6 * 512]
                        );
                        assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
                        assert_eq!(&final_state.bytes[112 * 4096..112 * 4096 + 7], b"nested!");
                        drop(tree);
                        let counts = (final_state.writes, final_state.flushes);
                        recover(&mut final_state, [0xa5; 16], (read, audit), &r, &r).unwrap();
                        assert_eq!((final_state.writes, final_state.flushes), counts);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
            eprintln!(
                "rename recovery committed={committed} initial_retained={initial_retained} programs={programs} barriers={barriers} four persistence profiles passed"
            );
        }
    }
}
#[test]
fn native_valid_but_semantically_invalid_rename_records_refuse_all_mutation() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    let make = |bytes: Vec<u8>| super::super::CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut backend = make(seed.clone());
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    let plan = prepare(&backend, (5, &old, &new), (read, audit), &r, &r).unwrap();
    backend.fail_flush = Some(4);
    assert!(publish(&mut backend, plan, &r, &r).is_err());
    let committed = backend.durable;
    let source = super::super::Borrowed {
        storage: &make(committed.clone()),
        length: committed.len() as u64,
        resources: &r,
    };
    let log = crate::fs_jfs::Physical {
        start: 482,
        count: 30,
    };
    let history = history_framing(
        &source,
        log,
        HistoryLimits {
            pages: 256,
            records: 8,
            data: 2048,
            work: 64 << 20,
        },
        &r,
        true,
    )
    .unwrap();
    let address = |index: usize, body: bool| {
        484 * 4096 + (history.records[index].end % 4096) as usize
            - 36
            - if body {
                history.records[index].body.len()
            } else {
                0
            }
    };
    let negatives = [
        (address(1, true) + 38, 1u8),
        (address(2, true) + 44, 1),
        (address(2, true) + 224, 1),
        (address(4, true) + 44, 1),
        (address(1, false) + 4, 1),
        (address(1, false) + 16, 1),
        (address(1, false) + 20, 1),
        (address(1, false) + 32, 1),
        (address(2, true) + 258, 1),
        (address(0, false), 1),
    ];
    drop(history);
    for (at, mask) in negatives {
        let mut bad = make(committed.clone());
        bad.bytes[at] ^= mask;
        let before = bad.bytes.clone();
        let durable = bad.durable.clone();
        assert!(
            recover(&mut bad, [0xa5; 16], (read, audit), &r, &r).is_err(),
            "semantically invalid at={at}"
        );
        assert_eq!((bad.writes, bad.flushes), (0, 0));
        assert_eq!(bad.bytes, before);
        assert_eq!(bad.durable, durable);
        assert_eq!(r.memory.used(), 0);
    }
    let healthy = make(seed);
    let tree = super::super::inspect(&healthy, read, audit, &r).unwrap();
    let mut used: Vec<usize> = tree
        .bitmap
        .iter()
        .enumerate()
        .filter_map(|(i, b)| (*b).then_some(i))
        .collect();
    drop(tree);
    used.push(200);
    let mut lost = make(committed);
    super::super::fixture::rebuild_map(&mut lost.bytes, &used);
    let before = lost.bytes.clone();
    assert!(recover(&mut lost, [0xa5; 16], (read, audit), &r, &r).is_err());
    assert_eq!((lost.writes, lost.flushes), (0, 0));
    assert_eq!(lost.bytes, before);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn rename_caps_cancellation_causal_read_errors_and_stale_native_bytes_are_prewrite() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    let make = |bytes: Vec<u8>| super::super::CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    let mut backend = make(seed.clone());
    for bad in [&old[..], &[47][..], &[46, 46][..], &[0x61; 255][..]] {
        assert!(prepare(&backend, (5, &old, bad), (read, audit), &r, &r).is_err());
        assert_eq!((backend.writes, backend.flushes), (0, 0));
        assert_eq!(r.memory.used(), 0);
    }
    let mut capped = read;
    capped.pages = 0;
    assert!(prepare(&backend, (5, &old, &new), (capped, audit), &r, &r).is_err());
    assert_eq!((backend.writes, backend.flushes), (0, 0));
    assert_eq!(r.memory.used(), 0);
    for cancelled in [false, true] {
        let phase = Resources {
            memory: Budget::new(if cancelled { 32 << 20 } else { 0 }),
            cancellation: Cancellation::default(),
        };
        if cancelled {
            phase.cancellation.cancel();
        }
        let plan = prepare(&backend, (5, &old, &new), (read, audit), &r, &r).unwrap();
        assert_eq!(
            publish(&mut backend, plan, &r, &phase).unwrap_err().kind,
            if cancelled {
                ErrorKind::Cancelled
            } else {
                ErrorKind::BudgetExhausted
            }
        );
        assert_eq!((backend.writes, backend.flushes), (0, 0));
        assert_eq!(r.memory.used(), 0);
    }
    let plan = prepare(&backend, (5, &old, &new), (read, audit), &r, &r).unwrap();
    backend.bytes[29 * 4096 + 5 * 512 + 44] ^= 1;
    assert_eq!(
        publish(&mut backend, plan, &r, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!((backend.writes, backend.flushes), (0, 0));
    assert_eq!(r.memory.used(), 0);
    struct Reads {
        inner: super::super::CowTestBackend,
    }
    impl crate::storage::Storage for Reads {
        fn len(&self) -> std::io::Result<u64> {
            crate::storage::Storage::len(&self.inner)
        }
        fn read_exact_at(&self, at: u64, b: &mut [u8]) -> std::io::Result<()> {
            if at == 32768 {
                return Err(std::io::Error::other(
                    "namespace causal metadata interruption",
                ));
            }
            crate::storage::Storage::read_exact_at(&self.inner, at, b)
        }
        fn write_at(&mut self, at: u64, b: &[u8]) -> std::io::Result<usize> {
            crate::storage::Storage::write_at(&mut self.inner, at, b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            crate::storage::Storage::flush(&mut self.inner)
        }
    }
    let mut broken = Reads { inner: make(seed) };
    let err = prepare(&broken, (5, &old, &new), (read, audit), &r, &r)
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Io);
    assert!(format!("{err:?}").contains("namespace causal metadata interruption"));
    assert_eq!((broken.inner.writes, broken.inner.flushes), (0, 0));
    assert_eq!(r.memory.used(), 0);
    let err = recover(&mut broken, [0xa5; 16], (read, audit), &r, &r).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Io);
    assert!(format!("{err:?}").contains("namespace causal metadata interruption"));
    assert_eq!((broken.inner.writes, broken.inner.flushes), (0, 0));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn owned_rename_session_stays_uncertain_through_cancelled_recovery_and_blocks_fresh_operations() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    let mut backend = super::super::CowTestBackend {
        durable: seed.clone(),
        bytes: seed,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: Some(4),
    };
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    let mut session = super::super::NativeSession::open(&mut backend, read, audit, &r).unwrap();
    assert_eq!(
        session
            .rename_inline_entry(5, &old, &new, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    assert!(session.uncertain);
    assert!(session.rename_pending);
    assert_eq!(
        session
            .rename_inline_entry(5, &old, &new, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    let cancelled = Resources {
        memory: r.memory.clone(),
        cancellation: Cancellation::default(),
    };
    cancelled.cancellation.cancel();
    assert_eq!(
        session.recover(&cancelled).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert!(session.uncertain);
    assert!(session.rename_pending);
    session.recover(&r).unwrap();
    assert!(!session.uncertain);
    assert!(!session.rename_pending);
    session.rename_inline_entry(5, &new, &old, &r).unwrap();
    drop(session);
    let tree = super::super::inspect(&backend, read, audit, &r).unwrap();
    assert_eq!(tree.nodes[&5].entries[0].name, old);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn rename_native_checkpoint_log_end_word_torn_at_each_byte_recovers_without_guessing_home() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut seed = super::super::journal_seed();
    super::super::fixture::small_hardlink(&mut seed);
    struct EndWord {
        inner: super::super::CowTestBackend,
        cut: Option<usize>,
    }
    impl crate::storage::Storage for EndWord {
        fn len(&self) -> std::io::Result<u64> {
            crate::storage::Storage::len(&self.inner)
        }
        fn read_exact_at(&self, at: u64, b: &mut [u8]) -> std::io::Result<()> {
            crate::storage::Storage::read_exact_at(&self.inner, at, b)
        }
        fn write_at(&mut self, at: u64, b: &[u8]) -> std::io::Result<usize> {
            if at == 483 * 4096
                && b.get(28) == Some(&1)
                && let Some(cut) = self.cut.take()
            {
                self.inner.writes += 1;
                self.inner.bytes[at as usize..at as usize + cut].copy_from_slice(&b[..cut]);
                return Err(std::io::Error::other("native log-end word interrupted"));
            }
            crate::storage::Storage::write_at(&mut self.inner, at, b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            crate::storage::Storage::flush(&mut self.inner)
        }
    }
    let old: Vec<_> = "Child".encode_utf16().collect();
    let new: Vec<_> = "z-long-native-name".encode_utf16().collect();
    for cut in 32..=36 {
        for retain in [false, true] {
            let inner = super::super::CowTestBackend {
                durable: seed.clone(),
                bytes: seed.clone(),
                writes: 0,
                flushes: 0,
                fail_write: None,
                fail_flush: None,
            };
            let mut backend = EndWord {
                inner,
                cut: Some(cut),
            };
            let plan = prepare(&backend, (5, &old, &new), (read, audit), &r, &r).unwrap();
            assert_eq!(
                publish(&mut backend, plan, &r, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            let bytes = if retain {
                backend.inner.bytes
            } else {
                backend.inner.durable
            };
            let mut recovered = super::super::CowTestBackend {
                durable: bytes.clone(),
                bytes,
                writes: 0,
                flushes: 0,
                fail_write: None,
                fail_flush: None,
            };
            recover(&mut recovered, [0xa5; 16], (read, audit), &r, &r)
                .unwrap_or_else(|e| panic!("log end cut={cut} retain={retain}: {e:?}"));
            let tree = super::super::inspect(&recovered, read, audit, &r).unwrap();
            assert_eq!(tree.nodes[&5].entries[1].name, new);
            drop(tree);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
