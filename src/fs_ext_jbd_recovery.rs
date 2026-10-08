//! Native redo checkpointing after complete preparation and ownership preflight.
//! Private staging only; this is not a public editor or recovery capability.
use super::*;
use crate::{fs_ext_audit::ExtAuditLimits, storage::Storage};

pub(crate) struct Outcome {
    pub(crate) transactions: usize,
    pub(crate) blocks: usize,
    pub(crate) next_sequence: u32,
}

pub(crate) fn recover(
    storage: &mut dyn Storage,
    scope: u128,
    limits: ExtAuditLimits,
    maximum_records: usize,
    resources: &Resources,
) -> io::Result<Outcome> {
    // A clean inactive journal has no published recovery work. This also covers
    // interruptions while descriptor/data blocks were being prepared privately,
    // before their preparation commit or journal activation became durable.
    if let Ok((decoder, proof)) =
        super::super::ExtDecoder::open_native_clean(storage, scope, resources)
    {
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, resources)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(invalid("JBD2 recovery clean-state ownership audit"));
        }
        return Ok(Outcome {
            transactions: 0,
            blocks: 0,
            next_sequence: proof.geometry.sequence,
        });
    }
    let length = storage.len()?;
    let bootstrap = bootstrap::Bootstrap::read(storage, 65536, limits.work, resources)?;
    let mut geometry = bootstrap.geometry;
    let mut first = [0; MAX_BLOCK];
    storage.read_exact_at(
        bootstrap.physical(geometry.first)?,
        &mut first[..geometry.block_bytes],
    )?;
    // The current sequence/start/CRC can be torn publication bytes. The complete
    // preparation validates the original sequence and all native static fields.
    geometry.sequence = be32(&first, 8);
    geometry.start = geometry.first;
    let preparation = preparation(&geometry, resources, |logical, bytes| {
        storage.read_exact_at(bootstrap.physical(logical)?, bytes)
    })?;
    let replay = scan(
        &geometry,
        maximum_records,
        limits.work,
        resources,
        |logical, bytes| storage.read_exact_at(bootstrap.physical(logical)?, bytes),
        |physical| bootstrap.destination(physical),
    )?;
    if replay.committed_transactions == 0 {
        return Err(invalid("JBD2 recovery lacks committed preparation"));
    }
    bootstrap.validate_preparation(&preparation, replay.next_sequence)?;
    if bootstrap.journal == preparation.journal_superblock
        && super::super::u32le(&bootstrap.primary, 96) & 4 == 0
    {
        // Durable log records without journal activation are unpublished work.
        // A clean same-owner audit proves the unchanged home state; stale hidden
        // records must never turn that state into a committed mutation.
        let (decoder, _) = super::super::ExtDecoder::open_native_clean(storage, scope, resources)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, resources)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(invalid("JBD2 unpublished preparation home audit"));
        }
        return Ok(Outcome {
            transactions: 0,
            blocks: 0,
            next_sequence: geometry.sequence,
        });
    }
    let (_, audit) = overlay::Overlay::new(
        storage,
        &replay.blocks,
        geometry.block_bytes,
        Some(overlay::JournalControl {
            physical: bootstrap.physical(0)?,
            original: preparation.journal_superblock,
            geometry,
            next_sequence: replay.next_sequence,
        }),
        resources,
    )?
    .verify(scope, limits, Some(&bootstrap))?;
    drop(audit);
    let primary_block = u32::from(geometry.block_bytes == 1024);
    let fence = replay
        .blocks
        .iter()
        .find(|r| r.destination == primary_block)
        .ok_or_else(|| invalid("native recovery missing dirty superblock redo"))?;
    let inside = if geometry.block_bytes == 1024 {
        0
    } else {
        1024
    };
    if super::super::u32le(&fence.bytes, inside + 96) & 4 == 0 {
        return Err(invalid(
            "native recovery clears fence before complete checkpoint",
        ));
    }
    // No writes occur above this point. The borrowed exclusive Storage remains
    // the same capability throughout preflight, checkpoint and readback.
    let write = |storage: &mut dyn Storage, offset: u64, bytes: &[u8]| -> io::Result<()> {
        let mut done = 0;
        while done < bytes.len() {
            resources.cancellation.check().map_err(io::Error::other)?;
            if storage.len()? != length {
                return Err(io::Error::other(Error::new(
                    ErrorKind::StalePlan,
                    "JBD2 recovery source length changed",
                )));
            }
            let count = storage.write_at(offset + done as u64, &bytes[done..])?;
            if count == 0 || count > bytes.len() - done {
                return Err(io::ErrorKind::WriteZero.into());
            }
            done += count;
        }
        Ok(())
    };
    let verify = |storage: &dyn Storage, offset: u64, expected: &[u8]| -> io::Result<()> {
        resources.cancellation.check().map_err(io::Error::other)?;
        if storage.len()? != length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "JBD2 recovery source length changed",
            )));
        }
        let mut found = [0; MAX_BLOCK];
        storage.read_exact_at(offset, &mut found[..expected.len()])?;
        if found[..expected.len()] != *expected {
            return Err(invalid("JBD2 recovery durable readback"));
        }
        Ok(())
    };
    for record in &replay.blocks {
        write(
            storage,
            u64::from(record.destination) * geometry.block_bytes as u64,
            &record.bytes[..geometry.block_bytes],
        )?;
    }
    resources.cancellation.check().map_err(io::Error::other)?;
    storage.flush()?;
    for record in &replay.blocks {
        verify(
            storage,
            u64::from(record.destination) * geometry.block_bytes as u64,
            &record.bytes[..geometry.block_bytes],
        )?;
    }
    let mut journal = preparation.journal_superblock;
    put32(&mut journal, 24, replay.next_sequence);
    put32(&mut journal, 252, 0);
    let checksum = crc32c(!0, &journal);
    put32(&mut journal, 252, checksum);
    write(storage, bootstrap.physical(0)?, &journal)?;
    resources.cancellation.check().map_err(io::Error::other)?;
    storage.flush()?;
    verify(storage, bootstrap.physical(0)?, &journal)?;
    let mut primary = [0; 1024];
    storage.read_exact_at(1024, &mut primary)?;
    let features = super::super::u32le(&primary, 96) & !4;
    primary[96..100].copy_from_slice(&features.to_le_bytes());
    if super::super::u32le(&primary, 100) & 0x400 != 0 {
        let checksum = crc32c(!0, &primary[..1020]);
        primary[1020..].copy_from_slice(&checksum.to_le_bytes());
    }
    write(storage, 1024, &primary)?;
    resources.cancellation.check().map_err(io::Error::other)?;
    storage.flush()?;
    verify(storage, 1024, &primary)?;
    let (decoder, proof) = super::super::ExtDecoder::open_native_clean(storage, scope, resources)?;
    let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, resources)
        .map_err(io::Error::other)?;
    if !audit.is_clean() || proof.geometry.sequence != replay.next_sequence {
        return Err(invalid("JBD2 recovery final native state/audit"));
    }
    Ok(Outcome {
        transactions: replay.committed_transactions,
        blocks: replay.blocks.len(),
        next_sequence: replay.next_sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    struct Fault {
        visible: Vec<u8>,
        durable: Vec<u8>,
        events: usize,
        cut: usize,
        immediate: bool,
        failed_flush_persists: bool,
        torn: bool,
    }
    impl Storage for Fault {
        fn len(&self) -> io::Result<u64> {
            Ok(self.visible.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(
                self.visible
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.events += 1;
            let fail = self.events == self.cut;
            let count = if fail {
                if self.torn { bytes.len() / 2 } else { 0 }
            } else {
                bytes.len()
            };
            let at = at as usize;
            self.visible[at..at + count].copy_from_slice(&bytes[..count]);
            if self.immediate {
                self.durable[at..at + count].copy_from_slice(&bytes[..count]);
            }
            if fail {
                return Err(io::Error::other("injected write cut"));
            }
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.events += 1;
            let fail = self.events == self.cut;
            if !fail || self.failed_flush_persists {
                self.durable.clone_from(&self.visible);
            }
            if fail {
                return Err(io::Error::other("injected barrier cut"));
            }
            Ok(())
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> ExtAuditLimits {
        ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        }
    }
    fn fixture(r: &Resources) -> Vec<u8> {
        let mut image = bootstrap::tests::fixture().0;
        let source = bootstrap::tests::Owned(image.clone());
        let boot = bootstrap::Bootstrap::read(&source, 1024, 100000, r).unwrap();
        let mut geometry = boot.geometry;
        geometry.start = geometry.first;
        let prepared = prepare(&geometry, &image[1024..2048], &boot.journal, r).unwrap();
        for record in &prepared.blocks {
            let at = boot.physical(record.logical).unwrap() as usize;
            image[at..at + 1024].copy_from_slice(&record.bytes[..1024]);
        }
        geometry.start = prepared.next_logical;
        geometry.sequence = geometry.sequence.wrapping_add(1);
        let mut changed = [0; MAX_BLOCK];
        changed[..1024].copy_from_slice(&prepared.blocks[1].bytes[..1024]);
        changed[48..52].copy_from_slice(&123456789u32.to_le_bytes());
        let encoded = encode(
            &geometry,
            &[ReplayBlock {
                destination: 1,
                bytes: changed,
            }],
            100000,
            r,
            |physical| boot.destination(physical),
        )
        .unwrap();
        for record in &encoded.blocks {
            let at = boot.physical(record.logical).unwrap() as usize;
            image[at..at + 1024].copy_from_slice(&record.bytes[..1024]);
        }
        let mut header = boot.journal;
        put32(&mut header, 28, boot.geometry.first);
        put32(&mut header, 252, 0);
        let checksum = crc32c(!0, &header);
        put32(&mut header, 252, checksum);
        image[100 * 1024..101 * 1024].copy_from_slice(&header);
        image[1024..2048].copy_from_slice(&prepared.blocks[1].bytes[..1024]);
        image
    }
    #[test]
    fn complete_native_recovery_restart_every_write_barrier_torn_cut_and_refunds() {
        let r = resources();
        let image = fixture(&r);
        assert_eq!(r.memory.used(), 0);
        let make = |immediate, failed_flush_persists, torn, cut| Fault {
            visible: image.clone(),
            durable: image.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let mut success = make(true, true, false, usize::MAX);
        let outcome = recover(&mut success, 18u128 << 64, limits(), 8, &r).unwrap();
        assert_eq!(outcome.transactions, 2);
        assert_eq!(outcome.blocks, 1);
        assert_eq!(outcome.next_sequence, 39);
        assert_eq!(
            &success.visible[1024 + 48..1024 + 52],
            &123456789u32.to_le_bytes()
        );
        let events = success.events;
        assert_eq!(events, 6);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut failed = make(immediate, failed_flush_persists, torn, cut);
                        assert!(recover(&mut failed, 18u128 << 64, limits(), 8, &r).is_err());
                        assert_eq!(r.memory.used(), 0);
                        failed.visible.clone_from(&failed.durable);
                        failed.cut = usize::MAX;
                        recover(&mut failed, 18u128 << 64, limits(), 8, &r).unwrap();
                        assert_eq!(
                            failed.durable, success.durable,
                            "cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
        // A static journal change fails complete preflight without any mutation.
        let mut malformed = make(true, true, false, usize::MAX);
        malformed.visible[100 * 1024 + 256] ^= 1;
        let before = malformed.visible.clone();
        assert!(recover(&mut malformed, 18u128 << 64, limits(), 8, &r).is_err());
        assert_eq!(malformed.events, 0);
        assert_eq!(malformed.visible, before);
        assert_eq!(r.memory.used(), 0);
        let mut unpublished = make(true, true, false, usize::MAX);
        let bootstrap = bootstrap::Bootstrap::read(&unpublished, 1024, 100000, &r).unwrap();
        let capsule = preparation(&bootstrap.geometry, &r, |logical, bytes| {
            unpublished.read_exact_at(bootstrap.physical(logical)?, bytes)
        })
        .unwrap();
        unpublished.visible[100 * 1024..101 * 1024].copy_from_slice(&capsule.journal_superblock);
        unpublished.visible[1024 + 96..1024 + 100].copy_from_slice(&2u32.to_le_bytes());
        drop((bootstrap, capsule));
        let before = unpublished.visible.clone();
        let outcome = recover(&mut unpublished, 18u128 << 64, limits(), 8, &r).unwrap();
        assert_eq!(outcome.transactions, 0);
        assert_eq!(unpublished.events, 0);
        assert_eq!(unpublished.visible, before);
        assert_eq!(r.memory.used(), 0);
        let mut cancelled = make(true, true, false, usize::MAX);
        r.cancellation.cancel();
        assert!(recover(&mut cancelled, 18u128 << 64, limits(), 8, &r).is_err());
        assert_eq!(cancelled.events, 0);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn complete_native_publication_lifecycle_every_write_barrier_cut_old_or_new() {
        let r = resources();
        let image = bootstrap::tests::fixture().0;
        let mut changed = [0; MAX_BLOCK];
        changed[..1024].copy_from_slice(&image[1024..2048]);
        changed[48..52].copy_from_slice(&123456789u32.to_le_bytes());
        changed[96..100].copy_from_slice(&6u32.to_le_bytes());
        let records = [ReplayBlock {
            destination: 1,
            bytes: changed,
        }];
        let make = |immediate, failed_flush_persists, torn, cut| Fault {
            visible: image.clone(),
            durable: image.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let mut success = make(true, true, false, usize::MAX);
        let mut invalid_fence = changed;
        invalid_fence[96..100].copy_from_slice(&2u32.to_le_bytes());
        let mut rejected = make(true, true, false, usize::MAX);
        assert!(
            transaction::commit(
                &mut rejected,
                18u128 << 64,
                limits(),
                8,
                32 * 1024,
                &[ReplayBlock {
                    destination: 1,
                    bytes: invalid_fence
                }],
                &r
            )
            .is_err()
        );
        assert_eq!(rejected.events, 0);
        assert_eq!(rejected.visible, image);
        assert_eq!(r.memory.used(), 0);
        let outcome = transaction::commit(
            &mut success,
            18u128 << 64,
            limits(),
            8,
            32 * 1024,
            &records,
            &r,
        )
        .unwrap();
        assert_eq!(outcome.transactions, 2);
        let events = success.events;
        assert_eq!(events, 24);
        assert_eq!(r.memory.used(), 0);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut failed = make(immediate, failed_flush_persists, torn, cut);
                        assert!(
                            transaction::commit(
                                &mut failed,
                                18u128 << 64,
                                limits(),
                                8,
                                32 * 1024,
                                &records,
                                &r
                            )
                            .is_err()
                        );
                        assert_eq!(r.memory.used(), 0);
                        failed.visible.clone_from(&failed.durable);
                        failed.cut = usize::MAX;
                        recover(&mut failed, 18u128 << 64, limits(), 8, &r).unwrap();
                        let timestamp = u32::from_le_bytes(
                            failed.durable[1024 + 48..1024 + 52].try_into().unwrap(),
                        );
                        assert!(
                            timestamp == 0 || timestamp == 123456789,
                            "cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        // All home bytes except the declared timestamp/RECOVER
                        // controls remain exact, including bitmap/inode metadata.
                        for (at, byte) in image.iter().enumerate() {
                            if (1024 + 48..1024 + 52).contains(&at)
                                || (100 * 1024..1124 * 1024).contains(&at)
                            {
                                continue;
                            }
                            assert_eq!(
                                failed.durable[at], *byte,
                                "outside home change at={at} cut={cut}"
                            );
                        }
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}
