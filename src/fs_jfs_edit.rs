//! Staged exclusive native-journal editor bootstrap; no public mutation API yet.
use super::*;
use crate::{
    fs_jfs_audit::{JfsAuditLimits, audit_decoded},
    storage::Storage,
};

struct CowTestBackend {
    bytes: Vec<u8>,
    writes: usize,
    durable: Vec<u8>,
    flushes: usize,
    fail_write: Option<usize>,
    fail_flush: Option<usize>,
}
impl Storage for CowTestBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let n = bytes.len().min(71);
        if self.fail_write == Some(self.writes) {
            let partial = n / 2;
            self.bytes[at as usize..at as usize + partial].copy_from_slice(&bytes[..partial]);
            return Err(io::Error::other("three-block partial program"));
        }
        self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush == Some(self.flushes) {
            return Err(io::Error::other("three-block flush interruption"));
        }
        self.durable.clone_from(&self.bytes);
        Ok(())
    }
}
struct CowTestPayload {
    id: ObjectId,
    fail_second: bool,
    size: u64,
}
impl FileRead for CowTestPayload {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        if self.fail_second && at >= 4096 {
            return Err(Error::io(
                "deferred second-block model",
                io::Error::other("source interruption"),
            ));
        }
        if at >= self.len() {
            return Ok(0);
        }
        let n = out.len().min((self.len() - at) as usize).min(113);
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = ((at + i as u64) * 31 % 251) as u8;
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, "test payload only"))
    }
}
#[test]
fn bounded_recorded_run_cow_streams_multiple_blocks_and_preserves_hardlinks() {
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
    let mut bytes = journal_seed();
    fixture::small_hardlink(&mut bytes);
    let inode = 29 * fixture::BLOCK + 6 * 512;
    fixture::p64(&mut bytes, inode + 24, 9000);
    fixture::p64(&mut bytes, inode + 32, 3);
    bytes[inode + 224..inode + 512].copy_from_slice(&fixture::xt(&[(0, 112, 3, 0)], false, None));
    let mut used: Vec<_> = (0..22).chain(23..35).collect();
    used.extend([90, 100, 102, 110, 112, 113, 114]);
    fixture::rebuild_map(&mut bytes, &used);
    bytes[112 * 4096..115 * 4096].fill(0xa7);
    let seed = bytes.clone();
    let mut storage = CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![2],
        },
        fail_second: false,
        size: 9000,
    });
    let plan = journal::prepare_cow(
        &storage,
        journal::CowRequest {
            inode: 6,
            new: 120,
            file: source,
        },
        read,
        audit,
        &r,
        &r,
    )
    .unwrap();
    assert_eq!(storage.writes, 0);
    journal::publish_cow(&mut storage, plan, &r, &r).unwrap();
    let publication_writes = storage.writes;
    let publication_flushes = storage.flushes;
    let decoded = inspect(&storage, read, audit, &r).unwrap();
    let node = &decoded.nodes[&6];
    assert_eq!(node.length, 9000);
    assert_eq!(node.runs[0].physical.start, 120);
    assert_eq!(node.runs[0].physical.count, 3);
    assert_eq!(le32(&node.raw, 40), 2);
    for block in 112..115 {
        assert!(!decoded.bitmap[block]);
    }
    for block in 120..123 {
        assert!(decoded.bitmap[block]);
    }
    for (i, byte) in storage.bytes[120 * 4096..120 * 4096 + 9000]
        .iter()
        .enumerate()
    {
        assert_eq!(*byte, (i as u64 * 31 % 251) as u8);
    }
    assert!(
        storage.bytes[120 * 4096 + 9000..123 * 4096]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        storage.bytes[112 * 4096..115 * 4096]
            .iter()
            .all(|byte| *byte == 0xa7)
    );
    drop(decoded);
    storage.writes = 0;
    journal::recover_cow(&mut storage, [0xa5; 16], read, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
    let before = storage.bytes.clone();
    let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![3],
        },
        fail_second: true,
        size: 9000,
    });
    let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
    let error = session.replace_recorded_run(6, 130, file, &r).unwrap_err();
    assert!(session.uncertain && session.cow_pending);
    assert_eq!(
        session.write_uid(4, 777, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    let blocked: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![4],
        },
        fail_second: false,
        size: 9000,
    });
    assert_eq!(
        session
            .replace_recorded_run(6, 140, blocked, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    session.recover(&r).unwrap();
    assert!(!session.uncertain && !session.cow_pending);
    drop(session);
    assert_eq!(error.kind, ErrorKind::UncertainDurability);
    assert!(error.context.contains("deferred second-block model"));
    assert!(storage.writes > 0);
    assert_eq!(storage.writes, 4096usize.div_ceil(71));
    assert_eq!(&storage.bytes[..130 * 4096], &before[..130 * 4096]);
    assert_eq!(&storage.bytes[131 * 4096..], &before[131 * 4096..]);
    let decoded = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].runs[0].physical.start, 120);
    assert!(!decoded.bitmap[130]);
    drop(decoded);
    storage.writes = 0;
    journal::recover_cow(&mut storage, [0xa5; 16], read, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
    for (write_cut, cut) in (1..=publication_writes)
        .map(|cut| (true, cut))
        .chain((1..=publication_flushes).map(|cut| (false, cut)))
    {
        for first_retained in [false, true] {
            for recovery_retained in [false, true] {
                let mut trial = CowTestBackend {
                    bytes: seed.clone(),
                    durable: seed.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_write: write_cut.then_some(cut),
                    fail_flush: (!write_cut).then_some(cut),
                };
                let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
                    id: ObjectId {
                        source: 123,
                        generation: 0,
                        native: vec![2],
                    },
                    fail_second: false,
                    size: 9000,
                });
                let plan = journal::prepare_cow(
                    &trial,
                    journal::CowRequest {
                        inode: 6,
                        new: 120,
                        file,
                    },
                    read,
                    audit,
                    &r,
                    &r,
                )
                .unwrap();
                assert_eq!(
                    journal::publish_cow(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let committed = if write_cut {
                    trial.flushes >= 8
                } else {
                    // A failed COMMIT flush retained by the first restart is
                    // still volatile. The first recovery program fails before
                    // any recovery flush; a second discard loses that COMMIT.
                    cut > 8 || cut == 8 && first_retained && recovery_retained
                };
                if !first_retained {
                    trial.bytes.clone_from(&trial.durable);
                }
                trial.writes = 0;
                trial.flushes = 0;
                trial.fail_flush = None;
                trial.fail_write = Some(1);
                let first = journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r);
                if let Err(error) = first {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                if !recovery_retained {
                    trial.bytes.clone_from(&trial.durable);
                }
                trial.fail_write = None;
                journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                let decoded = inspect(&trial, read, audit, &r).unwrap();
                assert_eq!(
                    decoded.nodes[&6].runs[0].physical.start,
                    if committed { 120 } else { 112 },
                    "cut={cut} write={write_cut} first={first_retained} recovery={recovery_retained}"
                );
                assert_eq!(decoded.nodes[&6].runs[0].physical.count, 3);
                assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
                for old in 112..115 {
                    assert_eq!(decoded.bitmap[old], !committed);
                }
                for new in 120..123 {
                    assert_eq!(decoded.bitmap[new], committed);
                }
                drop(decoded);
                if committed {
                    for (i, byte) in trial.bytes[120 * 4096..120 * 4096 + 9000]
                        .iter()
                        .enumerate()
                    {
                        assert_eq!(*byte, (i * 31 % 251) as u8);
                    }
                    assert!(
                        trial.bytes[120 * 4096 + 9000..123 * 4096]
                            .iter()
                            .all(|byte| *byte == 0)
                    );
                } else {
                    assert!(
                        trial.bytes[112 * 4096..115 * 4096]
                            .iter()
                            .all(|byte| *byte == 0xa7)
                    );
                }
                trial.writes = 0;
                journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                assert_eq!(trial.writes, 0);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    eprintln!(
        "three-block COW: {publication_writes} partial-program and {publication_flushes} barrier cuts x4 persistence histories, recovery interrupted at its first program"
    );
    // Size-changing INODE and ROOT records must survive the same two-restart
    // persistence extremes as the established length-preserving transaction.
    for size in [7u64, 4200] {
        let make_file = || -> Arc<dyn FileRead> {
            Arc::new(CowTestPayload {
                id: ObjectId {
                    source: 123,
                    generation: 0,
                    native: vec![9],
                },
                fail_second: false,
                size,
            })
        };
        let backend = || CowTestBackend {
            bytes: seed.clone(),
            durable: seed.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        let mut complete = backend();
        let plan = journal::prepare_cow_resized(
            &complete,
            journal::CowRequest {
                inode: 6,
                new: 160,
                file: make_file(),
            },
            read,
            audit,
            &r,
            &r,
        )
        .unwrap();
        journal::publish_cow(&mut complete, plan, &r, &r).unwrap();
        let commit_flush = size.div_ceil(4096) as usize + 5;
        let mut committed_fixture = backend();
        committed_fixture.fail_flush = Some(commit_flush);
        let plan = journal::prepare_cow_resized(
            &committed_fixture,
            journal::CowRequest {
                inode: 6,
                new: 160,
                file: make_file(),
            },
            read,
            audit,
            &r,
            &r,
        )
        .unwrap();
        assert_eq!(
            journal::publish_cow(&mut committed_fixture, plan, &r, &r)
                .unwrap_err()
                .kind,
            ErrorKind::UncertainDurability
        );
        let committed_bytes = committed_fixture.bytes;
        let log_page = 484 * 4096;
        let end = log_page + usize::from(le16(&committed_bytes, log_page + 6));
        let commit_descriptor = end - 36;
        let free_end = log_page + le32(&committed_bytes, commit_descriptor + 4) as usize % 4096;
        let free_descriptor = free_end - 36;
        let root_end = log_page + le32(&committed_bytes, free_descriptor + 4) as usize % 4096;
        let root_descriptor = root_end - 36;
        let inode_end = log_page + le32(&committed_bytes, root_descriptor + 4) as usize % 4096;
        let inode_descriptor = inode_end - 36;
        let inode_body =
            inode_descriptor - usize::from(le16(&committed_bytes, inode_descriptor + 10));
        for (at, mask) in [
            (inode_body + 31, 0x80),   // impossible EOF for declared fresh run
            (inode_body + 32, 8),      // native allocated-block agreement
            (inode_body + 48, 1),      // unrelated metadata cannot change
            (inode_body + 130, 2),     // INODE vector must cover exactly one slot
            (inode_descriptor + 4, 1), // unexpected transaction backchain
            (20 * 4096 + 33, 0x80),    // unauthorized allocation metadata
        ] {
            let mut negative = backend();
            negative.bytes.clone_from(&committed_bytes);
            negative.bytes[at] ^= mask;
            let before = negative.bytes.clone();
            let durable_before = negative.durable.clone();
            assert!(journal::recover_cow(&mut negative, [0xa5; 16], read, audit, &r, &r).is_err());
            assert_eq!(negative.writes, 0);
            assert_eq!(negative.flushes, 0);
            assert_eq!(negative.bytes, before);
            assert_eq!(negative.durable, durable_before);
            assert_eq!(r.memory.used(), 0);
        }
        for (write_cut, cut) in (1..=complete.writes)
            .map(|cut| (true, cut))
            .chain((1..=complete.flushes).map(|cut| (false, cut)))
        {
            for first_retained in [false, true] {
                for recovery_retained in [false, true] {
                    let mut trial = backend();
                    trial.fail_write = write_cut.then_some(cut);
                    trial.fail_flush = (!write_cut).then_some(cut);
                    let plan = journal::prepare_cow_resized(
                        &trial,
                        journal::CowRequest {
                            inode: 6,
                            new: 160,
                            file: make_file(),
                        },
                        read,
                        audit,
                        &r,
                        &r,
                    )
                    .unwrap();
                    assert_eq!(
                        journal::publish_cow(&mut trial, plan, &r, &r)
                            .unwrap_err()
                            .kind,
                        ErrorKind::UncertainDurability
                    );
                    let committed = if write_cut {
                        trial.flushes >= commit_flush
                    } else {
                        cut > commit_flush
                            || cut == commit_flush && first_retained && recovery_retained
                    };
                    if !first_retained {
                        trial.bytes.clone_from(&trial.durable);
                    }
                    trial.writes = 0;
                    trial.flushes = 0;
                    trial.fail_flush = None;
                    trial.fail_write = Some(1);
                    if let Err(error) =
                        journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r)
                    {
                        assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    }
                    if !recovery_retained {
                        trial.bytes.clone_from(&trial.durable);
                    }
                    trial.fail_write = None;
                    journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                    let decoded = inspect(&trial, read, audit, &r).unwrap();
                    let node = &decoded.nodes[&6];
                    assert_eq!(
                        node.length,
                        if committed { size } else { 9000 },
                        "resize={size} cut={cut} write={write_cut} first={first_retained} recovery={recovery_retained}"
                    );
                    assert_eq!(
                        node.runs[0].physical.start,
                        if committed { 160 } else { 112 }
                    );
                    assert_eq!(
                        super::le64(&node.raw, 32),
                        if committed { size.div_ceil(4096) } else { 3 }
                    );
                    assert_eq!(le32(&node.raw, 40), 2);
                    drop(decoded);
                    assert!(
                        trial.bytes[112 * 4096..115 * 4096]
                            .iter()
                            .all(|byte| *byte == 0xa7)
                    );
                    if committed {
                        for (i, byte) in trial.bytes[160 * 4096..160 * 4096 + size as usize]
                            .iter()
                            .enumerate()
                        {
                            assert_eq!(*byte, (i * 31 % 251) as u8);
                        }
                        assert!(
                            trial.bytes[160 * 4096 + size as usize
                                ..(160 + size.div_ceil(4096)) as usize * 4096]
                                .iter()
                                .all(|byte| *byte == 0)
                        );
                    }
                    trial.writes = 0;
                    journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                    assert_eq!(trial.writes, 0);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
        eprintln!(
            "dense resize {size}: {} program and {} barrier cuts x4 restart persistence histories",
            complete.writes, complete.flushes
        );
    }
    for (size, new) in [(7, 160), (4200, 180), (65536, 200), (9000, 240)] {
        let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
            id: ObjectId {
                source: 123,
                generation: 0,
                native: vec![size as u8],
            },
            fail_second: false,
            size,
        });
        let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
        session.replace_dense_file(6, new, file, &r).unwrap();
        session.recover(&r).unwrap();
        drop(session);
        let decoded = inspect(&storage, read, audit, &r).unwrap();
        assert_eq!(decoded.nodes[&6].length, size);
        assert_eq!(
            decoded.nodes[&6].runs[0].physical.count,
            size.div_ceil(4096)
        );
        assert_eq!(super::le64(&decoded.nodes[&6].raw, 32), size.div_ceil(4096));
        assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
        drop(decoded);
        for (i, byte) in storage.bytes[new as usize * 4096..new as usize * 4096 + size as usize]
            .iter()
            .enumerate()
        {
            assert_eq!(*byte, (i * 31 % 251) as u8);
        }
        assert!(
            storage.bytes
                [new as usize * 4096 + size as usize..(new + size.div_ceil(4096)) as usize * 4096]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn borrowed_dense_range_cow_preserves_old_spans_and_materializes_gap() {
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
    let mut bytes = journal_seed();
    fixture::small_hardlink(&mut bytes);
    let inode = 29 * fixture::BLOCK + 6 * 512;
    fixture::p64(&mut bytes, inode + 24, 9000);
    fixture::p64(&mut bytes, inode + 32, 3);
    bytes[inode + 224..inode + 512].copy_from_slice(&fixture::xt(&[(0, 112, 3, 0)], false, None));
    let mut used: Vec<_> = (0..22).chain(23..35).collect();
    used.extend([90, 100, 102, 110, 112, 113, 114]);
    fixture::rebuild_map(&mut bytes, &used);
    bytes[112 * 4096..115 * 4096].fill(0xa7);
    let seed = bytes.clone();
    for offset in [4090u64, 12000] {
        let replacement_length = 5000;
        let mut trial = CowTestBackend {
            bytes: seed.clone(),
            durable: seed.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        let source: Arc<dyn FileRead> = Arc::new(CowTestPayload {
            id: ObjectId {
                source: 123,
                generation: 0,
                native: vec![10],
            },
            fail_second: false,
            size: replacement_length,
        });
        assert_eq!(trial.writes, 0);
        let mut session = NativeSession::open(&mut trial, read, audit, &r).unwrap();
        session
            .replace_dense_range(6, 160, offset, source, &r)
            .unwrap();
        session.recover(&r).unwrap();
        drop(session);
        let size = 9000.max(offset + replacement_length);
        let decoded = inspect(&trial, read, audit, &r).unwrap();
        assert_eq!(decoded.nodes[&6].length, size);
        assert_eq!(super::le64(&decoded.nodes[&6].raw, 32), size.div_ceil(4096));
        assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
        drop(decoded);
        for at in 0..size {
            let expected = if (offset..offset + replacement_length).contains(&at) {
                ((at - offset) * 31 % 251) as u8
            } else if at < 9000 {
                0xa7
            } else {
                0
            };
            assert_eq!(trial.bytes[160 * 4096 + at as usize], expected);
        }
        assert!(
            trial.bytes[160 * 4096 + size as usize..(160 + size.div_ceil(4096)) as usize * 4096]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            trial.bytes[112 * 4096..115 * 4096]
                .iter()
                .all(|byte| *byte == 0xa7)
        );
        let publication_writes = trial.writes;
        let publication_flushes = trial.flushes;
        trial.writes = 0;
        journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
        assert_eq!(trial.writes, 0);
        assert_eq!(r.memory.used(), 0);
        let make_file = || -> Arc<dyn FileRead> {
            Arc::new(CowTestPayload {
                id: ObjectId {
                    source: 123,
                    generation: 0,
                    native: vec![10],
                },
                fail_second: false,
                size: replacement_length,
            })
        };
        let commit_flush = size.div_ceil(4096) as usize + 5;
        for (write_cut, cut) in (1..=publication_writes)
            .map(|cut| (true, cut))
            .chain((1..=publication_flushes).map(|cut| (false, cut)))
        {
            for first_retained in [false, true] {
                for recovery_retained in [false, true] {
                    let mut fault = CowTestBackend {
                        bytes: seed.clone(),
                        durable: seed.clone(),
                        writes: 0,
                        flushes: 0,
                        fail_write: write_cut.then_some(cut),
                        fail_flush: (!write_cut).then_some(cut),
                    };
                    let mut session = NativeSession::open(&mut fault, read, audit, &r).unwrap();
                    assert_eq!(
                        session
                            .replace_dense_range(6, 160, offset, make_file(), &r)
                            .unwrap_err()
                            .kind,
                        ErrorKind::UncertainDurability
                    );
                    assert!(session.uncertain && session.cow_pending);
                    assert_eq!(
                        session.write_uid(6, 1, &r).unwrap_err().kind,
                        ErrorKind::UncertainDurability
                    );
                    drop(session);
                    let committed = if write_cut {
                        fault.flushes >= commit_flush
                    } else {
                        cut > commit_flush
                            || cut == commit_flush && first_retained && recovery_retained
                    };
                    if !first_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.writes = 0;
                    fault.flushes = 0;
                    fault.fail_flush = None;
                    fault.fail_write = Some(1);
                    if let Err(error) =
                        journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r)
                    {
                        assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    }
                    if !recovery_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.fail_write = None;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    let decoded = inspect(&fault, read, audit, &r).unwrap();
                    let node = &decoded.nodes[&6];
                    assert_eq!(
                        node.length,
                        if committed { size } else { 9000 },
                        "range={offset} cut={cut} write={write_cut} first={first_retained} recovery={recovery_retained}"
                    );
                    assert_eq!(
                        node.runs[0].physical.start,
                        if committed { 160 } else { 112 }
                    );
                    assert_eq!(
                        super::le64(&node.raw, 32),
                        if committed { size.div_ceil(4096) } else { 3 }
                    );
                    assert_eq!(le32(&node.raw, 40), 2);
                    for block in 112..115 {
                        assert_eq!(decoded.bitmap[block], !committed);
                    }
                    for block in 160..160 + size.div_ceil(4096) as usize {
                        assert_eq!(decoded.bitmap[block], committed);
                    }
                    drop(decoded);
                    assert!(
                        fault.bytes[112 * 4096..115 * 4096]
                            .iter()
                            .all(|byte| *byte == 0xa7)
                    );
                    if committed {
                        for at in 0..size {
                            let expected = if (offset..offset + replacement_length).contains(&at) {
                                ((at - offset) * 31 % 251) as u8
                            } else if at < 9000 {
                                0xa7
                            } else {
                                0
                            };
                            assert_eq!(fault.bytes[160 * 4096 + at as usize], expected);
                        }
                        assert!(
                            fault.bytes[160 * 4096 + size as usize
                                ..(160 + size.div_ceil(4096)) as usize * 4096]
                                .iter()
                                .all(|byte| *byte == 0)
                        );
                    }
                    fault.writes = 0;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    assert_eq!(fault.writes, 0);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
        eprintln!(
            "dense range {offset}: {publication_writes} program and {publication_flushes} barrier cuts x4 restart persistence histories"
        );
    }
}

#[test]
fn dense_range_preflight_and_deferred_failure_preserve_exclusive_authority() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    let make_file = |size, fail_second| -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 123,
                generation: 0,
                native: vec![11],
            },
            size,
            fail_second,
        })
    };
    for (offset, size) in [(u64::MAX, 5000), (32 * 4096 + 1, 5000), (0, 0)] {
        let mut storage = CowTestBackend {
            bytes: seed.clone(),
            durable: seed.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
        assert!(
            session
                .replace_dense_range(6, 160, offset, make_file(size, false), &r)
                .is_err()
        );
        assert!(!session.uncertain);
        drop(session);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.flushes, 0);
        assert_eq!(storage.bytes, seed);
        assert_eq!(r.memory.used(), 0);
    }
    for cancelled in [false, true] {
        let mut storage = CowTestBackend {
            bytes: seed.clone(),
            durable: seed.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        let limited = Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        };
        if cancelled {
            limited.cancellation.cancel();
        }
        let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
        assert!(
            session
                .replace_dense_range(6, 160, 0, make_file(5000, false), &limited)
                .is_err()
        );
        assert!(!session.uncertain);
        drop(session);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.flushes, 0);
        assert_eq!(storage.bytes, seed);
        assert_eq!(limited.memory.used(), 0);
        assert_eq!(r.memory.used(), 0);
    }
    let mut storage = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
    let error = session
        .replace_dense_range(6, 160, 0, make_file(9000, true), &r)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::UncertainDurability);
    assert!(error.context.contains("deferred second-block model"));
    assert!(session.uncertain && session.cow_pending);
    assert_eq!(
        session
            .replace_dense_range(6, 170, 0, make_file(9000, false), &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    session.recover(&r).unwrap();
    assert!(!session.uncertain && !session.cow_pending);
    drop(session);
    assert_eq!(storage.writes, 4096usize.div_ceil(71));
    assert_eq!(&storage.bytes[..160 * 4096], &seed[..160 * 4096]);
    assert_eq!(&storage.bytes[161 * 4096..], &seed[161 * 4096..]);
    let decoded = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].length, 7);
    assert_eq!(decoded.nodes[&6].runs[0].physical.start, 112);
    assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
    assert!(!decoded.bitmap[160]);
    drop(decoded);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_empty_truncation_frees_old_run_without_payload_programming() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    let mut storage = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![12],
        },
        size: 0,
        fail_second: true,
    });
    let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
    session.replace_dense_file(6, 0, file, &r).unwrap();
    session.recover(&r).unwrap();
    drop(session);
    let decoded = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].length, 0);
    assert_eq!(super::le64(&decoded.nodes[&6].raw, 32), 0);
    assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
    assert_eq!(le16(&decoded.nodes[&6].raw, 242), 2);
    assert!(decoded.nodes[&6].runs.is_empty());
    assert!(!decoded.bitmap[112]);
    drop(decoded);
    assert_eq!(
        &storage.bytes[112 * 4096..113 * 4096],
        &seed[112 * 4096..113 * 4096]
    );
    assert_eq!(&storage.bytes[..4096], &seed[..4096]);
    let publication_writes = storage.writes;
    let publication_flushes = storage.flushes;
    storage.writes = 0;
    journal::recover_cow(&mut storage, [0xa5; 16], read, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
    let make_file = || -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 123,
                generation: 0,
                native: vec![12],
            },
            size: 0,
            fail_second: true,
        })
    };
    for (write_cut, cut) in (1..=publication_writes)
        .map(|cut| (true, cut))
        .chain((1..=publication_flushes).map(|cut| (false, cut)))
    {
        for first_retained in [false, true] {
            for recovery_retained in [false, true] {
                let mut trial = CowTestBackend {
                    bytes: seed.clone(),
                    durable: seed.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_write: write_cut.then_some(cut),
                    fail_flush: (!write_cut).then_some(cut),
                };
                let mut session = NativeSession::open(&mut trial, read, audit, &r).unwrap();
                assert_eq!(
                    session
                        .replace_dense_file(6, 0, make_file(), &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                assert!(session.uncertain && session.cow_pending);
                drop(session);
                let committed = if write_cut {
                    trial.flushes >= 5
                } else {
                    cut > 5 || cut == 5 && first_retained && recovery_retained
                };
                if !first_retained {
                    trial.bytes.clone_from(&trial.durable);
                }
                trial.writes = 0;
                trial.flushes = 0;
                trial.fail_flush = None;
                trial.fail_write = Some(1);
                if let Err(error) =
                    journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r)
                {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                if !recovery_retained {
                    trial.bytes.clone_from(&trial.durable);
                }
                trial.fail_write = None;
                journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                let decoded = inspect(&trial, read, audit, &r).unwrap();
                let node = &decoded.nodes[&6];
                assert_eq!(
                    node.length,
                    if committed { 0 } else { 7 },
                    "empty cut={cut} write={write_cut} first={first_retained} recovery={recovery_retained}"
                );
                assert_eq!(super::le64(&node.raw, 32), u64::from(!committed));
                assert_eq!(node.runs.is_empty(), committed);
                assert_eq!(le16(&node.raw, 242), if committed { 2 } else { 3 });
                assert_eq!(le32(&node.raw, 40), 2);
                assert_eq!(decoded.bitmap[112], !committed);
                drop(decoded);
                assert_eq!(
                    &trial.bytes[112 * 4096..113 * 4096],
                    &seed[112 * 4096..113 * 4096]
                );
                assert_eq!(&trial.bytes[..4096], &seed[..4096]);
                trial.writes = 0;
                journal::recover_cow(&mut trial, [0xa5; 16], read, audit, &r, &r).unwrap();
                assert_eq!(trial.writes, 0);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    eprintln!(
        "empty truncation: {publication_writes} program and {publication_flushes} barrier cuts x4 restart persistence histories"
    );
    let mut committed = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: Some(5),
    };
    let plan = journal::prepare_cow_resized(
        &committed,
        journal::CowRequest {
            inode: 6,
            new: 0,
            file: make_file(),
        },
        read,
        audit,
        &r,
        &r,
    )
    .unwrap();
    assert_eq!(
        journal::publish_cow(&mut committed, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    let page = 484 * 4096;
    let end = page + usize::from(le16(&committed.bytes, page + 6));
    let commit_descriptor = end - 36;
    let free_end = page + le32(&committed.bytes, commit_descriptor + 4) as usize % 4096;
    let free_descriptor = free_end - 36;
    let root_end = page + le32(&committed.bytes, free_descriptor + 4) as usize % 4096;
    let root_descriptor = root_end - 36;
    let root_body = root_descriptor - usize::from(le16(&committed.bytes, root_descriptor + 10));
    let inode_end = page + le32(&committed.bytes, root_descriptor + 4) as usize % 4096;
    let inode_descriptor = inode_end - 36;
    let inode_body = inode_descriptor - usize::from(le16(&committed.bytes, inode_descriptor + 10));
    for (at, mask) in [
        (inode_body + 24, 1),
        (inode_body + 32, 1),
        (root_body + 18, 1),
        (root_body + 36, 1),
        (free_descriptor + 28, 1),
    ] {
        let mut negative = CowTestBackend {
            bytes: committed.bytes.clone(),
            durable: committed.durable.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        negative.bytes[at] ^= mask;
        let before = negative.bytes.clone();
        let durable_before = negative.durable.clone();
        assert!(journal::recover_cow(&mut negative, [0xa5; 16], read, audit, &r, &r).is_err());
        assert_eq!(negative.writes, 0);
        assert_eq!(negative.flushes, 0);
        assert_eq!(negative.bytes, before);
        assert_eq!(negative.durable, durable_before);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn fragmented_inline_cow_preserves_logical_holes_unwritten_data_and_hardlinks() {
    run_fragmented_cow_matrix(false, true);
}
#[test]
fn external_regular_cow_all_program_barrier_cuts_recover_four_persistence_profiles() {
    run_fragmented_cow_matrix(true, true);
}
#[test]
fn external_saved_root_and_metadata_free_errors_reject_before_mutation() {
    run_fragmented_cow_matrix(true, false);
}
fn run_fragmented_cow_matrix(external: bool, cuts: bool) {
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
    let mut seed = journal_seed();
    let old_length = if external {
        16 * 4096 + 123
    } else {
        5 * 4096 + 123
    };
    let old_blocks = if external { 18 } else { 4 };
    let new: usize = if external { 220 } else { 160 };
    let old_indices: Vec<usize> = if external {
        std::iter::once(130)
            .chain((0..17).map(|index| 150 + index * 2))
            .collect()
    } else {
        vec![112, 114, 116, 117]
    };
    let expected_old = |at: u64| -> u8 {
        if external {
            0x40 + (at / 4096) as u8
        } else if at < 4096 {
            0xa1
        } else if at >= 4 * 4096 {
            0xb2
        } else {
            0
        }
    };
    if external {
        external_regular_fixture(&mut seed);
    } else {
        fixture::small_hardlink(&mut seed);
        let inode = 29 * fixture::BLOCK + 6 * 512;
        fixture::p64(&mut seed, inode + 24, old_length);
        fixture::p64(&mut seed, inode + 32, old_blocks);
        seed[inode + 224..inode + 512].copy_from_slice(&fixture::xt(
            &[(0, 112, 1, 0), (2, 114, 1, 8), (4, 116, 2, 0)],
            false,
            None,
        ));
        let mut used: Vec<_> = (0..22).chain(23..35).collect();
        used.extend([90, 100, 102, 110, 112, 114, 116, 117]);
        fixture::rebuild_map(&mut seed, &used);
        seed[112 * 4096..113 * 4096].fill(0xa1);
        seed[114 * 4096..115 * 4096].fill(0xc3);
        seed[116 * 4096..118 * 4096].fill(0xb2);
    }
    let make_file = |size| -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 123,
                generation: 0,
                native: vec![13],
            },
            size,
            fail_second: false,
        })
    };
    for mode in 0..3 {
        let mut storage = CowTestBackend {
            bytes: seed.clone(),
            durable: seed.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        let before = inspect(&storage, read, audit, &r).unwrap();
        assert_eq!(before.nodes[&6].runs.len(), if external { 17 } else { 3 });
        assert_eq!(before.nodes[&6].pages.len(), usize::from(external));
        if !external {
            assert!(before.nodes[&6].runs[1].unwritten);
        }
        drop(before);
        let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
        match mode {
            0 => session
                .replace_dense_range(6, new as u64, 4090, make_file(5000), &r)
                .unwrap(),
            1 => session
                .replace_dense_file(6, new as u64, make_file(9000), &r)
                .unwrap(),
            _ => session.replace_dense_file(6, 0, make_file(0), &r).unwrap(),
        }
        session.recover(&r).unwrap();
        drop(session);
        let size = match mode {
            0 => old_length,
            1 => 9000,
            _ => 0,
        };
        let decoded = inspect(&storage, read, audit, &r).unwrap();
        assert_eq!(decoded.nodes[&6].length, size);
        assert_eq!(super::le64(&decoded.nodes[&6].raw, 32), size.div_ceil(4096));
        assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
        for &old in &old_indices {
            assert!(!decoded.bitmap[old]);
        }
        for block in new..new + size.div_ceil(4096) as usize {
            assert!(decoded.bitmap[block]);
        }
        drop(decoded);
        for at in 0..size {
            let expected = if mode == 1 {
                (at * 31 % 251) as u8
            } else if (4090..9090).contains(&at) {
                ((at - 4090) * 31 % 251) as u8
            } else {
                expected_old(at)
            };
            assert_eq!(storage.bytes[new * 4096 + at as usize], expected);
        }
        if size != 0 {
            assert!(
                storage.bytes[new * 4096 + size as usize
                    ..(new as u64 + size.div_ceil(4096)) as usize * 4096]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        for &old in &old_indices {
            assert_eq!(
                &storage.bytes[old * 4096..(old + 1) * 4096],
                &seed[old * 4096..(old + 1) * 4096]
            );
        }
        let publication_writes = storage.writes;
        let publication_flushes = storage.flushes;
        storage.writes = 0;
        journal::recover_cow(&mut storage, [0xa5; 16], read, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, 0);
        assert_eq!(r.memory.used(), 0);
        let commit_flush = size.div_ceil(4096) as usize + 5;
        for (write_cut, cut) in (1..=publication_writes)
            .map(|cut| (true, cut))
            .chain((1..=publication_flushes).map(|cut| (false, cut)))
            .filter(|_| cuts)
        {
            for first_retained in [false, true] {
                for recovery_retained in [false, true] {
                    let mut fault = CowTestBackend {
                        bytes: seed.clone(),
                        durable: seed.clone(),
                        writes: 0,
                        flushes: 0,
                        fail_write: write_cut.then_some(cut),
                        fail_flush: (!write_cut).then_some(cut),
                    };
                    let mut session = NativeSession::open(&mut fault, read, audit, &r).unwrap();
                    let result = match mode {
                        0 => session.replace_dense_range(6, new as u64, 4090, make_file(5000), &r),
                        1 => session.replace_dense_file(6, new as u64, make_file(9000), &r),
                        _ => session.replace_dense_file(6, 0, make_file(0), &r),
                    };
                    assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
                    assert!(session.uncertain && session.cow_pending);
                    assert_eq!(
                        session.write_uid(6, 1, &r).unwrap_err().kind,
                        ErrorKind::UncertainDurability
                    );
                    drop(session);
                    let committed = if write_cut {
                        fault.flushes >= commit_flush
                    } else {
                        cut > commit_flush
                            || cut == commit_flush && first_retained && recovery_retained
                    };
                    if !first_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.writes = 0;
                    fault.flushes = 0;
                    fault.fail_flush = None;
                    fault.fail_write = Some(1);
                    if let Err(error) =
                        journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r)
                    {
                        assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    }
                    if !recovery_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.fail_write = None;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    let decoded = inspect(&fault, read, audit, &r).unwrap();
                    let node = &decoded.nodes[&6];
                    assert_eq!(
                        node.length,
                        if committed { size } else { old_length },
                        "fragmented mode={mode} cut={cut} write={write_cut} first={first_retained} recovery={recovery_retained}"
                    );
                    assert_eq!(
                        super::le64(&node.raw, 32),
                        if committed {
                            size.div_ceil(4096)
                        } else {
                            old_blocks
                        }
                    );
                    assert_eq!(
                        le16(&node.raw, 242),
                        if !committed {
                            if external { 3 } else { 5 }
                        } else if size == 0 {
                            2
                        } else {
                            3
                        }
                    );
                    assert_eq!(le32(&node.raw, 40), 2);
                    for &old in &old_indices {
                        assert_eq!(decoded.bitmap[old], !committed);
                    }
                    for block in new..new + size.div_ceil(4096) as usize {
                        assert_eq!(decoded.bitmap[block], committed);
                    }
                    if !committed && !external {
                        assert!(node.runs[1].unwritten);
                    }
                    assert_eq!(node.pages.len(), usize::from(external && !committed));
                    drop(decoded);
                    if committed {
                        for at in 0..size {
                            let expected = if mode == 1 {
                                (at * 31 % 251) as u8
                            } else if (4090..9090).contains(&at) {
                                ((at - 4090) * 31 % 251) as u8
                            } else {
                                expected_old(at)
                            };
                            assert_eq!(fault.bytes[new * 4096 + at as usize], expected);
                        }
                        if size != 0 {
                            assert!(
                                fault.bytes[new * 4096 + size as usize
                                    ..(new as u64 + size.div_ceil(4096)) as usize * 4096]
                                    .iter()
                                    .all(|byte| *byte == 0)
                            );
                        }
                    }
                    for &old in &old_indices {
                        assert_eq!(
                            &fault.bytes[old * 4096..(old + 1) * 4096],
                            &seed[old * 4096..(old + 1) * 4096]
                        );
                    }
                    fault.writes = 0;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    assert_eq!(fault.writes, 0);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
        eprintln!(
            "external={external} mode={mode}: publication programs={publication_writes} barriers={publication_flushes} exhaustive_four_persistence_cuts_executed={cuts}"
        );
    }
    let mut committed = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: Some(old_length.div_ceil(4096) as usize + 5),
    };
    let plan = journal::prepare_cow_range(
        &committed,
        journal::CowRequest {
            inode: 6,
            new: new as u64,
            file: make_file(5000),
        },
        read,
        audit,
        &r,
        &r,
        4090,
    )
    .unwrap();
    assert_eq!(
        journal::publish_cow(&mut committed, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    let page = 484 * 4096;
    let end = page + usize::from(le16(&committed.bytes, page + 6));
    let commit_descriptor = end - 36;
    let free_end = page + le32(&committed.bytes, commit_descriptor + 4) as usize % 4096;
    let free_end = if external {
        page + le32(&committed.bytes, free_end - 36 + 4) as usize % 4096
    } else {
        free_end
    };
    let free_descriptor = free_end - 36;
    assert_eq!(le16(&committed.bytes, free_descriptor + 24), 8);
    assert_eq!(
        le16(&committed.bytes, free_descriptor + 26),
        if external { 17 } else { 3 }
    );
    let free_body = free_descriptor - usize::from(le16(&committed.bytes, free_descriptor + 10));
    for (at, mask) in [
        (free_body, 1),            // NEW is not an old allocation
        (free_body + 17, 1),       // reserved XAD byte
        (free_body + 20, 2),       // logical overlap
        (free_body + 28, 2),       // physical overlap
        (free_body + 36, 16),      // logical end beyond profile
        (free_descriptor + 24, 4), // wrong native map subtype
        (free_descriptor + 27, 1), // excessive native count
    ] {
        let mut negative = CowTestBackend {
            bytes: committed.bytes.clone(),
            durable: committed.durable.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        negative.bytes[at] ^= mask;
        let before = negative.bytes.clone();
        let durable_before = negative.durable.clone();
        assert!(journal::recover_cow(&mut negative, [0xa5; 16], read, audit, &r, &r).is_err());
        assert_eq!(negative.writes, 0);
        assert_eq!(negative.flushes, 0);
        assert_eq!(negative.bytes, before);
        assert_eq!(negative.durable, durable_before);
        assert_eq!(r.memory.used(), 0);
    }
    if external {
        let metadata_descriptor =
            page + le32(&committed.bytes, commit_descriptor + 4) as usize % 4096 - 36;
        let root_end = page + le32(&committed.bytes, free_descriptor + 4) as usize % 4096;
        let root_descriptor = root_end - 36;
        let root_body = root_descriptor - usize::from(le16(&committed.bytes, root_descriptor + 10));
        let inode_end = page + le32(&committed.bytes, root_descriptor + 4) as usize % 4096;
        let inode_descriptor = inode_end - 36;
        let old_root_end = page + le32(&committed.bytes, inode_descriptor + 4) as usize % 4096;
        let old_root_descriptor = old_root_end - 36;
        let old_root_body =
            old_root_descriptor - usize::from(le16(&committed.bytes, old_root_descriptor + 10));
        for (at, mask) in [
            (metadata_descriptor + 32, 2),  // wrong metadata page
            (metadata_descriptor + 28, 1),  // zero metadata extent length
            (metadata_descriptor + 24, 16), // unsupported metadata subtype
            (metadata_descriptor + 16, 1),  // foreign fileset
            (old_root_body + 16, 6),        // old leaf cannot authenticate external pages
            (old_root_body + 36, 1),        // transient NEW child is not old metadata
            (old_root_body + 44, 2),        // saved child differs from declared FREE metadata
            (old_root_body + 18, 1),        // inconsistent saved ROOT slots
            (old_root_body + 54, 1),        // malformed native vector count
            (old_root_descriptor + 4, 1),   // old ROOT must begin transaction backchain
            (root_descriptor + 4, 1),       // new ROOT skips native INODE afterimage
            (inode_descriptor + 4, 1),      // INODE skips saved ROOT
            (root_body + 16, 128),          // unauthorized immutable header flag change
        ] {
            let mut negative = CowTestBackend {
                bytes: committed.bytes.clone(),
                durable: committed.durable.clone(),
                writes: 0,
                flushes: 0,
                fail_write: None,
                fail_flush: None,
            };
            negative.bytes[at] ^= mask;
            let before = negative.bytes.clone();
            let durable_before = negative.durable.clone();
            assert!(
                journal::recover_cow(&mut negative, [0xa5; 16], read, audit, &r, &r).is_err(),
                "external native history byte={at} mask={mask}"
            );
            assert_eq!(negative.writes, 0);
            assert_eq!(negative.flushes, 0);
            assert_eq!(negative.bytes, before);
            assert_eq!(negative.durable, durable_before);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

struct Borrowed<'a> {
    storage: &'a dyn Storage,
    length: u64,
    resources: &'a Resources,
}
impl DecodeRead for Borrowed<'_> {
    fn length(&self) -> Result<u64> {
        self.resources.cancellation.check()?;
        let length = self
            .storage
            .len()
            .map_err(|e| Error::io("JFS exclusive length", e))?;
        if length != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS exclusive geometry changed",
            ));
        }
        Ok(length)
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let length = self.length()?;
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > length)
        {
            return Err(bad("JFS exclusive read bounds"));
        }
        self.storage
            .read_exact_at(at, out)
            .map_err(|e| Error::io("JFS exclusive metadata", e))?;
        self.length()?;
        Ok(())
    }
}
fn inspect(
    storage: &dyn Storage,
    limits: JfsReadLimits,
    audit: JfsAuditLimits,
    r: &Resources,
) -> Result<Decoded> {
    inspect_with(storage, limits, audit, r, r)
}
fn inspect_with(
    storage: &dyn Storage,
    limits: JfsReadLimits,
    audit: JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<Decoded> {
    let source = Borrowed {
        storage,
        length: storage
            .len()
            .map_err(|e| Error::io("JFS exclusive open", e))?,
        resources: original,
    };
    let decoded = decode(&source, limits, r)?;
    let proof = audit_decoded(&decoded, audit, r)?;
    if !proof.is_clean() {
        return Err(bad("JFS exclusive baseline not allocation/reference clean"));
    }
    source.length()?;
    Ok(decoded)
}

struct Overlay<'a> {
    source: Borrowed<'a>,
    patches: &'a [(u64, Vec<u8>)],
}
impl DecodeRead for Overlay<'_> {
    fn length(&self) -> Result<u64> {
        self.source.length()
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        self.source.exact(at, out)?;
        let end = at + out.len() as u64;
        for (start, bytes) in self.patches {
            let left = at.max(*start);
            let right = end.min(*start + bytes.len() as u64);
            if left < right {
                out[(left - at) as usize..(right - at) as usize]
                    .copy_from_slice(&bytes[(left - *start) as usize..(right - *start) as usize]);
            }
        }
        self.source.length()?;
        Ok(())
    }
}
// Private metadata overlay atop the existing positional decoder contract.
// Retention charge belongs to the prepared rotation/COW plans.
struct SourceOverlay<'a> {
    source: &'a dyn DecodeRead,
    patches: &'a [(u64, Vec<u8>)],
}
impl DecodeRead for SourceOverlay<'_> {
    fn length(&self) -> Result<u64> {
        self.source.length()
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let end = at
            .checked_add(out.len() as u64)
            .ok_or_else(|| bad("JFS projected read overflow"))?;
        self.source.exact(at, out)?;
        for (start, bytes) in self.patches {
            let patch_end = start
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| bad("JFS projected patch overflow"))?;
            let left = at.max(*start);
            let right = end.min(patch_end);
            if left < right {
                out[(left - at) as usize..(right - at) as usize]
                    .copy_from_slice(&bytes[(left - *start) as usize..(right - *start) as usize]);
            }
        }
        self.source.length()?;
        Ok(())
    }
}
struct NativeSession<'a> {
    storage: &'a mut dyn Storage,
    resources: Resources,
    read: JfsReadLimits,
    audit: JfsAuditLimits,
    uncertain: bool,
    cow_pending: bool,
    rollover_pending: bool,
    rotating_cow_pending: bool,
    rename_pending: bool,
    binding: [u8; 16],
}
impl<'a> NativeSession<'a> {
    fn open(
        storage: &'a mut dyn Storage,
        read: JfsReadLimits,
        audit: JfsAuditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let decoded = inspect(storage, read, audit, r)?;
        let mut binding = [0u8; 16];
        binding.copy_from_slice(&decoded.header[136..152]);
        drop(decoded);
        Ok(Self {
            storage,
            resources: r.clone(),
            read,
            audit,
            uncertain: false,
            cow_pending: false,
            rollover_pending: false,
            rotating_cow_pending: false,
            rename_pending: false,
            binding,
        })
    }
    fn write_uid(&mut self, inode: u32, uid: u32, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let prepared = journal::prepare_uid(
            self.storage,
            inode,
            uid,
            self.read,
            self.audit,
            &self.resources,
            r,
        )?;
        let result = journal::publish_uid(self.storage, prepared, &self.resources, r);
        if result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability)
        {
            self.uncertain = true;
        }
        result
    }
    fn advance_checkpoint(&mut self, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let plan = journal::rollover::prepare(
            self.storage,
            self.binding,
            self.read,
            self.audit,
            &self.resources,
            r,
            false,
        )?;
        self.rollover_pending = true;
        let result = journal::rollover::publish(self.storage, plan, &self.resources, r);
        self.uncertain = result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability);
        if !self.uncertain {
            self.rollover_pending = false;
        }
        result
    }
    fn replace_rotating_dense_file(
        &mut self,
        inode: u32,
        new: u64,
        file: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let plan = journal::prepare_rotating_cow(
            self.storage,
            self.binding,
            journal::CowRequest { inode, new, file },
            (self.read, self.audit),
            &self.resources,
            r,
            journal::CowMode::Replace(true),
        )?;
        self.rotating_cow_pending = true;
        let result = journal::publish_rotating_cow(self.storage, plan, &self.resources, r);
        self.uncertain = result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability);
        if !self.uncertain {
            self.rotating_cow_pending = false;
        }
        result
    }
    fn rename_inline_entry(
        &mut self,
        inode: u32,
        old: &[u16],
        new: &[u16],
        r: &Resources,
    ) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS session requires explicit recovery before rename",
            ));
        }
        let plan = journal::rename::prepare(
            self.storage,
            (inode, old, new),
            (self.read, self.audit),
            &self.resources,
            r,
        )?;
        self.rename_pending = true;
        let result = journal::rename::publish(self.storage, plan, &self.resources, r);
        self.uncertain = result
            .as_ref()
            .is_err_and(|e| e.kind == ErrorKind::UncertainDurability);
        if !self.uncertain {
            self.rename_pending = false;
        }
        result
    }
    fn recover(&mut self, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.rename_pending {
            journal::rename::recover(
                self.storage,
                self.binding,
                (self.read, self.audit),
                &self.resources,
                r,
            )?;
            self.uncertain = false;
            self.rename_pending = false;
            return Ok(());
        }
        if self.rotating_cow_pending {
            journal::recover_rotating_cow(
                self.storage,
                self.binding,
                self.read,
                self.audit,
                &self.resources,
                r,
            )?;
            self.uncertain = false;
            self.rotating_cow_pending = false;
            return Ok(());
        }
        if self.rollover_pending {
            let plan = journal::rollover::prepare(
                self.storage,
                self.binding,
                self.read,
                self.audit,
                &self.resources,
                r,
                true,
            )?;
            journal::rollover::publish(self.storage, plan, &self.resources, r)?;
            self.uncertain = false;
            self.rollover_pending = false;
            return Ok(());
        }
        let recover = if self.cow_pending {
            journal::recover_cow
        } else {
            journal::recover_uid
        };
        recover(
            self.storage,
            self.binding,
            self.read,
            self.audit,
            &self.resources,
            r,
        )?;
        self.uncertain = false;
        self.cow_pending = false;
        Ok(())
    }
    fn replace_recorded_run(
        &mut self,
        inode: u32,
        new: u64,
        file: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<()> {
        self.replace_inner(inode, new, file, r, false)
    }
    fn replace_dense_file(
        &mut self,
        inode: u32,
        new: u64,
        file: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<()> {
        self.replace_inner(inode, new, file, r, true)
    }
    fn replace_dense_range(
        &mut self,
        inode: u32,
        new: u64,
        offset: u64,
        file: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let plan = journal::prepare_cow_range(
            self.storage,
            journal::CowRequest { inode, new, file },
            self.read,
            self.audit,
            &self.resources,
            r,
            offset,
        )?;
        let result = journal::publish_cow(self.storage, plan, &self.resources, r);
        if result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability)
        {
            self.uncertain = true;
            self.cow_pending = true;
        }
        result
    }
    fn replace_inner(
        &mut self,
        inode: u32,
        new: u64,
        file: Arc<dyn FileRead>,
        r: &Resources,
        resize: bool,
    ) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let prepare = if resize {
            journal::prepare_cow_resized
        } else {
            journal::prepare_cow
        };
        let plan = prepare(
            self.storage,
            journal::CowRequest { inode, new, file },
            self.read,
            self.audit,
            &self.resources,
            r,
        )?;
        let result = journal::publish_cow(self.storage, plan, &self.resources, r);
        if result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability)
        {
            self.uncertain = true;
            self.cow_pending = true;
        }
        result
    }
}

#[path = "../tests/fixtures/jfs_clean.rs"]
mod fixture;
#[test]
fn borrowed_storage_bootstrap_never_reads_payload_or_writes_and_refunds() {
    use std::cell::RefCell;
    struct Backend {
        bytes: Vec<u8>,
        reads: RefCell<Vec<(u64, usize)>>,
        writes: usize,
        fail: bool,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.reads.borrow_mut().push((at, out.len()));
            if self.fail {
                return Err(io::Error::other("independent exclusive failure"));
            }
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            Err(io::Error::other("must not write"))
        }
        fn flush(&mut self) -> io::Result<()> {
            self.writes += 1;
            Err(io::Error::other("must not flush"))
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: fixture::jfs_seed(),
        reads: RefCell::new(Vec::new()),
        writes: 0,
        fail: false,
    };
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    for inode in decoded.nodes.values().filter(|i| !i.directory) {
        for run in &inode.runs {
            let start = run.physical.start * 4096;
            let end = start + run.physical.count * 4096;
            assert!(
                !storage
                    .reads
                    .borrow()
                    .iter()
                    .any(|(at, n)| *at < end && start < *at + *n as u64)
            );
        }
    }
    drop(decoded);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(storage.writes, 0);
    let mut inserted = fixture::jfs_seed();
    let block_map = 16 * 4096;
    for block in [90usize, 91, 100, 102, 110, 112] {
        let word = block / 32;
        let bit = 0x80000000u32 >> (block % 32);
        for map in [2048, 3072] {
            let at = block_map + 4 * 4096 + map + word * 4;
            let value = le32(&inserted, at) & !bit;
            fixture::p32(&mut inserted, at, value);
        }
    }
    fixture::insert_native(&mut inserted);
    let expanded = Backend {
        bytes: inserted,
        reads: RefCell::new(Vec::new()),
        writes: 0,
        fail: false,
    };
    drop(inspect(&expanded, limits, audit, &r).unwrap());
    assert_eq!(expanded.writes, 0);
    assert_eq!(r.memory.used(), 0);
    storage.fail = true;
    assert!(inspect(&storage, limits, audit, &r).is_err());
    assert_eq!(r.memory.used(), 0);
    assert_eq!(storage.writes, 0);
    storage.fail = false;
    fixture::p32(&mut storage.bytes, 32768 + 40, 1);
    assert!(inspect(&storage, limits, audit, &r).is_err());
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
}
#[path = "fs_jfs_edit_allocation.rs"]
mod allocation;
#[path = "fs_jfs_edit_journal.rs"]
mod journal;

// Independent fixture construction only; no production encoder.
fn external_regular_fixture(image: &mut [u8]) {
    fixture::small_hardlink(image);
    let inode = 29 * 4096 + 6 * 512;
    let runs: Vec<_> = (0..17u64)
        .map(|logical| (logical, 150 + logical * 2, 1, 0))
        .collect();
    image[inode + 224..inode + 512].copy_from_slice(&fixture::xt(&[(0, 130, 1, 0)], true, None));
    image[130 * 4096..131 * 4096].copy_from_slice(&fixture::xt(&runs, false, Some(130)));
    fixture::p64(image, inode + 24, 16 * 4096 + 123);
    fixture::p64(image, inode + 32, 18); // 17 data blocks and one external xtree page.
    for (logical, physical, _, _) in &runs {
        image[*physical as usize * 4096..(*physical as usize + 1) * 4096]
            .fill(0x40 + *logical as u8);
    }
    let mut used: Vec<_> = (0..22).chain(23..35).collect();
    used.extend([90, 100, 102, 110, 130]);
    used.extend(runs.iter().map(|entry| entry.1 as usize));
    fixture::rebuild_map(image, &used);
}

#[test]
fn independently_authored_external_regular_tree_cow_preserves_hardlinks_and_frees_metadata() {
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
    let mut seed = journal_seed();
    external_regular_fixture(&mut seed);
    let mut storage = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let decoded = inspect(&storage, read, audit, &r).unwrap();
    let node = &decoded.nodes[&6];
    assert_eq!(node.runs.len(), 17);
    assert_eq!(
        node.pages,
        [super::Physical {
            start: 130,
            count: 1
        }]
    );
    assert_eq!(node.length, 16 * 4096 + 123);
    assert_eq!(super::le64(&node.raw, 32), 18);
    assert_eq!(le32(&node.raw, 40), 2);
    for (logical, run) in node.runs.iter().enumerate() {
        assert_eq!(run.logical, logical as u64);
        assert_eq!(run.physical.start, 150 + logical as u64 * 2);
        assert_eq!(run.physical.count, 1);
        assert!(!run.unwritten);
    }
    drop(decoded);
    let mut stale = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let plan = journal::prepare_cow_resized(
        &stale,
        journal::CowRequest {
            inode: 6,
            new: 220,
            file: Arc::new(CowTestPayload {
                id: ObjectId {
                    source: 123,
                    generation: 0,
                    native: vec![22],
                },
                size: 9000,
                fail_second: false,
            }),
        },
        read,
        audit,
        &r,
        &r,
    )
    .unwrap();
    // Preserve inode bytes, physical ownership and valid tree shape, but alter
    // logical semantics in the external leaf after preparation.
    stale.bytes[130 * 4096 + 32] = 8;
    let stale_before = stale.bytes.clone();
    assert_eq!(
        journal::publish_cow(&mut stale, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(stale.writes, 0);
    assert_eq!(stale.flushes, 0);
    assert_eq!(stale.bytes, stale_before);
    assert_eq!(stale.durable, seed);
    assert_eq!(r.memory.used(), 0);
    let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
    let source = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![17],
        },
        size: 9000,
        fail_second: false,
    });
    session.replace_dense_file(6, 220, source, &r).unwrap();
    session.recover(&r).unwrap();
    drop(session);
    let after = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(after.nodes[&6].length, 9000);
    assert_eq!(after.nodes[&6].runs.len(), 1);
    assert!(after.nodes[&6].pages.is_empty());
    assert_eq!(
        after.nodes[&6].runs[0].physical,
        super::Physical {
            start: 220,
            count: 3
        }
    );
    assert_eq!(le32(&after.nodes[&6].raw, 40), 2);
    for block in std::iter::once(130).chain((0..17).map(|index| 150 + index * 2)) {
        assert!(!after.bitmap[block]);
        assert_eq!(
            &storage.bytes[block * 4096..(block + 1) * 4096],
            &seed[block * 4096..(block + 1) * 4096]
        );
    }
    for offset in 0..9000 {
        assert_eq!(
            storage.bytes[220 * 4096 + offset],
            (offset as u64 * 31 % 251) as u8
        );
    }
    assert!(
        storage.bytes[220 * 4096 + 9000..223 * 4096]
            .iter()
            .all(|byte| *byte == 0)
    );
    drop(after);
    let writes = storage.writes;
    let flushes = storage.flushes;
    let mut session = NativeSession::open(&mut storage, read, audit, &r).unwrap();
    session.recover(&r).unwrap();
    drop(session);
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.flushes, flushes);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn external_regular_recovery_every_program_and_barrier_restarts_with_four_persistence_models() {
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
    let mut seed = journal_seed();
    external_regular_fixture(&mut seed);
    let size: u64 = 16 * 4096 + 123;
    let mut pending = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: Some(size.div_ceil(4096) as usize + 6),
    };
    let source: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![21],
        },
        size: 5000,
        fail_second: false,
    });
    let mut session = NativeSession::open(&mut pending, read, audit, &r).unwrap();
    assert_eq!(
        session
            .replace_dense_range(6, 220, 4090, source, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    drop(session);
    let assert_after = |storage: &CowTestBackend| {
        let decoded = inspect(storage, read, audit, &r).unwrap();
        let node = &decoded.nodes[&6];
        assert_eq!(node.length, size);
        assert_eq!(node.runs.len(), 1);
        assert_eq!(
            node.runs[0].physical,
            super::Physical {
                start: 220,
                count: 17
            }
        );
        assert!(node.pages.is_empty());
        assert_eq!(le32(&node.raw, 40), 2);
        for block in std::iter::once(130).chain((0..17).map(|index| 150 + index * 2)) {
            assert!(!decoded.bitmap[block]);
            assert_eq!(
                &storage.bytes[block * 4096..(block + 1) * 4096],
                &seed[block * 4096..(block + 1) * 4096]
            );
        }
        for at in 0..size {
            let expected = if (4090..9090).contains(&at) {
                ((at - 4090) * 31 % 251) as u8
            } else {
                0x40 + (at / 4096) as u8
            };
            assert_eq!(storage.bytes[220 * 4096 + at as usize], expected);
        }
        assert!(
            storage.bytes[220 * 4096 + size as usize..237 * 4096]
                .iter()
                .all(|byte| *byte == 0)
        );
    };
    for home_retained in [false, true] {
        let base = if home_retained {
            &pending.bytes
        } else {
            &pending.durable
        };
        let mut complete = CowTestBackend {
            bytes: base.clone(),
            durable: pending.durable.clone(),
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
        };
        journal::recover_cow(&mut complete, [0xa5; 16], read, audit, &r, &r).unwrap();
        assert_after(&complete);
        let programs = complete.writes;
        let barriers = complete.flushes;
        for (write_cut, cut) in (1..=programs)
            .map(|cut| (true, cut))
            .chain((1..=barriers).map(|cut| (false, cut)))
        {
            for first_retained in [false, true] {
                for second_retained in [false, true] {
                    let mut fault = CowTestBackend {
                        bytes: base.clone(),
                        durable: pending.durable.clone(),
                        writes: 0,
                        flushes: 0,
                        fail_write: write_cut.then_some(cut),
                        fail_flush: (!write_cut).then_some(cut),
                    };
                    assert_eq!(
                        journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r)
                            .unwrap_err()
                            .kind,
                        ErrorKind::UncertainDurability
                    );
                    if !first_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.writes = 0;
                    fault.flushes = 0;
                    fault.fail_write = Some(1);
                    fault.fail_flush = None;
                    if let Err(error) =
                        journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r)
                    {
                        assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    }
                    if !second_retained {
                        fault.bytes.clone_from(&fault.durable);
                    }
                    fault.fail_write = None;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    assert_after(&fault);
                    fault.writes = 0;
                    fault.flushes = 0;
                    journal::recover_cow(&mut fault, [0xa5; 16], read, audit, &r, &r).unwrap();
                    assert_eq!(fault.writes, 0);
                    assert_eq!(fault.flushes, 0);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
        eprintln!(
            "external recovery home_retained={home_retained}: programs={programs} barriers={barriers} all_positions_x_four_restart_persistence_models=passed"
        );
    }
}

fn journal_seed() -> Vec<u8> {
    let mut b = fixture::jfs_seed();
    for at in [32768 + 136, 61440 + 136] {
        b[at..at + 16].fill(0xa5);
    }
    for page in 2usize..30 {
        let at = (482 + page) * 4096;
        let seq = if page == 2 { 27 } else { page as u32 - 3 };
        fixture::p32(&mut b, at, seq);
        fixture::p32(&mut b, at + 4088, seq);
        let end = if page == 2 { 44 } else { 8 };
        fixture::p16(&mut b, at + 6, end);
        fixture::p16(&mut b, at + 4094, end);
    }
    fixture::p16(&mut b, 484 * 4096 + 16, 0x4000);
    fixture::p32(&mut b, 483 * 4096 + 32, 2 * 4096 + 44);
    b
}

#[test]
fn staged_native_uid_lifecycle_preserves_all_other_inode_bytes_and_is_sticky_after_write_failure() {
    struct Backend {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        fail: bool,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let n = if self.fail {
                16.min(bytes.len())
            } else {
                37.min(bytes.len())
            };
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.fail {
                return Err(io::Error::other("modeled partial native program"));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: journal_seed(),
        writes: 0,
        flushes: 0,
        fail: false,
    };
    let before = storage.bytes.clone();
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    session.write_uid(2, 777, &r).unwrap();
    assert!(!session.uncertain);
    drop(session);
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(le32(&decoded.nodes[&2].raw, 44), 777);
    drop(decoded);
    assert!(storage.writes > 0 && storage.flushes >= 8);
    assert_eq!(r.memory.used(), 0);
    for (at, (old, new)) in before.iter().zip(&storage.bytes).enumerate() {
        let allowed = [
            (32768 + 40, 4),
            (32768 + 68, 4),
            (61440 + 40, 4),
            (61440 + 68, 4),
            (483 * 4096, 4096),
            (484 * 4096, 4096),
            (29 * 4096 + 1024 + 44, 4),
        ]
        .iter()
        .any(|(start, n)| *start <= at && at < *start + *n);
        if !allowed {
            assert_eq!(old, new, "unexpected native mutation at {at}");
        }
    }
    let mut broken = Backend {
        bytes: journal_seed(),
        writes: 0,
        flushes: 0,
        fail: true,
    };
    let mut session = NativeSession::open(&mut broken, limits, audit, &r).unwrap();
    assert_eq!(
        session.write_uid(2, 777, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    assert!(session.uncertain);
    assert_eq!(
        session.write_uid(2, 888, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    drop(session);
    assert_eq!(broken.writes, 1);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn staged_native_committed_uid_recovery_validates_first_restarts_and_complete_does_not_write() {
    struct Backend {
        bytes: Vec<u8>,
        writes: usize,
        home_fail: bool,
        flushes: usize,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let n = 37.min(bytes.len());
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.home_fail && (29 * 4096 + 1024..29 * 4096 + 1152).contains(&(at as usize)) {
                return Err(io::Error::other("partial committed native home"));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: journal_seed(),
        writes: 0,
        home_fail: true,
        flushes: 0,
    };
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    assert_eq!(
        session.write_uid(2, 777, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    assert!(session.uncertain);
    drop(session);
    let writes = storage.writes;
    let before = storage.bytes.clone();
    assert!(journal::recover_uid(&mut storage, [0xb6; 16], limits, audit, &r, &r).is_err());
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, before);
    for at in [
        32768 + 68,
        483 * 4096 + 68,
        484 * 4096 + 80,
        484 * 4096 + 228,
        484 * 4096 + 240,
    ] {
        let old = storage.bytes[at];
        storage.bytes[at] ^= 1;
        let malformed = storage.bytes.clone();
        assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
        assert_eq!(storage.writes, writes);
        assert_eq!(storage.bytes, malformed);
        assert_eq!(r.memory.used(), 0);
        storage.bytes[at] = old;
    }
    assert_eq!(
        journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    assert_eq!(r.memory.used(), 0);
    storage.home_fail = false;
    journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(le32(&decoded.nodes[&2].raw, 44), 777);
    drop(decoded);
    let writes = storage.writes;
    let completed = storage.bytes.clone();
    journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, completed);
    assert_eq!(r.memory.used(), 0);
    let end_at = 483 * 4096 + 32;
    let original_end = storage.bytes[end_at..end_at + 4].to_vec();
    storage.bytes[end_at..end_at + 4].copy_from_slice(&44u32.to_le_bytes());
    let malformed = storage.bytes.clone();
    assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, malformed);
    assert_eq!(r.memory.used(), 0);
    storage.bytes[end_at..end_at + 4].copy_from_slice(&original_end);
    for at in [484 * 4096, 484 * 4096 + 6, 485 * 4096 + 6] {
        let old = storage.bytes[at];
        storage.bytes[at] ^= 1;
        let malformed = storage.bytes.clone();
        assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
        assert_eq!(storage.writes, writes);
        assert_eq!(storage.bytes, malformed);
        assert_eq!(r.memory.used(), 0);
        storage.bytes[at] = old;
    }
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    session.recover(&r).unwrap();
    assert!(!session.uncertain);
    drop(session);
    assert_eq!(storage.writes, writes);
}

#[test]
fn staged_native_committed_barrier_restart_retains_or_discards_volatile_bytes() {
    #[derive(Clone)]
    struct Durable {
        bytes: Vec<u8>,
        durable: Vec<u8>,
        flushes: usize,
        fail: usize,
        writes: usize,
        fail_page: usize,
        page_writes: usize,
        stop_at: Option<u64>,
    }
    impl Storage for Durable {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let mut n = 37.min(bytes.len());
            let interrupted = self
                .stop_at
                .is_some_and(|stop| at <= stop && stop < at + n as u64);
            if interrupted {
                n = (self.stop_at.unwrap() - at) as usize;
            }
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if interrupted {
                self.stop_at = None;
                return Err(io::Error::other("modeled partial native activation"));
            }
            if at == 484 * 4096 {
                self.page_writes += 1;
                if self.page_writes == self.fail_page {
                    return Err(io::Error::other("modeled ordered partial page"));
                }
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == self.fail {
                return Err(io::Error::other("modeled native barrier interruption"));
            }
            self.durable.copy_from_slice(&self.bytes);
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    // Barrier 3 is the native COMMIT barrier. Dropping that unsuccessful
    // barrier leaves an uncommitted REDO; the current recovery profile aborts it.
    for cut in 3..=8 {
        for retain in [false, true] {
            let bytes = journal_seed();
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: cut,
                writes: 0,
                fail_page: usize::MAX,
                page_writes: 0,
                stop_at: None,
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            // The selected bytes survived the modeled restart and form the
            // next boot's durable baseline; later cuts affect new writes.
            storage.durable.copy_from_slice(&storage.bytes);
            for recovery_retain in [false, true] {
                let mut retry = storage.clone();
                retry.fail = retry.flushes + 1;
                let outcome = journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r);
                // A fully clean surviving checkpoint needs no recovery writes.
                if let Err(error) = outcome {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    if !recovery_retain {
                        retry.bytes.copy_from_slice(&retry.durable);
                    }
                }
                retry.fail = usize::MAX;
                journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r).unwrap();
                let decoded = inspect(&retry, limits, audit, &r).unwrap();
                assert_eq!(
                    le32(&decoded.nodes[&2].raw, 44),
                    if cut == 3 && !retain { 501 } else { 777 }
                );
                drop(decoded);
                let writes = retry.writes;
                journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r).unwrap();
                assert_eq!(retry.writes, writes);
                assert_eq!(r.memory.used(), 0);
            }
            storage.fail = usize::MAX;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            let expected = if cut == 3 && !retain { 501 } else { 777 };
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                expected,
                "cut={cut} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
    for cut in 1..=3 {
        for retain in [false, true] {
            let bytes = journal_seed();
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: usize::MAX,
                writes: 0,
                fail_page: cut,
                page_writes: 0,
                stop_at: None,
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            storage.durable.copy_from_slice(&storage.bytes);
            storage.fail_page = usize::MAX;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                if cut == 3 { 777 } else { 501 },
                "page cut={cut} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
    for stop_at in [32768 + 69, 61440 + 69, 483 * 4096 + 9, 483 * 4096 + 73] {
        for retain in [false, true] {
            let mut bytes = journal_seed();
            for at in [32768 + 68, 61440 + 68, 483 * 4096 + 8] {
                bytes[at..at + 4].copy_from_slice(&255u32.to_le_bytes());
            }
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: usize::MAX,
                writes: 0,
                fail_page: usize::MAX,
                page_writes: 0,
                stop_at: Some(stop_at as u64),
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            storage.durable.copy_from_slice(&storage.bytes);
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                501,
                "activation cut={stop_at} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
#[ignore = "requires fresh PARTMGR_JFS_LIFECYCLE_EVIDENCE and JFS_TOOLS; private UID/dense-COW staging"]
fn native_owned_uid_publication_home_error_recovery_and_checker() {
    use crate::storage::FileStorage;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
    };
    fn hash(b: &[u8]) -> String {
        format!("{:x}", Sha256::digest(b))
    }
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_JFS_LIFECYCLE_EVIDENCE")
            .expect("fresh evidence directory required"),
    );
    assert!(root.is_dir());
    let receipt_path = root.join("receipt.txt");
    assert!(!receipt_path.exists());
    let tools =
        PathBuf::from(std::env::var_os("JFS_TOOLS").expect("native jfsutils tools required"));
    let sources = [
        ("src/lib.rs", include_bytes!("lib.rs").as_slice()),
        (
            "src/fs_jfs_edit_rollover.rs",
            include_bytes!("fs_jfs_edit_rollover.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_namespace.rs",
            include_bytes!("fs_jfs_edit_namespace.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_rename.rs",
            include_bytes!("fs_jfs_edit_rename.rs").as_slice(),
        ),
        ("src/fs_file.rs", include_bytes!("fs_file.rs").as_slice()),
        ("src/fs_jfs.rs", include_bytes!("fs_jfs.rs").as_slice()),
        (
            "src/fs_jfs_audit.rs",
            include_bytes!("fs_jfs_audit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_tree.rs",
            include_bytes!("fs_jfs_tree.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit.rs",
            include_bytes!("fs_jfs_edit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_journal.rs",
            include_bytes!("fs_jfs_edit_journal.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_allocation.rs",
            include_bytes!("fs_jfs_edit_allocation.rs").as_slice(),
        ),
        ("src/fs_core.rs", include_bytes!("fs_core.rs").as_slice()),
        ("src/storage.rs", include_bytes!("storage.rs").as_slice()),
        (
            "src/fs_storage.rs",
            include_bytes!("fs_storage.rs").as_slice(),
        ),
        (
            "tests/fixtures/jfs_clean.rs",
            include_bytes!("../tests/fixtures/jfs_clean.rs").as_slice(),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ];
    let mut receipt = String::from(
        "status=running\nprofile=staged-native-UID-and-dense-COW; native INODE/ROOT/FREE inline redo lifecycle/recovery; full write family/public exports unfinished\nmodel=normal and partial home/error plus recovery home/error restart; actual FileStorage sync_all; not physical power loss\n",
    );
    for (name, baked) in sources {
        assert!(
            fs::read(name).unwrap() == baked,
            "compiled source mismatch: {name}"
        );
        let dst = root.join("source").join(name);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::write(dst, baked).unwrap();
        receipt.push_str(&format!("source={name} sha256={}\n", hash(baked)));
    }
    let binary = std::env::current_exe().unwrap();
    let binary_hash = hash(&fs::read(&binary).unwrap());
    receipt.push_str(&format!(
        "binary={} sha256={binary_hash}\n",
        binary.display()
    ));
    let bindings = ["mkfs.jfs", "fsck.jfs", "jfs_debugfs"].map(|name| {
        let p = tools.join(name);
        let digest = hash(&fs::read(&p).unwrap());
        receipt.push_str(&format!("tool={} sha256={digest}\n", p.display()));
        (p, digest)
    });
    let run = |label: &str, name: &str, args: &[&str], input: Option<&str>| {
        let mut command = Command::new(tools.join(name));
        command
            .args(args)
            .current_dir(&root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        fs::write(root.join(format!("{label}.stdout")), &out.stdout).unwrap();
        fs::write(root.join(format!("{label}.stderr")), &out.stderr).unwrap();
        fs::write(
            root.join(format!("{label}.argv")),
            format!(
                "{} {args:?} stdin={input:?} exit={}\n",
                tools.join(name).display(),
                out.status
            ),
        )
        .unwrap();
        assert!(out.status.success(), "{label}: {:?}", out.stderr);
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .to_lowercase();
        assert!(
            !message.contains("logredo failed") && !message.contains("rc=-"),
            "{label}: {message}"
        );
        out
    };
    let original = root.join("source.img");
    fs::File::create(&original)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    run(
        "format",
        "mkfs.jfs",
        &["-q", original.to_str().unwrap()],
        None,
    );
    let mut source = fs::read(&original).unwrap();
    fixture::insert_native(&mut source);
    fixture::small_hardlink(&mut source);
    fs::write(&original, &source).unwrap();
    run(
        "source-check",
        "fsck.jfs",
        &["-n", original.to_str().unwrap()],
        None,
    );
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let storage = FileStorage::open(&original).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    let node = &decoded.nodes[&4];
    let home = pxd(&node.raw, 16, decoded.geometry.blocks).unwrap().start * 4096 + 4 * 512;
    let mut binding = [0u8; 16];
    binding.copy_from_slice(&decoded.header[136..152]);
    drop((decoded, storage));
    assert_eq!(r.memory.used(), 0);
    struct Backend {
        file: FileStorage,
        home: u64,
        fail: bool,
        writes: usize,
        stop_at: Option<u64>,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            self.file.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.file.read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail && at == self.home + 37 {
                self.fail = false;
                self.file.write_at(at, &bytes[..9.min(bytes.len())])?;
                return Err(io::Error::other("modeled partial UID word"));
            }
            let mut n = 37.min(bytes.len());
            if self
                .stop_at
                .is_some_and(|stop| at <= stop && stop < at + n as u64)
            {
                n = (self.stop_at.unwrap() - at) as usize;
                if n > 0 {
                    self.file.write_at(at, &bytes[..n])?;
                }
                self.stop_at = None;
                return Err(io::Error::other("modeled native activation prefix"));
            }
            self.file.write_at(at, &bytes[..n])
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    let mut normal_hash = None;
    for (label, cut, recovery_cut) in [
        ("normal", false, false),
        ("home-error", true, false),
        ("recovery-error", true, true),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&original, &image).unwrap();
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: cut,
            writes: 0,
            stop_at: None,
        };
        let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
        let result = session.write_uid(4, 0x12345678, &r);
        if cut {
            assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
        } else {
            result.unwrap();
        }
        drop(session);
        drop(storage);
        if cut {
            let native = root.join(format!("{label}-native-replay.img"));
            fs::copy(&image, &native).unwrap();
            let replay = run(
                &format!("{label}-native-replay"),
                "fsck.jfs",
                &["--replay_journal_only", native.to_str().unwrap()],
                None,
            );
            assert!(String::from_utf8_lossy(&replay.stdout).contains("Filesystem is clean"));
            let oracle = FileStorage::open(&native).unwrap();
            let native_index = inspect(&oracle, limits, audit, &r).unwrap();
            assert_eq!(le32(&native_index.nodes[&4].raw, 44), 0x12345678);
            drop((native_index, oracle));
            assert_eq!(r.memory.used(), 0);
        }
        if cut {
            let mut storage = Backend {
                file: FileStorage::open(&image).unwrap(),
                home,
                fail: recovery_cut,
                writes: 0,
                stop_at: None,
            };
            let result = journal::recover_uid(&mut storage, binding, limits, audit, &r, &r);
            if recovery_cut {
                assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
            } else {
                result.unwrap();
            }
            drop(storage);
            if recovery_cut {
                let mut storage = Backend {
                    file: FileStorage::open(&image).unwrap(),
                    home,
                    fail: false,
                    writes: 0,
                    stop_at: None,
                };
                journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
                drop(storage);
            }
        }
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: None,
        };
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, 0);
        let decoded = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(le32(&decoded.nodes[&4].raw, 44), 0x12345678);
        assert_eq!(le32(&decoded.nodes[&4].raw, 40), 2);
        drop((decoded, storage));
        assert_eq!(r.memory.used(), 0);
        let after = fs::read(&image).unwrap();
        let log_start = u64::from(le32(&source[32768..36864], 76));
        for (at, (before, now)) in source.iter().zip(&after).enumerate() {
            let at = at as u64;
            let allowed = [
                (32768 + 40, 4),
                (32768 + 68, 4),
                (61440 + 40, 4),
                (61440 + 68, 4),
                ((log_start + 1) * 4096, 4096),
                ((log_start + 2) * 4096, 4096),
                (home + 44, 4),
            ]
            .iter()
            .any(|(start, n)| *start <= at && at < *start + *n);
            if !allowed {
                assert_eq!(before, now, "native outside-byte mutation at {at}");
            }
        }
        let digest = hash(&after);
        if let Some(expected) = &normal_hash {
            assert_eq!(&digest, expected);
        } else {
            normal_hash = Some(digest.clone());
        }
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let debug = run(
            &format!("{label}-debug"),
            "jfs_debugfs",
            &[image.to_str().unwrap()],
            Some("inode 4\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&debug.stdout).contains("305419896"));
        assert_eq!(hash(&fs::read(&image).unwrap()), digest);
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={digest} uid=305419896 hardlinks=2 own_completed_recovery_writes=0 native_fsck=clean native_debugger_uid=exact outside_fields_payload_allocation_bytes=unchanged native_interrupted_copy_replay=checked-for-error-cases\n",hash(&source)));
    }
    let log_start = u64::from(le32(&source[32768..36864], 76));
    let old_uid = le32(&source, home as usize + 44);
    for (label, stop) in [
        ("bootstrap-primary-serial", 32768 + 69),
        ("bootstrap-log-activation", (log_start + 1) * 4096 + 73),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&original, &image).unwrap();
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: Some(stop),
        };
        let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
        assert_eq!(
            session.write_uid(4, 0x12345678, &r).unwrap_err().kind,
            ErrorKind::UncertainDurability
        );
        drop(session);
        drop(storage);
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: None,
        };
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        let writes = storage.writes;
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, writes);
        let decoded = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(le32(&decoded.nodes[&4].raw, 44), old_uid);
        assert_eq!(le32(&decoded.nodes[&4].raw, 40), 2);
        drop((decoded, storage));
        assert_eq!(r.memory.used(), 0);
        let after = fs::read(&image).unwrap();
        for (at, (before, now)) in source.iter().zip(&after).enumerate() {
            let at = at as u64;
            let allowed = [
                (32768 + 40, 4),
                (32768 + 68, 4),
                (61440 + 40, 4),
                (61440 + 68, 4),
                ((log_start + 1) * 4096, 4096),
                ((log_start + 2) * 4096, 4096),
            ]
            .iter()
            .any(|(start, n)| *start <= at && at < *start + *n);
            if !allowed {
                assert_eq!(before, now, "aborted transaction changed byte {at}");
            }
        }
        let digest = hash(&after);
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let debug = run(
            &format!("{label}-debug"),
            "jfs_debugfs",
            &[image.to_str().unwrap()],
            Some("inode 4\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&debug.stdout).contains(&format!("di_uid:\t\t{old_uid}")));
        assert_eq!(hash(&fs::read(&image).unwrap()), digest);
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={digest} uid={old_uid} hardlinks=2 own_completed_recovery_writes=0 native_fsck=clean native_debugger_uid=exact payload_allocation_all_home_inode_bytes=unchanged profile=uncommitted-abort-no-independent-native-interrupted-replay\n",hash(&source)));
    }
    // Independent native checker evidence for the allocation after-image
    // codec only: this authored fixture deliberately bypasses the journal.
    // It must never be described as an owned COW publication operation.
    let image = root.join("allocation-cow-codec-fixture.img");
    fs::copy(&original, &image).unwrap();
    let mut storage = FileStorage::open(&image).unwrap();
    let baseline = inspect(&storage, limits, audit, &r).unwrap();
    let node = &baseline.nodes[&6];
    assert_eq!(node.runs.len(), 1);
    let old = node.runs[0].physical.start;
    let new = (112..baseline.geometry.mapped)
        .find(|block| !baseline.bitmap[*block as usize])
        .unwrap();
    let plan = allocation::prepare_map(
        &Borrowed {
            storage: &storage,
            length: storage.len().unwrap(),
            resources: &r,
        },
        &baseline,
        &[(old, false), (new, true)],
        &r,
    )
    .unwrap();
    let mut raw = node.raw.clone();
    fixture::pxd(&mut raw, 224 + 40, new, 1);
    let inode_at = pxd(&node.raw, 16, baseline.geometry.blocks).unwrap().start * 4096 + 6 * 512;
    let mut patches: Vec<_> = plan
        .pages
        .iter()
        .map(|page| (page.at, page.after.to_vec()))
        .collect();
    patches.push((inode_at, raw.clone()));
    let overlay = Overlay {
        source: Borrowed {
            storage: &storage,
            length: storage.len().unwrap(),
            resources: &r,
        },
        patches: &patches,
    };
    let resulting = decode(&overlay, limits, &r).unwrap();
    assert!(audit_decoded(&resulting, audit, &r).unwrap().is_clean());
    drop(resulting);
    let mut payload = [0u8; 4096];
    storage
        .read_exact_at(old * 4096, &mut payload[..7])
        .unwrap();
    assert_eq!(&payload[..7], b"nested!");
    drop((patches, baseline));
    journal::write_checked(&mut storage, new * 4096, &payload, &r, &r).unwrap();
    storage.flush().unwrap();
    for page in &plan.pages {
        let mut observed = [0; 4096];
        storage.read_exact_at(page.at, &mut observed).unwrap();
        assert_eq!(observed, page.before);
        journal::write_checked(&mut storage, page.at, &page.after, &r, &r).unwrap();
    }
    journal::write_checked(&mut storage, inode_at, &raw, &r, &r).unwrap();
    storage.flush().unwrap();
    drop((plan, storage));
    assert_eq!(r.memory.used(), 0);
    let before_native = hash(&fs::read(&image).unwrap());
    let checked = run(
        "allocation-cow-codec-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    let debug = run(
        "allocation-cow-codec-xtree",
        "jfs_debugfs",
        &[image.to_str().unwrap()],
        Some("xtree 6\n\nx\nquit\n"),
    );
    assert!(String::from_utf8_lossy(&debug.stdout).contains(&format!("xad.addr\t  {new}")));
    let storage = FileStorage::open(&image).unwrap();
    assert!(inspect(&storage, limits, audit, &r).is_ok());
    let mut actual = [0; 7];
    storage.read_exact_at(new * 4096, &mut actual).unwrap();
    assert_eq!(&actual, b"nested!");
    drop(storage);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(hash(&fs::read(&image).unwrap()), before_native);
    receipt.push_str(&format!("case=allocation-cow-codec-fixture output_sha256={before_native} old_block={old} new_block={new} native_fsck=clean native_xtree_address=exact model_payload=exact codec-only-direct-fixture-no-journal-publication\n"));
    let image = root.join("allocation-native-redo-codec-fixture.img");
    fs::copy(&original, &image).unwrap();
    let mut storage = FileStorage::open(&image).unwrap();
    let baseline = inspect(&storage, limits, audit, &r).unwrap();
    let old = baseline.nodes[&6].runs[0].physical.start;
    let new = (112..baseline.geometry.mapped)
        .find(|block| !baseline.bitmap[*block as usize])
        .unwrap();
    drop(baseline);
    let mut payload = [0; 4096];
    storage
        .read_exact_at(old * 4096, &mut payload[..7])
        .unwrap();
    assert_eq!(&payload[..7], b"nested!");
    journal::write_checked(&mut storage, new * 4096, &payload, &r, &r).unwrap();
    storage.flush().unwrap();
    journal::author_cow_log_fixture(&mut storage, 6, new, limits, audit, &r).unwrap();
    journal::prove_cow_fixture(&storage, limits, audit, &r).unwrap();
    drop(storage);
    let replay = run(
        "allocation-native-redo-codec-replay",
        "fsck.jfs",
        &["--replay_journal_only", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&replay.stdout).contains("Filesystem is clean"));
    let storage = FileStorage::open(&image).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].runs[0].physical.start, new);
    assert!(!decoded.bitmap[old as usize] && decoded.bitmap[new as usize]);
    assert_eq!(decoded.nodes[&6].raw[224 + 32] & 3, 0);
    let mut actual = [0; 7];
    storage.read_exact_at(new * 4096, &mut actual).unwrap();
    assert_eq!(&actual, b"nested!");
    drop((decoded, storage));
    assert_eq!(r.memory.used(), 0);
    let digest = hash(&fs::read(&image).unwrap());
    let checked = run(
        "allocation-native-redo-codec-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    assert_eq!(hash(&fs::read(&image).unwrap()), digest);
    receipt.push_str(&format!("case=allocation-native-redo-codec-fixture output_sha256={digest} old_block={old} new_block={new} native_interrupted_replay=diagnostic-clean native_fsck=clean native_XAD_NEW=allocated-and-cleared native_UPDATEMAP_FREE=freed model_payload=exact codec-only-direct-native-dirty-fixture-no-owned-COW-publication\n"));
    let image = root.join("allocation-native-old-root-overlap-fixture.img");
    fs::copy(&original, &image).unwrap();
    let mut storage = FileStorage::open(&image).unwrap();
    let baseline = inspect(&storage, limits, audit, &r).unwrap();
    let old = baseline.nodes[&6].runs[0].physical.start;
    let new = (112..baseline.geometry.mapped)
        .find(|block| !baseline.bitmap[*block as usize])
        .unwrap();
    drop(baseline);
    let mut payload = [0; 4096];
    storage
        .read_exact_at(old * 4096, &mut payload[..7])
        .unwrap();
    assert_eq!(&payload[..7], b"nested!");
    journal::write_checked(&mut storage, new * 4096, &payload, &r, &r).unwrap();
    storage.flush().unwrap();
    journal::author_cow_overlap_fixture(&mut storage, 6, new, limits, audit, &r).unwrap();
    drop(storage);
    let replay = run(
        "allocation-native-old-root-overlap-replay",
        "fsck.jfs",
        &["--replay_journal_only", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&replay.stdout).contains("Filesystem is clean"));
    let storage = FileStorage::open(&image).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].runs[0].physical.start, new);
    assert!(!decoded.bitmap[old as usize] && decoded.bitmap[new as usize]);
    assert_eq!(decoded.nodes[&6].raw[224 + 32] & 3, 0);
    let mut actual = [0; 7];
    storage.read_exact_at(new * 4096, &mut actual).unwrap();
    assert_eq!(&actual, b"nested!");
    drop((decoded, storage));
    assert_eq!(r.memory.used(), 0);
    let digest = hash(&fs::read(&image).unwrap());
    let checked = run(
        "allocation-native-old-root-overlap-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    assert_eq!(hash(&fs::read(&image).unwrap()), digest);
    receipt.push_str(&format!("case=allocation-native-old-root-overlap-fixture output_sha256={digest} old_block={old} new_block={new} native_interrupted_replay=diagnostic-clean native_fsck=clean native_XAD_NEW=allocated-and-cleared native_UPDATEMAP_FREE=freed model_payload=exact codec-only-redundant-native-ROOT-latest-line-proof-intact-old-home-no-owned-publication\n"));
    struct CowPayload {
        id: ObjectId,
        size: u64,
    }
    impl FileRead for CowPayload {
        fn identity(&self) -> &ObjectId {
            &self.id
        }
        fn len(&self) -> u64 {
            self.size
        }
        fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
            r.cancellation.check()?;
            let at = usize::try_from(at).map_err(|_| bad("native COW source offset"))?;
            if at as u64 >= self.size {
                return Ok(0);
            }
            let n = out.len().min(self.size as usize - at).min(3);
            if self.size == 7 {
                out[..n].copy_from_slice(&b"changed"[at..at + n]);
            } else {
                for (i, byte) in out[..n].iter_mut().enumerate() {
                    *byte = ((at + i) * 31 % 251) as u8;
                }
            }
            Ok(n)
        }
        fn visit_extents(
            &self,
            _: &Resources,
            _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
        ) -> Result<()> {
            Err(Error::new(
                ErrorKind::Unsupported,
                "native fixture payload only",
            ))
        }
    }
    let mut cow_normal = None;
    for (label, cut, recovery_cut) in [
        ("owned-cow-normal", false, false),
        ("owned-cow-home-error", true, false),
        ("owned-cow-recovery-error", true, true),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&original, &image).unwrap();
        let raw = FileStorage::open(&image).unwrap();
        let indexed = inspect(&raw, limits, audit, &r).unwrap();
        let node = &indexed.nodes[&6];
        let old = node.runs[0].physical.start;
        let new = (112..indexed.geometry.mapped)
            .find(|block| !indexed.bitmap[*block as usize])
            .unwrap();
        let home = pxd(&node.raw, 16, indexed.geometry.blocks).unwrap().start * 4096 + 6 * 512;
        let inode_before = node.raw.clone();
        drop(indexed);
        let mut storage = Backend {
            file: raw,
            home,
            fail: false,
            writes: 0,
            stop_at: cut.then_some(home + 270),
        };
        let file: Arc<dyn FileRead> = Arc::new(CowPayload {
            size: 7,
            id: ObjectId {
                source: 456,
                generation: 0,
                native: vec![2],
            },
        });
        let result = {
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            let result = session.replace_recorded_run(6, new, file, &r);
            if cut {
                assert!(session.uncertain && session.cow_pending);
                assert_eq!(
                    session.write_uid(4, 777, &r).unwrap_err().kind,
                    ErrorKind::UncertainDurability
                );
            } else {
                assert!(!session.uncertain && !session.cow_pending);
            }
            result
        };
        if cut {
            assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
            let interrupted = root.join(format!("{label}-native-replay.img"));
            fs::copy(&image, &interrupted).unwrap();
            let native = run(
                &format!("{label}-native-replay"),
                "fsck.jfs",
                &["--replay_journal_only", interrupted.to_str().unwrap()],
                None,
            );
            assert!(String::from_utf8_lossy(&native.stdout).contains("Filesystem is clean"));
            let independently_replayed = FileStorage::open(&interrupted).unwrap();
            let verified = inspect(&independently_replayed, limits, audit, &r).unwrap();
            assert_eq!(verified.nodes[&6].runs[0].physical.start, new);
            assert!(!verified.bitmap[old as usize] && verified.bitmap[new as usize]);
            let mut actual = [0; 7];
            independently_replayed
                .read_exact_at(new * 4096, &mut actual)
                .unwrap();
            assert_eq!(&actual, b"changed");
            drop((verified, independently_replayed));
            if recovery_cut {
                storage.stop_at = Some(home + 270);
                assert_eq!(
                    journal::recover_cow(&mut storage, binding, limits, audit, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
            }
            journal::recover_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
        } else {
            result.unwrap();
        }
        let indexed = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(indexed.nodes[&6].runs[0].physical.start, new);
        assert!(!indexed.bitmap[old as usize] && indexed.bitmap[new as usize]);
        assert_eq!(&indexed.nodes[&6].raw[..256], &inode_before[..256]);
        assert_eq!(&indexed.nodes[&6].raw[272..], &inode_before[272..]);
        assert_eq!(le32(&indexed.nodes[&4].raw, 40), 2);
        assert_eq!(le32(&indexed.nodes[&6].raw, 40), 2);
        drop(indexed);
        storage.writes = 0;
        journal::recover_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, 0);
        let mut actual = [0; 4096];
        storage.read_exact_at(new * 4096, &mut actual).unwrap();
        assert_eq!(&actual[..7], b"changed");
        assert!(actual[7..].iter().all(|byte| *byte == 0));
        drop(storage);
        let output_hash = hash(&fs::read(&image).unwrap());
        if let Some(expected) = &cow_normal {
            assert_eq!(&output_hash, expected);
        } else {
            cow_normal = Some(output_hash.clone());
        }
        let native = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&native.stdout).contains("Filesystem is clean"));
        let dump = run(
            &format!("{label}-xtree"),
            "jfs_debugfs",
            &[image.to_str().unwrap()],
            Some("xtree 6\n\nx\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&dump.stdout).contains(&format!("xad.addr\t  {new}")));
        assert_eq!(hash(&fs::read(&image).unwrap()), output_hash);
        assert_eq!(r.memory.used(), 0);
        receipt.push_str(&format!("case={label} output_sha256={output_hash} old_block={old} new_block={new} owned_COW=one-recorded-block-deferred-short-read native_fsck=clean native_xtree_address=exact payload=changed-zero-tail metadata_hardlinks=preserved repeated_recovery=zero-writes native_interrupted_replay={}\n",if cut {"diagnostic-clean-exact-payload"} else {"not-applicable"}));
    }
    {
        let image = root.join("owned-cow-three-blocks.img");
        fn fixture_write(storage: &mut dyn Storage, at: u64, bytes: &[u8]) {
            let mut position = 0;
            while position < bytes.len() {
                let n = storage
                    .write_at(at + position as u64, &bytes[position..])
                    .unwrap();
                assert!(n > 0 && n <= bytes.len() - position);
                position += n;
            }
        }
        fs::copy(&original, &image).unwrap();
        let mut storage = FileStorage::open(&image).unwrap();
        let indexed = inspect(&storage, limits, audit, &r).unwrap();
        let mut inode = indexed.nodes[&6].raw.clone();
        let home = pxd(&inode, 16, indexed.geometry.blocks).unwrap().start * 4096 + 6 * 512;
        let source = Borrowed {
            storage: &storage,
            length: storage.len().unwrap(),
            resources: &r,
        };
        let maps =
            allocation::prepare_map(&source, &indexed, &[(113, true), (114, true)], &r).unwrap();
        drop(indexed);
        for page in &maps.pages {
            fixture_write(&mut storage, page.at, &page.after);
        }
        drop(maps);
        fixture::p64(&mut inode, 24, 9000);
        fixture::p64(&mut inode, 32, 3);
        inode[224..].copy_from_slice(&fixture::xt(&[(0, 112, 3, 0)], false, None));
        fixture_write(&mut storage, home, &inode);
        fixture_write(&mut storage, 112 * 4096, &vec![0xa7; 3 * 4096]);
        storage.flush().unwrap();
        drop(storage);
        let before = fs::read(&image).unwrap();
        let before_hash = hash(&before);
        fs::write(root.join("owned-cow-three-blocks-source.img"), &before).unwrap();
        let checked = run(
            "owned-cow-three-blocks-source-check",
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        assert_eq!(hash(&fs::read(&image).unwrap()), before_hash);
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: Some(home + 270),
        };
        let file: Arc<dyn FileRead> = Arc::new(CowPayload {
            size: 9000,
            id: ObjectId {
                source: 456,
                generation: 0,
                native: vec![3],
            },
        });
        let plan = journal::prepare_cow(
            &storage,
            journal::CowRequest {
                inode: 6,
                new: 120,
                file,
            },
            limits,
            audit,
            &r,
            &r,
        )
        .unwrap();
        assert_eq!(
            journal::publish_cow(&mut storage, plan, &r, &r)
                .unwrap_err()
                .kind,
            ErrorKind::UncertainDurability
        );
        let replay = root.join("owned-cow-three-blocks-native-replay.img");
        fs::copy(&image, &replay).unwrap();
        let checked = run(
            "owned-cow-three-blocks-native-replay",
            "fsck.jfs",
            &["--replay_journal_only", replay.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        journal::recover_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
        drop(storage);
        for (label, path) in [
            ("owned-cow-three-blocks", &image),
            ("owned-cow-three-blocks-replayed", &replay),
        ] {
            let raw = FileStorage::open(path).unwrap();
            let indexed = inspect(&raw, limits, audit, &r).unwrap();
            assert_eq!(indexed.nodes[&6].runs[0].physical.start, 120);
            assert_eq!(indexed.nodes[&6].runs[0].physical.count, 3);
            assert_eq!(indexed.nodes[&6].length, 9000);
            assert_eq!(le32(&indexed.nodes[&6].raw, 40), 2);
            for old in 112..115 {
                assert!(!indexed.bitmap[old]);
            }
            for new in 120..123 {
                assert!(indexed.bitmap[new]);
            }
            drop((indexed, raw));
            let after = fs::read(path).unwrap();
            for (i, byte) in after[120 * 4096..120 * 4096 + 9000].iter().enumerate() {
                assert_eq!(*byte, (i * 31 % 251) as u8);
            }
            assert!(
                after[120 * 4096 + 9000..123 * 4096]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert_eq!(
                &after[112 * 4096..115 * 4096],
                &before[112 * 4096..115 * 4096]
            );
            let digest = hash(&after);
            let checked = run(
                &format!("{label}-check"),
                "fsck.jfs",
                &["-n", path.to_str().unwrap()],
                None,
            );
            assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
            let dump = run(
                &format!("{label}-xtree"),
                "jfs_debugfs",
                &[path.to_str().unwrap()],
                Some("xtree 6\n\nx\nquit\n"),
            );
            assert!(String::from_utf8_lossy(&dump.stdout).contains("xad.addr\t  120"));
            assert_eq!(hash(&fs::read(path).unwrap()), digest);
            receipt.push_str(&format!("case={label} source_sha256={before_hash} output_sha256={digest} old_block=112 new_block=120 blocks=3 payload_bytes=9000 payload_model=exact zero_tail=exact metadata_hardlinks=preserved native_fsck=clean native_xtree_address=exact native_interrupted_replay=diagnostic-clean\n"));
        }
        assert_eq!(r.memory.used(), 0);
    }
    // Independently encoded external regular xtree source; no editor capability
    // follows from this source-only native checker gate.
    let external_source = root.join("external-regular-source.img");
    fs::copy(&original, &external_source).unwrap();
    {
        let mut raw = FileStorage::open(&external_source).unwrap();
        let decoded = inspect(&raw, limits, audit, &r).unwrap();
        let mut changes = vec![(112, false), (130, true)];
        changes.extend((0..17).map(|index| (150 + index * 2, true)));
        assert!(
            changes
                .iter()
                .all(|&(block, allocated)| decoded.bitmap[block as usize] != allocated)
        );
        let maps = allocation::prepare_map(
            &Borrowed {
                storage: &raw,
                length: raw.len().unwrap(),
                resources: &r,
            },
            &decoded,
            &changes,
            &r,
        )
        .unwrap();
        let home = pxd(&decoded.nodes[&6].raw, 16, decoded.geometry.blocks)
            .unwrap()
            .start as usize
            * 4096
            + 6 * 512;
        drop(decoded);
        for patch in &maps.pages {
            journal::write_checked(&mut raw, patch.at, &patch.after, &r, &r).unwrap();
        }
        raw.flush().unwrap();
        drop((maps, raw));
        let mut bytes = fs::read(&external_source).unwrap();
        let runs: Vec<_> = (0..17u64)
            .map(|logical| (logical, 150 + logical * 2, 1, 0))
            .collect();
        bytes[home + 224..home + 512].copy_from_slice(&fixture::xt(&[(0, 130, 1, 0)], true, None));
        bytes[130 * 4096..131 * 4096].copy_from_slice(&fixture::xt(&runs, false, Some(130)));
        fixture::p64(&mut bytes, home + 24, 16 * 4096 + 123);
        fixture::p64(&mut bytes, home + 32, 18);
        for (logical, physical, _, _) in &runs {
            bytes[*physical as usize * 4096..(*physical as usize + 1) * 4096]
                .fill(0x40 + *logical as u8);
        }
        fs::write(&external_source, &bytes).unwrap();
        let before_check = hash(&bytes);
        let checked = run(
            "external-regular-source-check",
            "fsck.jfs",
            &["-n", external_source.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        assert_eq!(hash(&fs::read(&external_source).unwrap()), before_check);
        let raw = FileStorage::open(&external_source).unwrap();
        let decoded = inspect(&raw, limits, audit, &r).unwrap();
        assert_eq!(decoded.nodes[&6].runs.len(), 17);
        assert_eq!(
            decoded.nodes[&6].pages,
            [super::Physical {
                start: 130,
                count: 1
            }]
        );
        assert_eq!(super::le64(&decoded.nodes[&6].raw, 32), 18);
        assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
        receipt.push_str(&format!("case=external-regular-source source_sha256={before_check} native_fsck=clean-and-readonly source_data_runs=17 source_metadata_pages=1 source_nblocks=18 source_isize=65659 source_hardlinks=2 source-only-no-external-edit-acceptance native-map-afterimages=checked-helper native-xtree-and-payload=independent-fixture\n"));
    }
    // Native formatter baseline plus explicitly staged sparse/unwritten inode
    // and bitmap afterimages; independent fsck validates the source before use.
    let fragmented_source = root.join("owned-fragmented-source.img");
    fs::copy(&original, &fragmented_source).unwrap();
    {
        let mut raw = FileStorage::open(&fragmented_source).unwrap();
        let decoded = inspect(&raw, limits, audit, &r).unwrap();
        let maps = allocation::prepare_map(
            &Borrowed {
                storage: &raw,
                length: raw.len().unwrap(),
                resources: &r,
            },
            &decoded,
            &[(114, true), (116, true), (117, true)],
            &r,
        )
        .unwrap();
        let home = pxd(&decoded.nodes[&6].raw, 16, decoded.geometry.blocks)
            .unwrap()
            .start as usize
            * 4096
            + 6 * 512;
        drop(decoded);
        for patch in &maps.pages {
            let mut written = 0;
            while written < patch.after.len() {
                let n = raw
                    .write_at(patch.at + written as u64, &patch.after[written..])
                    .unwrap();
                assert!(n != 0 && n <= patch.after.len() - written);
                written += n;
            }
        }
        raw.flush().unwrap();
        drop((maps, raw));
        let mut bytes = fs::read(&fragmented_source).unwrap();
        fixture::p64(&mut bytes, home + 24, 5 * 4096 + 123);
        fixture::p64(&mut bytes, home + 32, 4);
        bytes[home + 224..home + 512].copy_from_slice(&fixture::xt(
            &[(0, 112, 1, 0), (2, 114, 1, 8), (4, 116, 2, 0)],
            false,
            None,
        ));
        bytes[112 * 4096..113 * 4096].fill(0xa1);
        bytes[114 * 4096..115 * 4096].fill(0xc3);
        bytes[116 * 4096..118 * 4096].fill(0xb2);
        fs::write(&fragmented_source, &bytes).unwrap();
        let checked = run(
            "owned-fragmented-source-check",
            "fsck.jfs",
            &["-n", fragmented_source.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let raw = FileStorage::open(&fragmented_source).unwrap();
        let decoded = inspect(&raw, limits, audit, &r).unwrap();
        assert_eq!(decoded.nodes[&6].runs.len(), 3);
        assert!(decoded.nodes[&6].runs[1].unwritten);
        assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
    }
    for (label, size, baseline, range_offset) in [
        ("owned-dense-grow-two", 4200u64, original.clone(), None),
        ("owned-dense-grow-sixteen", 65536, original.clone(), None),
        (
            "owned-dense-shrink",
            7,
            root.join("owned-cow-three-blocks.img"),
            None,
        ),
        (
            "owned-range-cross-boundary",
            9090,
            root.join("owned-cow-three-blocks.img"),
            Some(4090u64),
        ),
        (
            "owned-range-zero-gap",
            17000,
            root.join("owned-cow-three-blocks.img"),
            Some(12000),
        ),
        ("owned-dense-empty", 0, original.clone(), None),
        (
            "owned-fragmented-range",
            5 * 4096 + 123,
            fragmented_source.clone(),
            Some(4090),
        ),
        (
            "owned-fragmented-replace",
            9000,
            fragmented_source.clone(),
            None,
        ),
        ("owned-fragmented-empty", 0, fragmented_source.clone(), None),
        (
            "owned-external-replace",
            9000,
            external_source.clone(),
            None,
        ),
        (
            "owned-external-range",
            16 * 4096 + 123,
            external_source.clone(),
            Some(4090),
        ),
        ("owned-external-empty", 0, external_source.clone(), None),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&baseline, &image).unwrap();
        let before = fs::read(&image).unwrap();
        let raw = FileStorage::open(&image).unwrap();
        let decoded = inspect(&raw, limits, audit, &r).unwrap();
        let node = &decoded.nodes[&6];
        let old = node.runs[0].physical;
        let old_runs = node.runs.clone();
        let old_pages = node.pages.clone();
        let old_blocks: u64 = old_runs.iter().map(|run| run.physical.count).sum::<u64>()
            + old_pages.iter().map(|page| page.count).sum::<u64>();
        let old_description = old_runs
            .iter()
            .map(|run| {
                format!(
                    "{}:{}:{}:{}",
                    run.logical,
                    run.physical.start,
                    run.physical.count,
                    if run.unwritten {
                        "unwritten"
                    } else {
                        "recorded"
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let prior = node.raw.clone();
        let home = pxd(&node.raw, 16, decoded.geometry.blocks).unwrap().start * 4096 + 6 * 512;
        let count = size.div_ceil(4096);
        let new = if count == 0 {
            0
        } else {
            (112..decoded.geometry.mapped - count)
                .find(|start| (*start..*start + count).all(|block| !decoded.bitmap[block as usize]))
                .unwrap()
        };
        drop(decoded);
        let mut storage = Backend {
            file: raw,
            home,
            fail: false,
            writes: 0,
            stop_at: Some(home + 270),
        };
        let file: Arc<dyn FileRead> = Arc::new(CowPayload {
            size: if range_offset.is_some() { 5000 } else { size },
            id: ObjectId {
                source: 456,
                generation: 0,
                native: vec![size as u8],
            },
        });
        let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
        let result = if let Some(offset) = range_offset {
            session.replace_dense_range(6, new, offset, file, &r)
        } else {
            session.replace_dense_file(6, new, file, &r)
        };
        assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
        assert!(session.cow_pending && session.uncertain);
        drop(session);
        let replay = root.join(format!("{label}-native-replay.img"));
        fs::copy(&image, &replay).unwrap();
        let checked = run(
            &format!("{label}-native-replay"),
            "fsck.jfs",
            &["--replay_journal_only", replay.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        journal::recover_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
        drop(storage);
        for (suffix, path) in [("owned", &image), ("native", &replay)] {
            let raw = FileStorage::open(path).unwrap();
            let decoded = inspect(&raw, limits, audit, &r).unwrap();
            let node = &decoded.nodes[&6];
            assert_eq!(node.length, size);
            assert_eq!(super::le64(&node.raw, 32), count);
            if count == 0 {
                assert!(node.runs.is_empty());
            } else {
                assert_eq!(node.runs[0].physical, Physical { start: new, count });
            }
            assert_eq!(&node.raw[..24], &prior[..24]);
            assert_eq!(&node.raw[40..240], &prior[40..240]);
            assert_eq!(node.raw[240], (prior[240] & !6) | 2);
            assert_eq!(node.raw[241], prior[241]);
            assert!(node.pages.is_empty());
            assert_eq!(le16(&node.raw, 242), if count == 0 { 2 } else { 3 });
            assert_eq!(&node.raw[244..256], &prior[244..256]);
            assert_eq!(&node.raw[272..], &prior[272..]);
            assert_eq!(le32(&node.raw, 40), 2);
            for run in &old_runs {
                for block in run.physical.start..run.physical.start + run.physical.count {
                    assert!(!decoded.bitmap[block as usize]);
                }
            }
            for page in &old_pages {
                assert!(!decoded.bitmap[page.start as usize]);
            }
            for block in new..new + count {
                assert!(decoded.bitmap[block as usize]);
            }
            drop((decoded, raw));
            let after = fs::read(path).unwrap();
            let payload = &after[new as usize * 4096..new as usize * 4096 + size as usize];
            if size == 7 {
                assert_eq!(payload, b"changed");
            } else {
                for (i, byte) in payload.iter().enumerate() {
                    let expected = if let Some(offset) = range_offset {
                        let at = i as u64;
                        if (offset..offset + 5000).contains(&at) {
                            ((at - offset) * 31 % 251) as u8
                        } else if at < super::le64(&prior, 24) {
                            let logical = at / 4096;
                            if let Some(run) = old_runs.iter().find(|run| {
                                (run.logical..run.logical + run.physical.count).contains(&logical)
                            }) {
                                if run.unwritten {
                                    0
                                } else {
                                    before[(run.physical.start + logical - run.logical) as usize
                                        * 4096
                                        + i % 4096]
                                }
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    } else {
                        (i * 31 % 251) as u8
                    };
                    assert_eq!(*byte, expected);
                }
            }
            assert!(
                after[new as usize * 4096 + size as usize..(new + count) as usize * 4096]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            for run in &old_runs {
                assert_eq!(
                    &after[run.physical.start as usize * 4096
                        ..(run.physical.start + run.physical.count) as usize * 4096],
                    &before[run.physical.start as usize * 4096
                        ..(run.physical.start + run.physical.count) as usize * 4096]
                );
            }
            for page in &old_pages {
                assert_eq!(
                    &after[page.start as usize * 4096..(page.start + page.count) as usize * 4096],
                    &before[page.start as usize * 4096..(page.start + page.count) as usize * 4096]
                );
            }
            let digest = hash(&after);
            let checked = run(
                &format!("{label}-{suffix}-check"),
                "fsck.jfs",
                &["-n", path.to_str().unwrap()],
                None,
            );
            assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
            let dump = run(
                &format!("{label}-{suffix}-inode"),
                "jfs_debugfs",
                &[path.to_str().unwrap()],
                Some("inode 6\nquit\n"),
            );
            let native_inode = String::from_utf8_lossy(&dump.stdout);
            assert!(native_inode.contains(&format!("di_size:\t0x{size:016x}")));
            assert!(native_inode.contains(&format!("di_nblocks:\t0x{count:016x}")));
            assert_eq!(hash(&fs::read(path).unwrap()), digest);
            receipt.push_str(&format!("case={label}-{suffix} source_sha256={} output_sha256={digest} old_block={} old_blocks={old_blocks} old_metadata_pages={} old_runs={old_description} new_block={new} new_blocks={count} payload_bytes={size} range_offset={range_offset:?} native_INODE_ROOT_FREE=accepted native_replay=diagnostic-clean native_fsck=clean full_payload_model=exact zero_tail=exact metadata_hardlinks=preserved\n",hash(&before),old.start,old_pages.len()));
        }
        assert_eq!(r.memory.used(), 0);
    }
    // Native proof that checkpoint rollover feeds the existing native UID
    // publisher/recovery on successive physical journal pages.
    let image = root.join("pristine-rollover.img");
    fs::copy(&original, &image).unwrap();
    for step in 0..3 {
        let mut storage = FileStorage::open(&image).unwrap();
        let before = fs::read(&image).unwrap();
        let log = pxd(&before, 32768 + 72, before.len() as u64 / 4096).unwrap();
        let plan =
            journal::rollover::prepare(&storage, binding, limits, audit, &r, &r, false).unwrap();
        journal::rollover::publish(&mut storage, plan, &r, &r).unwrap();
        drop(storage);
        let after = fs::read(&image).unwrap();
        assert_eq!(
            &before[..(log.start + 1) as usize * 4096],
            &after[..(log.start + 1) as usize * 4096]
        );
        let checked = run(
            &format!("rollover-{step}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        assert_eq!(hash(&fs::read(&image).unwrap()), hash(&after));
        receipt.push_str(&format!("case=pristine-rollover-{step} source_sha256={} output_sha256={} native_fsck=clean home_bytes=unchanged\n",hash(&before),hash(&after)));
    }
    // Independently place an inactive canonical SYNC at the last native log
    // page, with the unused page sequence layout derived from native geometry.
    // This exercises physical wrap into page two, not occupied-page recycling.
    let image = root.join("pristine-rollover-wrap.img");
    let mut wrap = source.clone();
    let log = pxd(&wrap, 32768 + 72, wrap.len() as u64 / 4096).unwrap();
    for number in 2..log.count as usize {
        let sequence = if number + 1 == log.count as usize {
            log.count as u32 - 3
        } else {
            number as u32 - 2
        };
        let end = if number + 1 == log.count as usize {
            44
        } else {
            8
        };
        for at in [
            (log.start as usize + number) * 4096,
            (log.start as usize + number) * 4096 + 4088,
        ] {
            fixture::p32(&mut wrap, at, sequence);
            fixture::p16(&mut wrap, at + 6, end);
        }
    }
    fixture::p32(
        &mut wrap,
        (log.start as usize + 1) * 4096 + 32,
        (log.count as u32 - 1) * 4096 + 44,
    );
    fs::write(&image, &wrap).unwrap();
    let checked = run(
        "rollover-wrap-source-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    assert_eq!(hash(&fs::read(&image).unwrap()), hash(&wrap));
    let mut storage = FileStorage::open(&image).unwrap();
    let plan = journal::rollover::prepare(&storage, binding, limits, audit, &r, &r, false).unwrap();
    journal::rollover::publish(&mut storage, plan, &r, &r).unwrap();
    drop(storage);
    let bytes = fs::read(&image).unwrap();
    assert_eq!(
        le32(&bytes, (log.start as usize + 1) * 4096 + 32),
        2 * 4096 + 44
    );
    assert_eq!(
        &bytes[..(log.start as usize + 1) * 4096],
        &wrap[..(log.start as usize + 1) * 4096]
    );
    receipt.push_str(&format!("case=pristine-physical-wrap source_sha256={} output_sha256={} old_page={} new_page=2 home_bytes=unchanged\n",hash(&wrap),hash(&bytes),log.count-1));
    let mut storage = Backend {
        file: FileStorage::open(&image).unwrap(),
        home,
        fail: true,
        writes: 0,
        stop_at: None,
    };
    let plan = journal::prepare_uid(&storage, 4, 0x44556677, limits, audit, &r, &r).unwrap();
    assert_eq!(
        journal::publish_uid(&mut storage, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    drop(storage);
    let native = root.join("pristine-rollover-native-replay.img");
    fs::copy(&image, &native).unwrap();
    run(
        "rollover-native-replay",
        "fsck.jfs",
        &["--replay_journal_only", native.to_str().unwrap()],
        None,
    );
    let mut storage = FileStorage::open(&image).unwrap();
    journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
    drop(storage);
    for (label, path) in [("rollover-owned", &image), ("rollover-native", &native)] {
        let bytes = fs::read(path).unwrap();
        assert_eq!(le32(&bytes, home as usize + 44), 0x44556677);
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", path.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let dump = run(
            &format!("{label}-inode"),
            "jfs_debugfs",
            &[path.to_str().unwrap()],
            Some("inode 4\nquit\n"),
        );
        assert!(
            String::from_utf8_lossy(&dump.stdout)
                .contains(&format!("di_uid:\t\t{}", 0x44556677u32))
        );
        assert_eq!(hash(&fs::read(path).unwrap()), hash(&bytes));
        receipt.push_str(&format!("case={label} output_sha256={} native_uid=44556677 native_replay=diagnostic-clean native_fsck=clean\n",hash(&bytes)));
    }
    assert_eq!(r.memory.used(), 0);
    let mut storage = FileStorage::open(&image).unwrap();
    let before = inspect(&storage, limits, audit, &r).unwrap();
    let old = before.nodes[&6].runs[0].physical.start;
    drop(before);
    let payload: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 901,
            generation: 0,
            native: vec![6],
        },
        fail_second: false,
        size: 9000,
    });
    let plan = journal::prepare_cow_resized(
        &storage,
        journal::CowRequest {
            inode: 6,
            new: 120,
            file: payload,
        },
        limits,
        audit,
        &r,
        &r,
    )
    .unwrap();
    journal::publish_cow(&mut storage, plan, &r, &r).unwrap();
    journal::recover_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(decoded.nodes[&6].length, 9000);
    assert_eq!(le32(&decoded.nodes[&6].raw, 40), 2);
    assert!(!decoded.bitmap[old as usize]); // old allocation released
    drop((decoded, storage));
    let bytes = fs::read(&image).unwrap();
    for (at, byte) in bytes[120 * 4096..120 * 4096 + 9000].iter().enumerate() {
        assert_eq!(*byte, (at * 31 % 251) as u8);
    }
    assert!(bytes[120 * 4096 + 9000..123 * 4096].iter().all(|b| *b == 0));
    let checked = run(
        "rollover-wrap-cow-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    let dump = run(
        "rollover-wrap-cow-inode",
        "jfs_debugfs",
        &[image.to_str().unwrap()],
        Some("inode 6\nquit\n"),
    );
    assert!(String::from_utf8_lossy(&dump.stdout).contains("di_size:\t0x0000000000002328"));
    assert_eq!(hash(&fs::read(&image).unwrap()), hash(&bytes));
    receipt.push_str(&format!("case=pristine-wrap-followed-native-COW output_sha256={} payload_bytes=9000 full_payload_model=exact zero_tail=exact hardlinks=2 native_fsck=clean\n",hash(&bytes)));
    let rotating = root.join("combined-rotating-cow-home-error.img");
    fs::copy(&original, &rotating).unwrap();
    let storage = FileStorage::open(&rotating).unwrap();
    let tree = inspect(&storage, limits, audit, &r).unwrap();
    let home6 = pxd(&tree.nodes[&6].raw, 16, tree.geometry.blocks)
        .unwrap()
        .start
        * 4096
        + 6 * 512;
    drop((tree, storage));
    let mut storage = Backend {
        file: FileStorage::open(&rotating).unwrap(),
        home: home6,
        fail: false,
        writes: 0,
        stop_at: Some(home6 + 270),
    };
    let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 994,
            generation: 0,
            native: vec![6],
        },
        size: 9000,
        fail_second: false,
    });
    let plan = journal::prepare_rotating_cow(
        &storage,
        binding,
        journal::CowRequest {
            inode: 6,
            new: 120,
            file,
        },
        (limits, audit),
        &r,
        &r,
        journal::CowMode::Replace(true),
    )
    .unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(
        journal::publish_rotating_cow(&mut storage, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    drop(storage);
    let oracle = root.join("combined-rotating-cow-native-replay.img");
    fs::copy(&rotating, &oracle).unwrap();
    run(
        "combined-rotating-cow-native-replay",
        "fsck.jfs",
        &["--replay_journal_only", oracle.to_str().unwrap()],
        None,
    );
    let mut storage = FileStorage::open(&rotating).unwrap();
    journal::recover_rotating_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
    drop(storage);
    for (label, path) in [
        ("combined-rotating-owned", &rotating),
        ("combined-rotating-native", &oracle),
    ] {
        let bytes = fs::read(path).unwrap();
        for (i, b) in bytes[120 * 4096..120 * 4096 + 9000].iter().enumerate() {
            assert_eq!(*b, (i * 31 % 251) as u8);
        }
        assert!(bytes[120 * 4096 + 9000..123 * 4096].iter().all(|b| *b == 0));
        let storage = FileStorage::open(path).unwrap();
        let tree = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(tree.nodes[&6].length, 9000);
        assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
        assert!(!tree.bitmap[112]);
        drop((tree, storage));
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", path.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let dump = run(
            &format!("{label}-inode"),
            "jfs_debugfs",
            &[path.to_str().unwrap()],
            Some("inode 6\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&dump.stdout).contains("di_size:\t0x0000000000002328"));
        assert_eq!(hash(&fs::read(path).unwrap()), hash(&bytes));
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={} payload_bytes=9000 full_payload_model=exact zero_tail=exact hardlinks=2 native_replay=diagnostic-clean native_fsck=clean combined_preflight_writes=0\n",hash(&source),hash(&bytes)));
    }
    let rotating = root.join("recycling-rotating-cow-home-error.img");
    fs::copy(&original, &rotating).unwrap();
    let mut recycling_storage = FileStorage::open(&rotating).unwrap();
    let mut aggregate = [0; 4096];
    recycling_storage
        .read_exact_at(32768, &mut aggregate)
        .unwrap();
    let log_pages = pxd(&aggregate, 72, recycling_storage.len().unwrap() / 4096)
        .unwrap()
        .count;
    let laps = 2 * (log_pages - 2) + 3;
    for step in 0..laps {
        let plan = journal::rollover::prepare_recycling(
            &recycling_storage,
            binding,
            limits,
            audit,
            &r,
            &r,
            false,
        )
        .unwrap();
        journal::rollover::publish(&mut recycling_storage, plan, &r, &r).unwrap();
        if step % 32 == 0 {
            let plan = journal::prepare_uid(
                &recycling_storage,
                4,
                0x70000000 + step as u32,
                limits,
                audit,
                &r,
                &r,
            )
            .unwrap();
            journal::publish_uid(&mut recycling_storage, plan, &r, &r).unwrap();
            journal::recover_uid(&mut recycling_storage, binding, limits, audit, &r, &r).unwrap();
        }
    }
    assert!(
        journal::rollover::prepare(&recycling_storage, binding, limits, audit, &r, &r, false)
            .is_err()
    );
    drop(recycling_storage);
    receipt.push_str(&format!("case=checkpointed-native-page-reuse ring_pages={log_pages} rotations={laps} completed_uid_histories=every32 default_pristine_rejects=passed\n"));
    let storage = FileStorage::open(&rotating).unwrap();
    let tree = inspect(&storage, limits, audit, &r).unwrap();
    let home6 = pxd(&tree.nodes[&6].raw, 16, tree.geometry.blocks)
        .unwrap()
        .start
        * 4096
        + 6 * 512;
    drop((tree, storage));
    let mut storage = Backend {
        file: FileStorage::open(&rotating).unwrap(),
        home: home6,
        fail: false,
        writes: 0,
        stop_at: Some(home6 + 270),
    };
    let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 994,
            generation: 0,
            native: vec![6],
        },
        size: 9000,
        fail_second: false,
    });
    let plan = journal::prepare_recycling_cow(
        &storage,
        binding,
        journal::CowRequest {
            inode: 6,
            new: 120,
            file,
        },
        (limits, audit),
        &r,
        &r,
        journal::CowMode::Replace(true),
    )
    .unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(
        journal::publish_rotating_cow(&mut storage, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    drop(storage);
    let oracle = root.join("recycling-rotating-cow-native-replay.img");
    fs::copy(&rotating, &oracle).unwrap();
    run(
        "recycling-rotating-cow-native-replay",
        "fsck.jfs",
        &["--replay_journal_only", oracle.to_str().unwrap()],
        None,
    );
    let mut storage = FileStorage::open(&rotating).unwrap();
    journal::recover_recycling_cow(&mut storage, binding, limits, audit, &r, &r).unwrap();
    drop(storage);
    for (label, path) in [
        ("recycling-rotating-owned", &rotating),
        ("recycling-rotating-native", &oracle),
    ] {
        let bytes = fs::read(path).unwrap();
        for (i, b) in bytes[120 * 4096..120 * 4096 + 9000].iter().enumerate() {
            assert_eq!(*b, (i * 31 % 251) as u8);
        }
        assert!(bytes[120 * 4096 + 9000..123 * 4096].iter().all(|b| *b == 0));
        let storage = FileStorage::open(path).unwrap();
        let tree = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(tree.nodes[&6].length, 9000);
        assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
        assert!(!tree.bitmap[112]);
        drop((tree, storage));
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", path.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let dump = run(
            &format!("{label}-inode"),
            "jfs_debugfs",
            &[path.to_str().unwrap()],
            Some("inode 6\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&dump.stdout).contains("di_size:\t0x0000000000002328"));
        assert_eq!(hash(&fs::read(path).unwrap()), hash(&bytes));
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={} payload_bytes=9000 full_payload_model=exact zero_tail=exact hardlinks=2 native_replay=diagnostic-clean native_fsck=clean combined_preflight_writes=0\n",hash(&source),hash(&bytes)));
    }
    let image = root.join("namespace-native-overlap-fixture.img");
    fs::copy(&original, &image).unwrap();
    let mut storage = FileStorage::open(&image).unwrap();
    let expected = journal::author_namespace_overlap_fixture(
        &mut storage,
        (
            5,
            &"Child".encode_utf16().collect::<Vec<_>>(),
            &"z-long-native-name".encode_utf16().collect::<Vec<_>>(),
        ),
        (limits, audit),
        &r,
    )
    .unwrap();
    drop(storage);
    run(
        "namespace-native-overlap-replay",
        "fsck.jfs",
        &["--replay_journal_only", image.to_str().unwrap()],
        None,
    );
    let storage = FileStorage::open(&image).unwrap();
    let tree = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(tree.nodes[&5].raw, expected);
    assert_eq!(
        tree.nodes[&5].entries[0].name,
        "Peer".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(
        tree.nodes[&5].entries[1].name,
        "z-long-native-name".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
    let mut data = [0; 7];
    storage
        .read_exact_at(tree.nodes[&6].runs[0].physical.start * 4096, &mut data)
        .unwrap();
    assert_eq!(&data, b"nested!");
    drop((tree, storage));
    let checked = run(
        "namespace-native-overlap-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    let bytes = fs::read(&image).unwrap();
    receipt.push_str(&format!("case=namespace-native-overlap output_sha256={} native_replay=diagnostic-clean native_fsck=clean inode512=exact cookie_reorder=exact UTF16_long_chain=exact unchanged_hardlinks=2 payload_nested=exact codec-only-no-owned-namespace-protocol\n",hash(&bytes)));
    struct NamespaceCaseContext<'a> {
        root: &'a std::path::Path,
        original: &'a std::path::Path,
        r: &'a Resources,
        limits: JfsReadLimits,
        audit: JfsAuditLimits,
        binding: [u8; 16],
    }
    type NativeNamespaceRunner<'a> =
        dyn Fn(&str, &str, &[&str], Option<&str>) -> std::process::Output + 'a;
    fn qualify_namespace_cases(
        context: NamespaceCaseContext<'_>,
        run: &NativeNamespaceRunner<'_>,
        receipt: &mut String,
    ) {
        let NamespaceCaseContext {
            root,
            original,
            r,
            limits,
            audit,
            binding,
        } = context;
        let old_name: Vec<_> = "Child".encode_utf16().collect();
        let new_name: Vec<_> = "z-long-native-name".encode_utf16().collect();
        let source_storage = FileStorage::open(original).unwrap();
        let source_tree = inspect(&source_storage, limits, audit, r).unwrap();
        let directory_home = pxd(&source_tree.nodes[&5].raw, 16, source_tree.geometry.blocks)
            .unwrap()
            .start
            * 4096
            + 5 * 512;
        let file_before = source_tree.nodes[&6].raw.clone();
        drop((source_tree, source_storage));
        for (case, home_error, recovery_error) in [
            ("normal", false, false),
            ("home-error", true, false),
            ("recovery-error", true, true),
        ] {
            let image = root.join(format!("owned-namespace-{case}.img"));
            fs::copy(original, &image).unwrap();
            let mut backend = Backend {
                file: FileStorage::open(&image).unwrap(),
                home: directory_home,
                fail: false,
                writes: 0,
                stop_at: home_error.then_some(directory_home + 300),
            };
            let mut session = NativeSession::open(&mut backend, limits, audit, r).unwrap();
            let result = session.rename_inline_entry(5, &old_name, &new_name, r);
            if home_error {
                assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
                assert!(session.uncertain);
            } else {
                result.unwrap();
            }
            drop(session);
            drop(backend);
            let oracle = root.join(format!("owned-namespace-{case}-native-replay.img"));
            if home_error {
                fs::copy(&image, &oracle).unwrap();
                run(
                    &format!("owned-namespace-{case}-native-replay"),
                    "fsck.jfs",
                    &["--replay_journal_only", oracle.to_str().unwrap()],
                    None,
                );
            }
            let mut backend = Backend {
                file: FileStorage::open(&image).unwrap(),
                home: directory_home,
                fail: false,
                writes: 0,
                stop_at: recovery_error.then_some(directory_home + 301),
            };
            if recovery_error {
                assert_eq!(
                    journal::rename::recover(&mut backend, binding, (limits, audit), r, r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                drop(backend);
                backend = Backend {
                    file: FileStorage::open(&image).unwrap(),
                    home: directory_home,
                    fail: false,
                    writes: 0,
                    stop_at: None,
                };
            }
            journal::rename::recover(&mut backend, binding, (limits, audit), r, r).unwrap();
            let counts = backend.writes;
            journal::rename::recover(&mut backend, binding, (limits, audit), r, r).unwrap();
            assert_eq!(backend.writes, counts);
            drop(backend);
            for (label, path) in [
                ("owned", &image),
                ("native", if home_error { &oracle } else { &image }),
            ] {
                let storage = FileStorage::open(path).unwrap();
                let tree = inspect(&storage, limits, audit, r).unwrap();
                assert_eq!(
                    tree.nodes[&5].entries[0].name,
                    "Peer".encode_utf16().collect::<Vec<_>>()
                );
                assert_eq!(tree.nodes[&5].entries[1].name, new_name);
                assert_eq!(tree.nodes[&6].raw, file_before);
                let mut data = [0; 7];
                storage
                    .read_exact_at(tree.nodes[&6].runs[0].physical.start * 4096, &mut data)
                    .unwrap();
                assert_eq!(&data, b"nested!");
                let expected = tree.nodes[&5].raw.clone();
                drop((tree, storage));
                let bytes = fs::read(path).unwrap();
                let checked = run(
                    &format!("owned-namespace-{case}-{label}-check"),
                    "fsck.jfs",
                    &["-n", path.to_str().unwrap()],
                    None,
                );
                assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
                let debug = run(
                    &format!("owned-namespace-{case}-{label}-directory"),
                    "jfs_debugfs",
                    &[path.to_str().unwrap()],
                    Some("dtree 5\n\n\n\nx\nquit\n"),
                );
                let text = String::from_utf8_lossy(&debug.stdout);
                assert!(
                    text.contains("z-long-nati")
                        && text.contains("ve-name")
                        && text.contains("namlen\t18")
                );
                assert_eq!(hash(&fs::read(path).unwrap()), hash(&bytes));
                receipt.push_str(&format!("case=owned-namespace-{case}-{label} output_sha256={} directory_inode_sha256={} file_inode_sha256={} native_fsck=clean native_dtname_head11=z-long-nati native_dtname_tail7=ve-name native_namlen=18 cookie_reorder=exact full_file_metadata=unchanged hardlinks=2 payload_nested=exact native_replay={} borrowed_owned_rename=yes completed_recovery_zero_writes=yes\n",hash(&bytes),hash(&expected),hash(&file_before),if home_error{"diagnostic-clean"}else{"not-needed"}));
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
    qualify_namespace_cases(
        NamespaceCaseContext {
            root: &root,
            original: &original,
            r: &r,
            limits,
            audit,
            binding,
        },
        &run,
        &mut receipt,
    );
    assert_eq!(r.memory.used(), 0);
    for (name, baked) in sources {
        assert!(
            fs::read(name).unwrap() == baked,
            "compiled source mismatch: {name}"
        );
    }
    for (p, digest) in bindings {
        assert_eq!(hash(&fs::read(p).unwrap()), digest);
    }
    assert_eq!(hash(&fs::read(binary).unwrap()), binary_hash);
    receipt.push_str("end_source_tool_binary_revalidation=passed\nstatus=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}

#[test]
fn committed_native_cow_replay_preserves_namespace_payload_and_refunds() {
    struct Backend {
        bytes: Vec<u8>,
        writes: usize,
        durable: Vec<u8>,
        flushes: usize,
        fail_flush: Option<usize>,
        fail_write: Option<usize>,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let n = bytes.len().min(37);
            if self.fail_write == Some(self.writes) {
                let partial = n / 2;
                self.bytes[at as usize..at as usize + partial].copy_from_slice(&bytes[..partial]);
                return Err(io::Error::other("modeled COW partial positional program"));
            }
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_flush == Some(self.flushes) {
                return Err(io::Error::other("modeled COW flush interruption"));
            }
            self.durable.clone_from(&self.bytes);
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: journal_seed(),
        durable: journal_seed(),
        writes: 0,
        flushes: 0,
        fail_flush: None,
        fail_write: None,
    };
    fixture::small_hardlink(&mut storage.bytes);
    storage.durable.clone_from(&storage.bytes);
    let original = storage.bytes.clone();
    storage.bytes[113 * 4096..113 * 4096 + 7].copy_from_slice(b"nested!");
    journal::author_cow_log_fixture(&mut storage, 6, 113, read, audit, &r).unwrap();
    let committed = storage.bytes.clone();
    storage.writes = 0;
    let mut binding = [0; 16];
    binding.copy_from_slice(&original[32768 + 136..32768 + 152]);
    let mut wrong = binding;
    wrong[0] ^= 1;
    assert!(journal::recover_cow(&mut storage, wrong, read, audit, &r, &r).is_err());
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, committed);
    journal::recover_cow(&mut storage, binding, read, audit, &r, &r).unwrap();
    assert!(storage.writes > 0);
    let resulting = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(resulting.nodes[&6].runs[0].physical.start, 113);
    assert!(!resulting.bitmap[112] && resulting.bitmap[113]);
    assert_eq!(resulting.nodes[&6].raw[256], 0);
    assert_eq!(&storage.bytes[113 * 4096..113 * 4096 + 7], b"nested!");
    assert_eq!(
        &storage.bytes[112 * 4096..112 * 4096 + 4096],
        &original[112 * 4096..112 * 4096 + 4096]
    );
    assert_eq!(le32(&resulting.nodes[&4].raw, 40), 2);
    assert_eq!(le32(&resulting.nodes[&6].raw, 40), 2);
    drop(resulting);
    storage.writes = 0;
    journal::recover_cow(&mut storage, binding, read, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, 0);
    let page = 484 * 4096;
    let end = page + usize::from(le16(&committed, page + 6));
    let commit_descriptor = end - 36;
    let mapping_end = page + (le32(&committed, commit_descriptor + 4) as usize % 4096);
    let mapping_descriptor = mapping_end - 36;
    let root_end = page + (le32(&committed, mapping_descriptor + 4) as usize % 4096);
    let root_descriptor = root_end - 36;
    let root_body = root_descriptor - usize::from(le16(&committed, root_descriptor + 10));
    for (at, mask) in [
        (root_body + 36, 8),
        (mapping_descriptor + 32, 2),
        (root_descriptor + 20, 1),
        (root_descriptor + 10, 4),
        (20 * 4096 + 33, 0x80),
    ] {
        let mut bytes = committed.clone();
        bytes[at] ^= mask;
        let expected = bytes.clone();
        let mut corrupt = Backend {
            bytes,
            durable: committed.clone(),
            writes: 0,
            flushes: 0,
            fail_flush: None,
            fail_write: None,
        };
        assert!(journal::recover_cow(&mut corrupt, binding, read, audit, &r, &r).is_err());
        assert_eq!(corrupt.writes, 0);
        assert_eq!(corrupt.bytes, expected);
        assert_eq!(corrupt.durable, committed);
        assert_eq!(r.memory.used(), 0);
    }
    struct Payload {
        id: ObjectId,
    }
    impl FileRead for Payload {
        fn identity(&self) -> &ObjectId {
            &self.id
        }
        fn len(&self) -> u64 {
            7
        }
        fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
            r.cancellation.check()?;
            let bytes = b"changed";
            let at = usize::try_from(at).map_err(|_| bad("test source offset"))?;
            if at >= bytes.len() {
                return Ok(0);
            }
            let n = out.len().min(bytes.len() - at).min(3);
            out[..n].copy_from_slice(&bytes[at..at + n]);
            Ok(n)
        }
        fn visit_extents(
            &self,
            _: &Resources,
            _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
        ) -> Result<()> {
            Err(Error::new(ErrorKind::Unsupported, "test payload only"))
        }
    }
    let file: Arc<dyn FileRead> = Arc::new(Payload {
        id: ObjectId {
            source: 123,
            generation: 0,
            native: vec![1],
        },
    });
    let before_preparation = storage.bytes.clone();
    storage.writes = 0;
    for (inode, new) in [(5, 114), (4, 114), (6, 113), (6, 480)] {
        assert!(
            journal::prepare_cow(
                &storage,
                journal::CowRequest {
                    inode,
                    new,
                    file: file.clone()
                },
                read,
                audit,
                &r,
                &r
            )
            .is_err()
        );
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.bytes, before_preparation);
        assert_eq!(r.memory.used(), 0);
    }
    struct CancelsOwner {
        id: ObjectId,
        cancellation: Cancellation,
    }
    impl FileRead for CancelsOwner {
        fn identity(&self) -> &ObjectId {
            &self.id
        }
        fn len(&self) -> u64 {
            7
        }
        fn read_at(&self, _: u64, out: &mut [u8], _: &Resources) -> Result<usize> {
            let count = out.len().min(3);
            out[..count].fill(7);
            self.cancellation.cancel();
            Ok(count)
        }
        fn visit_extents(
            &self,
            _: &Resources,
            _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
        ) -> Result<()> {
            Err(Error::new(
                ErrorKind::Unsupported,
                "cancellation fixture has no extent visitor",
            ))
        }
    }
    let owner = Resources {
        memory: r.memory.clone(),
        cancellation: Cancellation::default(),
    };
    let cancels: Arc<dyn FileRead> = Arc::new(CancelsOwner {
        id: ObjectId {
            source: 124,
            generation: 0,
            native: vec![2],
        },
        cancellation: owner.cancellation.clone(),
    });
    let cancelled = journal::prepare_cow(
        &storage,
        journal::CowRequest {
            inode: 6,
            new: 114,
            file: cancels,
        },
        read,
        audit,
        &owner,
        &r,
    )
    .unwrap();
    assert_eq!(
        journal::publish_cow(&mut storage, cancelled, &owner, &r)
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, before_preparation);
    assert_eq!(r.memory.used(), 0);
    let stale = journal::prepare_cow(
        &storage,
        journal::CowRequest {
            inode: 6,
            new: 114,
            file: file.clone(),
        },
        read,
        audit,
        &r,
        &r,
    )
    .unwrap();
    storage.bytes[29 * 4096 + 6 * 512 + 44] ^= 1;
    let stale_bytes = storage.bytes.clone();
    assert_eq!(
        journal::publish_cow(&mut storage, stale, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, stale_bytes);
    storage.bytes.clone_from(&before_preparation);
    let plan = journal::prepare_cow(
        &storage,
        journal::CowRequest {
            inode: 6,
            new: 114,
            file,
        },
        read,
        audit,
        &r,
        &r,
    )
    .unwrap();
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, before_preparation);
    journal::publish_cow(&mut storage, plan, &r, &r).unwrap();
    let publication_write_calls = storage.writes;
    let resulting = inspect(&storage, read, audit, &r).unwrap();
    assert_eq!(resulting.nodes[&6].runs[0].physical.start, 114);
    assert!(!resulting.bitmap[113] && resulting.bitmap[114]);
    assert_eq!(&storage.bytes[114 * 4096..114 * 4096 + 7], b"changed");
    assert_eq!(&storage.bytes[114 * 4096 + 7..115 * 4096], &[0; 4089]);
    assert_eq!(&storage.bytes[113 * 4096..113 * 4096 + 7], b"nested!");
    assert_eq!(le32(&resulting.nodes[&4].raw, 40), 2);
    assert_eq!(le32(&resulting.nodes[&6].raw, 40), 2);
    drop(resulting);
    storage.writes = 0;
    journal::recover_cow(&mut storage, binding, read, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, 0);
    // Inline native log and target share one declared flush authority.
    // First restart and interrupted recovery independently retain or discard
    // all bytes since their last successful flush: four persistence histories.
    for barrier in 1..=14 {
        for retain in [false, true] {
            for retry_retain in [false, true] {
                let mut trial = Backend {
                    bytes: before_preparation.clone(),
                    durable: before_preparation.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_flush: Some(barrier),
                    fail_write: None,
                };
                let file: Arc<dyn FileRead> = Arc::new(Payload {
                    id: ObjectId {
                        source: 123,
                        generation: 0,
                        native: vec![1],
                    },
                });
                let plan = journal::prepare_cow(
                    &trial,
                    journal::CowRequest {
                        inode: 6,
                        new: 114,
                        file,
                    },
                    read,
                    audit,
                    &r,
                    &r,
                )
                .unwrap();
                assert_eq!(trial.writes, 0);
                assert_eq!(
                    journal::publish_cow(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let surviving = if retain { trial.bytes } else { trial.durable };
                let mut restarted = Backend {
                    durable: surviving.clone(),
                    bytes: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: Some(1),
                    fail_write: None,
                };
                let first = journal::recover_cow(&mut restarted, binding, read, audit, &r, &r);
                if let Err(error) = first {
                    assert_eq!(
                        error.kind,
                        ErrorKind::UncertainDurability,
                        "barrier {barrier}, retain {retain}"
                    );
                }
                let surviving = if retry_retain {
                    restarted.bytes
                } else {
                    restarted.durable
                };
                let mut retry = Backend {
                    durable: surviving.clone(),
                    bytes: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: None,
                };
                journal::recover_cow(&mut retry,binding,read,audit,&r,&r).unwrap_or_else(|error|panic!("barrier {barrier}, retain {retain}, retry retain {retry_retain}: {error:?}"));
                let resulting = inspect(&retry, read, audit, &r).unwrap();
                let actual = resulting.nodes[&6].runs[0].physical.start;
                let expected_new = barrier > 6 || barrier == 6 && retain;
                assert_eq!(actual, if expected_new { 114 } else { 113 });
                assert_eq!(
                    &retry.bytes[actual as usize * 4096..actual as usize * 4096 + 7],
                    if expected_new { b"changed" } else { b"nested!" }
                );
                assert_eq!(le32(&resulting.nodes[&4].raw, 40), 2);
                assert_eq!(le32(&resulting.nodes[&6].raw, 40), 2);
                drop(resulting);
                retry.writes = 0;
                journal::recover_cow(&mut retry, binding, read, audit, &r, &r).unwrap();
                assert_eq!(retry.writes, 0);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    for cut in 1..=publication_write_calls {
        for retain in [false, true] {
            for retry_retain in [false, true] {
                let mut trial = Backend {
                    bytes: before_preparation.clone(),
                    durable: before_preparation.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: Some(cut),
                };
                let file: Arc<dyn FileRead> = Arc::new(Payload {
                    id: ObjectId {
                        source: 123,
                        generation: 0,
                        native: vec![1],
                    },
                });
                let plan = journal::prepare_cow(
                    &trial,
                    journal::CowRequest {
                        inode: 6,
                        new: 114,
                        file,
                    },
                    read,
                    audit,
                    &r,
                    &r,
                )
                .unwrap();
                assert_eq!(
                    journal::publish_cow(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let expected_new = trial.flushes >= 6;
                let surviving = if retain { trial.bytes } else { trial.durable };
                let mut restarted = Backend {
                    durable: surviving.clone(),
                    bytes: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: Some(1),
                };
                if let Err(error) =
                    journal::recover_cow(&mut restarted, binding, read, audit, &r, &r)
                {
                    assert_eq!(
                        error.kind,
                        ErrorKind::UncertainDurability,
                        "write cut {cut}"
                    );
                }
                let surviving = if retry_retain {
                    restarted.bytes
                } else {
                    restarted.durable
                };
                let mut retry = Backend {
                    durable: surviving.clone(),
                    bytes: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: None,
                };
                journal::recover_cow(&mut retry,binding,read,audit,&r,&r).unwrap_or_else(|error|panic!("write cut {cut}, retain {retain}, retry retain {retry_retain}: {error:?}"));
                let resulting = inspect(&retry, read, audit, &r).unwrap();
                let block = resulting.nodes[&6].runs[0].physical.start;
                assert_eq!(block, if expected_new { 114 } else { 113 });
                assert_eq!(
                    &retry.bytes[block as usize * 4096..block as usize * 4096 + 7],
                    if expected_new { b"changed" } else { b"nested!" }
                );
                assert_eq!(le32(&resulting.nodes[&6].raw, 40), 2);
                drop(resulting);
                retry.writes = 0;
                journal::recover_cow(&mut retry, binding, read, audit, &r, &r).unwrap();
                assert_eq!(retry.writes, 0);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    let mut prepared_history = committed.clone();
    let prepared_eor = (mapping_end - page) as u16;
    prepared_history[page + 6..page + 8].copy_from_slice(&prepared_eor.to_le_bytes());
    prepared_history[page + 4094..page + 4096].copy_from_slice(&prepared_eor.to_le_bytes());
    let mut recovery_calls = 0usize;
    for history in [committed.clone(), prepared_history] {
        let mut normal_recovery = Backend {
            bytes: history.clone(),
            durable: history.clone(),
            writes: 0,
            flushes: 0,
            fail_flush: None,
            fail_write: None,
        };
        journal::recover_cow(&mut normal_recovery, binding, read, audit, &r, &r).unwrap();
        recovery_calls += normal_recovery.writes;
        for barrier in 1..=normal_recovery.flushes {
            for retain in [false, true] {
                let mut interrupted = Backend {
                    bytes: history.clone(),
                    durable: history.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_flush: Some(barrier),
                    fail_write: None,
                };
                assert_eq!(
                    journal::recover_cow(&mut interrupted, binding, read, audit, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let surviving = if retain {
                    interrupted.bytes
                } else {
                    interrupted.durable
                };
                let mut retry = Backend {
                    bytes: surviving.clone(),
                    durable: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: None,
                };
                journal::recover_cow(&mut retry, binding, read, audit, &r, &r).unwrap();
                assert_eq!(retry.bytes, normal_recovery.bytes);
                assert_eq!(r.memory.used(), 0);
            }
        }
        for cut in 1..=normal_recovery.writes {
            for retain in [false, true] {
                let mut interrupted = Backend {
                    bytes: history.clone(),
                    durable: history.clone(),
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: Some(cut),
                };
                assert_eq!(
                    journal::recover_cow(&mut interrupted, binding, read, audit, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let surviving = if retain {
                    interrupted.bytes
                } else {
                    interrupted.durable
                };
                let mut retry = Backend {
                    durable: surviving.clone(),
                    bytes: surviving,
                    writes: 0,
                    flushes: 0,
                    fail_flush: None,
                    fail_write: None,
                };
                journal::recover_cow(&mut retry, binding, read, audit, &r, &r).unwrap_or_else(
                    |error| panic!("recovery write cut {cut}, retain {retain}: {error:?}"),
                );
                assert_eq!(retry.bytes, normal_recovery.bytes);
                retry.writes = 0;
                journal::recover_cow(&mut retry, binding, read, audit, &r, &r).unwrap();
                assert_eq!(retry.writes, 0);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    eprintln!(
        "COW publication={publication_write_calls} short-write cuts x4 persistence histories; committed+prepared recovery={recovery_calls} short-write cuts x2 persistence outcomes; all publication/recovery barriers; whole shared volume retains/drops only"
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn pristine_native_checkpoint_rollover_and_cold_cuts_preserve_every_home_byte() {
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
    let mut seed = journal_seed();
    for number in 3..30 {
        fixture::p16(&mut seed, (482 + number) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut normal = make(seed.clone());
    let plan = journal::rollover::prepare(&normal, [0xa5; 16], read, audit, &r, &r, false).unwrap();
    journal::rollover::publish(&mut normal, plan, &r, &r).unwrap();
    assert_eq!(&normal.bytes[..483 * 4096], &seed[..483 * 4096]);
    assert_eq!(le32(&normal.bytes, 483 * 4096 + 32), 3 * 4096 + 44);
    let programs = normal.writes;
    let barriers = normal.flushes;
    for retained in [false, true] {
        for program in 0..programs + barriers {
            let mut trial = make(seed.clone());
            let plan =
                journal::rollover::prepare(&trial, [0xa5; 16], read, audit, &r, &r, false).unwrap();
            if program < programs {
                trial.fail_write = Some(program + 1);
            } else {
                trial.fail_flush = Some(program - programs + 1);
            }
            assert_eq!(
                journal::rollover::publish(&mut trial, plan, &r, &r)
                    .unwrap_err()
                    .kind,
                ErrorKind::UncertainDurability
            );
            let bytes = if retained { trial.bytes } else { trial.durable };
            let mut recovered = make(bytes);
            let plan =
                journal::rollover::prepare(&recovered, [0xa5; 16], read, audit, &r, &r, true)
                    .unwrap();
            journal::rollover::publish(&mut recovered, plan, &r, &r).unwrap();
            assert_eq!(&recovered.bytes[..483 * 4096], &seed[..483 * 4096]);
            assert!(
                [2 * 4096 + 44, 3 * 4096 + 44].contains(&le32(&recovered.bytes, 483 * 4096 + 32))
            );
            let writes = recovered.writes;
            let flushes = recovered.flushes;
            let plan =
                journal::rollover::prepare(&recovered, [0xa5; 16], read, audit, &r, &r, true)
                    .unwrap();
            journal::rollover::publish(&mut recovered, plan, &r, &r).unwrap();
            assert_eq!((writes, flushes), (recovered.writes, recovered.flushes));
        }
    }
    let mut torn = make(seed.clone());
    let plan = journal::rollover::prepare(&torn, [0xa5; 16], read, audit, &r, &r, false).unwrap();
    torn.fail_write = Some(1);
    assert_eq!(
        journal::rollover::publish(&mut torn, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    let mut reference = make(torn.bytes.clone());
    let plan =
        journal::rollover::prepare(&reference, [0xa5; 16], read, audit, &r, &r, true).unwrap();
    journal::rollover::publish(&mut reference, plan, &r, &r).unwrap();
    let recovery_programs = reference.writes;
    let recovery_barriers = reference.flushes;
    for first_retained in [false, true] {
        for second_retained in [false, true] {
            for cut in 0..recovery_programs + recovery_barriers {
                let mut trial = make(torn.bytes.clone());
                let plan =
                    journal::rollover::prepare(&trial, [0xa5; 16], read, audit, &r, &r, true)
                        .unwrap();
                if cut < recovery_programs {
                    trial.fail_write = Some(cut + 1);
                } else {
                    trial.fail_flush = Some(cut - recovery_programs + 1);
                }
                assert_eq!(
                    journal::rollover::publish(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let bytes = if first_retained {
                    trial.bytes
                } else {
                    trial.durable
                };
                let mut second = make(bytes);
                let plan =
                    journal::rollover::prepare(&second, [0xa5; 16], read, audit, &r, &r, true)
                        .unwrap();
                second.fail_write = Some(1);
                if let Err(error) = journal::rollover::publish(&mut second, plan, &r, &r) {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                let bytes = if second_retained {
                    second.bytes
                } else {
                    second.durable
                };
                let mut final_state = make(bytes);
                let plan =
                    journal::rollover::prepare(&final_state, [0xa5; 16], read, audit, &r, &r, true)
                        .unwrap();
                journal::rollover::publish(&mut final_state, plan, &r, &r).unwrap();
                assert_eq!(&final_state.bytes[..483 * 4096], &seed[..483 * 4096]);
                assert_eq!(le32(&final_state.bytes, 483 * 4096 + 32), 3 * 4096 + 44);
            }
        }
    }
    for case in 0..5 {
        let mut bytes = torn.bytes.clone();
        match case {
            0 => bytes[485 * 4096 + 20] = 1,
            1 => fixture::p32(&mut bytes, 485 * 4096, 999),
            2 => bytes[486 * 4096 + 4094] = 12,
            3 => bytes[483 * 4096 + 32] = 0xff,
            _ => bytes[484 * 4096 + 17] = 0,
        }
        let trial = make(bytes.clone());
        assert!(journal::rollover::prepare(&trial, [0xa5; 16], read, audit, &r, &r, true).is_err());
        assert_eq!((trial.writes, trial.flushes), (0, 0));
        assert_eq!(trial.bytes, bytes);
        assert_eq!(trial.durable, bytes);
    }
    let mut stale = make(seed.clone());
    let plan = journal::rollover::prepare(&stale, [0xa5; 16], read, audit, &r, &r, false).unwrap();
    stale.bytes[486 * 4096 + 1000] = 1;
    assert_eq!(
        journal::rollover::publish(&mut stale, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!((stale.writes, stale.flushes), (0, 0));
    for _ in 0..3 {
        let plan =
            journal::rollover::prepare(&normal, [0xa5; 16], read, audit, &r, &r, false).unwrap();
        journal::rollover::publish(&mut normal, plan, &r, &r).unwrap();
    }
    assert_eq!(le32(&normal.bytes, 483 * 4096 + 32), 6 * 4096 + 44);
    let mut wrap = seed.clone();
    for number in 2..30 {
        let sequence = if number == 29 { 27 } else { number as u32 - 2 };
        let end = if number == 29 { 44 } else { 8 };
        for at in [(482 + number) * 4096, (482 + number) * 4096 + 4088] {
            fixture::p32(&mut wrap, at, sequence);
            fixture::p16(&mut wrap, at + 6, end);
        }
    }
    fixture::p32(&mut wrap, 483 * 4096 + 32, 29 * 4096 + 44);
    let mut wrap = make(wrap);
    let plan = journal::rollover::prepare(&wrap, [0xa5; 16], read, audit, &r, &r, false).unwrap();
    journal::rollover::publish(&mut wrap, plan, &r, &r).unwrap();
    assert_eq!(le32(&wrap.bytes, 483 * 4096 + 32), 2 * 4096 + 44);
    let mut sticky = make(seed.clone());
    sticky.fail_write = Some(1);
    let mut session = NativeSession::open(&mut sticky, read, audit, &r).unwrap();
    assert_eq!(
        session.advance_checkpoint(&r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    assert_eq!(
        session.write_uid(2, 99, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    session.recover(&r).unwrap();
    session.advance_checkpoint(&r).unwrap();
    drop(session);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn pristine_rollover_caps_cancellation_and_read_failure_are_causal_and_prewrite() {
    let seed = journal_seed();
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
    struct Fault {
        bytes: Vec<u8>,
        writes: usize,
        fail: bool,
    }
    impl Storage for Fault {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            if self.fail && at == 485 * 4096 {
                return Err(io::Error::other("independent unused-log-page read failure"));
            }
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            panic!("preflight wrote")
        }
        fn flush(&mut self) -> io::Result<()> {
            self.writes += 1;
            panic!("preflight flushed")
        }
    }
    for case in 0..4 {
        let r = Resources {
            memory: Budget::new(if case == 0 { 1024 } else { 32 << 20 }),
            cancellation: Cancellation::default(),
        };
        if case == 1 {
            r.cancellation.cancel();
        }
        let storage = Fault {
            bytes: seed.clone(),
            writes: 0,
            fail: case == 2,
        };
        let mut limits = read;
        if case == 3 {
            limits.pages = 2;
        }
        let error = journal::rollover::prepare(&storage, [0xa5; 16], limits, audit, &r, &r, false)
            .err()
            .unwrap();
        let expected = match case {
            0 | 3 => ErrorKind::BudgetExhausted,
            1 => ErrorKind::Cancelled,
            _ => ErrorKind::Io,
        };
        assert_eq!(error.kind, expected);
        if case == 2 {
            assert!(error.source.is_some());
            assert!(
                error
                    .source
                    .unwrap()
                    .to_string()
                    .contains("independent unused")
            );
        }
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.bytes, seed);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn rotating_cow_prepares_complete_projection_before_any_program() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let mut backend = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source: Arc<dyn FileRead> = Arc::new(CowTestPayload {
        id: ObjectId {
            source: 92,
            generation: 0,
            native: vec![6],
        },
        size: 9000,
        fail_second: false,
    });
    let plan = journal::prepare_rotating_cow(
        &backend,
        [0xa5; 16],
        journal::CowRequest {
            inode: 6,
            new: 120,
            file: source,
        },
        (read, audit),
        &r,
        &r,
        journal::CowMode::Replace(true),
    )
    .unwrap();
    assert_eq!((backend.writes, backend.flushes), (0, 0));
    journal::publish_rotating_cow(&mut backend, plan, &r, &r).unwrap();
    journal::recover_rotating_cow(&mut backend, [0xa5; 16], read, audit, &r, &r).unwrap();
    assert_eq!(
        inspect(&backend, read, audit, &r).unwrap().nodes[&6].length,
        9000
    );
    for (i, b) in backend.bytes[120 * 4096..120 * 4096 + 9000]
        .iter()
        .enumerate()
    {
        assert_eq!(*b, (i * 31 % 251) as u8);
    }
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn rotating_cow_every_mutation_cut_cold_restarts_four_models() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source = || -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 92,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second: false,
        })
    };
    let prepare = |storage: &CowTestBackend| {
        journal::prepare_rotating_cow(
            storage,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new: 120,
                file: source(),
            },
            (read, audit),
            &r,
            &r,
            journal::CowMode::Replace(true),
        )
        .unwrap()
    };
    let mut reference = make(seed.clone());
    let plan = prepare(&reference);
    journal::publish_rotating_cow(&mut reference, plan, &r, &r).unwrap();
    let programs = reference.writes;
    let barriers = reference.flushes;
    for first_retained in [false, true] {
        for second_retained in [false, true] {
            for cut in 0..programs + barriers {
                let mut trial = make(seed.clone());
                let plan = prepare(&trial);
                if cut < programs {
                    trial.fail_write = Some(cut + 1);
                } else {
                    trial.fail_flush = Some(cut - programs + 1);
                }
                assert_eq!(
                    journal::publish_rotating_cow(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let bytes = if first_retained {
                    trial.bytes
                } else {
                    trial.durable
                };
                let mut retry = make(bytes);
                retry.fail_write = Some(1);
                if let Err(error) =
                    journal::recover_rotating_cow(&mut retry, [0xa5; 16], read, audit, &r, &r)
                {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                let bytes = if second_retained {
                    retry.bytes
                } else {
                    retry.durable
                };
                let mut recovered = make(bytes);
                journal::recover_rotating_cow(&mut recovered, [0xa5; 16], read, audit, &r, &r)
                    .unwrap();
                let tree = inspect(&recovered, read, audit, &r).unwrap();
                let node = &tree.nodes[&6];
                assert_eq!(le32(&node.raw, 40), 2);
                assert!([7, 9000].contains(&node.length));
                if node.length == 9000 {
                    for (i, b) in recovered.bytes[120 * 4096..120 * 4096 + 9000]
                        .iter()
                        .enumerate()
                    {
                        assert_eq!(*b, (i * 31 % 251) as u8);
                    }
                } else {
                    assert_eq!(node.runs[0].physical.start, 112);
                }
                drop(tree);
                assert_eq!(
                    &recovered.bytes[112 * 4096..113 * 4096],
                    &seed[112 * 4096..113 * 4096]
                );
                let writes = recovered.writes;
                let flushes = recovered.flushes;
                journal::recover_rotating_cow(&mut recovered, [0xa5; 16], read, audit, &r, &r)
                    .unwrap();
                assert_eq!((writes, flushes), (recovered.writes, recovered.flushes));
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    println!(
        "isolated combined rotation+COW programs={programs} barriers={barriers} four-persistence mutation+cold-recovery profiles passed"
    );
}

#[test]
fn rotating_session_preflight_failure_has_zero_writes_and_then_accepts_valid_operation() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let mut backend = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source = |size| -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 993,
                generation: 0,
                native: vec![6],
            },
            size,
            fail_second: false,
        })
    };
    let mut session = NativeSession::open(&mut backend, read, audit, &r).unwrap();
    assert_eq!(
        session
            .replace_rotating_dense_file(6, 120, source(32 * 4096 + 1), &r)
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    drop(session);
    assert_eq!((backend.writes, backend.flushes), (0, 0));
    assert_eq!(backend.bytes, seed);
    let mut session = NativeSession::open(&mut backend, read, audit, &r).unwrap();
    session
        .replace_rotating_dense_file(6, 120, source(9000), &r)
        .unwrap();
    session.recover(&r).unwrap();
    drop(session);
    assert_eq!(
        inspect(&backend, read, audit, &r).unwrap().nodes[&6].length,
        9000
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn rotating_cow_every_recovery_position_restarts_under_four_persistence_profiles() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    for committed in [false, true] {
        let mut interrupted = make(seed.clone());
        let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
            id: ObjectId {
                source: 995,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second: false,
        });
        let plan = journal::prepare_rotating_cow(
            &interrupted,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new: 120,
                file,
            },
            (read, audit),
            &r,
            &r,
            journal::CowMode::Replace(true),
        )
        .unwrap();
        if committed {
            interrupted.fail_flush = Some(11);
        } else {
            interrupted.fail_write = Some(1);
        }
        assert_eq!(
            journal::publish_rotating_cow(&mut interrupted, plan, &r, &r)
                .unwrap_err()
                .kind,
            ErrorKind::UncertainDurability
        );
        for initial_retained in [false, true] {
            let saved = if initial_retained {
                interrupted.bytes.clone()
            } else {
                interrupted.durable.clone()
            };
            let mut reference = make(saved.clone());
            journal::recover_rotating_cow(&mut reference, [0xa5; 16], read, audit, &r, &r).unwrap();
            let programs = reference.writes;
            let barriers = reference.flushes;
            for first_retained in [false, true] {
                for second_retained in [false, true] {
                    for cut in 0..programs + barriers {
                        let mut trial = make(saved.clone());
                        if cut < programs {
                            trial.fail_write = Some(cut + 1);
                        } else {
                            trial.fail_flush = Some(cut - programs + 1);
                        }
                        assert_eq!(
                            journal::recover_rotating_cow(
                                &mut trial, [0xa5; 16], read, audit, &r, &r
                            )
                            .unwrap_err()
                            .kind,
                            ErrorKind::UncertainDurability
                        );
                        let bytes = if first_retained {
                            trial.bytes
                        } else {
                            trial.durable
                        };
                        let mut second = make(bytes);
                        second.fail_write = Some(1);
                        if let Err(error) = journal::recover_rotating_cow(
                            &mut second,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        ) {
                            assert_eq!(error.kind, ErrorKind::UncertainDurability);
                        }
                        let bytes = if second_retained {
                            second.bytes
                        } else {
                            second.durable
                        };
                        let mut recovered = make(bytes);
                        journal::recover_rotating_cow(
                            &mut recovered,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        )
                        .unwrap();
                        let tree = inspect(&recovered, read, audit, &r).unwrap();
                        let node = &tree.nodes[&6];
                        assert_eq!(node.length, if committed { 9000 } else { 7 });
                        assert_eq!(le32(&node.raw, 40), 2);
                        drop(tree);
                        if committed {
                            for (i, b) in recovered.bytes[120 * 4096..120 * 4096 + 9000]
                                .iter()
                                .enumerate()
                            {
                                assert_eq!(*b, (i * 31 % 251) as u8);
                            }
                        }
                        assert_eq!(
                            &recovered.bytes[112 * 4096..113 * 4096],
                            &seed[112 * 4096..113 * 4096]
                        );
                        let writes = recovered.writes;
                        let flushes = recovered.flushes;
                        journal::recover_rotating_cow(
                            &mut recovered,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        )
                        .unwrap();
                        assert_eq!((writes, flushes), (recovered.writes, recovered.flushes));
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
            println!(
                "combined recovery committed={committed} initial_retained={initial_retained} programs={programs} barriers={barriers} four-persistence profiles passed"
            );
        }
    }
}

#[test]
fn rotating_cow_stale_ring_and_deferred_causal_failure_preserve_old_authority() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source = |fail_second| -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 996,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second,
        })
    };
    let mut stale = make(seed.clone());
    let plan = journal::prepare_rotating_cow(
        &stale,
        [0xa5; 16],
        journal::CowRequest {
            inode: 6,
            new: 120,
            file: source(false),
        },
        (read, audit),
        &r,
        &r,
        journal::CowMode::Replace(true),
    )
    .unwrap();
    stale.bytes[485 * 4096 + 1000] = 1;
    let before = stale.bytes.clone();
    assert_eq!(
        journal::publish_rotating_cow(&mut stale, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!((stale.writes, stale.flushes), (0, 0));
    assert_eq!(stale.bytes, before);
    assert_eq!(stale.durable, seed);
    assert_eq!(r.memory.used(), 0);
    let mut backend = make(seed.clone());
    let mut session = NativeSession::open(&mut backend, read, audit, &r).unwrap();
    let error = session
        .replace_rotating_dense_file(6, 120, source(true), &r)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::UncertainDurability);
    assert!(
        error
            .source
            .unwrap()
            .to_string()
            .contains("source interruption")
    );
    assert_eq!(
        session.write_uid(2, 55, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    session.recover(&r).unwrap();
    drop(session);
    let tree = inspect(&backend, read, audit, &r).unwrap();
    assert_eq!(tree.nodes[&6].length, 7);
    assert_eq!(tree.nodes[&6].runs[0].physical.start, 112);
    assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
    assert!(!tree.bitmap[120]);
    drop(tree);
    assert_eq!(
        &backend.bytes[112 * 4096..113 * 4096],
        &seed[112 * 4096..113 * 4096]
    );
    assert_eq!(r.memory.used(), 0);
    for case in 0..2 {
        let phase = Resources {
            memory: Budget::new(if case == 0 { 65536 } else { 32 << 20 }),
            cancellation: Cancellation::default(),
        };
        if case == 1 {
            phase.cancellation.cancel();
        }
        let backend = make(seed.clone());
        let error = journal::prepare_rotating_cow(
            &backend,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new: 120,
                file: source(false),
            },
            (read, audit),
            &r,
            &phase,
            journal::CowMode::Replace(true),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.kind,
            if case == 0 {
                ErrorKind::BudgetExhausted
            } else {
                ErrorKind::Cancelled
            }
        );
        assert_eq!((backend.writes, backend.flushes), (0, 0));
        assert_eq!(backend.bytes, seed);
        assert_eq!(phase.memory.used(), 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn checkpointed_native_log_reuse_exceeds_two_laps_and_cold_cuts() {
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
    let mut seed = journal_seed();
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut backend = make(seed.clone());
    for _ in 0..60 {
        let plan =
            journal::rollover::prepare_recycling(&backend, [0xa5; 16], read, audit, &r, &r, false)
                .unwrap();
        journal::rollover::publish(&mut backend, plan, &r, &r).unwrap();
        assert_eq!(&backend.bytes[..483 * 4096], &seed[..483 * 4096]);
    }
    let saved = backend.bytes.clone();
    assert!(journal::rollover::prepare(&backend, [0xa5; 16], read, audit, &r, &r, false).is_err());
    let mut reference = make(saved.clone());
    let plan =
        journal::rollover::prepare_recycling(&reference, [0xa5; 16], read, audit, &r, &r, false)
            .unwrap();
    journal::rollover::publish(&mut reference, plan, &r, &r).unwrap();
    let programs = reference.writes;
    let barriers = reference.flushes;
    for first_retained in [false, true] {
        for second_retained in [false, true] {
            for cut in 0..programs + barriers {
                let mut trial = make(saved.clone());
                let plan = journal::rollover::prepare_recycling(
                    &trial, [0xa5; 16], read, audit, &r, &r, false,
                )
                .unwrap();
                if cut < programs {
                    trial.fail_write = Some(cut + 1);
                } else {
                    trial.fail_flush = Some(cut - programs + 1);
                }
                assert_eq!(
                    journal::rollover::publish(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let bytes = if first_retained {
                    trial.bytes
                } else {
                    trial.durable
                };
                let mut retry = make(bytes);
                let plan = journal::rollover::prepare_recycling(
                    &retry, [0xa5; 16], read, audit, &r, &r, true,
                )
                .unwrap();
                retry.fail_write = Some(1);
                if let Err(error) = journal::rollover::publish(&mut retry, plan, &r, &r) {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                let bytes = if second_retained {
                    retry.bytes
                } else {
                    retry.durable
                };
                let mut recovered = make(bytes);
                let plan = journal::rollover::prepare_recycling(
                    &recovered, [0xa5; 16], read, audit, &r, &r, true,
                )
                .unwrap();
                journal::rollover::publish(&mut recovered, plan, &r, &r).unwrap();
                assert_eq!(&recovered.bytes[..483 * 4096], &seed[..483 * 4096]);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn recycled_journal_laps_include_native_cow_histories_and_preserve_hardlinks() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let mut backend = CowTestBackend {
        durable: seed.clone(),
        bytes: seed,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    for step in 0..60 {
        let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
            id: ObjectId {
                source: 997,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second: false,
        });
        let new = if step % 2 == 0 { 120 } else { 123 };
        let plan = journal::prepare_recycling_cow(
            &backend,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new,
                file,
            },
            (read, audit),
            &r,
            &r,
            journal::CowMode::Replace(true),
        )
        .unwrap();
        journal::publish_rotating_cow(&mut backend, plan, &r, &r).unwrap();
        journal::recover_recycling_cow(&mut backend, [0xa5; 16], read, audit, &r, &r).unwrap();
        let tree = inspect(&backend, read, audit, &r).unwrap();
        assert_eq!(tree.nodes[&6].length, 9000);
        assert_eq!(le32(&tree.nodes[&6].raw, 40), 2);
        assert_eq!(tree.nodes[&6].runs[0].physical.start, new);
        drop(tree);
        for (i, b) in backend.bytes[new as usize * 4096..new as usize * 4096 + 9000]
            .iter()
            .enumerate()
        {
            assert_eq!(*b, (i * 31 % 251) as u8);
        }
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn recycling_cow_every_mutation_cut_cold_restarts_four_models() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let mut filled = CowTestBackend {
        bytes: seed.clone(),
        durable: seed.clone(),
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    for _ in 0..60 {
        let plan =
            journal::rollover::prepare_recycling(&filled, [0xa5; 16], read, audit, &r, &r, false)
                .unwrap();
        journal::rollover::publish(&mut filled, plan, &r, &r).unwrap();
    }
    seed = filled.bytes;
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let source = || -> Arc<dyn FileRead> {
        Arc::new(CowTestPayload {
            id: ObjectId {
                source: 92,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second: false,
        })
    };
    let prepare = |storage: &CowTestBackend| {
        journal::prepare_recycling_cow(
            storage,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new: 120,
                file: source(),
            },
            (read, audit),
            &r,
            &r,
            journal::CowMode::Replace(true),
        )
        .unwrap()
    };
    let mut reference = make(seed.clone());
    let plan = prepare(&reference);
    journal::publish_rotating_cow(&mut reference, plan, &r, &r).unwrap();
    let programs = reference.writes;
    let barriers = reference.flushes;
    for first_retained in [false, true] {
        for second_retained in [false, true] {
            for cut in 0..programs + barriers {
                let mut trial = make(seed.clone());
                let plan = prepare(&trial);
                if cut < programs {
                    trial.fail_write = Some(cut + 1);
                } else {
                    trial.fail_flush = Some(cut - programs + 1);
                }
                assert_eq!(
                    journal::publish_rotating_cow(&mut trial, plan, &r, &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::UncertainDurability
                );
                let bytes = if first_retained {
                    trial.bytes
                } else {
                    trial.durable
                };
                let mut retry = make(bytes);
                retry.fail_write = Some(1);
                if let Err(error) =
                    journal::recover_recycling_cow(&mut retry, [0xa5; 16], read, audit, &r, &r)
                {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                }
                let bytes = if second_retained {
                    retry.bytes
                } else {
                    retry.durable
                };
                let mut recovered = make(bytes);
                journal::recover_recycling_cow(&mut recovered, [0xa5; 16], read, audit, &r, &r)
                    .unwrap();
                let tree = inspect(&recovered, read, audit, &r).unwrap();
                let node = &tree.nodes[&6];
                assert_eq!(le32(&node.raw, 40), 2);
                assert!([7, 9000].contains(&node.length));
                if node.length == 9000 {
                    for (i, b) in recovered.bytes[120 * 4096..120 * 4096 + 9000]
                        .iter()
                        .enumerate()
                    {
                        assert_eq!(*b, (i * 31 % 251) as u8);
                    }
                } else {
                    assert_eq!(node.runs[0].physical.start, 112);
                }
                drop(tree);
                assert_eq!(
                    &recovered.bytes[112 * 4096..113 * 4096],
                    &seed[112 * 4096..113 * 4096]
                );
                let writes = recovered.writes;
                let flushes = recovered.flushes;
                journal::recover_recycling_cow(&mut recovered, [0xa5; 16], read, audit, &r, &r)
                    .unwrap();
                assert_eq!((writes, flushes), (recovered.writes, recovered.flushes));
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
    println!(
        "isolated combined rotation+COW programs={programs} barriers={barriers} four-persistence mutation+cold-recovery profiles passed"
    );
}

#[test]
fn recycling_cow_every_recovery_position_restarts_under_four_persistence_profiles() {
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
    let mut seed = journal_seed();
    fixture::small_hardlink(&mut seed);
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut filled = make(seed.clone());
    for _ in 0..60 {
        let plan =
            journal::rollover::prepare_recycling(&filled, [0xa5; 16], read, audit, &r, &r, false)
                .unwrap();
        journal::rollover::publish(&mut filled, plan, &r, &r).unwrap();
    }
    seed = filled.bytes;
    for committed in [false, true] {
        let mut interrupted = make(seed.clone());
        let file: Arc<dyn FileRead> = Arc::new(CowTestPayload {
            id: ObjectId {
                source: 995,
                generation: 0,
                native: vec![6],
            },
            size: 9000,
            fail_second: false,
        });
        let plan = journal::prepare_recycling_cow(
            &interrupted,
            [0xa5; 16],
            journal::CowRequest {
                inode: 6,
                new: 120,
                file,
            },
            (read, audit),
            &r,
            &r,
            journal::CowMode::Replace(true),
        )
        .unwrap();
        if committed {
            interrupted.fail_flush = Some(11);
        } else {
            interrupted.fail_write = Some(1);
        }
        assert_eq!(
            journal::publish_rotating_cow(&mut interrupted, plan, &r, &r)
                .unwrap_err()
                .kind,
            ErrorKind::UncertainDurability
        );
        for initial_retained in [false, true] {
            let saved = if initial_retained {
                interrupted.bytes.clone()
            } else {
                interrupted.durable.clone()
            };
            let mut reference = make(saved.clone());
            journal::recover_recycling_cow(&mut reference, [0xa5; 16], read, audit, &r, &r)
                .unwrap();
            let programs = reference.writes;
            let barriers = reference.flushes;
            for first_retained in [false, true] {
                for second_retained in [false, true] {
                    for cut in 0..programs + barriers {
                        let mut trial = make(saved.clone());
                        if cut < programs {
                            trial.fail_write = Some(cut + 1);
                        } else {
                            trial.fail_flush = Some(cut - programs + 1);
                        }
                        assert_eq!(
                            journal::recover_recycling_cow(
                                &mut trial, [0xa5; 16], read, audit, &r, &r
                            )
                            .unwrap_err()
                            .kind,
                            ErrorKind::UncertainDurability
                        );
                        let bytes = if first_retained {
                            trial.bytes
                        } else {
                            trial.durable
                        };
                        let mut second = make(bytes);
                        second.fail_write = Some(1);
                        if let Err(error) = journal::recover_recycling_cow(
                            &mut second,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        ) {
                            assert_eq!(error.kind, ErrorKind::UncertainDurability);
                        }
                        let bytes = if second_retained {
                            second.bytes
                        } else {
                            second.durable
                        };
                        let mut recovered = make(bytes);
                        journal::recover_recycling_cow(
                            &mut recovered,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        )
                        .unwrap();
                        let tree = inspect(&recovered, read, audit, &r).unwrap();
                        let node = &tree.nodes[&6];
                        assert_eq!(node.length, if committed { 9000 } else { 7 });
                        assert_eq!(le32(&node.raw, 40), 2);
                        drop(tree);
                        if committed {
                            for (i, b) in recovered.bytes[120 * 4096..120 * 4096 + 9000]
                                .iter()
                                .enumerate()
                            {
                                assert_eq!(*b, (i * 31 % 251) as u8);
                            }
                        }
                        assert_eq!(
                            &recovered.bytes[112 * 4096..113 * 4096],
                            &seed[112 * 4096..113 * 4096]
                        );
                        let writes = recovered.writes;
                        let flushes = recovered.flushes;
                        journal::recover_recycling_cow(
                            &mut recovered,
                            [0xa5; 16],
                            read,
                            audit,
                            &r,
                            &r,
                        )
                        .unwrap();
                        assert_eq!((writes, flushes), (recovered.writes, recovered.flushes));
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
            println!(
                "combined recovery committed={committed} initial_retained={initial_retained} programs={programs} barriers={barriers} four-persistence profiles passed"
            );
        }
    }
}

#[test]
fn recycling_checkpoint_has_independent_ring_model_and_zero_write_negatives() {
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
    let mut seed = journal_seed();
    for n in 3..30 {
        fixture::p16(&mut seed, (482 + n) * 4096 + 16, 0x4000);
    }
    let make = |bytes: Vec<u8>| CowTestBackend {
        durable: bytes.clone(),
        bytes,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut backend = make(seed.clone());
    let initial_sequence = le32(&seed, 484 * 4096);
    for step in 1..=60usize {
        let plan =
            journal::rollover::prepare_recycling(&backend, [0xa5; 16], read, audit, &r, &r, false)
                .unwrap();
        journal::rollover::publish(&mut backend, plan, &r, &r).unwrap();
        let number = 2 + step % 28;
        let at = (482 + number) * 4096;
        assert_eq!(le32(&backend.bytes, at), initial_sequence + step as u32);
        assert_eq!(le16(&backend.bytes, at + 6), 44);
        assert_eq!(
            &backend.bytes[at..at + 8],
            &backend.bytes[at + 4088..at + 4096]
        );
        assert_eq!(
            le32(&backend.bytes, 483 * 4096 + 32),
            (number * 4096 + 44) as u32
        );
        assert_eq!(&backend.bytes[at + 8..at + 4088], &seed[at + 8..at + 4088]);
    }
    let saved = backend.bytes;
    let anchor = 2 + 60 % 28;
    let target = 2 + 61 % 28;
    for (at, mask) in [
        (32768 + 40, 1u8),                   // aggregate is active/dirty
        (32768 + 136, 1),                    // foreign caller binding
        ((482 + anchor) * 4096 + 8 + 16, 1), // nonzero SYNC stop address
        ((482 + target) * 4096, 1),          // wrong old page sequence
        ((482 + target) * 4096 + 8 + 8, 1),  // first native record is not canonical SYNC
        (32768 + 72, 1),                     // changed inline log geometry
    ] {
        let mut negative = make(saved.clone());
        negative.bytes[at] ^= mask;
        let before = negative.bytes.clone();
        assert!(
            journal::rollover::prepare_recycling(&negative, [0xa5; 16], read, audit, &r, &r, false)
                .is_err(),
            "negative at={at}"
        );
        assert_eq!((negative.writes, negative.flushes), (0, 0));
        assert_eq!(negative.bytes, before);
        assert_eq!(r.memory.used(), 0);
    }
    let plan = journal::rollover::prepare_recycling(
        &make(saved.clone()),
        [0xa5; 16],
        read,
        audit,
        &r,
        &r,
        false,
    )
    .unwrap();
    let mut stale = make(saved);
    stale.bytes[(482 + target) * 4096 + 3000] ^= 1;
    assert_eq!(
        journal::rollover::publish(&mut stale, plan, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!((stale.writes, stale.flushes), (0, 0));
    assert_eq!(r.memory.used(), 0);
}
