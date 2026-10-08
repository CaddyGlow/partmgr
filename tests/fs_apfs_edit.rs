use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_apfs_edit::*, fs_core::*, storage::Storage};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
struct Target {
    bytes: Arc<Mutex<Vec<u8>>>,
    reads: Arc<AtomicUsize>,
    fail: Option<usize>,
}
impl Storage for Target {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail == Some(n) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "independent owned read failure",
            ));
        }
        assert_eq!(out.len(), 4096);
        // Independent fixture places ordinary payload only in these blocks.
        assert!(
            ![100, 102, 110, 112].contains(&(at / 4096)),
            "metadata preparation read payload"
        );
        let bytes = self.bytes.lock().unwrap();
        let start = at as usize;
        out.copy_from_slice(
            bytes
                .get(start..start + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        panic!("preparation must not mutate")
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("preparation must not flush")
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 64,
        attempts: 65,
        work: 16 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: 512,
            checkpoint_blocks: 8,
            objects: 256,
            records: 256,
            work: 64 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks: 512,
            objects: 512,
            depth: 32,
            work: 64 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn target() -> (Target, Arc<Mutex<Vec<u8>>>) {
    let bytes = Arc::new(Mutex::new(fixture::apfs_seed()));
    (
        Target {
            bytes: bytes.clone(),
            reads: Arc::new(AtomicUsize::new(0)),
            fail: None,
        },
        bytes,
    )
}
#[test]
fn owned_metadata_snapshot_proves_without_payload_or_mutation_and_refunds() {
    let r = resources();
    let (t, bytes) = target();
    let before = bytes.lock().unwrap().clone();
    let session = ApfsEditor::open(t, 1026, limits(), &r).unwrap();
    assert_eq!(session.checkpoint_xid(), 1);
    assert!(session.allocation_proof().is_clean());
    assert!(session.copied_metadata_blocks() < 40);
    session.revalidate(&r).unwrap();
    assert_eq!(*bytes.lock().unwrap(), before);
    bytes.lock().unwrap()[32] ^= 1;
    assert_eq!(
        session.revalidate(&r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    drop(session);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn copied_metadata_caps_real_io_cancellation_and_malformed_errors_are_not_retries() {
    for which in 0..6 {
        let r = resources();
        let (mut t, bytes) = target();
        let mut cap = limits();
        match which {
            0 => cap.metadata_blocks = 1,
            1 => cap.attempts = 1,
            2 => cap.work = 1,
            3 => t.fail = Some(0),
            4 => r.cancellation.cancel(),
            _ => bytes.lock().unwrap()[32] ^= 1,
        }
        let error = match ApfsEditor::open(t, 1026, cap, &r) {
            Ok(_) => panic!("accepted bad preparation"),
            Err(e) => e,
        };
        assert_eq!(
            error.kind,
            match which {
                0..=2 => ErrorKind::BudgetExhausted,
                3 => ErrorKind::Io,
                4 => ErrorKind::Cancelled,
                _ => ErrorKind::InvalidData,
            }
        );
        if which == 3 {
            assert_eq!(
                error.source.unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert_eq!(r.memory.used(), 0);
    }
}
struct CowTarget {
    bytes: Arc<Mutex<Vec<u8>>>,
    flushes: Arc<AtomicUsize>,
}
impl Storage for CowTarget {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let bytes = self.bytes.lock().unwrap();
        let start = at as usize;
        out.copy_from_slice(
            bytes
                .get(start..start + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let n = input.len().min(73);
        let mut bytes = self.bytes.lock().unwrap();
        let start = at as usize;
        bytes
            .get_mut(start..start + n)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&input[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Input {
    id: ObjectId,
    length: u64,
}
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = out
            .len()
            .min(7)
            .min(self.length.saturating_sub(at) as usize);
        for (i, v) in out[..n].iter_mut().enumerate() {
            *v = ((at + i as u64) * 31 + 9) as u8;
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        visitor(LogicalExtent {
            offset: 0,
            length: self.length,
            kind: ExtentKind::Data,
        })
    }
}
#[test]
fn native_cow_range_retains_old_checkpoint_and_invalidates_owner_handles() {
    let r = resources();
    let bytes = Arc::new(Mutex::new(fixture::apfs_seed()));
    let original = bytes.lock().unwrap().clone();
    let flushes = Arc::new(AtomicUsize::new(0));
    let target = CowTarget {
        bytes: bytes.clone(),
        flushes: flushes.clone(),
    };
    let mut editor = ApfsEditor::open(target, 1026, limits(), &r).unwrap();
    let id = editor.file_identity(16, &r).unwrap();
    assert_eq!(id.source >> 64, 17);
    let input = Arc::new(Input {
        id: ObjectId {
            source: 99,
            generation: 3,
            native: vec![1],
        },
        length: 29,
    });
    let anchor = editor.recovery_anchor();
    let plan = editor.plan_range(&id, 4091, input, &r).unwrap();
    let receipt = editor.commit_range(plan, &anchor, &r).unwrap();
    assert_eq!(receipt.xid, 2);
    assert_eq!(flushes.load(Ordering::SeqCst), 5);
    assert_eq!(editor.checkpoint_xid(), 2);
    assert!(editor.allocation_proof().is_clean());
    assert_eq!(
        editor
            .read_file_at(&id, 0, &mut [0; 1], &r)
            .unwrap_err()
            .kind,
        ErrorKind::StalePlan
    );
    let fresh = editor.file_identity(16, &r).unwrap();
    let mut actual = vec![0; 16397];
    editor.read_file_at(&fresh, 0, &mut actual, &r).unwrap();
    let mut expected = vec![0; 16397];
    expected[..4096].copy_from_slice(&original[100 * 4096..101 * 4096]);
    expected[8192..12288].copy_from_slice(&original[102 * 4096..103 * 4096]);
    expected[16384..].copy_from_slice(&original[110 * 4096..110 * 4096 + 13]);
    for i in 0..29 {
        expected[4091 + i] = (i * 31 + 9) as u8;
    }
    assert_eq!(actual, expected);
    assert_eq!(&bytes.lock().unwrap()[16..24], &2u64.to_le_bytes());
    assert_eq!(
        &bytes.lock().unwrap()[100 * 4096..101 * 4096],
        &original[100 * 4096..101 * 4096]
    );
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
#[derive(Clone)]
struct DurableState {
    volatile: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    flushes: usize,
}
struct CutStore {
    state: Arc<Mutex<DurableState>>,
    write_cut: Option<usize>,
    flush_cut: Option<usize>,
    write_persistent: bool,
    failed_flush_persistent: bool,
}
impl Storage for CutStore {
    fn len(&self) -> io::Result<u64> {
        Ok(self.state.lock().unwrap().volatile.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        let at = at as usize;
        out.copy_from_slice(
            state
                .volatile
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        let at = at as usize;
        let n = bytes.len().min(73);
        let fail = self.write_cut == Some(state.writes);
        state.writes += 1;
        let written = if fail { n / 2 } else { n };
        state.volatile[at..at + written].copy_from_slice(&bytes[..written]);
        if self.write_persistent {
            state.durable[at..at + written].copy_from_slice(&bytes[..written]);
        }
        if fail {
            Err(io::Error::other("independent torn write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let fail = self.flush_cut == Some(state.flushes);
        state.flushes += 1;
        if !fail || self.failed_flush_persistent {
            state.durable = state.volatile.clone();
        }
        if fail {
            Err(io::Error::other("independent uncertain flush"))
        } else {
            Ok(())
        }
    }
}
fn cut_store(
    image: Vec<u8>,
    write_cut: Option<usize>,
    flush_cut: Option<usize>,
    model: usize,
) -> (CutStore, Arc<Mutex<DurableState>>) {
    let state = Arc::new(Mutex::new(DurableState {
        volatile: image.clone(),
        durable: image,
        writes: 0,
        flushes: 0,
    }));
    (
        CutStore {
            state: state.clone(),
            write_cut,
            flush_cut,
            write_persistent: model & 1 != 0,
            failed_flush_persistent: model & 2 != 0,
        },
        state,
    )
}
fn restart(
    state: &Arc<Mutex<DurableState>>,
    write_cut: Option<usize>,
    flush_cut: Option<usize>,
    model: usize,
) -> CutStore {
    let mut data = state.lock().unwrap();
    data.volatile = data.durable.clone();
    data.writes = 0;
    data.flushes = 0;
    drop(data);
    CutStore {
        state: state.clone(),
        write_cut,
        flush_cut,
        write_persistent: model & 1 != 0,
        failed_flush_persistent: model & 2 != 0,
    }
}
fn old_payload(image: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 16397];
    bytes[..4096].copy_from_slice(&image[100 * 4096..101 * 4096]);
    bytes[8192..12288].copy_from_slice(&image[102 * 4096..103 * 4096]);
    bytes[16384..].copy_from_slice(&image[110 * 4096..110 * 4096 + 13]);
    bytes
}
#[test]
fn all_native_block_stage_boundaries_and_torn_publication_boot_cuts_recover_four_persistence_models()
 {
    let original = fixture::apfs_seed();
    let old = old_payload(&original);
    let mut new = old.clone();
    for i in 0..29 {
        new[4091 + i] = (i * 31 + 9) as u8;
    }
    let mut cuts: Vec<_> = (0..=20).map(|block| (Some(block * 57), None)).collect();
    for step in [1, 7, 28, 55, 56] {
        cuts.push((Some(18 * 57 + step), None));
        cuts.push((Some(19 * 57 + step), None));
    }
    for flush in 0..5 {
        cuts.push((None, Some(flush)));
    }
    for model in 0..4 {
        for (write_cut, flush_cut) in &cuts {
            let r = resources();
            let (target, state) = cut_store(original.clone(), *write_cut, *flush_cut, model);
            let mut editor = ApfsEditor::open(target, 1026, limits(), &r).unwrap();
            let anchor = ApfsRecoveryAnchor::decode(&editor.recovery_anchor().encode()).unwrap();
            let id = editor.file_identity(16, &r).unwrap();
            let plan = editor
                .plan_range(
                    &id,
                    4091,
                    Arc::new(Input {
                        id: ObjectId {
                            source: 99,
                            generation: 3,
                            native: vec![1],
                        },
                        length: 29,
                    }),
                    &r,
                )
                .unwrap();
            let result = editor.commit_range(plan, &anchor, &r);
            if result.is_err() {
                assert_eq!(
                    editor
                        .read_file_at(&id, 0, &mut [0; 1], &r)
                        .unwrap_err()
                        .kind,
                    ErrorKind::InterruptedWrite
                );
            }
            drop(editor);
            let recovered = ApfsEditor::recover_with_anchor(
                restart(&state, None, None, model),
                &anchor,
                limits(),
                &r,
            )
            .unwrap_or_else(|e| panic!("model{model} write{write_cut:?} flush{flush_cut:?}: {e}"));
            assert!(recovered.allocation_proof().is_clean());
            let fresh = recovered.file_identity(16, &r).unwrap();
            let mut bytes = vec![0; 16397];
            recovered.read_file_at(&fresh, 0, &mut bytes, &r).unwrap();
            match recovered.checkpoint_xid() {
                1 => assert_eq!(bytes, old),
                2 => assert_eq!(bytes, new),
                xid => panic!("unexpected recoveredXID{xid}"),
            };
            drop(recovered);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn torn_boot_recovery_itself_is_restartable_and_anchor_damage_refuses_before_mutation() {
    let r = resources();
    let (target, state) = cut_store(fixture::apfs_seed(), Some(19 * 57 + 7), None, 1);
    let mut editor = ApfsEditor::open(target, 1026, limits(), &r).unwrap();
    let anchor = editor.recovery_anchor();
    let id = editor.file_identity(16, &r).unwrap();
    let plan = editor
        .plan_range(
            &id,
            4091,
            Arc::new(Input {
                id: ObjectId {
                    source: 99,
                    generation: 3,
                    native: vec![1],
                },
                length: 29,
            }),
            &r,
        )
        .unwrap();
    assert!(editor.commit_range(plan, &anchor, &r).is_err());
    drop(editor);
    let cut_state = state.lock().unwrap().durable.clone();
    for model in 0..4 {
        for cut in [0, 1, 7, 28, 55, 56] {
            let (target, state) = cut_store(cut_state.clone(), Some(cut), None, model);
            assert!(ApfsEditor::recover_with_anchor(target, &anchor, limits(), &r).is_err());
            let recovered = ApfsEditor::recover_with_anchor(
                restart(&state, None, None, model),
                &anchor,
                limits(),
                &r,
            )
            .unwrap();
            assert_eq!(recovered.checkpoint_xid(), 2);
            assert!(recovered.allocation_proof().is_clean());
            drop(recovered);
            assert_eq!(r.memory.used(), 0);
        }
    }
    let mut encoded = anchor.encode();
    encoded[16] ^= 1;
    assert_eq!(
        ApfsRecoveryAnchor::decode(&encoded).unwrap_err().kind,
        ErrorKind::InvalidOperation
    );
    let mut wrong = anchor.encode();
    wrong[8..16].copy_from_slice(&(4 * 1024 * 1024u64).to_le_bytes());
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&wrong[..64]);
    wrong[64..].copy_from_slice(&hash);
    let wrong = ApfsRecoveryAnchor::decode(&wrong).unwrap();
    let (target, state) = cut_store(cut_state, None, None, 1);
    assert_eq!(
        ApfsEditor::recover_with_anchor(target, &wrong, limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(state.lock().unwrap().writes, 0);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn metadata_discovery_runs_once_with_non_send_exclusive_storage() {
    struct LocalTarget {
        target: Target,
        _local: std::rc::Rc<()>,
    }
    impl Storage for LocalTarget {
        fn len(&self) -> io::Result<u64> {
            self.target.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.target.read_exact_at(offset, out)
        }
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
            self.target.write_at(offset, bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.target.flush()
        }
    }
    let r = resources();
    let (target, _) = target();
    let reads = target.reads.clone();
    let mut cap = limits();
    let two_decodes = 2 * (cap.read.work + cap.audit.work);
    cap.work = two_decodes + 4 * 1024 * 1024;
    let session = ApfsEditor::open(
        LocalTarget {
            target,
            _local: std::rc::Rc::new(()),
        },
        1026,
        cap,
        &r,
    )
    .unwrap();
    assert_eq!(
        reads.load(Ordering::Relaxed),
        2 * session.copied_metadata_blocks()
    );
    assert!(session.work_used() <= cap.work);
    assert!(session.work_used() >= two_decodes);
    drop(session);
    assert_eq!(r.memory.used(), 0);
}
