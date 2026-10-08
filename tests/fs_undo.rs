#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_undo::{self, UndoBinding, UndoLimits, UndoPlan, UndoState},
    storage::{Storage, WriteRange},
};
use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Clock {
    events: usize,
    fail: Option<usize>,
}
struct Model {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    clock: Arc<Mutex<Clock>>,
    short: usize,
    writes: usize,
    stage_gate: bool,
}
impl Model {
    fn new(bytes: Vec<u8>, clock: Arc<Mutex<Clock>>) -> Self {
        Self {
            durable: bytes.clone(),
            bytes,
            clock,
            short: usize::MAX,
            writes: 0,
            stage_gate: false,
        }
    }
    fn event(&self) -> bool {
        let mut clock = self.clock.lock().unwrap();
        clock.events += 1;
        clock.fail == Some(clock.events)
    }
    fn crash(&mut self, retain_unflushed: bool) {
        if retain_unflushed {
            self.durable.clone_from(&self.bytes);
        }
        self.bytes.clone_from(&self.durable);
    }
}
impl Storage for Model {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
        let bytes = self
            .bytes
            .get(
                at..at
                    .checked_add(out.len())
                    .ok_or(io::ErrorKind::InvalidInput)?,
            )
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        if self.stage_gate && offset == 27 {
            assert_eq!(
                &self.durable[110..123],
                &[219; 13],
                "metadata write preceded durable initialized data"
            );
        }
        self.writes += 1;
        let fail = self.event();
        let n = if fail {
            bytes.len().div_ceil(2)
        } else {
            bytes.len().min(self.short)
        };
        let at = offset as usize;
        self.bytes[at..at + n].copy_from_slice(&bytes[..n]);
        if fail {
            Err(io::Error::other("modeled torn write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.event() {
            return Err(io::Error::other("modeled failed barrier"));
        }
        self.durable.clone_from(&self.bytes);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    }
}
fn binding() -> UndoBinding {
    UndoBinding {
        volume: [7; 32],
        generation: 19,
        transaction: [8; 16],
    }
}
type Fixture = (UndoPlan, Model, Model, Vec<u8>, Vec<u8>, Arc<Mutex<Clock>>);
fn fixture(r: &Resources) -> Fixture {
    let clock = Arc::new(Mutex::new(Clock::default()));
    let before: Vec<u8> = (0..256).map(|n| (n * 7 + 3) as u8).collect();
    let mut after = before.clone();
    after[27..38].fill(42);
    after[110..123].fill(219);
    let patches = vec![
        WriteRange::new(110, before[110..123].to_vec(), after[110..123].to_vec()).unwrap(),
        WriteRange::new(27, before[27..38].to_vec(), after[27..38].to_vec()).unwrap(),
    ];
    let plan = UndoPlan::new(binding(), 256, patches, UndoLimits::default(), r).unwrap();
    (
        plan,
        Model::new(before.clone(), clock.clone()),
        Model::new(vec![0; 2048], clock.clone()),
        before,
        after,
        clock,
    )
}
#[test]
fn every_write_and_barrier_cut_recovers_old_or_verified_committed_new() {
    let r = resources();
    let (plan, mut target, mut journal, _, _, clock) = fixture(&r);
    assert_eq!(
        plan.commit(&mut target, &mut journal, &r).unwrap().state,
        UndoState::Committed
    );
    let events = clock.lock().unwrap().events;
    assert!(events >= 12);
    drop(plan);
    for retain in [false, true] {
        for cut in 1..=events {
            let (plan, mut target, mut journal, before, after, clock) = fixture(&r);
            clock.lock().unwrap().fail = Some(cut);
            let error = plan.commit(&mut target, &mut journal, &r).unwrap_err();
            assert!(std::error::Error::source(&error).is_some());
            target.crash(retain);
            journal.crash(retain);
            clock.lock().unwrap().fail = None;
            match fs_undo::inspect(&journal, &r) {
                Ok(status) if status.state != UndoState::Empty => {
                    let result = fs_undo::recover(
                        &mut target,
                        &mut journal,
                        binding(),
                        UndoLimits::default(),
                        &r,
                    )
                    .unwrap();
                    assert_eq!(
                        target.bytes,
                        if result.state == UndoState::Committed {
                            after
                        } else {
                            before
                        },
                        "cut {cut}, retain {retain}"
                    );
                    let recovered = target.bytes.clone();
                    let writes = target.writes;
                    assert_eq!(
                        fs_undo::recover(
                            &mut target,
                            &mut journal,
                            binding(),
                            UndoLimits::default(),
                            &r
                        )
                        .unwrap()
                        .state,
                        result.state
                    );
                    assert_eq!(target.bytes, recovered);
                    assert_eq!(target.writes, writes);
                }
                _ => assert_eq!(
                    target.bytes, before,
                    "unpublished journal cannot accompany target mutation: cut {cut}"
                ),
            }
            drop(plan);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
fn prepared(r: &Resources) -> (UndoPlan, Model, Model, Vec<u8>, Arc<Mutex<Clock>>) {
    let (plan, mut target, mut journal, before, _, clock) = fixture(r);
    // Determine the first target event from an independent dry run's clear/body/marker protocol.
    // Eight journal writes/flushes precede target writes in this two-patch fixture.
    // Obtain the actual point by allowing one successful run, then replay until target changes.
    let mut cut = 1;
    loop {
        clock.lock().unwrap().events = 0;
        clock.lock().unwrap().fail = Some(cut);
        let result = plan.commit(&mut target, &mut journal, r);
        if result.as_ref().is_err_and(|e| e.target_may_have_changed) && target.bytes != before {
            break;
        }
        let c = clock.clone();
        target = Model::new(before.clone(), c.clone());
        journal = Model::new(vec![0; 2048], c);
        cut += 1;
        assert!(cut < 100);
    }
    assert_eq!(
        fs_undo::inspect(&journal, r).unwrap().state,
        UndoState::Prepared
    );
    clock.lock().unwrap().fail = None;
    (plan, target, journal, before, clock)
}
#[test]
fn every_rollback_cut_is_restartable_with_torn_writes_and_lost_flushes() {
    let r = resources();
    let (plan, target, journal, before, clock) = prepared(&r);
    let target_bytes = target.bytes.clone();
    let journal_bytes = journal.bytes.clone();
    drop(target);
    drop(journal);
    let mut target = Model::new(target_bytes.clone(), clock.clone());
    let mut journal = Model::new(journal_bytes.clone(), clock.clone());
    clock.lock().unwrap().events = 0;
    fs_undo::recover(
        &mut target,
        &mut journal,
        binding(),
        UndoLimits::default(),
        &r,
    )
    .unwrap();
    let events = clock.lock().unwrap().events;
    for retain in [false, true] {
        for cut in 1..=events {
            let mut target = Model::new(target_bytes.clone(), clock.clone());
            let mut journal = Model::new(journal_bytes.clone(), clock.clone());
            *clock.lock().unwrap() = Clock {
                events: 0,
                fail: Some(cut),
            };
            assert!(
                fs_undo::recover(
                    &mut target,
                    &mut journal,
                    binding(),
                    UndoLimits::default(),
                    &r
                )
                .is_err()
            );
            target.crash(retain);
            journal.crash(retain);
            clock.lock().unwrap().fail = None;
            assert_eq!(
                fs_undo::recover(
                    &mut target,
                    &mut journal,
                    binding(),
                    UndoLimits::default(),
                    &r
                )
                .unwrap()
                .state,
                UndoState::RolledBack
            );
            assert_eq!(target.bytes, before);
        }
    }
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn stale_bounds_pending_corruption_binding_and_limits_reject_before_target_writes() {
    let r = resources();
    let (plan, mut target, mut journal, _, _, _) = fixture(&r);
    target.bytes[28] ^= 1;
    let error = plan.commit(&mut target, &mut journal, &r).unwrap_err();
    assert_eq!(error.source.kind, ErrorKind::StalePlan);
    assert_eq!(target.writes, 0);
    assert_eq!(journal.writes, 0);
    drop(plan);
    let (plan, mut target, mut journal, _, _) = prepared(&r);
    let writes = target.writes;
    let pending = plan.commit(&mut target, &mut journal, &r).unwrap_err();
    assert!(pending.recovery_required);
    assert_eq!(target.writes, writes);
    let mut wrong = binding();
    wrong.volume[0] ^= 1;
    assert_eq!(
        fs_undo::recover(&mut target, &mut journal, wrong, UndoLimits::default(), &r)
            .unwrap_err()
            .source
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.writes, writes);
    assert_eq!(
        fs_undo::recover(
            &mut target,
            &mut journal,
            binding(),
            UndoLimits {
                patches: 1,
                body_bytes: 1 << 20
            },
            &r
        )
        .unwrap_err()
        .source
        .kind,
        ErrorKind::BudgetExhausted
    );
    journal.bytes[1041] ^= 1;
    assert_eq!(
        fs_undo::recover(
            &mut target,
            &mut journal,
            binding(),
            UndoLimits::default(),
            &r
        )
        .unwrap_err()
        .source
        .kind,
        ErrorKind::InvalidData
    );
    assert_eq!(target.writes, writes);
    assert!(
        UndoPlan::new(
            binding(),
            256,
            vec![WriteRange::new(250, vec![1; 8], vec![2; 8]).unwrap()],
            UndoLimits::default(),
            &r
        )
        .is_err()
    );
    assert!(
        UndoPlan::new(
            binding(),
            256,
            vec![
                WriteRange::new(2, vec![1; 4], vec![2; 4]).unwrap(),
                WriteRange::new(4, vec![1; 4], vec![2; 4]).unwrap()
            ],
            UndoLimits::default(),
            &r
        )
        .is_err()
    );
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn short_writes_cancellation_capacity_charges_and_terminal_mismatch() {
    let r = resources();
    let (plan, mut target, mut journal, _, after, _) = fixture(&r);
    target.short = 3;
    journal.short = 37;
    plan.commit(&mut target, &mut journal, &r).unwrap();
    assert_eq!(target.bytes, after);
    target.bytes[27] ^= 1;
    let writes = target.writes;
    assert_eq!(
        fs_undo::recover(
            &mut target,
            &mut journal,
            binding(),
            UndoLimits::default(),
            &r
        )
        .unwrap_err()
        .source
        .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.writes, writes);
    drop(plan);
    let (plan, mut target, mut journal, _, _, _) = fixture(&r);
    r.cancellation.cancel();
    assert_eq!(
        plan.commit(&mut target, &mut journal, &r)
            .unwrap_err()
            .source
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(target.writes, 0);
    assert_eq!(journal.writes, 0);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let mut before = Vec::with_capacity(4096);
    before.push(1);
    let p = UndoPlan::new(
        binding(),
        1,
        vec![WriteRange::new(0, before, vec![2]).unwrap()],
        UndoLimits::default(),
        &r,
    )
    .unwrap();
    assert!(r.memory.used() >= 4097);
    drop(p);
    assert_eq!(r.memory.used(), 0);
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(
        UndoPlan::new(
            binding(),
            1,
            vec![WriteRange::new(0, vec![1], vec![2]).unwrap()],
            UndoLimits::default(),
            &tiny
        )
        .is_err()
    );
    assert_eq!(tiny.memory.used(), 0);
}

fn staged_fixture(r: &Resources) -> Fixture {
    let (old, target, journal, before, after, clock) = fixture(r);
    drop(old);
    let patches = vec![
        WriteRange::new(110, before[110..123].to_vec(), after[110..123].to_vec()).unwrap(),
        WriteRange::new(27, before[27..38].to_vec(), after[27..38].to_vec()).unwrap(),
    ];
    let plan =
        UndoPlan::new_staged(binding(), 256, patches, &[1, 1], UndoLimits::default(), r).unwrap();
    (plan, target, journal, before, after, clock)
}
#[test]
fn staged_data_precedes_metadata_and_v1_journal_remains_identical() {
    let r = resources();
    let (one, mut target_one, mut journal_one, _, after, _) = fixture(&r);
    one.commit(&mut target_one, &mut journal_one, &r).unwrap();
    let (staged, mut target, mut journal, _, _, clock) = staged_fixture(&r);
    target.stage_gate = true;
    staged.commit(&mut target, &mut journal, &r).unwrap();
    assert_eq!(target.bytes, after);
    assert_eq!(target.durable, after);
    assert_eq!(
        journal.bytes, journal_one.bytes,
        "stages must not alter v1 body or headers"
    );
    assert_eq!(
        fs_undo::inspect(&journal, &r).unwrap().state,
        UndoState::Committed
    );
    assert!(clock.lock().unwrap().events > 0);
    drop(one);
    drop(staged);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn every_staged_write_and_barrier_cut_restores_complete_old_or_committed_new() {
    let r = resources();
    let (plan, mut target, mut journal, _, _, clock) = staged_fixture(&r);
    plan.commit(&mut target, &mut journal, &r).unwrap();
    let events = clock.lock().unwrap().events;
    drop(plan);
    for retain in [false, true] {
        for cut in 1..=events {
            let (plan, mut target, mut journal, before, after, clock) = staged_fixture(&r);
            target.stage_gate = true;
            clock.lock().unwrap().fail = Some(cut);
            let failure = plan.commit(&mut target, &mut journal, &r).unwrap_err();
            assert!(failure.source.source.is_some());
            target.crash(retain);
            journal.crash(retain);
            clock.lock().unwrap().fail = None;
            target.stage_gate = false;
            match fs_undo::inspect(&journal, &r) {
                Ok(status) if status.state != UndoState::Empty => {
                    let status = fs_undo::recover(
                        &mut target,
                        &mut journal,
                        binding(),
                        UndoLimits::default(),
                        &r,
                    )
                    .unwrap();
                    assert_eq!(
                        target.bytes,
                        if status.state == UndoState::Committed {
                            after
                        } else {
                            before
                        },
                        "cut{cut},retain{retain}"
                    );
                    let writes = target.writes;
                    fs_undo::recover(
                        &mut target,
                        &mut journal,
                        binding(),
                        UndoLimits::default(),
                        &r,
                    )
                    .unwrap();
                    assert_eq!(target.writes, writes);
                }
                _ => assert_eq!(
                    target.bytes, before,
                    "unpublished staged transaction changed target cut{cut}"
                ),
            }
            drop(plan);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
struct VerificationFault(Model);
impl Storage for VerificationFault {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, out)?;
        if offset == 110 && !out.is_empty() && self.0.writes > 0 && self.0.durable[110] == 219 {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.0.write_at(offset, data)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
#[test]
fn stage_readback_failure_prevents_reference_writes_and_allows_full_rollback() {
    let r = resources();
    let (plan, target, mut journal, before, _, _) = staged_fixture(&r);
    let mut target = VerificationFault(target);
    let failure = plan.commit(&mut target, &mut journal, &r).unwrap_err();
    assert_eq!(failure.stage, "target stage flush and verification");
    assert_eq!(failure.source.kind, ErrorKind::StalePlan);
    assert!(failure.recovery_required && failure.target_may_have_changed);
    assert_eq!(target.0.writes, 1);
    assert_eq!(target.0.bytes[27..38], before[27..38]);
    fs_undo::recover(
        &mut target,
        &mut journal,
        binding(),
        UndoLimits::default(),
        &r,
    )
    .unwrap();
    assert_eq!(target.0.bytes, before);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn invalid_stages_and_stage_reservations_fail_before_any_mutation() {
    let r = resources();
    for lengths in [&[][..], &[0, 2], &[1], &[1, 1, 1], &[usize::MAX, 1]] {
        let patches = vec![
            WriteRange::new(0, vec![0], vec![1]).unwrap(),
            WriteRange::new(2, vec![0], vec![2]).unwrap(),
        ];
        assert!(
            UndoPlan::new_staged(binding(), 4, patches, lengths, UndoLimits::default(), &r)
                .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(
        matches!(UndoPlan::new_staged(binding(),4,vec![WriteRange::new(0,vec![0],vec![1]).unwrap()],&[1],UndoLimits::default(),&tiny),Err(e) if e.kind==ErrorKind::BudgetExhausted)
    );
    assert_eq!(tiny.memory.used(), 0);
}
