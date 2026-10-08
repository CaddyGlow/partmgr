//! Every private resize write/barrier cut with cold original-image recovery.
use super::super::transaction::recovery::cuts::{Clock, Model};
use super::commit::ResizeRequest;
use super::*;
use crate::fs_undo::{UndoBinding, UndoLimits, UndoState};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::{Arc, Mutex};
#[cfg(feature = "std")]
#[test]
fn every_resize_commit_cut_recovers_exact_old_or_committed_projection() {
    commit_cuts(None);
}
fn commit_cuts(native: Option<&native::NativeCutGate>) {
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 256,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };
    for binary in [false, true] {
        for kind in [StreamKind::Data, StreamKind::ResourceFork] {
            for length in [0, 7, 4097, 70000] {
                let (original, path) = match native {
                    Some(gate) => gate.source(binary),
                    None => (
                        super::super::super::independent::hfsplus_seed(binary),
                        [NativeName::Utf16(
                            super::super::super::independent::native_name(binary),
                        )],
                    ),
                };
                let request = || ResizeRequest {
                    path: &path,
                    kind: &kind,
                    length,
                    offset: 0,
                    replacement: &[],
                };
                let run = |cut: Option<usize>,
                           keep_target: bool,
                           keep_journal: bool,
                           expected: Option<&[u8]>| {
                    let r = Resources {
                        memory: Budget::new(16 << 20),
                        cancellation: Cancellation::default(),
                    };
                    let clock = Arc::new(Mutex::new(Clock {
                        events: 0,
                        fail: cut,
                    }));
                    let prepared =
                        Prepared::open(Model::new(original.clone(), clock.clone()), limits, &r)
                            .unwrap();
                    let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
                    let result = prepared.commit_resize(request(), &mut journal, binding, undo, &r);
                    let events = clock.lock().unwrap().events;
                    let mut target = match result {
                        Ok(ready) => {
                            assert!(cut.is_none());
                            ready.into_storage()
                        }
                        Err(failed) => {
                            assert!(cut.is_some());
                            failed.target
                        }
                    };
                    let committed = target.bytes.clone();
                    target.crash(keep_target);
                    journal.crash(keep_journal);
                    clock.lock().unwrap().fail = None;
                    let writes = target.writes;
                    let journal_writes = journal.writes;
                    let result = super::recovery::recover_resize(
                        &mut target,
                        &mut journal,
                        request(),
                        binding,
                        limits,
                        undo,
                        &r,
                    );
                    match result {
                        Ok(status) if status.state == UndoState::Committed => {
                            assert_eq!(target.bytes, expected.unwrap_or(&committed));
                            if let Some(gate) = native {
                                gate.check(binary, &kind, length, &[], &target.bytes, true);
                            }
                        }
                        Ok(_) => {
                            assert_eq!(target.bytes, original);
                            if let Some(gate) = native {
                                gate.check(binary, &kind, length, &[], &target.bytes, false);
                            }
                        }
                        Err(error) => {
                            assert_eq!(error.source.kind, ErrorKind::InvalidData);
                            assert_eq!(target.bytes, original);
                            assert_eq!((target.writes, journal.writes), (writes, journal_writes));
                            if let Some(gate) = native {
                                gate.check(binary, &kind, length, &[], &target.bytes, false);
                            }
                        }
                    }

                    assert_eq!(r.memory.used(), 0);
                    (events, committed)
                };
                let (events, expected) = run(None, false, false, None);
                for keep_target in [false, true] {
                    for keep_journal in [false, true] {
                        for cut in 1..=events {
                            run(Some(cut), keep_target, keep_journal, Some(&expected));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn every_resize_rollback_cut_cold_retry_restores_complete_original() {
    rollback_cuts(None);
}
fn rollback_cuts(native: Option<&native::NativeCutGate>) {
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 256,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };

    for binary in [false, true] {
        for kind in [StreamKind::Data, StreamKind::ResourceFork] {
            for length in [0, 7, 4097, 70000] {
                let (original, path) = match native {
                    Some(gate) => gate.source(binary),
                    None => (
                        super::super::super::independent::hfsplus_seed(binary),
                        [NativeName::Utf16(
                            super::super::super::independent::native_name(binary),
                        )],
                    ),
                };
                let replacement: &[u8] = if length >= 7 { b"XYZ" } else { &[] };
                let request = || ResizeRequest {
                    path: &path,
                    kind: &kind,
                    length,
                    offset: if length >= 7 { 3 } else { 0 },
                    replacement,
                };
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let clock = Arc::new(Mutex::new(Clock::default()));
                let mut target = Model::new(original.clone(), clock.clone());
                let bitmap = u32::from_be_bytes(original[1152..1156].try_into().unwrap()) as u64
                    * u32::from_be_bytes(original[1064..1068].try_into().unwrap()) as u64;
                target.stop_at = Some(bitmap);
                let prepared = Prepared::open(target, limits, &r).unwrap();
                let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
                let failed =
                    match prepared.commit_resize(request(), &mut journal, binding, undo, &r) {
                        Ok(_) => panic!("bitmap interruption missed"),
                        Err(e) => e,
                    };
                assert!(failed.error.recovery_required);
                let stopped = failed.target.bytes.clone();
                let saved = journal.bytes.clone();
                drop((failed, journal));
                assert_eq!(r.memory.used(), 0);
                let run = |cut: Option<usize>, keep_target: bool, keep_journal: bool| {
                    *clock.lock().unwrap() = Clock {
                        events: 0,
                        fail: cut,
                    };
                    let mut target = Model::new(stopped.clone(), clock.clone());
                    let mut journal = Model::new(saved.clone(), clock.clone());
                    let result = super::recovery::recover_resize(
                        &mut target,
                        &mut journal,
                        request(),
                        binding,
                        limits,
                        undo,
                        &r,
                    );
                    let events = clock.lock().unwrap().events;
                    if cut.is_some() {
                        assert!(result.is_err());
                    } else {
                        assert_eq!(result.unwrap().state, UndoState::RolledBack);
                    }
                    target.crash(keep_target);
                    journal.crash(keep_journal);
                    clock.lock().unwrap().fail = None;
                    assert_eq!(
                        super::recovery::recover_resize(
                            &mut target,
                            &mut journal,
                            request(),
                            binding,
                            limits,
                            undo,
                            &r
                        )
                        .unwrap()
                        .state,
                        UndoState::RolledBack
                    );
                    assert_eq!(target.bytes, original);
                    assert_eq!(target.durable, original);
                    if let Some(gate) = native {
                        gate.check(binary, &kind, length, replacement, &target.bytes, false);
                    }
                    assert_eq!(r.memory.used(), 0);
                    events
                };
                let events = run(None, false, false);
                for keep_target in [false, true] {
                    for keep_journal in [false, true] {
                        for cut in 1..=events {
                            run(Some(cut), keep_target, keep_journal);
                        }
                    }
                }
            }
        }
    }
}

#[path = "fs_hfsplus_owned_resize_native_cuts.rs"]
mod native;

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native all-position resize commit and rollback cold recovery gate"]
fn native_all_resize_commit_and_rollback_cuts() {
    let gate = native::NativeCutGate::open();
    commit_cuts(Some(&gate));
    rollback_cuts(Some(&gate));
    gate.finish();
}
