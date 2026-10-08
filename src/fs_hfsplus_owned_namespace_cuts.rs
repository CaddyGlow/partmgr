//! Every private rename write/barrier cut with cold original-image recovery.
use super::super::transaction::recovery::cuts::{Clock, Model};
use super::*;
use crate::fs_undo::{UndoBinding, UndoLimits, UndoState};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::{Arc, Mutex};
#[cfg(feature = "std")]
#[test]
fn every_rename_commit_cut_recovers_exact_old_or_committed_projection() {
    commit_cuts(None, false, false);
}
fn commit_cuts(native: Option<&native_gate::Gate>, moving: bool, deleting: bool) {
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
        for &directory in if native.is_some_and(|g| g.file_deletes) {
            &[false][..]
        } else if native.is_some_and(|g| g.directory_moves) {
            &[true][..]
        } else if moving && native.is_some() {
            &[false][..]
        } else {
            &[false, true][..]
        } {
            {
                let (original, path) = match native {
                    Some(gate) => gate.source(binary, directory, moving),
                    None => (
                        if (deleting || moving) && directory {
                            super::super::super::independent::hfsplus_directory_seed(binary)
                        } else {
                            super::super::super::independent::hfsplus_seed(binary)
                        },
                        vec![NativeName::Utf16(if deleting && directory {
                            "Target".encode_utf16().collect()
                        } else if directory {
                            "Dir".encode_utf16().collect()
                        } else {
                            super::super::super::independent::native_name(binary)
                        })],
                    ),
                };
                let name: Vec<u16> = "Renamed".encode_utf16().collect();
                let destination = if native.is_some() && moving && !directory {
                    Vec::new()
                } else {
                    vec![NativeName::Utf16(
                        if directory { "Target" } else { "Dir" }
                            .encode_utf16()
                            .collect(),
                    )]
                };
                let request = || RenameRequest {
                    deleting,
                    destination: if moving { Some(&destination) } else { None },
                    path: &path,
                    name: &name,
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
                    let result =
                        commit_public(prepared, request(), &mut journal, binding, undo, &r);
                    let events = clock.lock().unwrap().events;
                    let mut target = match result {
                        Ok(ready) => {
                            assert!(cut.is_none());
                            if deleting {
                                assert!(ready.volume.lookup(&path, &r).is_err());
                            }
                            if moving {
                                let mut moved = destination.clone();
                                moved.push(NativeName::Utf16(name.clone()));
                                let id = ready.volume.lookup(&moved, &r).unwrap();
                                assert_eq!(ready.volume.node(&id).unwrap().directory, directory);
                                if directory {
                                    moved.push(NativeName::Utf16("child".encode_utf16().collect()));
                                    let child = ready.volume.lookup(&moved, &r).unwrap();
                                    assert_eq!(ready.volume.node(&child).unwrap().id, 18);
                                }
                                assert!(ready.volume.lookup(&path, &r).is_err());
                            }
                            ready.into_storage()
                        }
                        Err(failed) => {
                            assert!(cut.is_some());
                            failed.target
                        }
                    };
                    let committed = target.bytes.clone();
                    if deleting && cut.is_none() {
                        let wrong = [NativeName::Utf16("Dir".encode_utf16().collect())];
                        let before = clock.lock().unwrap().events;
                        assert!(
                            super::recover_rename(
                                &mut target,
                                &mut journal,
                                RenameRequest {
                                    deleting: true,
                                    destination: None,
                                    path: &wrong,
                                    name: &[]
                                },
                                binding,
                                limits,
                                undo,
                                &r
                            )
                            .is_err()
                        );
                        assert_eq!(clock.lock().unwrap().events, before);
                        assert_eq!(target.bytes, committed);
                    }
                    target.crash(keep_target);
                    journal.crash(keep_journal);
                    clock.lock().unwrap().fail = None;
                    let writes = target.writes;
                    let journal_writes = journal.writes;
                    let result = recover_public(
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
                                gate.check(binary, directory, moving, &target.bytes, true);
                            }
                        }
                        Ok(_) => {
                            assert_eq!(target.bytes, original);
                            if let Some(gate) = native {
                                gate.check(binary, directory, moving, &target.bytes, false);
                            }
                        }
                        Err(error) => {
                            assert_eq!(error.source.kind, ErrorKind::InvalidData);
                            assert_eq!(target.bytes, original);
                            if let Some(gate) = native {
                                gate.check(binary, directory, moving, &target.bytes, false);
                            }
                            assert_eq!((target.writes, journal.writes), (writes, journal_writes));
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
fn every_rename_rollback_cut_cold_retry_restores_complete_original() {
    rollback_cuts(None, false, false);
}
fn rollback_cuts(native: Option<&native_gate::Gate>, moving: bool, deleting: bool) {
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
        for &directory in if native.is_some_and(|g| g.file_deletes) {
            &[false][..]
        } else if native.is_some_and(|g| g.directory_moves) {
            &[true][..]
        } else if moving && native.is_some() {
            &[false][..]
        } else {
            &[false, true][..]
        } {
            {
                let (original, path) = match native {
                    Some(gate) => gate.source(binary, directory, moving),
                    None => (
                        if (deleting || moving) && directory {
                            super::super::super::independent::hfsplus_directory_seed(binary)
                        } else {
                            super::super::super::independent::hfsplus_seed(binary)
                        },
                        vec![NativeName::Utf16(if deleting && directory {
                            "Target".encode_utf16().collect()
                        } else if directory {
                            "Dir".encode_utf16().collect()
                        } else {
                            super::super::super::independent::native_name(binary)
                        })],
                    ),
                };
                let name: Vec<u16> = "Renamed".encode_utf16().collect();
                let destination = if native.is_some() && moving && !directory {
                    Vec::new()
                } else {
                    vec![NativeName::Utf16(
                        if directory { "Target" } else { "Dir" }
                            .encode_utf16()
                            .collect(),
                    )]
                };
                let request = || RenameRequest {
                    deleting,
                    destination: if moving { Some(&destination) } else { None },
                    path: &path,
                    name: &name,
                };
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let clock = Arc::new(Mutex::new(Clock::default()));
                let mut target = Model::new(original.clone(), clock.clone());
                target.stop_at = Some(
                    u64::from(u32::from_be_bytes(original[1312..1316].try_into().unwrap()))
                        * u64::from(u32::from_be_bytes(original[1064..1068].try_into().unwrap())),
                );
                let prepared = Prepared::open(target, limits, &r).unwrap();
                let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
                let failed =
                    match commit_public(prepared, request(), &mut journal, binding, undo, &r) {
                        Ok(_) => panic!("catalog interruption missed"),
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
                    let result = recover_public(
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
                        recover_public(
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
                    if let Some(gate) = native {
                        gate.check(binary, directory, moving, &target.bytes, false);
                    }
                    assert_eq!(target.durable, original);
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

#[path = "fs_hfsplus_owned_namespace_native_cuts.rs"]
mod native_gate;
#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native all-position rename commit and recovery gate"]
fn native_all_rename_commit_and_recovery_cuts() {
    let gate = native_gate::Gate::open();
    commit_cuts(Some(&gate), false, false);
    rollback_cuts(Some(&gate), false, false);
    gate.finish();
}

#[cfg(feature = "std")]
#[test]
fn every_move_commit_and_rollback_cut_recovers() {
    commit_cuts(None, true, false);
    rollback_cuts(None, true, false);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native all-position cross-parent file move commit/recovery gate"]
fn native_all_move_commit_and_recovery_cuts() {
    let gate = native_gate::Gate::open();
    commit_cuts(Some(&gate), true, false);
    rollback_cuts(Some(&gate), true, false);
    gate.finish();
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native populated directory move all-position gate"]
fn native_all_directory_move_commit_and_recovery_cuts() {
    let gate = native_gate::Gate::open_directories();
    commit_cuts(Some(&gate), true, false);
    rollback_cuts(Some(&gate), true, false);
    gate.finish();
}

fn public_limits(limits: Limits, undo: UndoLimits) -> crate::fs_hfsplus::edit::HfsPlusEditLimits {
    crate::fs_hfsplus::edit::HfsPlusEditLimits {
        pages: limits.pages,
        attempts: limits.attempts,
        work: limits.work,
        range_bytes: limits.range_bytes,
        read: limits.read,
        audit: limits.audit,
        undo,
    }
}
fn commit_public<S: Storage>(
    prepared: Prepared<S>,
    request: RenameRequest<'_>,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<Prepared<S>, RenameFailure<S>> {
    use crate::fs_hfsplus::edit::*;
    let limits = prepared.limits;
    let session =
        HfsPlusEditSession::open(prepared.into_storage(), public_limits(limits, undo), r).unwrap();
    let result = if request.deleting {
        session.delete_entry(
            HfsPlusDeleteRequest { path: request.path },
            journal,
            binding,
            r,
        )
    } else {
        match request.destination {
            Some(destination) => session.move_entry(
                HfsPlusMoveRequest {
                    path: request.path,
                    destination,
                    name: request.name,
                },
                journal,
                binding,
                r,
            ),
            None => session.rename(
                HfsPlusRenameRequest {
                    path: request.path,
                    name: request.name,
                },
                journal,
                binding,
                r,
            ),
        }
    };
    result
        .map(|ready| Prepared::open(ready.into_storage(), limits, r).unwrap())
        .map_err(|failed| RenameFailure {
            target: failed.storage,
            error: failed.failure,
        })
}
fn recover_public(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: RenameRequest<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    use crate::fs_hfsplus::edit::*;
    if request.deleting {
        return recover_delete(
            target,
            journal,
            HfsPlusDeleteRequest { path: request.path },
            binding,
            public_limits(limits, undo),
            r,
        );
    }
    match request.destination {
        Some(destination) => recover_move(
            target,
            journal,
            HfsPlusMoveRequest {
                path: request.path,
                destination,
                name: request.name,
            },
            binding,
            public_limits(limits, undo),
            r,
        ),
        None => crate::fs_hfsplus::edit::recover_rename(
            target,
            journal,
            HfsPlusRenameRequest {
                path: request.path,
                name: request.name,
            },
            binding,
            public_limits(limits, undo),
            r,
        ),
    }
}

#[cfg(feature = "std")]
#[test]
fn every_file_and_empty_directory_delete_commit_and_rollback_cut_recovers() {
    commit_cuts(None, false, true);
    rollback_cuts(None, false, true);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native empty-directory deletion all-position gate"]
fn native_all_empty_directory_delete_commit_and_recovery_cuts() {
    let gate = native_gate::Gate::open_deletions();
    commit_cuts(Some(&gate), false, true);
    rollback_cuts(Some(&gate), false, true);
    gate.finish();
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native fragmented DATA/resource file deletion all-position gate"]
fn native_all_file_delete_commit_and_recovery_cuts() {
    let gate = native_gate::Gate::open_file_deletions();
    commit_cuts(Some(&gate), false, true);
    rollback_cuts(Some(&gate), false, true);
    gate.finish();
}
