//! Closed same-fork undo validation and deferred native clean-state restoration.
use super::*;
use crate::fs_undo::{self, UndoRecoveryValidator, UndoState};

pub(crate) struct Selection<'a> {
    pub(crate) path: &'a [NativeName],
    pub(crate) kind: &'a StreamKind,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) binding: UndoBinding,
}
struct Validator {
    states: [(u64, u8); 2],
    state_seen: [bool; 2],
    allowed: Vec<(u64, usize)>,
    seen: Vec<bool>,
}
impl UndoRecoveryValidator for Validator {
    fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
        for (i, (position, clean)) in self.states.iter().enumerate() {
            if at == *position {
                if self.state_seen[i] || old != [*clean] || new != [*clean] {
                    return Err(bad("HFS+ undo native clean-state framing"));
                }
                self.state_seen[i] = true;
                return Ok(());
            }
        }
        let index = self
            .allowed
            .binary_search(&(at, old.len()))
            .map_err(|_| bad("HFS+ undo patch is outside selected audited fork range"))?;
        if self.seen[index] || new.len() != old.len() {
            return Err(bad("HFS+ undo duplicated/malformed selected range"));
        }
        self.seen[index] = true;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        if self.state_seen != [true; 2] || self.seen.iter().any(|seen| !seen) {
            return Err(bad(
                "HFS+ undo does not cover selected range and both native states",
            ));
        }
        Ok(())
    }
}
struct Restore<'a> {
    target: &'a mut dyn Storage,
    states: [(u64, u8); 2],
    state_seen: [bool; 2],
    started: bool,
    saved: Vec<(u64, Vec<u8>)>,
    recorded: u64,
    undo: UndoLimits,
    limits: Limits,
    r: &'a Resources,
}
impl Storage for Restore<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            fence(self.target, self.states, false, self.r)?;
        }
        for (i, (position, clean)) in self.states.iter().enumerate() {
            if at == *position {
                if bytes != [*clean] {
                    return Err(io::Error::other("HFS+ restoration state framing"));
                }
                self.state_seen[i] = true;
                return Ok(1);
            }
        }
        if self
            .recorded
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > self.undo.body_bytes)
        {
            return Err(io::Error::other(budget(
                "HFS+ restored byte recording ceiling",
            )));
        }
        let adjacent = self
            .saved
            .last()
            .is_some_and(|(offset, old)| offset.checked_add(old.len() as u64) == Some(at));
        if !adjacent && self.saved.len() >= self.undo.patches as usize {
            return Err(io::Error::other(budget(
                "HFS+ restored range recording ceiling",
            )));
        }
        let n = self.target.write_at(at, bytes)?;
        if n == 0 || n > bytes.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.recorded += n as u64;
        if adjacent {
            let old = &mut self.saved.last_mut().unwrap().1;
            old.try_reserve(n).map_err(io::Error::other)?;
            old.extend_from_slice(&bytes[..n]);
        } else {
            let mut old = vector(n).map_err(io::Error::other)?;
            old.extend_from_slice(&bytes[..n]);
            self.saved.push((at, old));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()?;
        if self.state_seen != [true; 2] {
            return Err(io::Error::other("HFS+ restoration omitted native states"));
        }
        let mut actual = [0; 512];
        for (at, bytes) in &self.saved {
            for (i, expected) in bytes.chunks(actual.len()).enumerate() {
                self.r.cancellation.check().map_err(io::Error::other)?;
                self.target
                    .read_exact_at(*at + (i * 512) as u64, &mut actual[..expected.len()])?;
                if &actual[..expected.len()] != expected {
                    return Err(io::Error::other("HFS+ restored payload readback mismatch"));
                }
            }
        }
        let prepared = Prepared::open(
            Masked {
                target: self.target,
                states: self.states,
            },
            self.limits,
            self.r,
        )
        .map_err(io::Error::other)?;
        if !prepared.proof.is_clean() {
            return Err(io::Error::other("HFS+ restoration complete audit failed"));
        }
        drop(prepared);
        for (at, clean) in self.states {
            write_full(self.target, at, &[clean], self.r)?;
        }
        self.target.flush()?;
        for (at, clean) in self.states {
            let mut actual = [0];
            self.target.read_exact_at(at, &mut actual)?;
            if actual != [clean] {
                return Err(io::Error::other("HFS+ restored native clean state differs"));
            }
        }
        Ok(())
    }
}
fn recovery_failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "HFS+ recovery preflight",
        recovery_required: true,
        target_may_have_changed: false,
        source,
    }
}
pub(crate) fn recover_range(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    selection: Selection<'_>,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    r.cancellation.check().map_err(recovery_failure)?;
    if selection.length == 0 || selection.length > limits.range_bytes {
        return Err(recovery_failure(budget("HFS+ recovery range byte ceiling")));
    }
    let length = target
        .len()
        .map_err(|e| recovery_failure(Error::io("HFS+ recovery target length", e)))?;
    if length < 4096 {
        return Err(recovery_failure(bad("HFS+ recovery target geometry")));
    }
    let mut primary = [0];
    let mut alternate = [0];
    target
        .read_exact_at(1030, &mut primary)
        .map_err(|e| recovery_failure(Error::io("HFS+ recovery primary state", e)))?;
    target
        .read_exact_at(length - 1018, &mut alternate)
        .map_err(|e| recovery_failure(Error::io("HFS+ recovery alternate state", e)))?;
    let clean = primary[0] | 1;
    if alternate[0] | 1 != clean {
        return Err(recovery_failure(bad(
            "HFS+ recovery native state disagreement",
        )));
    }
    let states = [(1030, clean), (length - 1018, clean)];
    let status = fs_undo::inspect(journal, r).map_err(recovery_failure)?;
    if status.state == UndoState::Empty && (primary != [clean] || alternate != [clean]) {
        return Err(recovery_failure(bad(
            "HFS+ dirty target lacks published undo authority",
        )));
    }
    let prepared =
        Prepared::open(Masked { target, states }, limits, r).map_err(recovery_failure)?;
    let id = prepared
        .volume
        .lookup(selection.path, r)
        .map_err(recovery_failure)?;
    let fork = prepared
        .volume
        .open_fork(&id, selection.kind, r)
        .map_err(recovery_failure)?;
    let end = selection
        .offset
        .checked_add(selection.length)
        .filter(|end| *end <= fork.len())
        .ok_or_else(|| recovery_failure(bad("HFS+ recovery exceeds selected fork EOF")))?;
    let extents = fork.file.extents();
    let _mapping_lease = r
        .memory
        .reserve(
            (extents.len() as u64)
                .checked_mul(64)
                .ok_or_else(|| recovery_failure(budget("HFS+ recovery mapping charge")))?,
        )
        .map_err(recovery_failure)?;
    let mut allowed = vector(extents.len()).map_err(recovery_failure)?;
    let mut covered = 0u64;
    for extent in extents {
        let first = selection.offset.max(extent.offset);
        r.cancellation.check().map_err(recovery_failure)?;
        let extent_end = extent
            .offset
            .checked_add(extent.length)
            .ok_or_else(|| recovery_failure(bad("HFS+ recovery logical extent overflow")))?;
        let last = end.min(extent_end);
        if first >= last {
            continue;
        }
        let crate::fs_file::ExtentKind::Data(physical) = extent.kind else {
            return Err(recovery_failure(bad(
                "HFS+ recovery selected range is not allocated",
            )));
        };
        let offset = physical
            .checked_add(first - extent.offset)
            .ok_or_else(|| recovery_failure(bad("HFS+ recovery physical overflow")))?;
        let count = usize::try_from(last - first)
            .map_err(|_| recovery_failure(budget("HFS+ recovery host range length")))?;
        allowed.push((offset, count));
        covered = covered
            .checked_add(count as u64)
            .ok_or_else(|| recovery_failure(bad("HFS+ recovery mapping coverage overflow")))?;
    }
    if covered != selection.length {
        return Err(recovery_failure(bad(
            "HFS+ recovery incomplete selected mapping",
        )));
    }
    allowed.sort_unstable();
    for pair in allowed.windows(2) {
        let end = pair[0]
            .0
            .checked_add(pair[0].1 as u64)
            .ok_or_else(|| recovery_failure(bad("HFS+ recovery physical range overflow")))?;
        if end > pair[1].0 {
            return Err(recovery_failure(bad(
                "HFS+ recovery selected physical ranges overlap",
            )));
        }
    }
    prepared.revalidate(r).map_err(recovery_failure)?;
    drop((fork, prepared));
    let mut seen = vector(allowed.len()).map_err(recovery_failure)?;
    seen.resize(allowed.len(), false);
    let mut validator = Validator {
        states,
        state_seen: [false; 2],
        allowed,
        seen,
    };
    let charge = undo
        .body_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(u64::from(undo.patches) * 64))
        .ok_or_else(|| recovery_failure(budget("HFS+ recovery recording charge")))?;
    let _lease = r.memory.reserve(charge).map_err(recovery_failure)?;
    let saved = vector(undo.patches as usize).map_err(recovery_failure)?;
    let mut restore = Restore {
        target,
        states,
        state_seen: [false; 2],
        started: false,
        saved,
        recorded: 0,
        undo,
        limits,
        r,
    };
    fs_undo::recover_validated(
        &mut restore,
        journal,
        selection.binding,
        undo,
        r,
        &mut validator,
    )
}

#[test]
fn cold_restore_interrupted_fragmented_range_and_retry_without_writes() {
    struct Memory {
        bytes: Vec<u8>,
        fail: Option<u64>,
        writes: usize,
        flushes: usize,
    }
    impl Storage for Memory {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            if self.fail.is_some_and(|cut| at >= cut && at < cut + 23) {
                return Err(io::Error::from_raw_os_error(5));
            }
            let n = bytes.len().min(3);
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            self.writes += 1;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 32,
        range_bytes: 1 << 16,
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
        patches: 16,
        body_bytes: 1 << 15,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x22; 16],
    };
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let original = super::super::super::independent::hfsplus_seed(binary);
        let path = [NativeName::Utf16(
            super::super::super::independent::native_name(binary),
        )];
        let mut prepared = Prepared::open(
            Memory {
                bytes: original.clone(),
                fail: Some(28 * 4096),
                writes: 0,
                flushes: 0,
            },
            limits,
            &r,
        )
        .unwrap();
        let range = prepared
            .plan_range(&path, &StreamKind::Data, 32760, &[0x5a; 31], &r)
            .unwrap();
        let mut journal = Memory {
            bytes: vec![0; 1 << 16],
            fail: None,
            writes: 0,
            flushes: 0,
        };
        let failure = prepared
            .commit_range(range, &mut journal, binding, undo, &r)
            .unwrap_err();
        assert!(failure.recovery_required && prepared.uncertain);
        assert_eq!(prepared.target.bytes[1030] & 1, 0);
        assert_eq!(
            &prepared.target.bytes[26 * 4096 + 4088..27 * 4096],
            &[0x5a; 8]
        );
        assert!(
            prepared
                .plan_range(&path, &StreamKind::Data, 0, b"x", &r)
                .is_err()
        );
        let mut target = Memory {
            bytes: prepared.target.bytes.clone(),
            fail: None,
            writes: 0,
            flushes: 0,
        };
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
        let select = || Selection {
            path: &path,
            kind: &StreamKind::Data,
            offset: 32760,
            length: 31,
            binding,
        };
        // A valid journal cannot authorize a different selected fork range.
        let mut wrong = select();
        wrong.offset -= 1;
        assert!(recover_range(&mut target, &mut journal, wrong, limits, undo, &r).is_err());
        assert_eq!((target.writes, target.flushes), (0, 0));
        let mut unbound = select();
        unbound.binding.transaction[0] ^= 1;
        let journal_counts = (journal.writes, journal.flushes);
        assert!(recover_range(&mut target, &mut journal, unbound, limits, undo, &r).is_err());
        let mut empty = Memory {
            bytes: vec![0; 1 << 16],
            fail: None,
            writes: 0,
            flushes: 0,
        };
        assert!(recover_range(&mut target, &mut empty, select(), limits, undo, &r).is_err());
        assert_eq!(
            (target.writes, target.flushes, empty.writes, empty.flushes),
            (0, 0, 0, 0)
        );
        assert_eq!((journal.writes, journal.flushes), journal_counts);
        assert_eq!(r.memory.used(), 0);
        // Recovery may itself stop after restoring the inline fragment. Both
        // headers must remain dirty and the prepared journal remains reusable.
        target.fail = Some(28 * 4096);
        let interrupted =
            recover_range(&mut target, &mut journal, select(), limits, undo, &r).unwrap_err();
        assert!(interrupted.recovery_required && interrupted.target_may_have_changed);
        assert_eq!(target.bytes[1030] & 1, 0);
        assert_eq!(target.bytes[target.bytes.len() - 1018] & 1, 0);
        assert_eq!(
            fs_undo::inspect(&journal, &r).unwrap().state,
            UndoState::Prepared
        );
        assert_eq!(r.memory.used(), 0);
        let mut target = Memory {
            bytes: target.bytes,
            fail: None,
            writes: 0,
            flushes: 0,
        };
        let status = recover_range(&mut target, &mut journal, select(), limits, undo, &r).unwrap();
        assert_eq!(status.state, UndoState::RolledBack);
        assert_eq!(target.bytes, original);
        let counts = (
            target.writes,
            target.flushes,
            journal.writes,
            journal.flushes,
        );
        assert_eq!(
            recover_range(&mut target, &mut journal, select(), limits, undo, &r)
                .unwrap()
                .state,
            UndoState::RolledBack
        );
        assert_eq!(
            counts,
            (
                target.writes,
                target.flushes,
                journal.writes,
                journal.flushes
            )
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[cfg(test)]
#[path = "fs_hfsplus_owned_cuts.rs"]
pub(crate) mod cuts;

pub(crate) fn recover_patches(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
    expected: &[WriteRange],
) -> std::result::Result<UndoStatus, UndoFailure> {
    struct Exact<'a> {
        patches: &'a [WriteRange],
        seen: Vec<bool>,
    }
    impl UndoRecoveryValidator for Exact<'_> {
        fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
            let index = self
                .patches
                .binary_search_by_key(&at, WriteRange::offset)
                .map_err(|_| bad("HFS+ resize recovery unexpected range"))?;
            let patch = &self.patches[index];
            if self.seen[index] || old != patch.expected() || new != patch.replacement() {
                return Err(bad("HFS+ resize recovery differs from proved plan"));
            }
            self.seen[index] = true;
            Ok(())
        }
        fn finish(&mut self) -> Result<()> {
            if self.seen.iter().any(|v| !*v) {
                Err(bad("HFS+ resize recovery missing range"))
            } else {
                Ok(())
            }
        }
    }
    let length = target
        .len()
        .map_err(|e| recovery_failure(Error::io("HFS+ resize recovery length", e)))?;
    let mut states = [(1030, 0), (length - 1018, 0)];
    for (at, clean) in &mut states {
        let patch = expected
            .iter()
            .find(|p| p.offset() == *at && p.expected().len() == 1)
            .ok_or_else(|| recovery_failure(bad("HFS+ resize recovery clean authority")))?;
        *clean = patch.expected()[0];
    }
    let _lease = r
        .memory
        .reserve(
            undo.body_bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(u64::from(undo.patches) * 128))
                .ok_or_else(|| recovery_failure(budget("HFS+ resize restore charge")))?,
        )
        .map_err(recovery_failure)?;
    let mut seen = vector(expected.len()).map_err(recovery_failure)?;
    seen.resize(expected.len(), false);
    let mut validator = Exact {
        patches: expected,
        seen,
    };
    let mut restore = Restore {
        target,
        states,
        state_seen: [false; 2],
        started: false,
        saved: vector(undo.patches as usize).map_err(recovery_failure)?,
        recorded: 0,
        undo,
        limits,
        r,
    };
    fs_undo::recover_validated(&mut restore, journal, binding, undo, r, &mut validator)
}
