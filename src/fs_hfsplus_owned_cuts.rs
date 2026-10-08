//! HFS+ native-state and external-undo persistence cuts.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::{Arc, Mutex};
#[derive(Default)]
pub(crate) struct Clock {
    pub(crate) events: usize,
    pub(crate) fail: Option<usize>,
}
pub(crate) struct Model {
    pub(crate) bytes: Vec<u8>,
    pub(crate) durable: Vec<u8>,
    pub(crate) clock: Arc<Mutex<Clock>>,
    pub(crate) short: usize,
    pub(crate) writes: usize,
    pub(crate) stop_at: Option<u64>,
}
impl Model {
    pub(crate) fn new(bytes: Vec<u8>, clock: Arc<Mutex<Clock>>) -> Self {
        Self {
            durable: bytes.clone(),
            bytes,
            clock,
            short: usize::MAX,
            writes: 0,
            stop_at: None,
        }
    }
    fn event(&self) -> bool {
        let mut clock = self.clock.lock().unwrap();
        clock.events += 1;
        clock.fail == Some(clock.events)
    }
    pub(crate) fn crash(&mut self, retain_unflushed: bool) {
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
        self.writes += 1;
        let fail = self.event() || self.stop_at == Some(offset);
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

#[cfg(feature = "std")]
#[test]
fn every_native_range_commit_cut_cold_recovers_exact_image() {
    commit_cuts(None);
}
fn commit_cuts(native: Option<&crate::platform::path::Path>) {
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
        let label = if binary { "hfsx" } else { "hfsplus" };
        let original = if native.is_some() {
            crate::platform::fs::read(format!(
                "/data/cache/partmgr-hfsplus-public-builder-native-v2/{label}-source.img"
            ))
            .unwrap()
        } else {
            super::super::super::super::independent::hfsplus_seed(binary)
        };
        let path = if native.is_some() {
            vec![
                NativeName::Utf16("DIR".encode_utf16().collect()),
                NativeName::Utf16("payload".encode_utf16().collect()),
            ]
        } else {
            vec![NativeName::Utf16(
                super::super::super::super::independent::native_name(binary),
            )]
        };
        let offset = if native.is_some() { 3 } else { 32760 };
        let replacement = vec![0x5a; if native.is_some() { 5 } else { 31 }];
        let mut expected = original.clone();
        if native.is_some() {
            let positions: Vec<_> = original
                .windows(22)
                .enumerate()
                .filter(|(_, b)| *b == b"typed metadata payload")
                .map(|(at, _)| at)
                .collect();
            assert_eq!(positions.len(), 1);
            expected[positions[0] + 3..positions[0] + 8].fill(0x5a);
        } else {
            expected[26 * 4096 + 4088..27 * 4096].fill(0x5a);
            expected[28 * 4096..28 * 4096 + 23].fill(0x5a);
        }
        let run = |cut: Option<usize>, retain_target: bool, retain_journal: bool| {
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let clock = Arc::new(Mutex::new(Clock {
                events: 0,
                fail: cut,
            }));
            let mut prepared =
                Prepared::open(Model::new(original.clone(), clock.clone()), limits, &r).unwrap();
            let range = prepared
                .plan_range(&path, &StreamKind::Data, offset, &replacement, &r)
                .unwrap();
            let mut journal = Model::new(vec![0; 1 << 16], clock.clone());
            let result = prepared.commit_range(range, &mut journal, binding, undo, &r);
            let events = clock.lock().unwrap().events;
            if cut.is_some() {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().state, UndoState::Committed);
            }
            let mut target = Model::new(prepared.target.bytes.clone(), clock.clone());
            target.durable = prepared.target.durable.clone();
            drop(prepared);
            target.crash(retain_target);
            journal.crash(retain_journal);
            clock.lock().unwrap().fail = None;
            let writes_before = target.writes;
            let result = recover_range(
                &mut target,
                &mut journal,
                Selection {
                    path: &path,
                    kind: &StreamKind::Data,
                    offset,
                    length: replacement.len() as u64,
                    binding,
                },
                limits,
                undo,
                &r,
            );
            if let Err(error) = &result {
                // A torn first journal header can safely reject only while the
                // target remains exactly untouched and clean.
                assert_eq!(error.source.kind, ErrorKind::InvalidData);
                assert_eq!(target.bytes, original);
                assert_eq!(target.writes, writes_before);
            } else if result.unwrap().state == UndoState::Committed {
                assert_eq!(target.bytes, expected);
            } else {
                assert_eq!(target.bytes, original);
            }
            assert_eq!(target.bytes[1030] & 1, 1);
            assert_eq!(target.bytes[target.bytes.len() - 1018] & 1, 1);
            assert_eq!(r.memory.used(), 0);
            if let Some(output) = native {
                let stem = format!(
                    "{label}-cut{:03}-t{}-j{}",
                    cut.unwrap_or(0),
                    u8::from(retain_target),
                    u8::from(retain_journal)
                );
                let image = output.join(format!("{stem}.img"));
                crate::platform::fs::write(&image, &target.bytes).unwrap();
                let check=crate::platform::process::Command::new("/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus").arg("-fn").arg(&image).output().unwrap();
                crate::platform::fs::write(
                    output.join(format!("{stem}-fsck.stdout")),
                    &check.stdout,
                )
                .unwrap();
                crate::platform::fs::write(
                    output.join(format!("{stem}-fsck.stderr")),
                    &check.stderr,
                )
                .unwrap();
                assert!(check.status.success(), "{stem}: {check:?}");
                assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
                let cat = crate::platform::process::Command::new(
                    "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat",
                )
                .args(["-f", "hfs"])
                .arg(&image)
                .arg("17")
                .output()
                .unwrap();
                assert!(cat.status.success());
                let mut payload = b"typed metadata payload".to_vec();
                if target.bytes == expected {
                    payload[3..8].fill(0x5a);
                }
                assert_eq!(cat.stdout, payload, "{stem}");
                crate::platform::fs::write(output.join(format!("{stem}-icat.stdout")), cat.stdout)
                    .unwrap();
                assert_eq!(crate::platform::fs::read(image).unwrap(), target.bytes);
            }
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

#[cfg(feature = "std")]
#[test]
fn every_native_rollback_cut_retries_from_cold_state() {
    rollback_cuts(None);
}
fn rollback_cuts(native: Option<&crate::platform::path::Path>) {
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
        let label = if binary { "hfsx" } else { "hfsplus" };
        let original = if native.is_some() {
            crate::platform::fs::read(format!(
                "/data/cache/partmgr-hfsplus-public-builder-native-v2/{label}-source.img"
            ))
            .unwrap()
        } else {
            super::super::super::super::independent::hfsplus_seed(binary)
        };
        let path = if native.is_some() {
            vec![
                NativeName::Utf16("DIR".encode_utf16().collect()),
                NativeName::Utf16("payload".encode_utf16().collect()),
            ]
        } else {
            vec![NativeName::Utf16(
                super::super::super::super::independent::native_name(binary),
            )]
        };
        let offset = if native.is_some() { 3 } else { 32760 };
        let replacement = vec![0x5a; if native.is_some() { 5 } else { 31 }];
        let physical = if native.is_some() {
            let positions: Vec<_> = original
                .windows(22)
                .enumerate()
                .filter(|(_, b)| *b == b"typed metadata payload")
                .map(|(at, _)| at)
                .collect();
            assert_eq!(positions.len(), 1);
            positions[0] as u64 + 3
        } else {
            26 * 4096 + 4088
        };
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let clock = Arc::new(Mutex::new(Clock::default()));
        let mut target = Model::new(original.clone(), clock.clone());
        target.stop_at = Some(physical);
        let mut prepared = Prepared::open(target, limits, &r).unwrap();
        let range = prepared
            .plan_range(&path, &StreamKind::Data, offset, &replacement, &r)
            .unwrap();
        let mut journal = Model::new(vec![0; 1 << 16], clock.clone());
        assert!(
            prepared
                .commit_range(range, &mut journal, binding, undo, &r)
                .unwrap_err()
                .recovery_required
        );
        let stopped = prepared.target.bytes.clone();
        let saved = journal.bytes.clone();
        drop((prepared, journal));
        assert_eq!(r.memory.used(), 0);
        let select = || Selection {
            path: &path,
            kind: &StreamKind::Data,
            offset,
            length: replacement.len() as u64,
            binding,
        };
        let run = |cut: Option<usize>, keep_target: bool, keep_journal: bool| {
            *clock.lock().unwrap() = Clock {
                events: 0,
                fail: cut,
            };
            let mut target = Model::new(stopped.clone(), clock.clone());
            let mut journal = Model::new(saved.clone(), clock.clone());
            let result = recover_range(&mut target, &mut journal, select(), limits, undo, &r);
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
                recover_range(&mut target, &mut journal, select(), limits, undo, &r)
                    .unwrap()
                    .state,
                UndoState::RolledBack
            );
            assert_eq!(target.bytes, original);
            assert_eq!(target.durable, original);
            assert_eq!(r.memory.used(), 0);
            if let Some(output) = native {
                let stem = format!(
                    "{label}-rollback{:03}-t{}-j{}",
                    cut.unwrap_or(0),
                    u8::from(keep_target),
                    u8::from(keep_journal)
                );
                let image = output.join(format!("{stem}.img"));
                crate::platform::fs::write(&image, &target.bytes).unwrap();
                let check=crate::platform::process::Command::new("/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus").arg("-fn").arg(&image).output().unwrap();
                crate::platform::fs::write(
                    output.join(format!("{stem}-fsck.stdout")),
                    &check.stdout,
                )
                .unwrap();
                crate::platform::fs::write(
                    output.join(format!("{stem}-fsck.stderr")),
                    &check.stderr,
                )
                .unwrap();
                assert!(check.status.success(), "{stem}: {check:?}");
                assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
                let cat = crate::platform::process::Command::new(
                    "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat",
                )
                .args(["-f", "hfs"])
                .arg(&image)
                .arg("17")
                .output()
                .unwrap();
                assert!(cat.status.success());
                assert_eq!(cat.stdout, b"typed metadata payload");
                crate::platform::fs::write(output.join(format!("{stem}-icat.stdout")), cat.stdout)
                    .unwrap();
                assert_eq!(crate::platform::fs::read(image).unwrap(), original);
            }
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

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit HFS+ native commit persistence-cut gate"]
fn native_commit_cuts_fsck_and_full_payload() {
    let output = crate::platform::path::PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_CUT_EVIDENCE")
            .expect("fresh output required"),
    );
    assert!(!output.exists());
    crate::platform::fs::create_dir(&output).unwrap();
    commit_cuts(Some(&output));
    crate::platform::fs::write(output.join("receipt.txt"),"status=passed;scope=all modeled commit writes/barriers;four persistence combinations;HFSplus and HFSX;native fsck/full TSK payload;macOS/public editor open\n").unwrap();
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit HFS+ native rollback persistence-cut gate"]
fn native_rollback_cuts_fsck_and_full_payload() {
    let output = crate::platform::path::PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_ROLLBACK_EVIDENCE")
            .expect("fresh output required"),
    );
    assert!(!output.exists());
    crate::platform::fs::create_dir(&output).unwrap();
    rollback_cuts(Some(&output));
    crate::platform::fs::write(output.join("receipt.txt"),"status=passed;scope=all modeled rollback writes/barriers;four persistence combinations;HFSplus and HFSX;native fsck/full TSK payload;macOS/public editor open\n").unwrap();
}
