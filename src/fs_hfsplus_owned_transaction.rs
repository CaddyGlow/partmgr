//! Private dirty-fenced range commits. Cold native recovery qualification follows.
use super::*;
use crate::fs_undo::{UndoBinding, UndoFailure, UndoLimits, UndoPlan, UndoStatus};

fn failure(source: Error) -> UndoFailure {
    UndoFailure {
        stage: "HFS+ range preflight",
        recovery_required: false,
        target_may_have_changed: false,
        source,
    }
}
fn write_full(target: &mut dyn Storage, at: u64, bytes: &[u8], r: &Resources) -> io::Result<()> {
    let mut done = 0;
    while done < bytes.len() {
        r.cancellation.check().map_err(io::Error::other)?;
        let n = target.write_at(at + done as u64, &bytes[done..])?;
        if n == 0 || n > bytes.len() - done {
            return Err(io::ErrorKind::WriteZero.into());
        }
        done += n;
    }
    Ok(())
}
fn fence(
    target: &mut dyn Storage,
    states: [(u64, u8); 2],
    require_clean: bool,
    r: &Resources,
) -> io::Result<()> {
    for (position, clean) in states {
        let mut actual = [0];
        target.read_exact_at(position, &mut actual)?;
        if actual[0] != clean && (require_clean || actual[0] != clean & !1) {
            return Err(io::Error::other("HFS+ unexpected native state fence"));
        }
    }
    for (position, clean) in states {
        write_full(target, position, &[clean & !1], r)?;
    }
    target.flush()?;
    for (position, clean) in states {
        let mut actual = [0];
        target.read_exact_at(position, &mut actual)?;
        if actual[0] != clean & !1 {
            return Err(io::Error::other("HFS+ dirty native state readback"));
        }
    }
    Ok(())
}
struct Masked<'a> {
    target: &'a dyn Storage,
    states: [(u64, u8); 2],
}
impl Storage for Masked<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)?;
        for (position, clean) in self.states {
            if position >= at && position - at < out.len() as u64 {
                out[(position - at) as usize] = clean;
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
struct DirtyTarget<'a> {
    target: &'a mut dyn Storage,
    states: [(u64, u8); 2],
    started: bool,
    clean_audited: bool,
    limits: Limits,
    r: &'a Resources,
}
impl Storage for DirtyTarget<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            fence(self.target, self.states, true, self.r)?;
        }
        for (position, clean) in self.states {
            if position >= at && position - at < bytes.len() as u64 {
                if at != position || bytes != [clean] {
                    return Err(io::Error::other("HFS+ clean state framing"));
                }
                if !self.clean_audited {
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
                        return Err(io::Error::other(
                            "HFS+ clean publication requires complete proof",
                        ));
                    }
                    drop(prepared);
                    self.clean_audited = true;
                }
            }
        }
        self.target.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()
    }
}
#[path = "fs_hfsplus_owned_recovery.rs"]
pub(crate) mod recovery;
impl<S: Storage> Prepared<S> {
    pub(crate) fn commit_range(
        &mut self,
        range: RangePlan,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo_limits: UndoLimits,
        r: &Resources,
    ) -> std::result::Result<UndoStatus, UndoFailure> {
        if self.uncertain {
            return Err(failure(Error::new(
                ErrorKind::InvalidOperation,
                "HFS+ owned session requires recovery",
            )));
        }
        if range.source != self.volume.root_identity().source || range.generation != self.generation
        {
            return Err(failure(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated HFS+ range plan",
            )));
        }
        self.revalidate(r).map_err(failure)?;
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| failure(budget("HFS+ range generation exhausted")))?;
        let clean = self.volume.header()[6];
        if clean & 1 == 0 || self.volume.alternate(r).map_err(failure)?[6] != clean {
            return Err(failure(bad("HFS+ mirrored native unmounted state")));
        }
        let states = [(1030, clean), (self.snapshot.length - 1018, clean)];
        let count = range.patches.len();
        let _scratch = r
            .memory
            .reserve(
                (count as u64 + 2)
                    .checked_mul(128)
                    .ok_or_else(|| failure(budget("HFS+ range framing charge")))?,
            )
            .map_err(failure)?;
        let mut patches = vector(count + 2).map_err(failure)?;
        patches.extend(range.patches);
        for (at, clean) in states {
            patches.push(
                WriteRange::new(at, vec![clean], vec![clean])
                    .map_err(|e| failure(Error::io("HFS+ state patch", e)))?,
            );
        }
        let plan = UndoPlan::new_staged(
            binding,
            self.snapshot.length,
            patches,
            &[count, 2],
            undo_limits,
            r,
        )
        .map_err(failure)?;
        drop(range._lease);
        self.generation = next;
        self.uncertain = true;
        let result = plan.commit(
            &mut DirtyTarget {
                target: &mut self.target,
                states,
                started: false,
                clean_audited: false,
                limits: self.limits,
                r,
            },
            journal,
            r,
        );
        match result {
            Ok(status) => {
                self.revalidate(r).map_err(|source| UndoFailure {
                    stage: "HFS+ committed metadata revalidation",
                    recovery_required: true,
                    target_may_have_changed: true,
                    source,
                })?;
                self.uncertain = false;
                Ok(status)
            }
            Err(error) => {
                self.uncertain = error.recovery_required || error.target_may_have_changed;
                Err(error)
            }
        }
    }
}

#[test]
fn private_dirty_fenced_range_commit_exact_bytes_and_stale_generation() {
    use crate::fs_undo::{self, UndoState};
    struct Memory {
        bytes: Vec<u8>,
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
            if self.bytes.len() == 1 << 20 && at != 1030 && at != (1 << 20) - 1018 {
                assert_eq!(
                    self.bytes[1030] & 1,
                    0,
                    "payload before primary dirty fence"
                );
                assert_eq!(
                    self.bytes[(1 << 20) - 1018] & 1,
                    0,
                    "payload before alternate dirty fence"
                );
            }
            self.writes += 1;
            let at = at as usize;
            let n = bytes.len().min(3);
            self.bytes
                .get_mut(at..at + n)
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(&bytes[..n]);
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
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let original = super::super::independent::hfsplus_seed(binary);
        let mut prepared = Prepared::open(
            Memory {
                bytes: original.clone(),
                writes: 0,
                flushes: 0,
            },
            limits,
            &r,
        )
        .unwrap();
        let path = [NativeName::Utf16(super::super::independent::native_name(
            binary,
        ))];
        let range = prepared
            .plan_range(&path, &StreamKind::Data, 32760, &[0x5a; 31], &r)
            .unwrap();
        let stale = prepared
            .plan_range(&path, &StreamKind::ResourceFork, 0, b"x", &r)
            .unwrap();
        let mut journal = Memory {
            bytes: vec![0; 1 << 16],
            writes: 0,
            flushes: 0,
        };
        let binding = UndoBinding {
            volume: [0x55; 32],
            generation: 1,
            transaction: [0x22; 16],
        };
        let undo_limits = UndoLimits {
            patches: 16,
            body_bytes: 1 << 15,
        };
        let status = prepared
            .commit_range(range, &mut journal, binding, undo_limits, &r)
            .unwrap();
        assert_eq!(status.state, UndoState::Committed);
        assert_eq!(
            fs_undo::inspect(&journal, &r).unwrap().state,
            UndoState::Committed
        );
        let mut expected = original;
        expected[26 * 4096 + 4088..27 * 4096].fill(0x5a);
        expected[28 * 4096..28 * 4096 + 23].fill(0x5a);
        assert_eq!(prepared.target.bytes, expected);
        assert_eq!(prepared.target.flushes, 3);
        let counts = (
            prepared.target.writes,
            prepared.target.flushes,
            journal.writes,
            journal.flushes,
        );
        assert_eq!(
            prepared
                .commit_range(stale, &mut journal, binding, undo_limits, &r)
                .unwrap_err()
                .source
                .kind,
            ErrorKind::StalePlan
        );
        assert_eq!(
            counts,
            (
                prepared.target.writes,
                prepared.target.flushes,
                journal.writes,
                journal.flushes
            )
        );
        assert!(!prepared.uncertain);
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit fresh-image native HFS+ owned range commit gate"]
fn native_private_owned_range_commit_complete_payload_and_exact_image() {
    use crate::{
        fs_hfsplus::edit::{HfsPlusEditLimits, HfsPlusEditSession},
        fs_undo::{self, UndoState},
    };
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::FileExt, path::PathBuf, process::Command};
    struct FileStore(fs::File);
    impl Storage for FileStore {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.metadata()?.len())
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            FileExt::read_exact_at(&self.0, out, at)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            FileExt::write_at(&self.0, &bytes[..bytes.len().min(7)], at)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.sync_all()
        }
    }
    let output = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_OWNED_EVIDENCE").expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let istat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
    let mut receipt = String::new();
    let tools: Vec<_> = [checker, icat, istat]
        .iter()
        .map(|tool| (*tool, Sha256::digest(fs::read(tool).unwrap())))
        .collect();
    for (tool, digest) in &tools {
        receipt.push_str(&format!("tool={tool} sha256={digest:x}\n"));
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
    let public_limits = HfsPlusEditLimits {
        pages: limits.pages,
        attempts: limits.attempts,
        work: limits.work,
        range_bytes: limits.range_bytes,
        read: limits.read,
        audit: limits.audit,
        undo: UndoLimits {
            patches: 16,
            body_bytes: 1 << 15,
        },
    };
    for label in ["hfsplus", "hfsx"] {
        let source = PathBuf::from("/data/cache/partmgr-hfsplus-public-builder-native-v2")
            .join(format!("{label}-source.img"));
        let original = fs::read(&source).unwrap();
        let source_hash = Sha256::digest(&original);
        let path = output.join(format!("{label}.img"));
        fs::write(&path, &original).unwrap();
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut prepared = HfsPlusEditSession::open(FileStore(file), public_limits, &r).unwrap();
        let names = [
            NativeName::Utf16("DIR".encode_utf16().collect()),
            NativeName::Utf16("payload".encode_utf16().collect()),
        ];
        let range = prepared
            .plan_range(&names, &StreamKind::Data, 3, b"OWNED", &r)
            .unwrap();
        let journal_path = output.join(format!("{label}.undo"));
        let journal_file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&journal_path)
            .unwrap();
        journal_file.set_len(1 << 16).unwrap();
        let mut journal = FileStore(journal_file);
        let binding = UndoBinding {
            volume: source_hash.into(),
            generation: 1,
            transaction: [0x77; 16],
        };
        assert_eq!(
            prepared
                .commit_range(range, &mut journal, binding, &r)
                .unwrap()
                .state,
            UndoState::Committed
        );
        assert_eq!(
            fs_undo::inspect(&journal, &r).unwrap().state,
            UndoState::Committed
        );
        drop((prepared, journal));
        assert_eq!(r.memory.used(), 0);
        let payload = b"typed metadata payload";
        let positions: Vec<_> = original
            .windows(payload.len())
            .enumerate()
            .filter(|(_, bytes)| *bytes == payload)
            .map(|(at, _)| at)
            .collect();
        assert_eq!(positions.len(), 1);
        let mut expected = original.clone();
        expected[positions[0] + 3..positions[0] + 8].copy_from_slice(b"OWNED");
        let actual = fs::read(&path).unwrap();
        assert_eq!(actual, expected);
        let result = Command::new(checker)
            .arg("-fn")
            .arg(&path)
            .output()
            .unwrap();
        fs::write(output.join(format!("{label}-fsck.stdout")), &result.stdout).unwrap();
        fs::write(output.join(format!("{label}-fsck.stderr")), &result.stderr).unwrap();
        assert!(result.status.success(), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("appears to be OK"));
        let result = Command::new(icat)
            .args(["-f", "hfs"])
            .arg(&path)
            .arg("17")
            .output()
            .unwrap();
        let mut expected_payload = payload.to_vec();
        expected_payload[3..8].copy_from_slice(b"OWNED");
        assert!(result.status.success());
        assert_eq!(result.stdout, expected_payload);
        fs::write(output.join(format!("{label}-icat.stdout")), &result.stdout).unwrap();
        let result = Command::new(istat)
            .env("TZ", "UTC")
            .args(["-f", "hfs"])
            .arg(&path)
            .arg("17")
            .output()
            .unwrap();
        assert!(result.status.success());
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(
            text.contains("uid / gid: 1001 / 1002") && text.contains("Mode:\trrw-r-----"),
            "{text}"
        );
        fs::write(output.join(format!("{label}-istat.stdout")), &result.stdout).unwrap();
        assert_eq!(fs::read(&path).unwrap(), actual);
        assert_eq!(Sha256::digest(fs::read(&source).unwrap()), source_hash);
        receipt.push_str(&format!(
            "case={label} source_sha256={source_hash:x} image_sha256={:x} journal_sha256={:x}\n",
            Sha256::digest(&actual),
            Sha256::digest(fs::read(&journal_path).unwrap())
        ));
    }
    for (tool, digest) in tools {
        assert_eq!(Sha256::digest(fs::read(tool).unwrap()), digest);
    }
    receipt.push_str("status=passed;scope=private successful range commits only;recovery-cuts-and-public-writer-open\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit fresh-image native HFS+ cold recovery gate"]
fn native_private_owned_range_recovery_complete_payload_and_exact_image() {
    use crate::{
        fs_hfsplus::edit::{HfsPlusEditLimits, HfsPlusEditSession, HfsPlusRecoverySelection},
        fs_undo::{self, UndoState},
    };
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::FileExt, path::PathBuf, process::Command};
    struct FileStore(fs::File);
    struct StopPayload(FileStore);
    impl Storage for StopPayload {
        fn len(&self) -> io::Result<u64> {
            self.0.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            if at != 1030 && at != self.len()? - 1018 {
                self.0.write_at(at, &bytes[..1])?;
                self.0.flush()?;
                return Err(io::Error::from_raw_os_error(5));
            }
            self.0.write_at(at, bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    impl Storage for FileStore {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.metadata()?.len())
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            FileExt::read_exact_at(&self.0, out, at)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            FileExt::write_at(&self.0, &bytes[..bytes.len().min(7)], at)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.sync_all()
        }
    }
    let output = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_RECOVERY_EVIDENCE").expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let istat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
    let mut receipt = String::new();
    let tools: Vec<_> = [checker, icat, istat]
        .iter()
        .map(|tool| (*tool, Sha256::digest(fs::read(tool).unwrap())))
        .collect();
    for (tool, digest) in &tools {
        receipt.push_str(&format!("tool={tool} sha256={digest:x}\n"));
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
    let public_limits = HfsPlusEditLimits {
        pages: limits.pages,
        attempts: limits.attempts,
        work: limits.work,
        range_bytes: limits.range_bytes,
        read: limits.read,
        audit: limits.audit,
        undo: UndoLimits {
            patches: 16,
            body_bytes: 1 << 15,
        },
    };
    for label in ["hfsplus", "hfsx"] {
        let source = PathBuf::from("/data/cache/partmgr-hfsplus-public-builder-native-v2")
            .join(format!("{label}-source.img"));
        let original = fs::read(&source).unwrap();
        let source_hash = Sha256::digest(&original);
        let path = output.join(format!("{label}.img"));
        fs::write(&path, &original).unwrap();
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut prepared =
            HfsPlusEditSession::open(StopPayload(FileStore(file)), public_limits, &r).unwrap();
        let names = [
            NativeName::Utf16("DIR".encode_utf16().collect()),
            NativeName::Utf16("payload".encode_utf16().collect()),
        ];
        let range = prepared
            .plan_range(&names, &StreamKind::Data, 3, b"OWNED", &r)
            .unwrap();
        let journal_path = output.join(format!("{label}.undo"));
        let journal_file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&journal_path)
            .unwrap();
        journal_file.set_len(1 << 16).unwrap();
        let mut journal = FileStore(journal_file);
        let binding = UndoBinding {
            volume: source_hash.into(),
            generation: 1,
            transaction: [0x77; 16],
        };
        let error = prepared
            .commit_range(range, &mut journal, binding, &r)
            .unwrap_err();
        assert!(error.recovery_required && prepared.needs_recovery());
        drop((prepared, journal));
        assert_eq!(r.memory.used(), 0);
        let interrupted = fs::read(&path).unwrap();
        assert_eq!(interrupted[1030] & 1, 0);
        assert_eq!(interrupted[interrupted.len() - 1018] & 1, 0);
        fs::write(
            output.join(format!("{label}-interrupted.img")),
            &interrupted,
        )
        .unwrap();
        let mut target = FileStore(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        let mut journal = FileStore(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&journal_path)
                .unwrap(),
        );
        assert_eq!(
            crate::fs_hfsplus::edit::recover_range(
                &mut target,
                &mut journal,
                HfsPlusRecoverySelection {
                    path: &names,
                    kind: &StreamKind::Data,
                    offset: 3,
                    length: 5,
                    binding
                },
                public_limits,
                &r
            )
            .unwrap()
            .state,
            UndoState::RolledBack
        );
        assert_eq!(
            fs_undo::inspect(&journal, &r).unwrap().state,
            UndoState::RolledBack
        );
        drop((target, journal));
        assert_eq!(r.memory.used(), 0);
        let payload = b"typed metadata payload";
        let positions: Vec<_> = original
            .windows(payload.len())
            .enumerate()
            .filter(|(_, bytes)| *bytes == payload)
            .map(|(at, _)| at)
            .collect();
        assert_eq!(positions.len(), 1);
        let expected = original.clone();
        assert_eq!(interrupted[positions[0] + 3], b'O');
        let actual = fs::read(&path).unwrap();
        assert_eq!(actual, expected);
        let result = Command::new(checker)
            .arg("-fn")
            .arg(&path)
            .output()
            .unwrap();
        fs::write(output.join(format!("{label}-fsck.stdout")), &result.stdout).unwrap();
        fs::write(output.join(format!("{label}-fsck.stderr")), &result.stderr).unwrap();
        assert!(result.status.success(), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("appears to be OK"));
        let result = Command::new(icat)
            .args(["-f", "hfs"])
            .arg(&path)
            .arg("17")
            .output()
            .unwrap();
        let expected_payload = payload.to_vec();
        assert!(result.status.success());
        assert_eq!(result.stdout, expected_payload);
        fs::write(output.join(format!("{label}-icat.stdout")), &result.stdout).unwrap();
        let result = Command::new(istat)
            .env("TZ", "UTC")
            .args(["-f", "hfs"])
            .arg(&path)
            .arg("17")
            .output()
            .unwrap();
        assert!(result.status.success());
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(
            text.contains("uid / gid: 1001 / 1002") && text.contains("Mode:\trrw-r-----"),
            "{text}"
        );
        fs::write(output.join(format!("{label}-istat.stdout")), &result.stdout).unwrap();
        assert_eq!(fs::read(&path).unwrap(), actual);
        assert_eq!(Sha256::digest(fs::read(&source).unwrap()), source_hash);
        receipt.push_str(&format!(
            "case={label} source_sha256={source_hash:x} image_sha256={:x} journal_sha256={:x}\n",
            Sha256::digest(&actual),
            Sha256::digest(fs::read(&journal_path).unwrap())
        ));
    }
    for (tool, digest) in tools {
        assert_eq!(Sha256::digest(fs::read(tool).unwrap()), digest);
    }
    receipt.push_str("status=passed;scope=private real-file interrupted range cold recovery;exhaustive-cuts-and-public-writer-open\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

pub(super) fn commit_dirty(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    plan: &UndoPlan,
    states: [(u64, u8); 2],
    limits: Limits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    plan.commit(
        &mut DirtyTarget {
            target,
            states,
            started: false,
            clean_audited: false,
            limits,
            r,
        },
        journal,
        r,
    )
}
