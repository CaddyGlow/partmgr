use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_fat::FatVolume,
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_file::ExtentKind,
    fs_storage::{BoundedSession, SectorGeometry},
    fs_undo::{UndoBinding, UndoLimits, UndoPlan, UndoState, recover},
    storage::{FileStorage, Storage, WriteRange},
};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, io, path::Path, process::Command, sync::Arc};
use virtdisk::{DiskView, RawDisk};

struct Torn<S> {
    storage: S,
    fail: bool,
}
impl<S: Storage> Storage for Torn<S> {
    fn len(&self) -> io::Result<u64> {
        self.storage.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.storage.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if self.fail {
            self.fail = false;
            let half = bytes.len().div_ceil(2);
            let n = self.storage.write_at(at, &bytes[..half])?;
            assert_eq!(n, half);
            self.storage.flush()?;
            return Err(io::Error::other(
                "modeled partial target write after actual flush",
            ));
        }
        self.storage.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.storage.flush()
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn session(path: &Path, length: u64) -> BoundedSession<FileStorage> {
    BoundedSession::new(
        FileStorage::open(path).unwrap(),
        8192,
        length,
        SectorGeometry::new(Some(512), Some(512)).unwrap(),
    )
    .unwrap()
}
fn audit(source: Arc<dyn virtdisk::ReadAt>, r: &Resources) {
    let report = audit_fat(
        source,
        FatAuditLimits {
            clusters: 65536,
            entries: 100,
            directory_slots: 1024,
            findings: 100,
        },
        r,
    )
    .unwrap();
    assert!(report.namespace_complete());
    assert!(report.findings().is_empty());
}
#[test]
#[ignore = "enabled native gate requires evidence directory, mkfs.fat, fsck.fat, mcopy and sha256sum"]
fn native_fat16_external_undo_existing_payload_commit_and_restartable_rollback() {
    let evidence = std::env::var_os("PARTMGR_UNDO_NATIVE_EVIDENCE")
        .expect("enabled gate requires PARTMGR_UNDO_NATIVE_EVIDENCE");
    std::fs::create_dir_all(&evidence).unwrap();
    let temp = tempfile::Builder::new()
        .prefix("fat16-undo-")
        .tempdir_in(&evidence)
        .unwrap();
    let mut receipt = String::from(
        "schema=1\nprofile=fat16-external-undo-existing-payload-v1\nfailure_model=partial-target-write-followed-by-error-with-actual-flush\nphysical_power_loss=not-tested\n",
    );
    let mut command = |tool: &OsStr, args: &[&OsStr]| {
        let mut cmd = Command::new(tool);
        cmd.args(args);
        let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
        receipt.push_str(&format!(
            "command={cmd:?}\nexit={}\nstdout={}\nstderr={}\n",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
        out
    };
    let mkfs = std::env::var_os("PARTMGR_UNDO_MKFS")
        .unwrap_or_else(|| "/run/current-system/sw/bin/mkfs.fat".into());
    let fsck = std::env::var_os("PARTMGR_UNDO_FSCK")
        .unwrap_or_else(|| "/run/current-system/sw/bin/fsck.fat".into());
    let mcopy = std::env::var_os("PARTMGR_UNDO_MCOPY")
        .unwrap_or_else(|| "/run/current-system/sw/bin/mcopy".into());
    for (tool, version) in [(&mkfs, "--help"), (&fsck, "--help"), (&mcopy, "-V")] {
        command(tool, &[OsStr::new(version)]);
        assert!(command(OsStr::new("sha256sum"), &[tool]).status.success());
    }
    let image = temp.path().join("independent-fat16.img");
    let length = 16 << 20;
    std::fs::File::create(&image)
        .unwrap()
        .set_len(length)
        .unwrap();
    assert!(
        command(
            &mkfs,
            &[
                OsStr::new("--invariant"),
                OsStr::new("-F"),
                OsStr::new("16"),
                OsStr::new("-s"),
                OsStr::new("1"),
                image.as_os_str()
            ]
        )
        .status
        .success()
    );
    let payload: Vec<u8> = (0..20000).map(|n| ((n * 17 + 9) % 251) as u8).collect();
    let other = b"unrelated FAT file remains byte-identical";
    let input = temp.path().join("payload.bin");
    std::fs::write(&input, &payload).unwrap();
    let unrelated = temp.path().join("other.bin");
    std::fs::write(&unrelated, other).unwrap();
    for (host, name) in [(&input, "::PAYLOAD.BIN"), (&unrelated, "::OTHER.BIN")] {
        assert!(
            command(
                &mcopy,
                &[
                    OsStr::new("-i"),
                    image.as_os_str(),
                    host.as_os_str(),
                    OsStr::new(name)
                ]
            )
            .status
            .success()
        );
    }
    assert!(
        command(&fsck, &[OsStr::new("-n"), image.as_os_str()])
            .status
            .success()
    );
    let volume_bytes = std::fs::read(&image).unwrap();
    let mut framed = vec![0xa7; 8192];
    framed.extend_from_slice(&volume_bytes);
    framed.extend_from_slice(&[0x5d; 4096]);
    let source = temp.path().join("source.framed");
    std::fs::write(&source, &framed).unwrap();
    let r = resources();
    let patches = {
        let view: Arc<dyn virtdisk::ReadAt> = Arc::new(
            DiskView::new(Arc::new(RawDisk::open(&source).unwrap()), 8192, length).unwrap(),
        );
        audit(view.clone(), &r);
        let volume = FatVolume::open(view).unwrap();
        let root = volume.root_directory(64, 1024, &r).unwrap();
        let entry = root
            .entries()
            .iter()
            .find(|e| e.short_name() == b"PAYLOAD BIN")
            .unwrap();
        let raw = entry.raw_metadata();
        let first = u16::from_le_bytes([raw[26], raw[27]]) as u32;
        let file = volume.open_file(first, entry.len(), 64, &r).unwrap();
        let mut read = vec![0; payload.len()];
        assert_eq!(file.read_at(0, &mut read, &r).unwrap(), payload.len());
        assert_eq!(read, payload);
        let mut patches = Vec::new();
        for (start, end, value) in [(123_u64, 400_u64, 0x31), (4000, 4500, 0xc9)] {
            for extent in file.extents() {
                let a = start.max(extent.offset);
                let b = end.min(extent.offset + extent.length);
                if a >= b {
                    continue;
                }
                let ExtentKind::Data(physical) = extent.kind else {
                    panic!("FAT payload must be recorded")
                };
                let at = physical + a - extent.offset;
                let old = volume_bytes[at as usize..(at + b - a) as usize].to_vec();
                patches.push(WriteRange::new(at, old, vec![value; (b - a) as usize]).unwrap());
            }
        }
        patches
    }; // All immutable readers and deferred maps are dropped before exclusive FileStorage opens.
    assert_eq!(r.memory.used(), 0);
    let binding_volume: [u8; 32] = Sha256::digest(&framed).into();
    let mut expected_payload = payload.clone();
    expected_payload[123..400].fill(0x31);
    expected_payload[4000..4500].fill(0xc9);
    for case in 0..3 {
        let target = temp.path().join(format!("target-{case}.framed"));
        std::fs::copy(&source, &target).unwrap();
        // Caller checks the complete bounded-region/framing identity before taking its editing session.
        assert_eq!(
            Sha256::digest(std::fs::read(&target).unwrap()).as_slice(),
            binding_volume
        );
        let binding = UndoBinding {
            volume: binding_volume,
            generation: 1,
            transaction: [case + 1; 16],
        };
        let writes = patches
            .iter()
            .map(|p| {
                WriteRange::new(p.offset(), p.expected().to_vec(), p.replacement().to_vec())
                    .unwrap()
            })
            .collect();
        let plan = UndoPlan::new(binding, length, writes, UndoLimits::default(), &r).unwrap();
        let journal = temp.path().join(format!("external-{case}.undo"));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal)
            .unwrap()
            .set_len(plan.journal_bytes())
            .unwrap();
        {
            let mut target = Torn {
                storage: session(&target, length),
                fail: case != 0,
            };
            let mut external = FileStorage::open(&journal).unwrap();
            if case == 0 {
                assert_eq!(
                    plan.commit(&mut target, &mut external, &r).unwrap().state,
                    UndoState::Committed
                );
            } else {
                assert!(plan.commit(&mut target, &mut external, &r).is_err());
            }
        }
        drop(plan);
        if case != 0 {
            if case == 2 {
                let mut target = Torn {
                    storage: session(&target, length),
                    fail: true,
                };
                let mut external = FileStorage::open(&journal).unwrap();
                assert!(
                    recover(
                        &mut target,
                        &mut external,
                        binding,
                        UndoLimits::default(),
                        &r
                    )
                    .is_err()
                );
            }
            for _ in 0..2 {
                let mut target = session(&target, length);
                let mut external = FileStorage::open(&journal).unwrap();
                assert_eq!(
                    recover(
                        &mut target,
                        &mut external,
                        binding,
                        UndoLimits::default(),
                        &r
                    )
                    .unwrap()
                    .state,
                    UndoState::RolledBack
                );
            }
        }
        let actual = std::fs::read(&target).unwrap();
        let mut expected = framed.clone();
        if case == 0 {
            for patch in &patches {
                let at = 8192 + patch.offset() as usize;
                expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
            }
        }
        assert_eq!(
            actual, expected,
            "all bytes outside reviewed patches and all rollback bytes must match"
        );
        assert_eq!(std::fs::read(&source).unwrap(), framed);
        let native = temp.path().join(format!("native-reopen-{case}.img"));
        std::fs::write(&native, &actual[8192..8192 + length as usize]).unwrap();
        assert!(
            command(&fsck, &[OsStr::new("-n"), native.as_os_str()])
                .status
                .success()
        );
        for (name, expected) in [
            (
                "::PAYLOAD.BIN",
                if case == 0 {
                    expected_payload.as_slice()
                } else {
                    payload.as_slice()
                },
            ),
            ("::OTHER.BIN", other.as_slice()),
        ] {
            let extracted = temp.path().join(format!(
                "extracted-{case}-{}.bin",
                if name.contains("PAYLOAD") { 0 } else { 1 }
            ));
            assert!(
                command(
                    &mcopy,
                    &[
                        OsStr::new("-i"),
                        native.as_os_str(),
                        OsStr::new(name),
                        extracted.as_os_str()
                    ]
                )
                .status
                .success()
            );
            assert_eq!(std::fs::read(&extracted).unwrap(), expected);
            assert!(
                command(OsStr::new("sha256sum"), &[extracted.as_os_str()])
                    .status
                    .success()
            );
        }
        {
            let view: Arc<dyn virtdisk::ReadAt> = Arc::new(
                DiskView::new(Arc::new(RawDisk::open(&target).unwrap()), 8192, length).unwrap(),
            );
            audit(view.clone(), &r);
            let volume = FatVolume::open(view).unwrap();
            let root = volume.root_directory(64, 1024, &r).unwrap();
            let entry = root
                .entries()
                .iter()
                .find(|e| e.short_name() == b"PAYLOAD BIN")
                .unwrap();
            let file = volume.open_entry(entry, 64, &r).unwrap();
            use partmgr::fs_core::FileRead;
            let mut read = vec![0; payload.len()];
            assert_eq!(file.read_at(0, &mut read, &r).unwrap(), payload.len());
            assert_eq!(
                &read,
                if case == 0 {
                    &expected_payload
                } else {
                    &payload
                }
            );
        }
        for artifact in [&target, &journal] {
            assert!(
                command(OsStr::new("sha256sum"), &[artifact.as_os_str()])
                    .status
                    .success()
            );
        }
    }
    for file in [
        source,
        input,
        unrelated,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fs_undo.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fs_undo_native.rs"),
        std::env::current_exe().unwrap(),
    ] {
        assert!(
            command(OsStr::new("sha256sum"), &[file.as_os_str()])
                .status
                .success()
        );
    }
    receipt.push_str(&format!("region_start=8192\nregion_length={length}\nregion_suffix=4096\nvolume_binding_sha256={:x}\ngeneration=1\ntransactions=01x16,02x16,03x16\nlogical_patches=123..400:31,4000..4500:c9\n", Sha256::digest(&framed)));
    for patch in &patches {
        receipt.push_str(&format!(
            "physical_patch_offset={} length={} old_sha256={:x} new_sha256={:x}\n",
            patch.offset(),
            patch.expected().len(),
            Sha256::digest(patch.expected()),
            Sha256::digest(patch.replacement())
        ));
    }
    receipt.push_str("commit=passed\npartial_write_restart_undo=passed\nrollback_error_retry=passed\nindependent_fsck_payload=passed\nunrelated_metadata_framing_source=byte-identical\nstatus=passed\n");
    let retained = temp.keep();
    std::fs::write(
        Path::new(&evidence).join("fat16-external-undo-existing-payload-v1.txt"),
        format!("artifact_directory={}\n{receipt}", retained.display()),
    )
    .unwrap();
}
