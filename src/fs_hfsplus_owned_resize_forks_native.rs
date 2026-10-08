//! Explicit real-file/native resize and interrupted-bitmap recovery gate.
use super::*;
use crate::fs_hfsplus::edit::{
    HfsPlusEditLimits, HfsPlusEditSession, HfsPlusResizeRequest as ResizeRequest,
};
use crate::fs_undo::{UndoBinding, UndoLimits, UndoState};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{fs, os::unix::fs::FileExt, path::PathBuf, process::Command};
use sha2::{Digest, Sha256};
struct FileStore(fs::File);
impl Storage for FileStore {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        FileExt::read_exact_at(&self.0, out, at)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        FileExt::write_at(&self.0, &bytes[..bytes.len().min(997)], at)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}
struct Stop {
    store: FileStore,
    bitmap: u64,
    enabled: bool,
}
impl Storage for Stop {
    fn len(&self) -> io::Result<u64> {
        self.store.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.store.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if self.enabled && at == self.bitmap {
            self.store.write_at(at, &bytes[..bytes.len().div_ceil(2)])?;
            self.store.flush()?;
            return Err(io::Error::from_raw_os_error(5));
        }
        self.store.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.store.flush()
    }
}
fn store(path: &crate::platform::path::Path) -> FileStore {
    FileStore(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap(),
    )
}
fn extract(icat: &str, path: &crate::platform::path::Path, resource: bool) -> Vec<u8> {
    let result = Command::new(icat)
        .args(["-f", "hfs"])
        .arg(path)
        .arg(if resource { "16-4353-1" } else { "16" })
        .output()
        .unwrap();
    if result.status.success() {
        return result.stdout;
    }
    assert!(resource, "DATA extraction failed: {result:?}");
    let info =
        Command::new("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat")
            .args(["-f", "hfs"])
            .arg(path)
            .arg("16")
            .output()
            .unwrap();
    assert!(info.status.success());
    assert!(String::from_utf8_lossy(&info.stdout).contains("Resource fork size:\t0"));
    Vec::new()
}
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit fresh native HFS+ resize commit/cold recovery gate"]
fn native_data_and_resource_resize_complete_fork_models() {
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_FORK_RESIZE_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let tools: Vec<_> = [checker, icat]
        .iter()
        .map(|p| (*p, Sha256::digest(fs::read(p).unwrap())))
        .collect();
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
    let public_limits = HfsPlusEditLimits {
        pages: limits.pages,
        attempts: limits.attempts,
        work: limits.work,
        range_bytes: limits.range_bytes,
        read: limits.read,
        audit: limits.audit,
        undo,
    };
    let mut receipt = String::new();
    for label in ["hfsplus", "hfsx"] {
        let source = PathBuf::from(format!(
            "/data/cache/partmgr-hfsplus-populated-native-v1/{label}-b4096.img"
        ));
        let original = fs::read(&source).unwrap();
        let source_hash = Sha256::digest(&original);
        let data = extract(icat, &source, false);
        let resource = extract(icat, &source, true);
        assert_eq!(data.len(), 65553);
        assert_eq!(resource.len(), 14);
        for resource_selected in [false, true] {
            let kind = if resource_selected {
                StreamKind::ResourceFork
            } else {
                StreamKind::Data
            };
            let selected = if resource_selected { &resource } else { &data };
            let other = if resource_selected { &data } else { &resource };
            for length in [0u64, 7, 4097, 70000] {
                for interrupted in [false, true] {
                    let stem = format!(
                        "{label}-fork{}-{length}-cut{}",
                        u8::from(resource_selected),
                        u8::from(interrupted)
                    );
                    let image = output.join(format!("{stem}.img"));
                    fs::write(&image, &original).unwrap();
                    let r = Resources {
                        memory: Budget::new(16 << 20),
                        cancellation: Cancellation::default(),
                    };
                    let block =
                        u64::from(u32::from_be_bytes(original[1064..1068].try_into().unwrap()));
                    let bitmap =
                        u64::from(u32::from_be_bytes(original[1152..1156].try_into().unwrap()))
                            * block;
                    let prepared = Prepared::open(
                        Stop {
                            store: store(&image),
                            bitmap,
                            enabled: interrupted,
                        },
                        limits,
                        &r,
                    )
                    .unwrap();
                    let names = [NativeName::Utf16("payload".encode_utf16().collect())];
                    let id = prepared.volume.lookup(&names, &r).unwrap();
                    let old = prepared.volume.node(&id).unwrap().forks
                        [usize::from(resource_selected)]
                    .extents
                    .clone();
                    let prepared =
                        HfsPlusEditSession::open(prepared.into_storage(), public_limits, &r)
                            .unwrap();
                    let journal_path = output.join(format!("{stem}.undo"));
                    let file = fs::OpenOptions::new()
                        .create_new(true)
                        .read(true)
                        .write(true)
                        .open(&journal_path)
                        .unwrap();
                    file.set_len(1 << 20).unwrap();
                    let mut journal = FileStore(file);
                    let binding = UndoBinding {
                        volume: source_hash.into(),
                        generation: 1,
                        transaction: [0x77; 16],
                    };
                    let replacement: &[u8] = if length >= 7 { b"XYZ" } else { &[] };
                    let offset = if length >= 7 { 3 } else { 0 };
                    let request = || ResizeRequest {
                        path: &names,
                        kind: &kind,
                        length,
                        offset,
                        replacement,
                    };
                    let result = prepared.resize(request(), &mut journal, binding, &r);
                    if interrupted {
                        let failed = match result {
                            Ok(_) => panic!("native bitmap cut missed"),
                            Err(e) => e,
                        };
                        assert!(failed.failure.recovery_required);
                        drop((failed.storage, journal));
                        fs::copy(&image, output.join(format!("{stem}-interrupted.img"))).unwrap();
                        let mut target = store(&image);
                        let mut journal = store(&journal_path);
                        assert_eq!(
                            crate::fs_hfsplus::edit::recover_resize(
                                &mut target,
                                &mut journal,
                                request(),
                                binding,
                                public_limits,
                                &r
                            )
                            .unwrap()
                            .state,
                            UndoState::RolledBack
                        );
                        drop((target, journal));
                        assert_eq!(fs::read(&image).unwrap(), original);
                    } else {
                        match result {
                            Ok(ready) => drop(ready),
                            Err(e) => panic!("{}", e.failure.source),
                        }
                        drop(journal);
                    }
                    assert_eq!(r.memory.used(), 0);
                    let actual = fs::read(&image).unwrap();
                    for extent in &old {
                        let a = (u64::from(extent.start) * block) as usize;
                        let b = a + (u64::from(extent.count) * block) as usize;
                        assert_eq!(&actual[a..b], &original[a..b]);
                    }
                    let check = Command::new(checker)
                        .arg("-fn")
                        .arg(&image)
                        .output()
                        .unwrap();
                    fs::write(output.join(format!("{stem}-fsck.stdout")), &check.stdout).unwrap();
                    fs::write(output.join(format!("{stem}-fsck.stderr")), &check.stderr).unwrap();
                    assert!(check.status.success(), "{stem}: {check:?}");
                    assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
                    let actual_selected = extract(icat, &image, resource_selected);
                    let mut expected = selected.to_vec();
                    if !interrupted {
                        expected.resize(length as usize, 0);
                        if length >= 7 {
                            expected[3..6].copy_from_slice(b"XYZ");
                        }
                    }
                    assert_eq!(actual_selected, expected, "{stem}");
                    fs::write(
                        output.join(format!("{stem}-selected.stdout")),
                        actual_selected,
                    )
                    .unwrap();
                    let actual_other = extract(icat, &image, !resource_selected);
                    assert_eq!(&actual_other, other, "{stem}");
                    fs::write(output.join(format!("{stem}-other.stdout")), actual_other).unwrap();
                    assert_eq!(fs::read(&image).unwrap(), actual);
                    assert_eq!(Sha256::digest(fs::read(&source).unwrap()), source_hash);
                    receipt.push_str(&format!(
                        "case={stem} image_sha256={:x} source_sha256={source_hash:x}\n",
                        Sha256::digest(&actual)
                    ));
                }
            }
        }
    }
    for (tool, hash) in tools {
        assert_eq!(Sha256::digest(fs::read(tool).unwrap()), hash);
        receipt.push_str(&format!("tool={tool} sha256={hash:x}\n"));
    }
    receipt.push_str("status=passed;scope=public native DATA/resource resize and bitmap-cut cold recovery;all-cut native and macOS acceptance open\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}
