//! Explicit real-file/native resize and interrupted-bitmap recovery gate.
use super::commit::ResizeRequest;
use super::*;
use crate::fs_undo::{UndoBinding, UndoLimits, UndoState};
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
fn store(path: &std::path::Path) -> FileStore {
    FileStore(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap(),
    )
}
fn resource_bytes(icat: &str, path: &std::path::Path) -> Vec<u8> {
    let result = Command::new(icat)
        .args(["-f", "hfs"])
        .arg(path)
        .arg("17-4353-1")
        .output()
        .unwrap();
    if result.status.success() {
        return result.stdout;
    }
    let info =
        Command::new("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat")
            .args(["-f", "hfs"])
            .arg(path)
            .arg("17")
            .output()
            .unwrap();
    assert!(info.status.success());
    assert!(String::from_utf8_lossy(&info.stdout).contains("Resource fork size:\t0"));
    Vec::new()
}
#[test]
#[ignore = "explicit fresh native HFS+ resize commit/cold recovery gate"]
fn native_resize_commit_and_torn_bitmap_cold_recovery() {
    let output = PathBuf::from(
        std::env::var_os("PARTMGR_HFSPLUS_RESIZE_EVIDENCE").expect("fresh evidence required"),
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
    let mut receipt = String::new();
    for label in ["hfsplus", "hfsx"] {
        let source = PathBuf::from(format!(
            "/data/cache/partmgr-hfsplus-public-builder-native-v2/{label}-source.img"
        ));
        let original = fs::read(&source).unwrap();
        let source_hash = Sha256::digest(&original);
        let resource = resource_bytes(icat, &source);
        for length in [0u64, 7, 4097, 70000] {
            for interrupted in [false, true] {
                let stem = format!("{label}-{length}-cut{}", u8::from(interrupted));
                let image = output.join(format!("{stem}.img"));
                fs::write(&image, &original).unwrap();
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let block = u64::from(u32::from_be_bytes(original[1064..1068].try_into().unwrap()));
                let bitmap =
                    u64::from(u32::from_be_bytes(original[1152..1156].try_into().unwrap())) * block;
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
                let names = [
                    NativeName::Utf16("DIR".encode_utf16().collect()),
                    NativeName::Utf16("payload".encode_utf16().collect()),
                ];
                let id = prepared.volume.lookup(&names, &r).unwrap();
                let old = prepared.volume.node(&id).unwrap().forks[0].extents.clone();
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
                    kind: &StreamKind::Data,
                    length,
                    offset,
                    replacement,
                };
                let result = prepared.commit_resize(request(), &mut journal, binding, undo, &r);
                if interrupted {
                    let failed = match result {
                        Ok(_) => panic!("native bitmap cut missed"),
                        Err(e) => e,
                    };
                    assert!(failed.error.recovery_required);
                    drop((failed.target, journal));
                    fs::copy(&image, output.join(format!("{stem}-interrupted.img"))).unwrap();
                    let mut target = store(&image);
                    let mut journal = store(&journal_path);
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
                    drop((target, journal));
                    assert_eq!(fs::read(&image).unwrap(), original);
                } else {
                    match result {
                        Ok(ready) => drop(ready),
                        Err(e) => panic!("{}", e.error.source),
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
                let cat = Command::new(icat)
                    .args(["-f", "hfs"])
                    .arg(&image)
                    .arg("17")
                    .output()
                    .unwrap();
                assert!(cat.status.success());
                let mut expected = b"typed metadata payload".to_vec();
                if !interrupted {
                    expected.resize(length as usize, 0);
                    if length >= 7 {
                        expected[3..6].copy_from_slice(b"XYZ");
                    }
                }
                assert_eq!(cat.stdout, expected, "{stem}");
                fs::write(output.join(format!("{stem}-icat.stdout")), &cat.stdout).unwrap();
                let resource_after = resource_bytes(icat, &image);
                assert_eq!(resource_after, resource);
                fs::write(
                    output.join(format!("{stem}-resource.stdout")),
                    resource_after,
                )
                .unwrap();
                assert_eq!(fs::read(&image).unwrap(), actual);
                assert_eq!(Sha256::digest(fs::read(&source).unwrap()), source_hash);
                receipt.push_str(&format!(
                    "case={stem} image_sha256={:x} source_sha256={source_hash:x}\n",
                    Sha256::digest(&actual)
                ));
            }
        }
    }
    for (tool, hash) in tools {
        assert_eq!(Sha256::digest(fs::read(tool).unwrap()), hash);
        receipt.push_str(&format!("tool={tool} sha256={hash:x}\n"));
    }
    receipt.push_str("status=passed;scope=private native resize/bitmap-cut cold recovery;exhaustive rollback cuts/public resize/macOS open\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}
