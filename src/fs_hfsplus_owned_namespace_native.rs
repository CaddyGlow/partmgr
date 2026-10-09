//! Native same-parent file/directory rename and cold recovery qualification.
use super::*;
use crate::fs_hfsplus::edit::{HfsPlusEditLimits, HfsPlusEditSession, HfsPlusRenameRequest};
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
        Ok(FileExt::read_exact_at(&self.0, out, at)?)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        Ok(FileExt::write_at(
            &self.0,
            &bytes[..bytes.len().min(997)],
            at,
        )?)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(self.0.sync_all()?)
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
            return Err(std::io::Error::from_raw_os_error(5).into());
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

#[cfg(feature = "std")]
#[test]
#[ignore = "explicit fresh native HFS+ rename namespace/fork recovery gate"]
fn native_rename_namespace_forks_and_cold_recovery() {
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_RENAME_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let toolroot = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin";
    let icat = format!("{toolroot}/icat");
    let fls = format!("{toolroot}/fls");
    let tools: Vec<_> = [checker, icat.as_str(), fls.as_str()]
        .iter()
        .map(|p| ((*p).to_owned(), Sha256::digest(fs::read(p).unwrap())))
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
        for directory in [false, true] {
            let source = PathBuf::from(if directory {
                format!("/data/cache/partmgr-hfsplus-public-builder-native-v2/{label}-source.img")
            } else {
                format!("/data/cache/partmgr-hfsplus-populated-native-v1/{label}-b4096.img")
            });
            let original = fs::read(&source).unwrap();
            let hash = Sha256::digest(&original);
            let cnid = if directory { "17" } else { "16" };
            let extract = |image: &crate::platform::path::Path, resource: bool| {
                let address = if resource {
                    format!("{cnid}-4353-1")
                } else {
                    cnid.to_owned()
                };
                let result = Command::new(&icat)
                    .args(["-f", "hfs"])
                    .arg(image)
                    .arg(address)
                    .output()
                    .unwrap();
                assert!(result.status.success(), "{result:?}");
                result.stdout
            };
            let data = extract(&source, false);
            let resource = if directory {
                Vec::new()
            } else {
                extract(&source, true)
            };
            for interrupted in [false, true] {
                let stem = format!(
                    "{label}-directory{}-cut{}",
                    u8::from(directory),
                    u8::from(interrupted)
                );
                let image = output.join(format!("{stem}.img"));
                fs::write(&image, &original).unwrap();
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let prepared = Prepared::open(
                    Stop {
                        store: store(&image),
                        bitmap: u64::from(u32::from_be_bytes(
                            original[1312..1316].try_into().unwrap(),
                        )) * u64::from(u32::from_be_bytes(
                            original[1064..1068].try_into().unwrap(),
                        )),
                        enabled: interrupted,
                    },
                    limits,
                    &r,
                )
                .unwrap();
                let path = [NativeName::Utf16(
                    if directory { "DIR" } else { "payload" }
                        .encode_utf16()
                        .collect(),
                )];
                let name: Vec<u16> = "Renamed".encode_utf16().collect();
                let id = prepared.volume.lookup(&path, &r).unwrap();
                let raw = prepared.volume.node(&id).unwrap().raw.clone();
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
                    volume: hash.into(),
                    generation: 1,
                    transaction: [0x77; 16],
                };
                let request = || HfsPlusRenameRequest {
                    path: &path,
                    name: &name,
                };
                let prepared = HfsPlusEditSession::open(
                    prepared.into_storage(),
                    HfsPlusEditLimits {
                        pages: limits.pages,
                        attempts: limits.attempts,
                        work: limits.work,
                        range_bytes: limits.range_bytes,
                        read: limits.read,
                        audit: limits.audit,
                        undo,
                    },
                    &r,
                )
                .unwrap();
                match prepared.rename(request(), &mut journal, binding, &r) {
                    Ok(ready) => {
                        assert!(!interrupted);
                        let ready = Prepared::open(ready.into_storage(), limits, &r).unwrap();
                        let renamed = [NativeName::Utf16(name.clone())];
                        let id = ready.volume.lookup(&renamed, &r).unwrap();
                        assert_eq!(ready.volume.node(&id).unwrap().raw, raw);
                        if directory {
                            let child = [
                                renamed[0].clone(),
                                NativeName::Utf16("payload".encode_utf16().collect()),
                            ];
                            ready.volume.lookup(&child, &r).unwrap();
                        }
                        drop(ready);
                        drop(journal);
                    }
                    Err(failed) => {
                        assert!(interrupted, "{}", failed.failure.source);
                        assert!(failed.failure.recovery_required);
                        drop((failed.storage, journal));
                        fs::copy(&image, output.join(format!("{stem}-interrupted.img"))).unwrap();
                        let mut target = store(&image);
                        let mut saved = store(&journal_path);
                        assert_eq!(
                            crate::fs_hfsplus::edit::recover_rename(
                                &mut target,
                                &mut saved,
                                request(),
                                binding,
                                HfsPlusEditLimits {
                                    pages: limits.pages,
                                    attempts: limits.attempts,
                                    work: limits.work,
                                    range_bytes: limits.range_bytes,
                                    read: limits.read,
                                    audit: limits.audit,
                                    undo
                                },
                                &r
                            )
                            .unwrap()
                            .state,
                            UndoState::RolledBack
                        );
                        drop((target, saved));
                        assert_eq!(fs::read(&image).unwrap(), original);
                    }
                }
                assert_eq!(r.memory.used(), 0);
                let actual = fs::read(&image).unwrap();
                let check = Command::new(checker)
                    .arg("-fn")
                    .arg(&image)
                    .output()
                    .unwrap();
                fs::write(output.join(format!("{stem}-fsck.stdout")), &check.stdout).unwrap();
                fs::write(output.join(format!("{stem}-fsck.stderr")), &check.stderr).unwrap();
                assert!(check.status.success(), "{stem}: {check:?}");
                assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
                let listing = Command::new(&fls)
                    .args(["-f", "hfs", "-r", "-p"])
                    .arg(&image)
                    .output()
                    .unwrap();
                assert!(listing.status.success());
                let expected_name = if interrupted {
                    if directory { "DIR" } else { "payload" }
                } else {
                    "Renamed"
                };
                assert!(String::from_utf8_lossy(&listing.stdout).contains(expected_name));
                fs::write(output.join(format!("{stem}-fls.stdout")), listing.stdout).unwrap();
                let actual_data = extract(&image, false);
                assert_eq!(actual_data, data);
                fs::write(output.join(format!("{stem}-data.stdout")), actual_data).unwrap();
                if !directory {
                    let actual_resource = extract(&image, true);
                    assert_eq!(actual_resource, resource);
                    fs::write(
                        output.join(format!("{stem}-resource.stdout")),
                        actual_resource,
                    )
                    .unwrap();
                }
                assert_eq!(fs::read(&image).unwrap(), actual);
                assert_eq!(Sha256::digest(fs::read(&source).unwrap()), hash);
                receipt.push_str(&format!(
                    "case={stem} image_sha256={:x} source_sha256={hash:x}\n",
                    Sha256::digest(actual)
                ));
            }
        }
    }
    for (tool, hash) in tools {
        assert_eq!(Sha256::digest(fs::read(&tool).unwrap()), hash);
        receipt.push_str(&format!("tool={tool} sha256={hash:x}\n"));
    }
    receipt.push_str("status=passed;scope=public same-parent rename native namespace/full forks/catalog interruption recovery;macOS acceptance open\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}
