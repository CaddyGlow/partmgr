//! Native fsck, namespace and complete fork validation for every resolved cut.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{cell::Cell, fs, path::PathBuf, process::Command};
use sha2::{Digest, Sha256};
const CHECKER: &str =
    "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
const FLS: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/fls";
const ISTAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
struct Source {
    path: PathBuf,
    bytes: Vec<u8>,
    hash: Vec<u8>,
    data: Vec<u8>,
    resource: Vec<u8>,
}
pub(super) struct Gate {
    pub(super) directory_moves: bool,
    directory_deletes: bool,
    pub(super) file_deletes: bool,
    output: PathBuf,
    sources: Vec<Source>,
    tools: Vec<(&'static str, Vec<u8>)>,
    cases: Cell<usize>,
}
fn extract(path: &crate::platform::path::Path, id: &str) -> Vec<u8> {
    let result = Command::new(ICAT)
        .args(["-f", "hfs"])
        .arg(path)
        .arg(id)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    result.stdout
}
impl Gate {
    pub(super) fn open() -> Self {
        Self::open_profile(false, false, false)
    }
    pub(super) fn open_directories() -> Self {
        Self::open_profile(true, false, false)
    }
    pub(super) fn open_deletions() -> Self {
        Self::open_profile(true, true, false)
    }
    pub(super) fn open_file_deletions() -> Self {
        Self::open_profile(false, false, true)
    }
    fn open_profile(directory_moves: bool, directory_deletes: bool, file_deletes: bool) -> Self {
        let output = PathBuf::from(
            crate::platform::env::var_os("PARTMGR_HFSPLUS_RENAME_CUT_EVIDENCE")
                .expect("fresh evidence required"),
        );
        assert!(!output.exists());
        fs::create_dir(&output).unwrap();
        let mut sources = Vec::new();
        for label in ["hfsplus", "hfsx"] {
            for directory in [false, true] {
                let path = PathBuf::from(if directory {
                    format!(
                        "/data/cache/partmgr-hfsplus-public-builder-native-v2/{label}-source.img"
                    )
                } else {
                    format!(
                        "/data/cache/partmgr-hfsplus-overflow-user-record-source-v1/{label}-b4096.img"
                    )
                });
                let path = if directory_moves || file_deletes {
                    let path = output.join(format!(
                        "{label}-source{}-directory.img",
                        u8::from(directory)
                    ));
                    let bytes = super::super::super::super::independent::hfsplus_directory_seed(
                        label == "hfsx",
                    );
                    fs::write(path.with_extension("constructed.img"), &bytes).unwrap();
                    fs::write(&path, &bytes).unwrap();
                    let normalized = Command::new(CHECKER)
                        .args(["-f", "-y"])
                        .arg(&path)
                        .output()
                        .unwrap();
                    fs::write(path.with_extension("normalize.stdout"), &normalized.stdout).unwrap();
                    fs::write(path.with_extension("normalize.stderr"), &normalized.stderr).unwrap();
                    assert!(normalized.status.success());
                    let normalized_bytes = fs::read(&path).unwrap();
                    for (i, (&before, &after)) in bytes.iter().zip(&normalized_bytes).enumerate() {
                        if before != after {
                            assert!(
                                [
                                    1028..1036,
                                    1100..1104,
                                    bytes.len() - 1020..bytes.len() - 1012,
                                    bytes.len() - 948..bytes.len() - 944
                                ]
                                .iter()
                                .any(|range| range.contains(&i)),
                                "native fixture normalization changed unexpected offset {i}"
                            );
                        }
                    }
                    let check = Command::new(CHECKER)
                        .args(["-f", "-n"])
                        .arg(&path)
                        .output()
                        .unwrap();
                    fs::write(path.with_extension("fsck.stdout"), &check.stdout).unwrap();
                    fs::write(path.with_extension("fsck.stderr"), &check.stderr).unwrap();
                    assert!(
                        check.status.success(),
                        "source directory fixture: {check:?}"
                    );
                    path
                } else {
                    path
                };
                let bytes = fs::read(&path).unwrap();
                let hash = Sha256::digest(&bytes).to_vec();
                let data = extract(
                    &path,
                    if directory_moves || file_deletes {
                        "18"
                    } else if directory {
                        "17"
                    } else {
                        "16"
                    },
                );
                let resource = if directory || directory_moves || file_deletes {
                    Vec::new()
                } else {
                    extract(&path, "16-4353-1")
                };
                sources.push(Source {
                    path,
                    bytes,
                    hash,
                    data,
                    resource,
                });
            }
        }
        Self {
            directory_moves,
            directory_deletes,
            file_deletes,
            output,
            sources,
            tools: [CHECKER, ICAT, FLS, ISTAT]
                .map(|p| (p, Sha256::digest(fs::read(p).unwrap()).to_vec()))
                .to_vec(),
            cases: Cell::new(0),
        }
    }
    pub(super) fn source(
        &self,
        binary: bool,
        directory: bool,
        moving: bool,
    ) -> (Vec<u8>, Vec<NativeName>) {
        let s = &self.sources[usize::from(binary) * 2 + usize::from(directory || moving)];
        (
            s.bytes.clone(),
            if self.file_deletes {
                vec![NativeName::Utf16("Data".encode_utf16().collect())]
            } else if self.directory_deletes {
                vec![NativeName::Utf16("Target".encode_utf16().collect())]
            } else if self.directory_moves {
                vec![NativeName::Utf16("Dir".encode_utf16().collect())]
            } else if moving {
                vec![
                    NativeName::Utf16("DIR".encode_utf16().collect()),
                    NativeName::Utf16("payload".encode_utf16().collect()),
                ]
            } else {
                vec![NativeName::Utf16(
                    if directory { "DIR" } else { "payload" }
                        .encode_utf16()
                        .collect(),
                )]
            },
        )
    }

    pub(super) fn check(
        &self,
        binary: bool,
        directory: bool,
        moving: bool,
        bytes: &[u8],
        committed: bool,
    ) {
        let n = self.cases.get();
        self.cases.set(n + 1);
        let stem = format!("case-{n:05}");
        let image = self.output.join(format!("{stem}.img"));
        fs::write(&image, bytes).unwrap();
        let s = &self.sources[usize::from(binary) * 2 + usize::from(directory || moving)];
        // Rename changes only catalog nodes; volume header, allocations, forks and other trees remain exact.
        let block = u32::from_be_bytes(s.bytes[1064..1068].try_into().unwrap()) as usize;
        let start = u32::from_be_bytes(s.bytes[1312..1316].try_into().unwrap()) as usize * block;
        let length = u64::from_be_bytes(s.bytes[1296..1304].try_into().unwrap()) as usize;
        if self.file_deletes && committed {
            let bitmap_start =
                u32::from_be_bytes(s.bytes[1152..1156].try_into().unwrap()) as usize * block;
            let bitmap_length =
                u64::from_be_bytes(s.bytes[1136..1144].try_into().unwrap()) as usize;
            let overflow_start =
                u32::from_be_bytes(s.bytes[1232..1236].try_into().unwrap()) as usize * block;
            let overflow_length =
                u64::from_be_bytes(s.bytes[1216..1224].try_into().unwrap()) as usize;
            let allowed = [
                start..start + length,
                bitmap_start..bitmap_start + bitmap_length,
                overflow_start..overflow_start + overflow_length,
                1056..1060,
                1072..1076,
                bytes.len() - 992..bytes.len() - 988,
                bytes.len() - 976..bytes.len() - 972,
            ];
            for (i, (&old, &new)) in s.bytes.iter().zip(bytes).enumerate() {
                if !allowed.iter().any(|r| r.contains(&i)) {
                    assert_eq!(old, new, "file deletion changed unrelated offset {i}");
                }
            }
            for at in [1056, bytes.len() - 992] {
                assert_eq!(u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()), 1);
            }
            let old_free = u32::from_be_bytes(s.bytes[1072..1076].try_into().unwrap());
            for at in [1072, bytes.len() - 976] {
                assert_eq!(
                    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()),
                    old_free + 10
                );
            }
        } else if self.directory_deletes && committed {
            for (i, (&old, &new)) in s.bytes.iter().zip(bytes).enumerate() {
                if !(start..start + length).contains(&i)
                    && ![1060..1064, bytes.len() - 988..bytes.len() - 984]
                        .iter()
                        .any(|r| r.contains(&i))
                {
                    assert_eq!(old, new, "delete changed unrelated offset {i}");
                }
            }
            let old = u32::from_be_bytes(s.bytes[1060..1064].try_into().unwrap());
            for at in [1060, bytes.len() - 988] {
                assert_eq!(
                    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()),
                    old - 1
                );
            }
        } else {
            assert_eq!(&bytes[..start], &s.bytes[..start]);
            assert_eq!(&bytes[start + length..], &s.bytes[start + length..]);
        }
        let check = Command::new(CHECKER)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stdout")),
            &check.stdout,
        )
        .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stderr")),
            &check.stderr,
        )
        .unwrap();
        assert!(check.status.success(), "{stem}: {check:?}");
        assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
        let listing = Command::new(FLS)
            .args(["-f", "hfs", "-r", "-p"])
            .arg(&image)
            .output()
            .unwrap();
        assert!(listing.status.success());
        let text = String::from_utf8_lossy(&listing.stdout);
        let name = if committed {
            "Renamed"
        } else if self.directory_moves {
            "Dir"
        } else if directory {
            "DIR"
        } else {
            "payload"
        };
        if self.file_deletes {
            assert_eq!(text.contains("Data"), !committed);
        } else if self.directory_deletes {
            assert_eq!(text.contains("Target"), !committed);
        } else {
            assert!(text.contains(name));
        }
        if moving && !self.directory_moves {
            assert!(text.contains(if committed { "Renamed" } else { "DIR/payload" }));
        }
        if directory || moving || self.file_deletes {
            let info = Command::new(ISTAT)
                .args(["-f", "hfs"])
                .arg(&image)
                .arg(if self.directory_moves || self.file_deletes {
                    "18"
                } else {
                    "17"
                })
                .output()
                .unwrap();
            assert!(info.status.success());
            assert!(String::from_utf8_lossy(&info.stdout).contains("Resource fork size:\t0"));
            fs::write(
                self.output.join(format!("{stem}-istat.stdout")),
                info.stdout,
            )
            .unwrap();
        }
        if self.directory_deletes || self.file_deletes {
            assert!(text.contains("Dir/child"));
        } else if self.directory_moves {
            assert!(text.contains(if committed {
                "Target/Renamed/child"
            } else {
                "Dir/child"
            }));
        } else if directory {
            assert!(text.contains(&format!("{name}/payload")));
        }
        fs::write(
            self.output.join(format!("{stem}-fls.stdout")),
            listing.stdout,
        )
        .unwrap();
        let data = extract(
            &image,
            if self.directory_moves || self.file_deletes {
                "18"
            } else if directory || moving {
                "17"
            } else {
                "16"
            },
        );
        assert_eq!(data, s.data);
        fs::write(self.output.join(format!("{stem}-data.stdout")), data).unwrap();
        if !directory && !moving && !self.file_deletes {
            let resource = extract(&image, "16-4353-1");
            assert_eq!(resource, s.resource);
            fs::write(
                self.output.join(format!("{stem}-resource.stdout")),
                resource,
            )
            .unwrap();
        }
        assert_eq!(fs::read(&image).unwrap(), bytes);
    }
    pub(super) fn finish(self) {
        let mut receipt = format!(
            "status=passed cases={} scope=native namespace operation as selected by bound gate (rename/move/empty-directory deletion) all modeled commit/recovery write-barrier cuts with four persistence combinations;macOS acceptance open\n",
            self.cases.get()
        );
        for s in self.sources {
            assert_eq!(Sha256::digest(fs::read(&s.path).unwrap()).to_vec(), s.hash);
            receipt.push_str(&format!(
                "source={} sha256={:x}\n",
                s.path.display(),
                Sha256::digest(s.bytes)
            ));
        }
        for (p, h) in self.tools {
            assert_eq!(Sha256::digest(fs::read(p).unwrap()).to_vec(), h);
            receipt.push_str(&format!(
                "tool={p} sha256={:x}\n",
                Sha256::digest(fs::read(p).unwrap())
            ));
        }
        fs::write(self.output.join("receipt.txt"), receipt).unwrap();
    }
}
