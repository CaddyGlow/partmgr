//! Independent native validation of every cold-resolved resize persistence model.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{cell::Cell, fs, path::PathBuf, process::Command};
use sha2::{Digest, Sha256};
const CHECKER: &str =
    "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
const ICAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
const ISTAT: &str = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
struct Source {
    path: PathBuf,
    bytes: Vec<u8>,
    streams: [Vec<u8>; 2],
}
pub(super) struct NativeCutGate {
    output: PathBuf,
    sources: [Source; 2],
    tools: Vec<(&'static str, Vec<u8>)>,
    cases: Cell<usize>,
}
impl NativeCutGate {
    #[cfg(target_os = "linux")]
    pub(super) fn open() -> Self {
        let output = PathBuf::from(
            crate::platform::env::var_os("PARTMGR_HFSPLUS_RESIZE_CUT_EVIDENCE")
                .expect("fresh native evidence directory required"),
        );
        assert!(!output.exists());
        fs::create_dir(&output).unwrap();
        let source_directory =
            crate::platform::env::var_os("PARTMGR_HFSPLUS_RESIZE_CUT_SOURCE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from("/data/cache/partmgr-hfsplus-populated-native-v1")
                });
        let sources = ["hfsplus", "hfsx"].map(|label| {
            let path = source_directory.join(format!("{label}-b4096.img"));
            let bytes = fs::read(&path).unwrap();
            let streams = ["16", "16-4353-1"].map(|id| {
                let result = Command::new(ICAT).arg(&path).arg(id).output().unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                result.stdout
            });
            assert_eq!(streams[0].len(), 65553);
            assert_eq!(streams[1].len(), 14);
            Source {
                path,
                bytes,
                streams,
            }
        });
        let tools = [CHECKER, ICAT, ISTAT]
            .map(|tool| (tool, Sha256::digest(fs::read(tool).unwrap()).to_vec()))
            .to_vec();
        Self {
            output,
            sources,
            tools,
            cases: Cell::new(0),
        }
    }
    pub(super) fn source(&self, binary: bool) -> (Vec<u8>, [NativeName; 1]) {
        (
            self.sources[usize::from(binary)].bytes.clone(),
            [NativeName::Utf16("payload".encode_utf16().collect())],
        )
    }
    pub(super) fn check(
        &self,
        binary: bool,
        kind: &StreamKind,
        length: u64,
        replacement: &[u8],
        bytes: &[u8],
        committed: bool,
    ) {
        let number = self.cases.get();
        self.cases.set(number + 1);
        let stem = format!("case-{number:05}");
        let image = self.output.join(format!("{stem}.img"));
        fs::write(&image, bytes).unwrap();
        let result = Command::new(CHECKER)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stdout")),
            &result.stdout,
        )
        .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stderr")),
            &result.stderr,
        )
        .unwrap();
        assert!(
            result.status.success(),
            "{stem}: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        let source = &self.sources[usize::from(binary)];
        assert_eq!(&bytes[1216..1296], &source.bytes[1216..1296]);
        let block = u32::from_be_bytes(source.bytes[1064..1068].try_into().unwrap()) as usize;
        let header_at =
            u32::from_be_bytes(source.bytes[1232..1236].try_into().unwrap()) as usize * block;
        let node_bytes = usize::from(u16::from_be_bytes(
            source.bytes[header_at + 32..header_at + 34]
                .try_into()
                .unwrap(),
        ));
        let old_header = &source.bytes[header_at..header_at + node_bytes];
        let new_header = &bytes[header_at..header_at + node_bytes];
        let old_ranges = crate::fs_hfsplus::offsets(old_header).unwrap();
        let new_ranges = crate::fs_hfsplus::offsets(new_header).unwrap();
        assert_eq!(
            &new_header[new_ranges[0].0 + 30..new_ranges[0].0 + 106],
            &old_header[old_ranges[0].0 + 30..old_ranges[0].0 + 106]
        );
        assert_eq!(
            &new_header[new_ranges[1].0..new_ranges[1].1],
            &old_header[old_ranges[1].0..old_ranges[1].1]
        );
        assert_eq!(&new_header[12..14], &old_header[12..14]);
        for (index, id) in ["16", "16-4353-1"].iter().enumerate() {
            let mut expected = source.streams[index].clone();
            let selected = index == usize::from(*kind == StreamKind::ResourceFork);
            if committed && selected {
                expected.resize(length as usize, 0);
                if !replacement.is_empty() {
                    expected[3..3 + replacement.len()].copy_from_slice(replacement);
                }
            }
            if index == 1 && expected.is_empty() {
                let metadata = Command::new(ISTAT)
                    .env("TZ", "UTC")
                    .arg(&image)
                    .arg("16")
                    .output()
                    .unwrap();
                assert!(metadata.status.success());
                assert!(
                    String::from_utf8_lossy(&metadata.stdout).contains("Resource fork size:\t0")
                );
                fs::write(
                    self.output.join(format!("{stem}-empty-resource.stdout")),
                    metadata.stdout,
                )
                .unwrap();
            } else {
                let actual = Command::new(ICAT).arg(&image).arg(id).output().unwrap();
                assert!(
                    actual.status.success(),
                    "{stem}: {}",
                    String::from_utf8_lossy(&actual.stderr)
                );
                assert_eq!(actual.stdout, expected, "{stem} fork{index}");
                fs::write(
                    self.output.join(format!("{stem}-fork{index}.stdout")),
                    actual.stdout,
                )
                .unwrap();
            }
        }
        assert_eq!(
            fs::read(&image).unwrap(),
            bytes,
            "native validation changed image"
        );
    }
    #[cfg(target_os = "linux")]
    pub(super) fn finish(self) {
        for source in &self.sources {
            assert_eq!(fs::read(&source.path).unwrap(), source.bytes);
        }
        for (tool, hash) in &self.tools {
            assert_eq!(Sha256::digest(fs::read(tool).unwrap()).as_slice(), hash);
        }
        fs::write(self.output.join("receipt.txt"),format!("status=passed\ncases={}\nscope=all modeled resize commit/rollback write and barrier cuts;both families/forks/four persistence models;native fsck/full streams;macOS/device acceptance open\n",self.cases.get())).unwrap();
    }
}
