#![cfg(feature = "std")]
//! Explicit Linux native-tool evidence for the resolved ownership reader profile.
//! It establishes no Windows, capture, replay, mutation, or firmware qualification.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs::NtfsReadLimits,
    fs_ntfs_audit::NtfsAuditLimits,
    io,
};
use std::sync::Arc;
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
#[test]
#[ignore = "explicit native expanded MFT allocation gate requires image, ntfsinfo, ntfscat, and fresh evidence"]
fn native_resolved_allocation_matches_independent_tools() {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let image = PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_RESOLVED_AUDIT_IMAGE").expect("native image required"),
    );
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_RESOLVED_AUDIT_EVIDENCE").expect("fresh evidence required"),
    );
    fs::create_dir(&out).unwrap();
    let source_root =
        PathBuf::from(std::env::var_os("PARTMGR_GATE_SOURCE_ROOT").expect("source root required"));
    let sources: &[(&str, &[u8])] = &[
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("src/fs_ntfs.rs", include_bytes!("../src/fs_ntfs.rs")),
        (
            "src/fs_ntfs_stream.rs",
            include_bytes!("../src/fs_ntfs_stream.rs"),
        ),
        (
            "src/fs_ntfs_bootstrap.rs",
            include_bytes!("../src/fs_ntfs_bootstrap.rs"),
        ),
        (
            "src/fs_ntfs_audit.rs",
            include_bytes!("../src/fs_ntfs_audit.rs"),
        ),
        (
            "src/fs_ntfs_tree.rs",
            include_bytes!("../src/fs_ntfs_tree.rs"),
        ),
        (
            "src/fs_ntfs_metadata.rs",
            include_bytes!("../src/fs_ntfs_metadata.rs"),
        ),
        (
            "src/fs_ntfs_security.rs",
            include_bytes!("../src/fs_ntfs_security.rs"),
        ),
        (
            "src/fs_ntfs_secure.rs",
            include_bytes!("../src/fs_ntfs_secure.rs"),
        ),
        (
            "src/fs_ntfs_compressed.rs",
            include_bytes!("../src/fs_ntfs_compressed.rs"),
        ),
        (
            "tests/fs_ntfs_audit_resolved_native.rs",
            include_bytes!("../tests/fs_ntfs_audit_resolved_native.rs"),
        ),
    ];
    let source_check = || {
        let mut manifest = String::new();
        for (name, baked) in sources {
            let live = fs::read(source_root.join(name)).unwrap();
            assert_eq!(
                Sha256::digest(&live),
                Sha256::digest(baked),
                "compiled source mismatch: {name}"
            );
            use std::fmt::Write;
            writeln!(manifest, "{:x}  {}", Sha256::digest(baked), name).unwrap();
        }
        manifest
    };
    let source_start = source_check();
    fs::write(out.join("source-start.sha256"), &source_start).unwrap();
    for (name, baked) in sources {
        let destination = out.join("compiled-source").join(name);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, baked).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();

    let ntfsinfo =
        PathBuf::from(std::env::var_os("PARTMGR_NTFSINFO").expect("native ntfsinfo required"));
    let ntfscat =
        PathBuf::from(std::env::var_os("PARTMGR_NTFSCAT").expect("native ntfscat required"));
    let info_tool_start = Sha256::digest(fs::read(&ntfsinfo).unwrap());
    let cat_tool_start = Sha256::digest(fs::read(&ntfscat).unwrap());
    fs::write(
        out.join("tools-start.sha256"),
        format!(
            "{:x}  {}\n{:x}  {}\n",
            info_tool_start,
            ntfsinfo.display(),
            cat_tool_start,
            ntfscat.display()
        ),
    )
    .unwrap();
    let run = |label: &str, tool: &std::path::Path, arguments: &[&std::ffi::OsStr]| {
        let result = Command::new(tool)
            .args(arguments)
            .output()
            .expect("native command launch");
        fs::write(out.join(format!("{label}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{label}.stderr")), &result.stderr).unwrap();
        fs::write(
            out.join(format!("{label}.command")),
            format!(
                "argv={:?}\nexit={:?}\n",
                std::iter::once(tool.as_os_str())
                    .chain(arguments.iter().copied())
                    .collect::<Vec<_>>(),
                result.status.code()
            ),
        )
        .unwrap();
        assert!(result.status.success(), "native command failed: {label}");
        result
    };
    run(
        "ntfsinfo-version",
        &ntfsinfo,
        &[std::ffi::OsStr::new("--version")],
    );
    run(
        "ntfscat-version",
        &ntfscat,
        &[std::ffi::OsStr::new("--version")],
    );
    let bytes = fs::read(&image).unwrap();
    let image_hash = Sha256::digest(&bytes);
    let info = run(
        "ntfsinfo-volume",
        &ntfsinfo,
        &[std::ffi::OsStr::new("-m"), image.as_os_str()],
    );
    fs::write(out.join("ntfsinfo-volume.txt"), &info.stdout).unwrap();
    let text = String::from_utf8(info.stdout).unwrap();
    let number = |prefix: &str| -> u64 {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(prefix))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    let clusters = number("Volume Size in Clusters:");
    let free = number("Free Clusters:");
    let native = run(
        "ntfscat-mft",
        &ntfscat,
        &[image.as_os_str(), std::ffi::OsStr::new("$MFT")],
    );
    fs::write(out.join("native-mft.bin"), &native.stdout).unwrap();
    assert!(native.stdout.len().is_multiple_of(1024));
    let mut allocated = 0;
    let mut extensions = 0;
    for record in native.stdout.chunks_exact(1024) {
        if &record[..4] != b"FILE"
            || u16::from_le_bytes(record[22..24].try_into().unwrap()) & 1 == 0
        {
            continue;
        }
        allocated += 1;
        if u64::from_le_bytes(record[32..40].try_into().unwrap()) != 0 {
            extensions += 1;
        }
    }
    assert!(
        extensions > 0,
        "native fixture must exercise allocated extensions"
    );
    let resources = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let read = NtfsReadLimits {
        attributes: 128,
        runs: 256,
        names: 64,
    };
    let streams = partmgr::fs_ntfs::NtfsStreamLimits {
        extension_records: 128,
        list_entries: 2048,
        list_bytes: 1 << 20,
        attributes: 256,
        runs: 1024,
        work: 2 << 20,
    };
    let cap = NtfsAuditLimits {
        clusters: 1 << 20,
        records: 1 << 18,
        attributes: 1 << 20,
        ranges: 8192,
        entries: 1024,
        index_blocks: 1024,
        depth: 64,
        work: 1_000_000_000,
        findings: 1024,
        free_ranges: 1024,
    };
    let report = partmgr::fs_ntfs_audit::audit_ntfs_resolved(
        Arc::new(Image::new(bytes)),
        read,
        streams,
        cap,
        &resources,
    )
    .unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert!(report.is_complete());
    assert_eq!(report.clusters(), clusters);
    assert_eq!(report.allocated_clusters(), clusters - free);
    assert_eq!(report.allocated_records(), allocated);
    assert_eq!(report.owned_clusters(), report.allocated_clusters());
    let report_text = format!(
        "clusters={}\nallocated={}\nrecords={}\nnative_extensions={}\nattributes={}\nwork={}\nimage_sha256={:x}\nreader_sha256={:x}\nstream_sha256={:x}\naudit_sha256={:x}\ntest_binary_sha256={:x}\n",
        report.clusters(),
        report.allocated_clusters(),
        report.allocated_records(),
        extensions,
        report.attributes(),
        report.work(),
        image_hash,
        Sha256::digest(include_bytes!("../src/fs_ntfs.rs")),
        Sha256::digest(include_bytes!("../src/fs_ntfs_stream.rs")),
        Sha256::digest(include_bytes!("../src/fs_ntfs_audit.rs")),
        Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    fs::write(out.join("report.txt"), report_text).unwrap();
    drop(report);
    assert_eq!(resources.memory.used(), 0);
    assert_eq!(Sha256::digest(fs::read(&image).unwrap()), image_hash);
    assert_eq!(source_check(), source_start);
    fs::write(out.join("source-end.sha256"), source_check()).unwrap();
    assert_eq!(
        Sha256::digest(fs::read(&ntfsinfo).unwrap()),
        info_tool_start
    );
    assert_eq!(Sha256::digest(fs::read(&ntfscat).unwrap()), cat_tool_start);
    fs::copy(out.join("tools-start.sha256"), out.join("tools-end.sha256")).unwrap();
}
